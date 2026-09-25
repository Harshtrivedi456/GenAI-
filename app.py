import json, os, collections
import pandas as pd
import streamlit as st
from google import genai
from google.genai import types

MODEL = os.getenv("LLM_MODEL", "gemini-3.6-flash")

def has(cmds, keys): return any(k in c for c in cmds for k in keys)

# (behaviour, MITRE ATT&CK id, detector)
RULES = [
    ("Brute-force login attempts", "T1110", lambda s: len(s["failed"]) >= 5),
    ("Valid account used", "T1078", lambda s: s["success"] is not None),
    ("System discovery / recon", "T1082", lambda s: has(s["cmds"], ["uname", "whoami", "cpuinfo", "lscpu", "ifconfig", "/etc/passwd"])),
    ("Malware / tool download", "T1105", lambda s: bool(s["downloads"]) or has(s["cmds"], ["wget", "curl", "tftp", "ftpget"])),
    ("Persistence (SSH key / cron)", "T1098.004", lambda s: has(s["cmds"], ["authorized_keys", "crontab"])),
    ("Cryptominer / resource hijacking", "T1496", lambda s: has(s["cmds"], ["xmrig", "minerd", "stratum"])),
    ("Log / history clearing", "T1070", lambda s: has(s["cmds"], ["history -c", "rm -rf /var/log", "unset HISTFILE"])),
]

def parse(text):
    out = []
    for line in text.splitlines():
        try: out.append(json.loads(line))
        except Exception: pass
    return out

def build_sessions(events):
    S = collections.defaultdict(lambda: {"ip": None, "start": None, "end": None, "failed": [],
                                         "success": None, "cmds": [], "downloads": []})
    for e in events:
        sid = e.get("session")
        if not sid: continue
        s, eid = S[sid], e.get("eventid", "")
        s["ip"] = s["ip"] or e.get("src_ip")
        s["start"] = s["start"] or e.get("timestamp"); s["end"] = e.get("timestamp")
        if eid == "cowrie.login.failed": s["failed"].append(f'{e.get("username")}:{e.get("password")}')
        elif eid == "cowrie.login.success": s["success"] = f'{e.get("username")}:{e.get("password")}'
        elif eid == "cowrie.command.input": s["cmds"].append(e.get("input", ""))
        elif eid == "cowrie.session.file_download": s["downloads"].append(e.get("url", ""))
    for s in S.values():
        s["tags"] = [(n, t) for n, t, f in RULES if f(s)]
        s["severity"] = "High" if len(s["tags"]) >= 4 else "Medium" if len(s["tags"]) >= 2 else "Low"
    return dict(S)

def facts_for_llm(sessions):
    return json.dumps([{
        "session": sid, "attacker_ip": s["ip"], "start": s["start"], "end": s["end"],
        "failed_logins": len(s["failed"]), "sample_failed_creds": s["failed"][:5],
        "successful_login": s["success"], "commands": s["cmds"][:30], "downloads": s["downloads"],
        "detected_behaviours": [f"{n} ({t})" for n, t in s["tags"]], "severity": s["severity"],
    } for sid, s in sessions.items()], indent=1)

SYSTEM = """You are a SOC analyst writing an incident report from honeypot data.
Use ONLY the facts provided. Never invent IPs, times, or commands. If something is unknown, say so.
Write in Markdown with these sections: Executive Summary, Timeline, Attacker Behaviour Analysis
(reference MITRE ATT&CK IDs given), Indicators of Compromise (IPs, URLs, credentials), Impact,
Recommended Actions. Note this is a honeypot, so no real systems were compromised."""

def generate_report(key, sessions):
    import time
    client = genai.Client(api_key=key)
    last_err = None
    for attempt in range(4):
        try:
            r = client.models.generate_content(
                model=MODEL,
                contents="Honeypot session data:\n" + facts_for_llm(sessions),
                config=types.GenerateContentConfig(system_instruction=SYSTEM),
            )
            return r.text
        except Exception as e:
            last_err = e
            if "503" in str(e) or "UNAVAILABLE" in str(e):
                time.sleep(2 ** attempt)  # 1s, 2s, 4s, 8s
                continue
            raise
    raise last_err

st.set_page_config(page_title="Honeypot Incident Reporter", layout="wide")
st.title("🍯 Honeypot Incident Report Generator")
key = st.sidebar.text_input("Gemini API key", value=os.getenv("GEMINI_API_KEY", ""), type="password")
up = st.sidebar.file_uploader("Cowrie JSON log (.json / .log)")
use_sample = st.sidebar.checkbox("Use sample data", value=up is None)

text = up.read().decode("utf-8", "ignore") if up else (open("sample_cowrie.json").read() if use_sample else "")
if not text: st.info("Upload a Cowrie log or tick 'Use sample data'."); st.stop()

sessions = build_sessions(parse(text))
st.subheader(f"{len(sessions)} attacker sessions")
st.dataframe(pd.DataFrame([{
    "session": sid, "ip": s["ip"], "failed logins": len(s["failed"]), "commands": len(s["cmds"]),
    "behaviours": ", ".join(f"{n} [{t}]" for n, t in s["tags"]), "severity": s["severity"]}
    for sid, s in sessions.items()]), use_container_width=True)

pick = st.selectbox("Inspect session", list(sessions))
st.code("\n".join(sessions[pick]["cmds"]) or "(no commands)", language="bash")

if st.button("Generate incident report", type="primary"):
    if not key:
        st.error("Add your Gemini API key in the sidebar.")
    else:
        try:
            with st.spinner("Writing report..."):
                rep = generate_report(key, sessions)
            st.markdown(rep)
            st.download_button("Download .md", rep, "incident_report.md")
        except Exception as e:
            st.error(f"Error: {e}")
