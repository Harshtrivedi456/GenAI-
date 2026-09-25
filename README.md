# Honeypot Incident Report Generator — Project Flow

## 1. Project Overview

This project is a **Generative AI–based cybersecurity tool** that turns raw honeypot
attack logs into a professional, human-readable security incident report.

A honeypot (here, **Cowrie**, a fake SSH/Telnet server) is deployed to attract
attackers. Every command they type, every login attempt, and every file they try to
download is logged. Manually reading these logs and writing an incident report is slow
and repetitive — this tool automates that process.

The system works in two stages:
1. **Rule-based detection (deterministic):** Python rules scan each attacker session
   and tag known attack behaviours (brute force, recon, malware download, persistence,
   cryptomining, log clearing), each mapped to a **MITRE ATT&CK** technique ID.
2. **LLM report writing (generative):** The tagged facts — not the raw logs — are sent
   to an LLM (Google Gemini), which writes a structured Markdown incident report:
   Executive Summary, Timeline, Attacker Behaviour Analysis, Indicators of Compromise,
   Impact, and Recommended Actions.

Splitting the work this way means the LLM never has to "decide" what happened — it only
has to explain facts that were already verified by code. This significantly reduces
hallucination risk, which is the main evaluation concern for any GenAI project.

## 2. Technologies Used

| Component            | Technology                                   |
|-----------------------|-----------------------------------------------|
| Honeypot (data source) | Cowrie (SSH/Telnet honeypot, JSON logs)       |
| Language              | Python 3.9+                                   |
| Web UI                | Streamlit                                     |
| Data handling         | Pandas                                        |
| Generative AI model   | Google Gemini API (`gemini-3.6-flash`)        |
| Threat mapping        | MITRE ATT&CK framework (technique IDs)        |
| Output format         | Markdown (downloadable `.md` report)          |

## 3. Project Workflow / Architecture

```
┌──────────────────┐
│  Cowrie Honeypot  │   (or sample_cowrie.json for demo)
│  (JSON logs)      │
└────────┬──────────┘
         │  raw events (login attempts, commands, downloads)
         ▼
┌───────────────────────────┐
│ parse() + build_sessions() │   groups events into attacker sessions
└────────┬────────────────────┘
         │ structured session data
         ▼
┌───────────────────────────┐
│   Rule Engine (RULES)      │   tags behaviours → MITRE ATT&CK IDs
│  Brute force → T1110       │
│  Recon → T1082              │
│  Malware download → T1105   │
│  Persistence → T1098.004    │
│  Cryptomining → T1496       │
│  Log clearing → T1070       │
└────────┬────────────────────┘
         │ facts_for_llm() → clean JSON of verified facts only
         ▼
┌───────────────────────────┐
│   Gemini API (LLM)         │   writes the incident report
│  system prompt: "use only  │   in Markdown, section by section
│  the facts provided"       │
└────────┬────────────────────┘
         │ Markdown report
         ▼
┌───────────────────────────┐
│   Streamlit UI              │   session table, command inspector,
│                              │   report view + .md download
└───────────────────────────┘
```

**Key design decision:** the LLM is never shown raw logs. It only sees the pre-verified
JSON facts produced by the rule engine. This keeps the report grounded in evidence and
gives a clean way to evaluate hallucination (compare the report against the facts JSON).

## 4. Key Features

- **Session reconstruction** — groups thousands of raw log lines into per-attacker
  sessions with a timeline, source IP, commands and downloads.
- **Attack behaviour detection** — rule-based tagging of 6 common attacker behaviours,
  each mapped to a MITRE ATT&CK technique ID.
- **Severity scoring** — sessions are automatically rated Low / Medium / High based on
  how many distinct behaviours were detected.
- **AI-generated incident report** — a full SOC-style Markdown report (summary,
  timeline, behaviour analysis, IOCs, impact, recommendations) generated on demand.
- **Grounded generation** — the LLM only sees verified structured facts, not raw logs,
  reducing hallucination.
- **Interactive UI** — browse sessions, inspect raw commands, and generate/download the
  report, all from a Streamlit web app.
- **Works with real or sample data** — includes a generated sample Cowrie log so the
  project can be demoed without deploying a live honeypot.

## 5. How to Run the Project

**Prerequisites:** Python 3.9+, a free Gemini API key from https://aistudio.google.com

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) regenerate sample honeypot data
python gen_sample.py

# 3. Set your API key
export GEMINI_API_KEY=your_key_here        # Mac/Linux
set GEMINI_API_KEY=your_key_here           # Windows (cmd)

# 4. Run the app
streamlit run app.py
```

Then, in the browser tab that opens (`http://localhost:8501`):
1. Tick **"Use sample data"** (or upload a real Cowrie `.json` log).
2. Review the session table and detected behaviours.
3. Select a session to inspect its raw commands.
4. Click **"Generate incident report"**.
5. Read the report and click **"Download .md"** to save it.


