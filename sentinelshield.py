from flask import Flask, request
import re, time, csv, os
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

SQL_PATTERN = r"(union.*select|select.*from|insert.*into|drop.*table|or\s+'1'='1|--|;)"
XSS_PATTERN = r"(<script|</script>|javascript:|onerror=|onload=|alert\()"
LFI_PATTERN = r"(\.\./|/etc/passwd|/etc/shadow|php://filter|file://)"
CMD_PATTERN = r"(whoami|cat\s|ls\s|rm\s|wget\s|curl\s|;\s*\w|&&|\|\|)"

RULES = [
    ("SQL Injection", SQL_PATTERN),
    ("XSS",           XSS_PATTERN),
    ("LFI/Traversal", LFI_PATTERN),
    ("Cmd Injection", CMD_PATTERN),
]

ip_requests = defaultdict(list)
MAX_REQUESTS = 5
TIME_WINDOW  = 10
LOG_FILE     = "sentinel_log.csv"

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        csv.writer(f).writerow(["Timestamp","IP","Method","Path","Action","Attack_Type","Details"])

def write_log(ip, method, path, action, attack_type="", details=""):
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, method, path, action, attack_type, details])

def is_rate_limited(ip):
    now = time.time()
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < TIME_WINDOW]
    ip_requests[ip].append(now)
    count = len(ip_requests[ip])
    return (True, count) if count > MAX_REQUESTS else (False, count)

def scan_value(value):
    for attack_type, pattern in RULES:
        if re.search(pattern, value, re.IGNORECASE):
            return "BLOCKED", attack_type
    return "ALLOWED", None

@app.route("/")
def home():
    return "SentinelShield is running!"

@app.route("/inspect")
def inspect():
    ip     = request.remote_addr
    method = request.method
    path   = request.path
    params = dict(request.args)

    limited, count = is_rate_limited(ip)
    if limited:
        write_log(ip, method, path, "BLOCKED", "Rate Limit", f"{count} requests in {TIME_WINDOW}s")
        return f"IP: {ip}\nSTATUS: BLOCKED - RATE LIMIT EXCEEDED\nREQUESTS: {count} in {TIME_WINDOW}s"

    results = []
    verdict = "ALL CLEAR - REQUEST ALLOWED"
    attack_found = ""
    for key, value in params.items():
        status, attack_type = scan_value(value)
        if status == "BLOCKED":
            results.append(f"{key} = {value}  ->  BLOCKED [{attack_type}]")
            verdict = f"ATTACK DETECTED [{attack_type}] - REQUEST BLOCKED"
            attack_found = attack_type
        else:
            results.append(f"{key} = {value}  ->  ALLOWED")

    if attack_found:
        write_log(ip, method, path, "BLOCKED", attack_found, str(params))
    else:
        write_log(ip, method, path, "ALLOWED", "", str(params))

    scan_output = "\n".join(results) if results else "No parameters"
    return f"""
METHOD:   {method}
PATH:     {path}
IP:       {ip}
REQUESTS: {count}/{MAX_REQUESTS} in {TIME_WINDOW}s
PARAMS:   {params}

--- WAF SCAN ---
{scan_output}

VERDICT:  {verdict}
"""

@app.route("/logs")
def view_logs():
    if not os.path.exists(LOG_FILE):
        return "No logs yet."
    with open(LOG_FILE, "r") as f:
        return f"<pre>{f.read()}</pre>"

@app.route("/dashboard")
def dashboard():
    total = blocked = allowed = 0
    attack_counts = defaultdict(int)
    recent = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            rows = list(csv.reader(f))[1:]
        total = len(rows)
        for row in rows:
            if row[4] == "BLOCKED":
                blocked += 1
                attack_counts[row[5]] += 1
            else:
                allowed += 1
        recent = rows[-5:]

    attack_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in attack_counts.items())
    recent_rows = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[4]}</td><td>{r[5]}</td></tr>" for r in recent)

    return f"""
<!DOCTYPE html>
<html>
<head>
<title>SentinelShield Dashboard</title>
<style>
  body {{ font-family: Arial; background: #0d1117; color: #c9d1d9; padding: 30px; }}
  h1   {{ color: #58a6ff; }}
  h2   {{ color: #79c0ff; margin-top: 30px; }}
  .cards {{ display: flex; gap: 20px; margin: 20px 0; }}
  .card  {{ background: #161b22; padding: 20px 30px; border-radius: 8px; text-align: center; border: 1px solid #30363d; }}
  .card h3 {{ font-size: 36px; margin: 5px 0; }}
  .total  {{ color: #58a6ff; }}
  .blocked {{ color: #f85149; }}
  .allowed {{ color: #3fb950; }}
  table {{ border-collapse: collapse; width: 100%; background: #161b22; border-radius: 8px; }}
  th {{ background: #21262d; color: #79c0ff; padding: 10px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #30363d; }}
</style>
</head>
<body>
<h1>SentinelShield Dashboard</h1>
<div class="cards">
  <div class="card"><p>Total Requests</p><h3 class="total">{total}</h3></div>
  <div class="card"><p>Blocked</p><h3 class="blocked">{blocked}</h3></div>
  <div class="card"><p>Allowed</p><h3 class="allowed">{allowed}</h3></div>
</div>
<h2>Attacks by Type</h2>
<table><tr><th>Attack Type</th><th>Count</th></tr>{attack_rows}</table>
<h2>Recent Events</h2>
<table><tr><th>Timestamp</th><th>IP</th><th>Action</th><th>Attack Type</th></tr>{recent_rows}</table>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)