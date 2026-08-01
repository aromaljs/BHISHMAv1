import datetime
import html
from risk_engine import summarize_findings, grade_from_score
from exploit_engine import calculate_risk_score

def generate_report(target, recon_data, enum_data, exploit_data):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{target.replace('.', '_')}_{timestamp}.html"

    risk_score = calculate_risk_score(exploit_data)
    grade = grade_from_score(risk_score)
    summary = summarize_findings(exploit_data)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"""
<!DOCTYPE html>
<html>
<head>
<title>BHISHMA Report</title>
<style>
body {{
    background:#0A0A0F;
    color:#F0F0FF;
    font-family:Arial, sans-serif;
    padding:30px;
}}
.card {{
    background:#16161F;
    padding:20px;
    margin:15px 0;
    border-radius:10px;
    border:1px solid #2E2E4E;
}}
.critical {{ color:#FF3B3B; }}
.high {{ color:#FF6B00; }}
.medium {{ color:#FFB300; }}
.low {{ color:#00BCD4; }}
.info {{ color:#AAAAAA; }}
pre {{
    background:#111118;
    padding:15px;
    border-radius:8px;
    overflow:auto;
}}
table {{
    width:100%;
    border-collapse:collapse;
}}
td, th {{
    border:1px solid #2E2E4E;
    padding:10px;
}}
th {{
    background:#1C1C28;
}}
</style>
</head>
<body>

<h1>⚡ BHISHMA Security Assessment Report</h1>
<p><b>Target:</b> {html.escape(target)}</p>
<p><b>Date:</b> {datetime.datetime.now()}</p>

<div class="card">
<h2>Executive Summary</h2>
<p><b>Risk Score:</b> {risk_score}/100</p>
<p><b>Grade:</b> {grade}</p>
<p>
Critical: {summary.get("CRITICAL", 0)} |
High: {summary.get("HIGH", 0)} |
Medium: {summary.get("MEDIUM", 0)} |
Low: {summary.get("LOW", 0)} |
Info: {summary.get("INFO", 0)}
</p>
</div>

<div class="card">
<h2>Recon Results</h2>
<pre>
{html.escape(chr(10).join(map(str, recon_data)))}
</pre>
</div>

<div class="card">
<h2>Service Enumeration</h2>
<table>
<tr><th>Port</th><th>Banner</th></tr>
""")

        for port, banner in enum_data.items():
            f.write(f"<tr><td>{port}</td><td>{html.escape(str(banner))}</td></tr>")

        f.write("""
</table>
</div>

<div class="card">
<h2>Vulnerability Findings</h2>
<table>
<tr>
<th>Port</th>
<th>Severity</th>
<th>Title</th>
<th>CVE</th>
<th>CVSS</th>
<th>Confidence</th>
<th>Evidence</th>
<th>Remediation</th>
</tr>
""")

        for port, findings in exploit_data.items():
            for finding in findings:
                sev = finding.get("severity", "INFO").lower()
                f.write(f"""
<tr>
<td>{port}</td>
<td class="{sev}">{html.escape(finding.get("severity", ""))}</td>
<td>{html.escape(finding.get("title", ""))}</td>
<td>{html.escape(str(finding.get("cve", "N/A")))}</td>
<td>{finding.get("cvss", 0)}</td>
<td>{html.escape(finding.get("confidence", ""))}</td>
<td>{html.escape(finding.get("evidence", ""))}</td>
<td>{html.escape(finding.get("remediation", ""))}</td>
</tr>
""")

        f.write("""
</table>
</div>

</body>
</html>
""")

    return filename
