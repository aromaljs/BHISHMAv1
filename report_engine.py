import datetime
import html
import os

def build_recommendations(recon_data, enum_data, exploit_data):
    recommendations = []
    ports = set()

    for port in enum_data.keys():
        try:
            ports.add(int(port))
        except Exception:
            pass

    if 80 in ports or 443 in ports or 8080 in ports:
        recommendations.append("Inspect web pages and page source for hidden comments, exposed paths, default pages, and developer notes.")

    if 139 in ports or 445 in ports:
        recommendations.append("Enumerate SMB shares, users, anonymous access, signing status, and exposed file permissions.")

    if 10000 in ports or 20000 in ports:
        recommendations.append("Review exposed Webmin/Usermin management interfaces and confirm whether access is restricted to trusted users.")

    if 22 in ports:
        recommendations.append("Review SSH exposure, authentication policy, weak credentials risk, and possible credential reuse.")

    for findings in exploit_data.values():
        for finding in findings:
            title = str(finding.get("title", "")).lower()
            evidence = str(finding.get("evidence", "")).lower()

            if "default web server page" in title or "default" in evidence:
                recommendations.append("Default web content was detected. Check whether it leaks environment details or hidden application hints.")

            if "version disclosure" in title:
                recommendations.append("Version disclosure was detected. Correlate disclosed versions with known vulnerabilities and patch status.")

            if "missing" in title and "header" in title:
                recommendations.append("Missing security headers were detected. Harden HTTP response headers before production exposure.")

            if "management interface" in evidence:
                recommendations.append("Management interfaces should be restricted, monitored, and protected with strong authentication.")

    if not recommendations:
        recommendations.append("Continue manual validation with directory discovery, service-specific enumeration, and configuration review.")

    unique = []

    for item in recommendations:
        if item not in unique:
            unique.append(item)

    return unique[:8]

def build_web_intelligence(web_recon_data):
    intelligence = []

    if not web_recon_data:
        return intelligence

    for port, result in web_recon_data.items():
        classifications = result.get(
            "form_classifications",
            [],
        )

        pages = result.get(
            "pages_crawled",
            [],
        )

        inputs = result.get(
            "inputs",
            [],
        )

        resources = result.get(
            "interesting_links",
            [],
        )

        cookies = result.get(
            "cookies",
            [],
        )

        comments = result.get(
            "comments",
            [],
        )

        auth_forms = sum(
            1
            for form in classifications
            if form.get("type") == "Authentication Form"
        )

        search_forms = sum(
            1
            for form in classifications
            if form.get("type") == "Search Form"
        )

        upload_forms = sum(
            1
            for form in classifications
            if form.get("type") == "File Upload Form"
        )

        management_surface = any(
            item.get("classification") == "Management"
            for item in resources
        )

        authentication_surface = auth_forms > 0

        if management_surface and authentication_surface:
            overall_exposure = "HIGH"
        elif management_surface or authentication_surface:
            overall_exposure = "MEDIUM"
        else:
            overall_exposure = "LOW"

        intelligence.append(
            {
                "port": port,
                "server": result.get(
                    "server",
                    "Unknown",
                ),
                "powered_by": result.get(
                    "powered_by",
                    "Unknown",
                ),
                "pages": pages,
                "page_count": len(pages),
                "authentication_forms": auth_forms,
                "search_forms": search_forms,
                "upload_forms": upload_forms,
                "input_count": len(inputs),
                "resource_count": len(resources),
                "cookie_count": len(cookies),
                "comment_count": len(comments),
                "forms": classifications,
                "inputs": inputs,
                "resources": resources,
                "cookies": cookies,
                "management_surface": (
                    "HIGH"
                    if management_surface
                    else "LOW"
                ),
                "authentication_surface": (
                    "HIGH"
                    if authentication_surface
                    else "LOW"
                ),
                "overall_exposure": overall_exposure,
            }
        )

    return intelligence

def clean_evidence(value):
    if isinstance(value, dict):
        return value.get("evidence", str(value))

    text = str(value)

    if "'evidence':" in text:
        try:
            start = text.split("'evidence':", 1)[1]
            evidence = start.split("'reason':", 1)[0]

            return (
                evidence
                .replace("'", "")
                .replace(",", "")
                .strip()
            )
        except Exception:
            return text

    return text

from risk_engine import summarize_findings, grade_from_score
from exploit_engine import calculate_risk_score


def generate_report(
    target,
    recon_data,
    enum_data,
    exploit_data,
    web_recon_data=None,
    web_detection_data=None,
    web_verification_data=None,
    correlation_data=None,
    roadmap_data=None,
):
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    generated_at = datetime.datetime.now()
    timestamp = generated_at.strftime("%Y%m%d_%H%M%S")

    safe_target = (
        str(target)
        .replace(".", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )

    filename = os.path.join(
        reports_dir,
        f"BHISHMA_Report_{safe_target}_{timestamp}.html",
    )

    risk_score = calculate_risk_score(exploit_data)
    grade = grade_from_score(risk_score)
    summary = summarize_findings(exploit_data)
    recommendations = build_recommendations(
        recon_data,
        enum_data,
        exploit_data,
    )

    web_intelligence = build_web_intelligence(
        web_recon_data or {},
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"""
<!DOCTYPE html>
<html>
<head>
<title>BHISHMA Enterprise Report</title>
<style>
body {{
    background:#070A12;
    color:#EAF2FF;
    font-family:Arial, sans-serif;
    padding:35px;
}}
.header {{
    border:1px solid #00B8FF;
    border-radius:16px;
    padding:28px;
    background:#0D1117;
    margin-bottom:20px;
}}
.title {{
    font-size:34px;
    font-weight:bold;
    color:#FFFFFF;
}}
.subtitle {{
    color:#00E5FF;
    font-size:14px;
    font-weight:bold;
    letter-spacing:1px;
}}
.card {{
    background:#0D1117;
    padding:20px;
    margin:16px 0;
    border-radius:14px;
    border:1px solid #1D5FA8;
}}
.grid {{
    display:grid;
    grid-template-columns:repeat(5, 1fr);
    gap:12px;
}}
.stat {{
    background:#111827;
    border:1px solid #274D7E;
    border-radius:12px;
    padding:16px;
}}
.stat h3 {{
    margin:0;
    color:#8B949E;
    font-size:12px;
}}
.stat p {{
    margin:8px 0 0;
    font-size:24px;
    font-weight:bold;
}}
.critical {{ color:#FF3D57; }}
.high {{ color:#FF6B00; }}
.medium {{ color:#FFB300; }}
.low {{ color:#00E676; }}
.info {{ color:#00E5FF; }}
pre {{
    background:#05070D;
    padding:16px;
    border-radius:10px;
    border:1px solid #1F2A3D;
    overflow:auto;
}}
table {{
    width:100%;
    border-collapse:collapse;
    margin-top:10px;
}}
td, th {{
    border:1px solid #1F2A3D;
    padding:10px;
    vertical-align:top;
}}
th {{
    background:#111827;
    color:#00E5FF;
}}
.roadmap-grid {{
    margin:14px 0 22px;
}}
.roadmap-step {{
    background:#080C14;
    border-left:4px solid #00B8FF;
    border-radius:10px;
    padding:16px 18px;
    margin:16px 0;
}}
.roadmap-step h3 {{ margin-top:0; }}
.disclaimer {{
    background:#111827;
    border:1px solid #274D7E;
    border-radius:10px;
    padding:14px;
    color:#B7C3D6;
}}
hr {{ border:0; border-top:1px solid #1F2A3D; margin:20px 0; }}
.progress-container{{
    width:100%;
    height:18px;
    background:#1B2432;
    border-radius:10px;
    overflow:hidden;
    border:1px solid #2D4A68;
    margin:10px 0;
}}

.progress-bar{{
    height:100%;
    background:linear-gradient(90deg,#00E676,#FFB300,#FF6B00,#FF3D57);
    text-align:center;
    color:white;
    font-size:11px;
    font-weight:bold;
    line-height:18px;
}}
.footer {{
    margin-top:30px;
    color:#8B949E;
    font-size:12px;
    text-align:center;
}}
</style>
</head>
<body>

<div class="header">
    <div class="title">BHISHMA ENTERPRISE</div>
    <div class="subtitle">SECURITY ASSESSMENT REPORT</div>
    <p><b>Target:</b> {html.escape(str(target))}</p>
    <p><b>Generated:</b> {generated_at.strftime("%d-%b-%Y %I:%M %p")}</p>
    <p><b>Overall Risk:</b> {html.escape(str(grade))}</p>
    <p><b>Risk Score:</b> {risk_score}/100</p>
</div>

<div class="grid">
    <div class="stat"><h3>CRITICAL</h3><p class="critical">{summary.get("CRITICAL", 0)}</p></div>
    <div class="stat"><h3>HIGH</h3><p class="high">{summary.get("HIGH", 0)}</p></div>
    <div class="stat"><h3>MEDIUM</h3><p class="medium">{summary.get("MEDIUM", 0)}</p></div>
    <div class="stat"><h3>LOW</h3><p class="low">{summary.get("LOW", 0)}</p></div>
    <div class="stat"><h3>INFO</h3><p class="info">{summary.get("INFO", 0)}</p></div>
</div>

<div class="card">
<h2>Executive Summary</h2>

<p>
BHISHMA performed an automated attack surface assessment against
<b>{html.escape(str(target))}</b>.
The assessment included reconnaissance, service fingerprinting,
web intelligence, vulnerability correlation, behavioral verification,
and attack-path analysis.
</p>

<table>
<tr>
    <th width="30%">Assessment Item</th>
    <th>Result</th>
</tr>

<tr>
    <td>Overall Risk</td>
    <td><b>{html.escape(str(grade))}</b> ({risk_score}/100)</td>
</tr>

<tr>
    <td>Critical Findings</td>
    <td>{summary.get("CRITICAL",0)}</td>
</tr>

<tr>
    <td>High Findings</td>
    <td>{summary.get("HIGH",0)}</td>
</tr>

<tr>
    <td>Services Enumerated</td>
    <td>{len(enum_data)}</td>
</tr>

<tr>
    <td>Web Applications</td>
    <td>{len(web_intelligence)}</td>
</tr>

<tr>
    <td>Assessment Scope</td>
    <td>
Reconnaissance →
Enumeration →
Web Intelligence →
Detection →
Verification →
Correlation
    </td>
</tr>

</table>

<p style="margin-top:15px;">
This report presents evidence gathered during the assessment and
correlates observations into potential attack paths.
Automated findings should be manually validated before concluding that a
vulnerability exists.
</p>

</div>

<div class="card">
<h2>Assessment Metadata</h2>

<table>

<tr>
    <th width="30%">Property</th>
    <th>Value</th>
</tr>

<tr>
    <td>Assessment Type</td>
    <td>Automated Unauthenticated Security Assessment</td>
</tr>

<tr>
    <td>Target Host</td>
    <td>{html.escape(str(target))}</td>
</tr>

<tr>
    <td>Generated</td>
    <td>{generated_at.strftime("%d %b %Y %I:%M:%S %p")}</td>
</tr>

<tr>
    <td>Risk Score</td>
    <td>{risk_score}/100 ({html.escape(str(grade))})</td>
</tr>

<tr>
    <td>Recon Records</td>
    <td>{len(recon_data)}</td>
</tr>

<tr>
    <td>Enumerated Services</td>
    <td>{len(enum_data)}</td>
</tr>

<tr>
    <td>Vulnerability Findings</td>
    <td>{len(exploit_data)}</td>
</tr>

<tr>
    <td>Modules Executed</td>
    <td>
Recon →
Enumeration →
Web Recon →
Detection →
Verification →
Correlation →
Roadmap
    </td>
</tr>

<tr>
    <td>Assessment Status</td>
    <td>
Completed Successfully
    </td>
</tr>

<tr>
    <td>Validation Notice</td>
    <td>
Automated observations should always be confirmed through authorized manual validation.
    </td>
</tr>

</table>

</div>

<div class="card">
<h2>Recon Results</h2>
<pre>{html.escape(chr(10).join(map(str, recon_data)))}</pre>
</div>

<div class="card">
<h2>Service Enumeration</h2>
<table>
<tr><th>Port</th><th>Service / Banner</th></tr>
""")

        for port, service in enum_data.items():

            if isinstance(service, dict):
                service_name = service.get("service", "Unknown")
                product = service.get("product", "Unknown")
                version = service.get("version", "Unknown")
                confidence = service.get("confidence", 0)
                quality = service.get("quality", "UNKNOWN")

                service_text = (
                    f"{service_name} | "
                    f"Product: {product} | "
                    f"Version: {version} | "
                    f"Confidence: {confidence}% ({quality})"
                )

            else:
                service_text = str(service)

            f.write(
                f"<tr><td>{html.escape(str(port))}</td>"
                f"<td>{html.escape(service_text)}</td></tr>"
            )

        f.write("""
</table>
</div>
""")

        if web_intelligence:
            f.write("""
<div class="card">
<h2>Web Application Intelligence</h2>
""")

            for result in web_intelligence:
                exposure_class = (
                    "high"
                    if result["overall_exposure"] == "HIGH"
                    else "medium"
                    if result["overall_exposure"] == "MEDIUM"
                    else "low"
                )

                f.write(f"""
<h3>Web Service — Port {html.escape(str(result["port"]))}/TCP</h3>

<table>
<tr>
<th>Metric</th>
<th>Result</th>
</tr>
<tr>
<td>Server</td>
<td>{html.escape(str(result["server"]))}</td>
</tr>
<tr>
<td>Powered By</td>
<td>{html.escape(str(result["powered_by"]))}</td>
</tr>
<tr>
<td>Pages Crawled</td>
<td>{result["page_count"]}</td>
</tr>
<tr>
<td>Authentication Forms</td>
<td>{result["authentication_forms"]}</td>
</tr>
<tr>
<td>Search Forms</td>
<td>{result["search_forms"]}</td>
</tr>
<tr>
<td>Upload Forms</td>
<td>{result["upload_forms"]}</td>
</tr>
<tr>
<td>Input Parameters</td>
<td>{result["input_count"]}</td>
</tr>
<tr>
<td>Interesting Resources</td>
<td>{result["resource_count"]}</td>
</tr>
<tr>
<td>Cookies</td>
<td>{result["cookie_count"]}</td>
</tr>
<tr>
<td>HTML Comments</td>
<td>{result["comment_count"]}</td>
</tr>
<tr>
<td>Management Surface</td>
<td>{result["management_surface"]}</td>
</tr>
<tr>
<td>Authentication Surface</td>
<td>{result["authentication_surface"]}</td>
</tr>
<tr>
<td>Overall Web Exposure</td>
<td class="{exposure_class}">{result["overall_exposure"]}</td>
</tr>
</table>

<h3>Pages Discovered</h3>
<ul>
""")

                for page in result["pages"]:
                    f.write(
                        f"<li>{html.escape(str(page))}</li>"
                    )

                f.write("""
</ul>

<h3>Form Intelligence</h3>
<ul>
""")

                if result["forms"]:
                    for form in result["forms"]:
                        form_text = (
                            f"[{form.get('type', 'General Form')}] "
                            f"{form.get('page', '/')} | "
                            f"{form.get('method', 'GET')} → "
                            f"{form.get('action', '') or '/'}"
                        )

                        f.write(
                            f"<li>{html.escape(form_text)}</li>"
                        )
                else:
                    f.write("<li>No forms detected.</li>")

                f.write("""
</ul>

<h3>Input Fields</h3>
<ul>
""")

                if result["inputs"]:
                    for item in result["inputs"]:
                        input_text = (
                            f"{item.get('page', '/')} | "
                            f"{item.get('field', '')}"
                        )

                        f.write(
                            f"<li>{html.escape(input_text)}</li>"
                        )
                else:
                    f.write("<li>No input fields detected.</li>")

                f.write("""
</ul>

<h3>Interesting Resources</h3>
<ul>
""")

                if result["resources"]:
                    for item in result["resources"]:
                        resource_text = (
                            f"[{item.get('classification', 'Resource')}] "
                            f"{item.get('path', '')}"
                        )

                        status_code = item.get(
                            "status_code",
                            "",
                        )

                        if status_code:
                            resource_text += (
                                f" — HTTP {status_code}"
                            )

                        f.write(
                            f"<li>{html.escape(resource_text)}</li>"
                        )
                else:
                    f.write(
                        "<li>No interesting resources detected.</li>"
                    )

                f.write("""
</ul>
""")

            f.write("""
</div>
""")

        f.write("""
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
                sev = str(finding.get("severity", "INFO")).lower()
                title = str(finding.get("title", "Unnamed Finding"))
                confidence = str(finding.get("confidence", "UNKNOWN"))
                status = str(finding.get("status", "")).upper()

                evidence_text = clean_evidence(
                    finding.get("evidence", "No evidence recorded.")
                )

                remediation_text = str(
                    finding.get(
                        "remediation",
                        "Review and manually validate the observation."
                    )
                )

                reason_text = str(
                    finding.get(
                        "reason",
                        "The observed service behavior, fingerprint, headers, "
                        "or application response matched BHISHMA's detection logic."
                    )
                )

                mitre_value = (
                    finding.get("mitre_attack")
                    or finding.get("mitre")
                    or finding.get("mitre_technique")
                    or finding.get("technique")
                    or "Not mapped — insufficient evidence for ATT&CK classification."
                )

                if isinstance(mitre_value, (list, tuple, set)):
                    mitre_text = ", ".join(map(str, mitre_value))
                elif isinstance(mitre_value, dict):
                    mitre_text = ", ".join(
                        f"{key}: {value}"
                        for key, value in mitre_value.items()
                    )
                else:
                    mitre_text = str(mitre_value)

                show_evidence_card = (
                    sev in ("critical", "high")
                    or title.lower() == "attack surface assessment"
                    or status in (
                        "CONFIRMED",
                        "VERIFIED",
                        "BEHAVIORALLY INDICATED",
                    )
                )

                f.write(f"""
<tr>
<td>{html.escape(str(port))}</td>
<td class="{html.escape(sev)}">{html.escape(str(finding.get("severity", "")))}</td>
<td>{html.escape(title)}</td>
<td>{html.escape(str(finding.get("cve", "N/A")))}</td>
<td>{html.escape(str(finding.get("cvss", 0)))}</td>
<td>{html.escape(confidence)}</td>
<td>{html.escape(evidence_text)}</td>
<td>{html.escape(remediation_text)}</td>
</tr>
""")

                if title.lower() == "attack surface assessment":
                    f.write(f"""
<tr>
<td colspan="8">

<div style="
background:#080C14;
border:1px solid #FF6B00;
border-left:6px solid #FF6B00;
padding:22px;
margin:12px 0;
border-radius:12px;
">

<h2 style="
margin-top:0;
margin-bottom:6px;
color:#FF6B00;
">
Attack Surface Intelligence
</h2>

<p style="
margin-top:0;
color:#B7C3D6;
">
Consolidated exposure analysis for port
<b>{html.escape(str(port))}</b>.
</p>

<div style="
display:grid;
grid-template-columns:repeat(3, 1fr);
gap:12px;
margin:18px 0;
">

<div class="stat">
<h3>EXPOSURE</h3>
<p class="{html.escape(sev)}">
{html.escape(str(finding.get("severity", "UNKNOWN")))}
</p>
</div>

<div class="stat">
<h3>CONFIDENCE</h3>
<p>{html.escape(confidence)}</p>
</div>

<div class="stat">
<h3>PORT</h3>
<p>{html.escape(str(port))}</p>
</div>

</div>

<h3>Attack Surface Score</h3>

<div class="progress-container">
<div class="progress-bar"
style="width:{min(max(int(float(finding.get('score',66))),0),100)}%;">
{html.escape(str(finding.get("score",66)))}%
</div>
</div>

<h3>Exposure Drivers</h3>

<div style="
background:#05070D;
border:1px solid #1F2A3D;
padding:16px;
border-radius:10px;
white-space:pre-wrap;
">{html.escape(evidence_text)}</div>

<h3>Why BHISHMA raised the exposure level</h3>

<p>
{html.escape(reason_text)}
</p>

<h3>Potential Investigation Progression</h3>

<div style="
background:#111827;
border:1px solid #274D7E;
padding:16px;
border-radius:10px;
text-align:center;
line-height:2;
">

Exposed Web Service
<br>↓<br>
Authentication or Management Surface Review
<br>↓<br>
Vulnerability Validation
<br>↓<br>
Credential and Access-Control Analysis
<br>↓<br>
Administrative Access Investigation

</div>

<h3>Recommended Investigation</h3>

<p>
{html.escape(remediation_text)}
</p>

<h3>MITRE ATT&amp;CK</h3>

<p>
{html.escape(mitre_text)}
</p>

<p class="disclaimer">
This exposure score represents correlated attack-surface indicators.
It does not establish successful exploitation or system compromise.
</p>

</div>

</td>
</tr>
""")

                elif show_evidence_card:
                    f.write(f"""
<tr>
<td colspan="8">

<div style="
background:#0A1018;
border-left:5px solid #00B8FF;
padding:18px;
margin:8px 0;
border-radius:10px;
">

<h3 style="margin-top:0;color:#00E5FF;">
Evidence Intelligence — {html.escape(title)}
</h3>

<table>

<tr>
<td width="25%"><b>Status</b></td>
<td>{html.escape(status or "AUTOMATED OBSERVATION")}</td>
</tr>

<tr>
<td><b>Confidence</b></td>
<td>{html.escape(confidence)}</td>
</tr>

<tr>
<td><b>Observed Evidence</b></td>
<td style="white-space:pre-wrap;">{html.escape(evidence_text)}</td>
</tr>

<tr>
<td><b>Why BHISHMA flagged this</b></td>
<td>{html.escape(reason_text)}</td>
</tr>

<tr>
<td><b>Evidence Still Required</b></td>
<td>
Authorized manual validation should determine whether the observation
is reproducible and security-relevant rather than ordinary application
or service behavior.
</td>
</tr>

<tr>
<td><b>Possible Progression</b></td>
<td>
Determine whether this finding strengthens an authentication,
management-interface, credential-access, or wider attack-path hypothesis.
</td>
</tr>

<tr>
<td><b>MITRE ATT&amp;CK</b></td>
<td>{html.escape(mitre_text)}</td>
</tr>

<tr>
<td><b>Analyst Recommendation</b></td>
<td>{html.escape(remediation_text)}</td>
</tr>

</table>

</div>

</td>
</tr>
""")

        f.write("""
</table>
</div>
""")

        # WEB DETECTION INTELLIGENCE
        detection_items = []
        for port, findings in (web_detection_data or {}).items():
            if isinstance(findings, dict):
                findings = findings.get("findings", findings.get("items", []))
            if not isinstance(findings, list):
                findings = [findings]
            for finding in findings:
                if isinstance(finding, dict):
                    detection_items.append((port, finding))

        if detection_items:
            f.write("""
<div class="card">
<h2>Web Detection Intelligence</h2>
<p class="info">Automated observations are hypotheses and require authorized manual validation.</p>
<table>
<tr><th>Port</th><th>Severity</th><th>Finding</th><th>Status</th><th>Confidence</th><th>Endpoint</th><th>Parameter</th><th>Reason</th></tr>
""")
            for port, item in detection_items:
                severity = str(item.get("severity", "INFO")).upper()
                sev_class = severity.lower() if severity.lower() in {"critical", "high", "medium", "low", "info"} else "info"
                title = item.get("title", item.get("finding", "Web Observation"))
                status = item.get("status", "HYPOTHESIS")
                confidence = item.get("confidence", "UNKNOWN")
                endpoint = item.get("endpoint", item.get("source_page", "N/A"))
                parameter = item.get("parameter", "N/A")
                reason = item.get("reason", item.get("evidence", ""))
                f.write(
                    "<tr>"
                    f"<td>{html.escape(str(port))}</td>"
                    f"<td class='{html.escape(sev_class)}'>{html.escape(severity)}</td>"
                    f"<td>{html.escape(str(title))}</td>"
                    f"<td>{html.escape(str(status))}</td>"
                    f"<td>{html.escape(str(confidence))}</td>"
                    f"<td>{html.escape(str(endpoint))}</td>"
                    f"<td>{html.escape(str(parameter))}</td>"
                    f"<td>{html.escape(clean_evidence(reason))}</td>"
                    "</tr>"
                )
            f.write("</table></div>")

        # DIFFERENTIAL WEB VERIFICATION
        verification_items = []
        for port, results in (web_verification_data or {}).items():
            if isinstance(results, dict):
                results = results.get("results", results.get("items", [results]))
            if not isinstance(results, list):
                results = [results]
            for result in results:
                if isinstance(result, dict):
                    verification_items.append((port, result))

        if verification_items:
            f.write("""
<div class="card">
<h2>Differential Web Verification</h2>
<p class="info">Behavioral differences are indicators, not proof of exploitation.</p>
<table>
<tr><th>Port</th><th>Status</th><th>Finding</th><th>Endpoint</th><th>Method</th><th>Parameter</th><th>Confidence</th><th>Comparison Evidence</th></tr>
""")
            for port, item in verification_items:
                status = str(item.get("status", "INCONCLUSIVE")).upper()
                title = item.get("title", item.get("finding", "Differential Verification"))
                endpoint = item.get("endpoint", "N/A")
                method = item.get("method", "N/A")
                parameter = item.get("parameter", "N/A")
                confidence = item.get("confidence", "UNKNOWN")
                comparison = item.get("comparison", item.get("response_comparison", {}))
                similarities = item.get("similarity", item.get("similarities", {}))
                reasons = item.get("reasons", item.get("verification_reasons", []))
                evidence_parts = []
                if isinstance(comparison, dict):
                    evidence_parts.extend(f"{k}: {v}" for k, v in comparison.items())
                elif comparison:
                    evidence_parts.append(str(comparison))
                if isinstance(similarities, dict):
                    evidence_parts.extend(f"{k}: {v}" for k, v in similarities.items())
                elif similarities:
                    evidence_parts.append(str(similarities))
                if isinstance(reasons, list):
                    evidence_parts.extend(str(x) for x in reasons)
                elif reasons:
                    evidence_parts.append(str(reasons))
                if not evidence_parts:
                    evidence_parts.append(str(item.get("evidence", item.get("reason", "No comparison details supplied."))))
                evidence_html = "<br>".join(html.escape(x) for x in evidence_parts)
                f.write(
                    "<tr>"
                    f"<td>{html.escape(str(port))}</td>"
                    f"<td><b>{html.escape(status)}</b></td>"
                    f"<td>{html.escape(str(title))}</td>"
                    f"<td>{html.escape(str(endpoint))}</td>"
                    f"<td>{html.escape(str(method))}</td>"
                    f"<td>{html.escape(str(parameter))}</td>"
                    f"<td>{html.escape(str(confidence))}</td>"
                    f"<td>{evidence_html}</td>"
                    "</tr>"
                )
            f.write("</table></div>")

        # CORRELATED ATTACK-PATH INTELLIGENCE
        correlations = correlation_data or []
        if isinstance(correlations, dict):
            correlations = correlations.get("items", correlations.get("findings", []))
        if correlations:
            f.write("""
<div class="card">
<h2>Correlated Attack-Path Intelligence</h2>
<p class="info">Correlation identifies investigation hypotheses; it does not establish compromise.</p>
""")
            for item in correlations:
                if not isinstance(item, dict):
                    continue
                severity = str(item.get("severity", "INFO")).upper()
                sev_class = severity.lower() if severity.lower() in {"critical", "high", "medium", "low", "info"} else "info"
                title = item.get("title", item.get("finding", "Correlated Hypothesis"))
                category = item.get("category", "Correlation")
                status = item.get("status", "CORRELATED HYPOTHESIS")
                confidence = item.get("confidence", "UNKNOWN")
                evidence = item.get("evidence", item.get("correlated_evidence", []))
                hypotheses = item.get("hypotheses", item.get("attack_path_hypotheses", []))
                actions = item.get("recommendations", item.get("recommended_investigation", item.get("actions", [])))
                f.write(
                    f"<h3><span class='{html.escape(sev_class)}'>[{html.escape(severity)}]</span> "
                    f"{html.escape(str(title))}</h3>"
                    f"<p><b>Category:</b> {html.escape(str(category))}<br>"
                    f"<b>Status:</b> {html.escape(str(status))}<br>"
                    f"<b>Confidence:</b> {html.escape(str(confidence))}</p>"
                )
                for heading, values in (("Correlated Evidence", evidence), ("Attack-Path Hypotheses", hypotheses), ("Recommended Investigation", actions)):
                    if not isinstance(values, list):
                        values = [values] if values else []
                    f.write(f"<h4>{heading}</h4><ul>")
                    for value in values:
                        f.write(f"<li>{html.escape(str(value))}</li>")
                    if not values:
                        f.write("<li>No additional details supplied.</li>")
                    f.write("</ul>")
                f.write("<hr>")
            f.write("</div>")

        # PRIORITIZED INVESTIGATION WORKFLOW
        roadmap = roadmap_data or {}
        roadmap_items = roadmap.get("items", []) if isinstance(roadmap, dict) else roadmap
        roadmap_summary = roadmap.get("summary", {}) if isinstance(roadmap, dict) else {}
        disclaimer = roadmap.get("disclaimer", "") if isinstance(roadmap, dict) else ""
        if roadmap_items:
            counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for item in roadmap_items:
                if isinstance(item, dict):
                    priority = str(item.get("severity", item.get("priority", "INFO"))).upper()
                    counts[priority if priority in counts else "INFO"] += 1
            f.write(f"""
<div class="card">
<h2>Prioritized Investigation Workflow</h2>
<div class="grid roadmap-grid">
<div class="stat"><h3>TOTAL STEPS</h3><p>{len(roadmap_items)}</p></div>
<div class="stat"><h3>HIGH</h3><p class="high">{counts['HIGH']}</p></div>
<div class="stat"><h3>MEDIUM</h3><p class="medium">{counts['MEDIUM']}</p></div>
<div class="stat"><h3>LOW</h3><p class="low">{counts['LOW']}</p></div>
<div class="stat"><h3>INFO</h3><p class="info">{counts['INFO']}</p></div>
</div>
""")
            for index, item in enumerate(roadmap_items, start=1):
                if not isinstance(item, dict):
                    continue
                priority = str(item.get("severity", item.get("priority", "INFO"))).upper()
                priority_class = priority.lower() if priority.lower() in {"critical", "high", "medium", "low", "info"} else "info"
                category = item.get("category", "Investigation")
                title = item.get("title", item.get("finding", f"Investigation Step {index}"))
                status = item.get("status", "")
                confidence = item.get("confidence", "")
                evidence = item.get("evidence", [])
                actions = item.get("actions", item.get("recommendations", []))
                objective = item.get("objective", "")
                source = item.get("source", "")
                f.write(
                    f"<div class='roadmap-step'>"
                    f"<h3>STEP {index} — <span class='{html.escape(priority_class)}'>{html.escape(priority)}</span></h3>"
                    f"<p><b>Category:</b> {html.escape(str(category))}<br>"
                    f"<b>Finding:</b> {html.escape(str(title))}"
                )
                if status:
                    f.write(f"<br><b>Status:</b> {html.escape(str(status))}")
                if confidence:
                    f.write(f"<br><b>Confidence:</b> {html.escape(str(confidence))}")
                if source:
                    f.write(f"<br><b>Source:</b> {html.escape(str(source))}")
                f.write("</p><h4>Evidence</h4><ul>")
                if not isinstance(evidence, list):
                    evidence = [evidence] if evidence else []
                for value in evidence:
                    f.write(f"<li>{html.escape(str(value))}</li>")
                if not evidence:
                    f.write("<li>No additional evidence supplied.</li>")
                f.write("</ul><h4>Recommended Actions</h4><ul>")
                if not isinstance(actions, list):
                    actions = [actions] if actions else []
                for value in actions:
                    f.write(f"<li>{html.escape(str(value))}</li>")
                if not actions:
                    f.write("<li>Perform authorized manual review.</li>")
                f.write("</ul>")
                if objective:
                    f.write(f"<p><b>Objective:</b> {html.escape(str(objective))}</p>")
                f.write("</div>")
            if disclaimer:
                f.write(f"<p class='disclaimer'>{html.escape(str(disclaimer))}</p>")
            f.write("</div>")

        f.write("""
<div class="card">
<h2>Next Investigation Recommendations</h2>
<ul>
""")

        for item in recommendations:
            f.write(f"<li>{html.escape(str(item))}</li>")

        f.write("""
</ul>
</div>

<div class="footer">
BHISHMA ENTERPRISE • Attack Surface Intelligence • Detection & Verification
</div>

</body>
</html>
""")

    return filename
