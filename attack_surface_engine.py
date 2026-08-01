def _risk_label(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "MINIMAL"


def analyze_attack_surface(port, banner, findings=None):
    findings = findings or []
    text = str(banner).lower()

    score = 0
    reasons = []
    category = "General Exposure"

    if port in [80, 443, 8080, 8443]:
        score += 15
        category = "Web Entry Point"
        reasons.append("Web service reachable")

    if port in [10000, 20000] or "webmin" in text or "miniserv" in text:
        score += 30
        category = "Management Interface"
        reasons.append("Administrative interface exposed")

    if port in [139, 445] or "smb" in text or "samba" in text:
        score += 25
        category = "Lateral Movement Surface"
        reasons.append("SMB/Samba reachable")

    if port in [3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211]:
        score += 30
        category = "Database/Data Service Exposure"
        reasons.append("Database or data service exposed")

    if port in [21, 23]:
        score += 20
        category = "Legacy Cleartext Service"
        reasons.append("Legacy or cleartext service reachable")

    if port == 22:
        score += 8
        category = "Remote Administration"
        reasons.append("Remote administration service reachable")

    for finding in findings:
        title = str(finding.get("title", "")).lower()
        ftype = str(finding.get("finding_type", "")).lower()
        severity = str(finding.get("severity", "")).upper()

        if "configuration" in ftype:
            score += 3
            reasons.append(f"Configuration issue: {finding.get('title')}")

        if "default web server page" in title:
            score += 6
            reasons.append("Default web page exposed")

        if "server version disclosure" in title:
            score += 5
            reasons.append("Version disclosure present")

        if "missing content-security-policy" in title:
            score += 4
            reasons.append("Missing CSP header")

        if severity == "CRITICAL":
            score += 25
            reasons.append("Critical finding present")
        elif severity == "HIGH":
            score += 15
            reasons.append("High severity finding present")
        elif severity == "MEDIUM":
            score += 8
            reasons.append("Medium severity finding present")

    score = min(score, 100)

    return {
        "score": score,
        "label": _risk_label(score),
        "category": category,
        "reasons": sorted(set(reasons)),
        "summary": f"{category} with {_risk_label(score)} exposure score ({score}/100).",
    }


def format_attack_surface(attack_surface):
    reasons = attack_surface.get("reasons", [])

    if not reasons:
        reason_text = "No major attack surface factors detected."
    else:
        reason_text = "\n".join(f"- {r}" for r in reasons)

    return (
        f"Attack Surface Score: {attack_surface.get('score', 0)}/100\n"
        f"Exposure Label: {attack_surface.get('label', 'UNKNOWN')}\n"
        f"Category: {attack_surface.get('category', 'Unknown')}\n"
        f"Reasons:\n{reason_text}"
    )
