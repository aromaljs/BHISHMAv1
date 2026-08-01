def grade_from_score(score):
    if score >= 90:
        return "A - CRITICAL RISK"
    elif score >= 70:
        return "B - HIGH RISK"
    elif score >= 40:
        return "C - MEDIUM RISK"
    elif score >= 15:
        return "D - LOW RISK"
    return "E - MINIMAL RISK"

def summarize_findings(exploit_results):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for findings in exploit_results.values():
        for finding in findings:
            sev = finding.get("severity", "INFO").upper()
            summary[sev] = summary.get(sev, 0) + 1

    return summary
