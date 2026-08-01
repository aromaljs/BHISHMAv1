SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    10000: "Webmin",
    20000: "Usermin",
}


def _extract_port(line):
    try:
        return int(line.split()[1])
    except Exception:
        return None


def _network_states(recon_results):
    open_ports = set()
    filtered_ports = set()

    for line in recon_results:
        text = str(line).strip()

        if text.startswith("[+]"):
            port = _extract_port(text)

            if port is not None:
                open_ports.add(port)

        elif text.startswith("[?]"):
            port = _extract_port(text)

            if port is not None:
                filtered_ports.add(port)

    return open_ports, filtered_ports


def _flatten_web_findings(web_detection_results):
    findings = []

    for port, port_findings in web_detection_results.items():
        for finding in port_findings:
            item = dict(finding)
            item["web_port"] = port
            findings.append(item)

    return findings


def _contains_hypothesis(findings, keyword):
    keyword = keyword.lower()

    for finding in findings:
        title = str(
            finding.get("title", "")
        ).lower()

        category = str(
            finding.get("category", "")
        ).lower()

        hypotheses = " ".join(
            str(item)
            for item in finding.get("hypotheses", [])
        ).lower()

        if (
            keyword in title
            or keyword in category
            or keyword in hypotheses
        ):
            return True

    return False


def _finding(
    title,
    severity,
    confidence,
    category,
    evidence,
    hypotheses,
    recommendations,
):
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "status": "CORRELATED HYPOTHESIS",
        "evidence": evidence,
        "hypotheses": hypotheses,
        "recommendations": recommendations,
    }


def correlate_findings(
    recon_results,
    web_recon_results,
    web_detection_results,
):
    correlated = []

    open_ports, filtered_ports = _network_states(
        recon_results
    )

    web_findings = _flatten_web_findings(
        web_detection_results
    )

    path_surface = (
        _contains_hypothesis(
            web_findings,
            "path traversal",
        )
        or _contains_hypothesis(
            web_findings,
            "local file inclusion",
        )
        or _contains_hypothesis(
            web_findings,
            "file or path",
        )
    )

    config_surface = any(
        (
            finding.get("category")
            == "Sensitive File Analysis"
        )
        or (
            finding.get("title")
            == "Backup Resource Exposed"
        )
        or (
            finding.get("title")
            == "Configuration Resource Exposed"
        )
        for finding in web_findings
    )

    injection_surface = _contains_hypothesis(
        web_findings,
        "injection",
    )

    authentication_surface = _contains_hypothesis(
        web_findings,
        "authentication",
    )

    management_surface = _contains_hypothesis(
        web_findings,
        "management",
    )

    for port in sorted(filtered_ports):
        service = SERVICE_NAMES.get(
            port,
            "Unknown Service",
        )

        evidence = [
            f"Port {port}/TCP is filtered.",
            f"Likely service: {service}.",
        ]

        hypotheses = [
            "Firewall or ACL restriction",
            "IDS/IPS filtering",
            "Conditional service exposure",
            "Dynamic access control",
        ]

        recommendations = [
            "Repeat the scan after additional enumeration.",
            "Review exposed configuration and backup resources.",
            "Investigate whether access conditions change over time.",
        ]

        if port == 22:
            hypotheses.append(
                "Possible SSH port-knocking protection"
            )

            recommendations.append(
                "Investigate possible port-knocking or dynamic SSH access controls."
            )

        if path_surface or config_surface:
            evidence.append(
                "Web findings suggest possible file, path, "
                "configuration, or sensitive-resource exposure."
            )

            hypotheses.append(
                "Configuration disclosure may reveal dynamic access rules"
            )

            recommendations.append(
                "Review file/path handling and disclosed configuration data."
            )

        correlated.append(
            _finding(
                title="Dynamic Network Access Surface",
                severity="MEDIUM",
                confidence="MEDIUM",
                category="Network Access Correlation",
                evidence=evidence,
                hypotheses=hypotheses,
                recommendations=recommendations,
            )
        )

    if injection_surface and authentication_surface:
        correlated.append(
            _finding(
                title="Credential Acquisition Attack Path",
                severity="HIGH",
                confidence="MEDIUM",
                category="Web Attack-Path Correlation",
                evidence=[
                    "An injection-oriented input surface was identified.",
                    "An authentication surface was identified.",
                ],
                hypotheses=[
                    "Injection weakness may expose credentials",
                    "Recovered credentials may be reusable",
                    "Authentication bypass may become possible",
                ],
                recommendations=[
                    "Perform authorized manual injection validation.",
                    "Review authentication behavior and credential reuse.",
                    "Do not classify the weakness as confirmed without verification.",
                ],
            )
        )

    if management_surface and authentication_surface:
        correlated.append(
            _finding(
                title="Administrative Access Attack Path",
                severity="HIGH",
                confidence="MEDIUM",
                category="Management Correlation",
                evidence=[
                    "A management-oriented resource was discovered.",
                    "Authentication fields were detected.",
                ],
                hypotheses=[
                    "Administrative login exposure",
                    "Credential reuse opportunity",
                    "Access-control weakness",
                ],
                recommendations=[
                    "Review management-interface access restrictions.",
                    "Validate authentication and authorization controls.",
                    "Inspect session handling and cookie security.",
                ],
            )
        )

    if injection_surface and filtered_ports:
        correlated.append(
            _finding(
                title="Web-to-Network Progression Hypothesis",
                severity="MEDIUM",
                confidence="LOW",
                category="Attack-Chain Correlation",
                evidence=[
                    "A possible injection surface was identified.",
                    (
                        "Filtered service ports were observed: "
                        + ", ".join(
                            str(port)
                            for port in sorted(filtered_ports)
                        )
                    ),
                ],
                hypotheses=[
                    "Web weakness may disclose access-control configuration",
                    "Web compromise may reveal credentials or knock sequences",
                    "Filtered services may become reachable after discovery",
                ],
                recommendations=[
                    "Validate the web hypothesis manually.",
                    "Search authorized application output for configuration evidence.",
                    "Repeat network state verification after meaningful findings.",
                ],
            )
        )

    if not correlated and open_ports:
        correlated.append(
            _finding(
                title="No Multi-Layer Attack Path Identified",
                severity="INFO",
                confidence="HIGH",
                category="Correlation Summary",
                evidence=[
                    (
                        "Open ports observed: "
                        + ", ".join(
                            str(port)
                            for port in sorted(open_ports)
                        )
                    )
                ],
                hypotheses=[
                    "Current findings remain isolated",
                ],
                recommendations=[
                    "Continue service-specific manual investigation.",
                    "Run verification before escalating finding status.",
                ],
            )
        )

    return correlated
