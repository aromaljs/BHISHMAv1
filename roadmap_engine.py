"""
BHISHMA Investigation Roadmap Engine

Creates an evidence-based, prioritized investigation plan from
network, web, verification, correlation, and CVE findings.

This module does not exploit targets or claim unverified
vulnerabilities as confirmed.
"""


SEVERITY_PRIORITY = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFO": 5,
}


def _clean_text(value, fallback="Unknown"):
    text = str(value or "").strip()
    return text if text else fallback


def _normalise_port(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return port


def _add_item(
    items,
    title,
    category,
    severity,
    confidence,
    status,
    evidence,
    actions,
    objective,
    source,
    port=None,
):
    cleaned_evidence = [
        _clean_text(item)
        for item in evidence
        if str(item or "").strip()
    ]

    cleaned_actions = [
        _clean_text(item)
        for item in actions
        if str(item or "").strip()
    ]

    item = {
        "title": _clean_text(title, "Investigation Item"),
        "category": _clean_text(category, "General Investigation"),
        "severity": _clean_text(severity, "INFO").upper(),
        "confidence": _clean_text(confidence, "UNKNOWN").upper(),
        "status": _clean_text(status, "RECOMMENDED"),
        "evidence": cleaned_evidence,
        "actions": cleaned_actions,
        "objective": _clean_text(
            objective,
            "Review the available evidence.",
        ),
        "source": _clean_text(source, "BHISHMA"),
        "port": _normalise_port(port) if port is not None else None,
    }

    items.append(item)


def _verification_items(
    items,
    verification_results,
):
    for port, findings in verification_results.items():
        for finding in findings:
            status = _clean_text(
                finding.get("status"),
                "INCONCLUSIVE",
            ).upper()

            if status not in {
                "BEHAVIORALLY INDICATED",
                "STRONGLY INDICATED",
                "INCONCLUSIVE",
            }:
                continue

            endpoint = _clean_text(
                finding.get("endpoint"),
                "/",
            )

            parameter = _clean_text(
                finding.get("parameter"),
                "Unknown",
            )

            method = _clean_text(
                finding.get("method"),
                "GET",
            ).upper()

            evidence = [
                (
                    f"{method} parameter '{parameter}' "
                    f"was tested at {endpoint}."
                ),
                (
                    f"Behavioral verification status: "
                    f"{status}."
                ),
            ]

            metrics = finding.get("metrics", {})

            baseline_control = metrics.get(
                "baseline_control_similarity"
            )

            baseline_quote = metrics.get(
                "baseline_quote_similarity"
            )

            true_false = metrics.get(
                "true_false_similarity"
            )

            if baseline_control is not None:
                evidence.append(
                    "Baseline/control similarity: "
                    f"{baseline_control}%."
                )

            if baseline_quote is not None:
                evidence.append(
                    "Baseline/altered-input similarity: "
                    f"{baseline_quote}%."
                )

            if true_false is not None:
                evidence.append(
                    "True/false comparison similarity: "
                    f"{true_false}%."
                )

            markers = finding.get(
                "database_error_markers",
                [],
            )

            if markers:
                evidence.append(
                    "Database-oriented error indicators: "
                    + ", ".join(str(marker) for marker in markers)
                )

            if status == "STRONGLY INDICATED":
                severity = "HIGH"
                confidence = "HIGH"

            elif status == "BEHAVIORALLY INDICATED":
                severity = "HIGH"
                confidence = _clean_text(
                    finding.get("confidence"),
                    "MEDIUM",
                )

            else:
                severity = "MEDIUM"
                confidence = "LOW"

            _add_item(
                items=items,
                title="Validate Differential Injection Behaviour",
                category="Web Input Investigation",
                severity=severity,
                confidence=confidence,
                status=status,
                evidence=evidence,
                actions=[
                    (
                        "Review the request and response pair in an "
                        "authorized testing proxy."
                    ),
                    (
                        "Repeat the comparison using controlled "
                        "baseline and altered inputs."
                    ),
                    (
                        "Determine whether the behavior is caused by "
                        "database processing, validation logic, or "
                        "ordinary application filtering."
                    ),
                    (
                        "Do not classify the issue as confirmed until "
                        "manual validation supports the conclusion."
                    ),
                ],
                objective=(
                    "Determine whether the parameter is processed "
                    "unsafely by a server-side database operation."
                ),
                source="Behavioral Verification Engine",
                port=port,
            )


def _web_detection_items(
    items,
    web_detection_results,
    verification_results,
):
    verified_keys = set()

    for port, findings in verification_results.items():
        for finding in findings:
            verified_keys.add(
                (
                    str(port),
                    _clean_text(finding.get("endpoint"), "/"),
                    _clean_text(
                        finding.get("parameter"),
                        "Unknown",
                    ),
                )
            )

    for port, findings in web_detection_results.items():
        for finding in findings:
            title = _clean_text(
                finding.get("title"),
                "Web Finding",
            )

            endpoint = _clean_text(
                finding.get("endpoint"),
                finding.get("page", "/"),
            )

            parameter = _clean_text(
                finding.get("parameter"),
                "N/A",
            )

            category = _clean_text(
                finding.get("category"),
                "Web Analysis",
            )

            severity = _clean_text(
                finding.get("severity"),
                "INFO",
            ).upper()

            confidence = _clean_text(
                finding.get("confidence"),
                "UNKNOWN",
            ).upper()

            reason = _clean_text(
                finding.get("reason"),
                "Web application surface was identified.",
            )

            verification_key = (
                str(port),
                endpoint,
                parameter,
            )

            if (
                title == "Possible Injection Surface"
                and verification_key in verified_keys
            ):
                continue

            if title == "Possible Injection Surface":
                actions = [
                    (
                        "Review the parameter using controlled "
                        "authorized testing."
                    ),
                    (
                        "Compare normal and altered input responses."
                    ),
                    (
                        "Verify whether differences are stable and "
                        "repeatable."
                    ),
                ]

                objective = (
                    "Determine whether the input reaches an unsafe "
                    "server-side query or processing function."
                )

            elif title == "Authentication Surface Detected":
                actions = [
                    "Review authentication error handling.",
                    "Inspect session creation and invalidation behavior.",
                    (
                        "Check whether authorization is enforced after "
                        "successful authentication."
                    ),
                ]

                objective = (
                    "Evaluate the authentication and session-control "
                    "design."
                )

            elif title == "Management Interface Exposed":
                actions = [
                    (
                        "Confirm that the management resource requires "
                        "authentication."
                    ),
                    (
                        "Review authorization restrictions for "
                        "administrative functions."
                    ),
                    (
                        "Check whether the interface is unnecessarily "
                        "exposed to untrusted networks."
                    ),
                ]

                objective = (
                    "Determine whether administrative functions are "
                    "adequately protected."
                )

            elif title == "Session Cookie Hardening Review":
                actions = [
                    "Review the cookie attributes.",
                    (
                        "Confirm whether Secure, HttpOnly, and SameSite "
                        "are appropriate for the application."
                    ),
                    (
                        "Inspect session expiration and logout "
                        "behavior."
                    ),
                ]

                objective = (
                    "Evaluate whether session cookies are protected "
                    "against common browser-based risks."
                )

            elif title == "Server Status Resource Detected":
                actions = [
                    (
                        "Confirm that the resource remains inaccessible "
                        "to unauthorized users."
                    ),
                    (
                        "Review the web-server configuration for "
                        "information disclosure."
                    ),
                ]

                objective = (
                    "Ensure diagnostic resources do not expose server "
                    "or request metadata."
                )

            else:
                actions = [
                    "Review the detected web resource manually.",
                    "Validate access-control and input-handling behavior.",
                ]

                objective = (
                    "Determine whether the detected surface represents "
                    "a meaningful security weakness."
                )

            _add_item(
                items=items,
                title=title,
                category=category,
                severity=severity,
                confidence=confidence,
                status=_clean_text(
                    finding.get("status"),
                    "HYPOTHESIS",
                ),
                evidence=[
                    f"Endpoint: {endpoint}",
                    f"Parameter: {parameter}",
                    reason,
                ],
                actions=actions,
                objective=objective,
                source="Web Detection Engine",
                port=port,
            )


def _correlation_items(
    items,
    correlation_results,
):
    for finding in correlation_results:
        title = _clean_text(
            finding.get("title"),
            "Correlated Investigation",
        )

        evidence = finding.get(
            "evidence",
            [],
        )

        recommendations = finding.get(
            "recommendations",
            [],
        )

        hypotheses = finding.get(
            "hypotheses",
            [],
        )

        combined_evidence = list(evidence)

        for hypothesis in hypotheses:
            combined_evidence.append(
                f"Hypothesis: {hypothesis}"
            )

        _add_item(
            items=items,
            title=title,
            category=_clean_text(
                finding.get("category"),
                "Attack-Path Correlation",
            ),
            severity=_clean_text(
                finding.get("severity"),
                "INFO",
            ),
            confidence=_clean_text(
                finding.get("confidence"),
                "UNKNOWN",
            ),
            status=_clean_text(
                finding.get("status"),
                "CORRELATED HYPOTHESIS",
            ),
            evidence=combined_evidence,
            actions=recommendations,
            objective=(
                "Determine whether the correlated observations form "
                "a repeatable multi-stage investigation path."
            ),
            source="Correlation Engine",
        )


def _exploit_items(
    items,
    exploit_results,
):
    for port, findings in exploit_results.items():
        for finding in findings:
            severity = _clean_text(
                finding.get("severity"),
                "INFO",
            ).upper()

            title = _clean_text(
                finding.get("title"),
                finding.get("finding_type", "Version Risk Review"),
            )

            service = _clean_text(
                finding.get("service"),
                "Unknown Service",
            )

            version = _clean_text(
                finding.get("version"),
                "Unknown",
            )

            cve = _clean_text(
                finding.get("cve"),
                "N/A",
            )

            evidence = [
                f"Service: {service}",
                f"Version: {version}",
            ]

            if cve != "N/A":
                evidence.append(f"CVE reference: {cve}")

            description = finding.get("description")

            if description:
                evidence.append(
                    _clean_text(description)
                )

            remediation = finding.get(
                "remediation",
                "",
            )

            actions = [
                (
                    "Confirm the detected version using at least one "
                    "additional source of evidence."
                ),
                (
                    "Compare the product and version against official "
                    "vendor advisories."
                ),
                (
                    "Do not treat version matching alone as proof that "
                    "the vulnerability is exploitable."
                ),
            ]

            if remediation:
                actions.append(
                    _clean_text(remediation)
                )

            _add_item(
                items=items,
                title=title,
                category="Service and CVE Review",
                severity=severity,
                confidence=_clean_text(
                    finding.get("confidence"),
                    "MEDIUM",
                ),
                status=_clean_text(
                    finding.get("cve_status"),
                    "REVIEW REQUIRED",
                ),
                evidence=evidence,
                actions=actions,
                objective=(
                    "Determine whether the observed service version is "
                    "affected in the target configuration."
                ),
                source="CVE and Risk Engine",
                port=port,
            )


def _network_fallback_items(
    items,
    recon_results,
):
    filtered_ports = []

    for line in recon_results:
        text = str(line or "").strip()

        if not text.startswith("[?]"):
            continue

        parts = text.split()

        if len(parts) < 2:
            continue

        try:
            filtered_ports.append(int(parts[1]))
        except ValueError:
            continue

    if 22 in filtered_ports:
        already_present = any(
            item.get("title")
            == "Dynamic Network Access Surface"
            for item in items
        )

        if not already_present:
            _add_item(
                items=items,
                title="Reassess Filtered SSH Access",
                category="Network Access Investigation",
                severity="MEDIUM",
                confidence="MEDIUM",
                status="HYPOTHESIS",
                evidence=[
                    "Port 22/TCP was observed in a filtered state.",
                ],
                actions=[
                    (
                        "Repeat the port-state check after completing "
                        "web and configuration review."
                    ),
                    (
                        "Determine whether a firewall, ACL, IDS/IPS, "
                        "or dynamic access rule is responsible."
                    ),
                    (
                        "Only investigate port-knocking behavior inside "
                        "the authorized lab environment."
                    ),
                ],
                objective=(
                    "Determine why SSH is conditionally inaccessible "
                    "and whether its state changes after legitimate "
                    "discovery steps."
                ),
                source="Recon Engine",
                port=22,
            )


def _deduplicate(items):
    unique = []
    seen = set()

    for item in items:
        key = (
            item.get("title"),
            item.get("port"),
            tuple(item.get("evidence", [])),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


def _sort_items(items):
    return sorted(
        items,
        key=lambda item: (
            SEVERITY_PRIORITY.get(
                item.get("severity", "INFO"),
                99,
            ),
            0 if item.get("confidence") == "HIGH" else 1,
            str(item.get("title", "")),
        ),
    )


def build_investigation_roadmap(
    recon_results,
    web_detection_results,
    web_verification_results,
    correlation_results,
    exploit_results=None,
):
    """
    Build and prioritize the final investigation roadmap.
    """

    items = []

    _verification_items(
        items,
        web_verification_results or {},
    )

    _web_detection_items(
        items,
        web_detection_results or {},
        web_verification_results or {},
    )

    _correlation_items(
        items,
        correlation_results or [],
    )

    _exploit_items(
        items,
        exploit_results or {},
    )

    _network_fallback_items(
        items,
        recon_results or [],
    )

    items = _deduplicate(items)
    items = _sort_items(items)

    for index, item in enumerate(items, start=1):
        item["priority"] = index

    summary = {
        "total_items": len(items),
        "high_priority": sum(
            1
            for item in items
            if item.get("severity") in {
                "CRITICAL",
                "HIGH",
            }
        ),
        "medium_priority": sum(
            1
            for item in items
            if item.get("severity") == "MEDIUM"
        ),
        "low_priority": sum(
            1
            for item in items
            if item.get("severity") in {
                "LOW",
                "INFO",
            }
        ),
    }

    return {
        "summary": summary,
        "items": items,
        "disclaimer": (
            "This roadmap provides evidence-based investigation "
            "guidance for authorized security assessment. Findings "
            "remain hypotheses or behavioral indicators until "
            "manually validated."
        ),
    }
