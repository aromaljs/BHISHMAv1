from urllib.parse import urlparse, parse_qs


INJECTION_NAMES = {
    "search",
    "query",
    "q",
    "id",
    "category",
    "item",
    "product",
    "page",
}

PATH_NAMES = {
    "file",
    "filename",
    "path",
    "page",
    "template",
    "include",
    "document",
    "folder",
    "dir",
}

COMMAND_NAMES = {
    "cmd",
    "command",
    "exec",
    "execute",
    "ping",
    "host",
    "ip",
    "domain",
}

REDIRECT_NAMES = {
    "url",
    "redirect",
    "redirect_url",
    "return",
    "return_url",
    "next",
    "continue",
    "destination",
}

OBJECT_NAMES = {
    "id",
    "user_id",
    "account",
    "account_id",
    "profile",
    "order",
    "order_id",
    "document_id",
}


def _finding(
    title,
    category,
    severity,
    confidence,
    page,
    endpoint,
    method,
    parameter,
    reason,
    hypotheses,
):
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "page": page,
        "endpoint": endpoint,
        "method": method,
        "parameter": parameter,
        "reason": reason,
        "hypotheses": hypotheses,
        "status": "HYPOTHESIS",
    }


def _extract_field_name(field):
    text = str(field)

    marker = "name="

    if marker not in text:
        return ""

    value = text.split(marker, 1)[1]
    value = value.split("|", 1)[0]

    value = value.strip()

    if value.upper() == "N/A":
        return ""

    return value.lower()


def _fields_for_page(inputs, page):
    fields = []

    for item in inputs:
        if item.get("page", "/") != page:
            continue

        name = _extract_field_name(
            item.get("field", "")
        )

        if name:
            fields.append(name)

    return fields


def _analyze_form(form, inputs):
    findings = []

    page = form.get("page", "/")
    method = form.get("method", "GET")
    endpoint = form.get("action", "") or page
    form_type = form.get("type", "General Form")

    fields = _fields_for_page(
        inputs,
        page,
    )

    for parameter in fields:
        if parameter in INJECTION_NAMES:
            findings.append(
                _finding(
                    title="Possible Injection Surface",
                    category="Injection Analysis",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    page=page,
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    reason=(
                        "User-controlled input is submitted "
                        "to a server-side application endpoint."
                    ),
                    hypotheses=[
                        "SQL Injection",
                        "Reflected Input Handling",
                        "Input Validation Weakness",
                    ],
                )
            )

        if parameter in PATH_NAMES:
            findings.append(
                _finding(
                    title="Possible File or Path Input Surface",
                    category="Path Analysis",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    page=page,
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    reason=(
                        "Parameter naming suggests possible "
                        "server-side file or path handling."
                    ),
                    hypotheses=[
                        "Path Traversal",
                        "Local File Inclusion",
                        "Unsafe File Selection",
                    ],
                )
            )

        if parameter in COMMAND_NAMES:
            findings.append(
                _finding(
                    title="Possible Command Processing Surface",
                    category="Command Analysis",
                    severity="HIGH",
                    confidence="MEDIUM",
                    page=page,
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    reason=(
                        "Parameter naming suggests host, "
                        "command, or execution-related processing."
                    ),
                    hypotheses=[
                        "Command Injection",
                        "Unsafe System Command Handling",
                    ],
                )
            )

        if parameter in REDIRECT_NAMES:
            findings.append(
                _finding(
                    title="Possible Redirect Surface",
                    category="Redirect Analysis",
                    severity="LOW",
                    confidence="MEDIUM",
                    page=page,
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    reason=(
                        "Parameter naming suggests a destination "
                        "or navigation target."
                    ),
                    hypotheses=[
                        "Open Redirect",
                        "Unsafe URL Handling",
                    ],
                )
            )

        if parameter in OBJECT_NAMES:
            findings.append(
                _finding(
                    title="Possible Object Reference Surface",
                    category="Access Control Analysis",
                    severity="MEDIUM",
                    confidence="LOW",
                    page=page,
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    reason=(
                        "Object-style identifier may reference "
                        "server-side application data."
                    ),
                    hypotheses=[
                        "IDOR",
                        "Broken Object Level Authorization",
                    ],
                )
            )

    if form_type == "Authentication Form":
        findings.append(
            _finding(
                title="Authentication Surface Detected",
                category="Authentication Analysis",
                severity="INFO",
                confidence="HIGH",
                page=page,
                endpoint=endpoint,
                method=method,
                parameter="Multiple",
                reason=(
                    "Username or password-oriented fields "
                    "were identified."
                ),
                hypotheses=[
                    "Credential Reuse",
                    "Authentication Control Review",
                    "Session Handling Review",
                ],
            )
        )

    if form_type == "File Upload Form":
        findings.append(
            _finding(
                title="File Upload Surface Detected",
                category="Upload Analysis",
                severity="MEDIUM",
                confidence="HIGH",
                page=page,
                endpoint=endpoint,
                method=method,
                parameter="File Input",
                reason=(
                    "A file input field was identified."
                ),
                hypotheses=[
                    "File Type Validation",
                    "Upload Storage Controls",
                    "Content Validation",
                ],
            )
        )

    return findings


def _analyze_cookies(cookies):
    findings = []

    for item in cookies:
        cookie = str(
            item.get("cookie", "")
        )

        page = item.get("page", "/")
        lower = cookie.lower()

        if not cookie:
            continue

        missing = []

        if "httponly" not in lower:
            missing.append("HttpOnly")

        if "samesite" not in lower:
            missing.append("SameSite")

        if "secure" not in lower:
            missing.append("Secure")

        if missing:
            findings.append(
                _finding(
                    title="Session Cookie Hardening Review",
                    category="Session Analysis",
                    severity="LOW",
                    confidence="HIGH",
                    page=page,
                    endpoint=page,
                    method="HTTP",
                    parameter="Cookie",
                    reason=(
                        "Observed cookie is missing attributes: "
                        + ", ".join(missing)
                    ),
                    hypotheses=[
                        "Session Cookie Misconfiguration",
                        "Session Hardening Weakness",
                    ],
                )
            )

    return findings


def _analyze_resources(resources):
    findings = []

    for item in resources:
        path = item.get("path", "")
        classification = item.get(
            "classification",
            "Resource",
        )

        status = item.get(
            "status_code",
            0,
        )

        if classification == "Management":
            findings.append(
                _finding(
                    title="Management Interface Exposed",
                    category="Exposure Analysis",
                    severity="MEDIUM",
                    confidence="HIGH",
                    page=path,
                    endpoint=path,
                    method="GET",
                    parameter="N/A",
                    reason=(
                        "A management-oriented resource "
                        "was discovered."
                    ),
                    hypotheses=[
                        "Administrative Access Review",
                        "Authentication Review",
                        "Access Control Review",
                    ],
                )
            )

        if classification == "Backup":
            findings.append(
                _finding(
                    title="Backup Resource Exposed",
                    category="Sensitive File Analysis",
                    severity="HIGH",
                    confidence="HIGH",
                    page=path,
                    endpoint=path,
                    method="GET",
                    parameter="N/A",
                    reason=(
                        f"Backup-oriented resource returned "
                        f"HTTP {status}."
                    ),
                    hypotheses=[
                        "Source Disclosure",
                        "Credential Disclosure",
                        "Sensitive Data Exposure",
                    ],
                )
            )

        if path == "/server-status":
            findings.append(
                _finding(
                    title="Server Status Resource Detected",
                    category="Server Exposure Analysis",
                    severity="LOW",
                    confidence="HIGH",
                    page=path,
                    endpoint=path,
                    method="GET",
                    parameter="N/A",
                    reason=(
                        f"Apache server-status returned "
                        f"HTTP {status}."
                    ),
                    hypotheses=[
                        "Server Metadata Exposure",
                        "Administrative Resource Exposure",
                    ],
                )
            )

    return findings


def _analyze_query_paths(pages):
    findings = []

    for page in pages:
        parsed = urlparse(page)

        parameters = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        for parameter in parameters:
            findings.append(
                _finding(
                    title="URL Parameter Surface Detected",
                    category="Parameter Analysis",
                    severity="INFO",
                    confidence="HIGH",
                    page=page,
                    endpoint=parsed.path or "/",
                    method="GET",
                    parameter=parameter,
                    reason=(
                        "A user-controlled URL parameter "
                        "was discovered during crawling."
                    ),
                    hypotheses=[
                        "Input Validation Review",
                        "Injection Review",
                        "Access Control Review",
                    ],
                )
            )

    return findings


def _deduplicate_findings(findings):
    unique = {}

    for finding in findings:
        key = (
            finding.get("title", ""),
            finding.get("page", ""),
            finding.get("endpoint", ""),
            finding.get("parameter", ""),
        )

        if key not in unique:
            unique[key] = finding

    return list(unique.values())


def analyze_web_recon(web_recon_results):
    results = {}

    for port, data in web_recon_results.items():
        findings = []

        inputs = data.get(
            "inputs",
            [],
        )

        forms = data.get(
            "form_classifications",
            [],
        )

        for form in forms:
            findings.extend(
                _analyze_form(
                    form,
                    inputs,
                )
            )

        findings.extend(
            _analyze_cookies(
                data.get("cookies", [])
            )
        )

        findings.extend(
            _analyze_resources(
                data.get("interesting_links", [])
            )
        )

        findings.extend(
            _analyze_query_paths(
                data.get("pages_crawled", [])
            )
        )

        results[port] = _deduplicate_findings(
            findings
        )

    return results
