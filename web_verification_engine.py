import difflib
import socket
from urllib.parse import urlencode


SQL_ERROR_MARKERS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli_",
    "pdoexception",
    "sqlite error",
    "sqlite3::",
    "postgresql",
    "pg_query",
    "ora-",
    "odbc sql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "warning: mysql",
    "database error",
]


def _status_code(status_line):
    try:
        return int(status_line.split()[1])
    except Exception:
        return 0


def _send_http_request(
    target,
    port,
    endpoint,
    method="GET",
    parameters=None,
    timeout=6,
):
    parameters = parameters or {}

    endpoint = str(endpoint or "/").strip()

    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"

    method = str(method or "GET").upper()

    body = ""

    if method == "GET" and parameters:
        query_string = urlencode(parameters)

        separator = "&" if "?" in endpoint else "?"
        request_path = f"{endpoint}{separator}{query_string}"
    else:
        request_path = endpoint

        if method == "POST":
            body = urlencode(parameters)

    request_lines = [
        f"{method} {request_path} HTTP/1.1",
        f"Host: {target}",
        "User-Agent: BHISHMA-WebVerification/1.0",
        "Accept: text/html,application/xhtml+xml,*/*",
        "Connection: close",
    ]

    if method == "POST":
        request_lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode())}",
            ]
        )

    request_text = "\r\n".join(request_lines)
    request_text += "\r\n\r\n"

    if method == "POST":
        request_text += body

    try:
        with socket.create_connection(
            (target, int(port)),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)
            sock.sendall(request_text.encode())

            data = b""

            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break

                if not chunk:
                    break

                data += chunk

                if len(data) >= 2_000_000:
                    break

        response = data.decode(
            "utf-8",
            errors="ignore",
        )

        header_text, separator, response_body = response.partition(
            "\r\n\r\n"
        )

        status_line = (
            header_text.splitlines()[0]
            if header_text
            else ""
        )

        return {
            "status": _status_code(status_line),
            "status_line": status_line,
            "body": response_body if separator else "",
            "length": len(response_body),
            "error": "",
        }

    except Exception as exc:
        return {
            "status": 0,
            "status_line": "",
            "body": "",
            "length": 0,
            "error": str(exc),
        }


def _similarity(first_body, second_body):
    first_text = str(first_body or "")
    second_text = str(second_body or "")

    if not first_text and not second_text:
        return 1.0

    return difflib.SequenceMatcher(
        None,
        first_text[:200_000],
        second_text[:200_000],
    ).ratio()


def _length_difference(first_length, second_length):
    largest = max(
        int(first_length or 0),
        int(second_length or 0),
        1,
    )

    return abs(
        int(first_length or 0)
        - int(second_length or 0)
    ) / largest


def _database_error_markers(body):
    lower_body = str(body or "").lower()

    return [
        marker
        for marker in SQL_ERROR_MARKERS
        if marker in lower_body
    ]


def _build_parameters(inputs, page, target_parameter, value):
    parameters = {}

    for item in inputs:
        if item.get("page", "/") != page:
            continue

        field_text = str(
            item.get("field", "")
        )

        if "name=" not in field_text:
            continue

        name = field_text.split(
            "name=",
            1,
        )[1].split(
            "|",
            1,
        )[0].strip()

        if not name or name.upper() == "N/A":
            continue

        field_type = ""

        if "type=" in field_text:
            field_type = field_text.split(
                "type=",
                1,
            )[1].split(
                "|",
                1,
            )[0].strip().lower()

        if field_type in {
            "submit",
            "button",
            "reset",
            "file",
        }:
            continue

        if name.lower() == target_parameter.lower():
            parameters[name] = value
        elif field_type == "password":
            parameters[name] = "BhishmaTest123!"
        else:
            parameters[name] = "bhishma"

    if target_parameter not in parameters:
        parameters[target_parameter] = value

    return parameters


def _verification_result(
    finding,
    port,
    baseline,
    control,
    quote_probe,
    true_probe,
    false_probe,
):
    baseline_control_similarity = _similarity(
        baseline["body"],
        control["body"],
    )

    baseline_quote_similarity = _similarity(
        baseline["body"],
        quote_probe["body"],
    )

    true_false_similarity = _similarity(
        true_probe["body"],
        false_probe["body"],
    )

    quote_length_delta = _length_difference(
        baseline["length"],
        quote_probe["length"],
    )

    true_false_length_delta = _length_difference(
        true_probe["length"],
        false_probe["length"],
    )

    baseline_errors = _database_error_markers(
        baseline["body"]
    )

    quote_errors = _database_error_markers(
        quote_probe["body"]
    )

    true_errors = _database_error_markers(
        true_probe["body"]
    )

    false_errors = _database_error_markers(
        false_probe["body"]
    )

    new_error_markers = sorted(
        set(
            quote_errors
            + true_errors
            + false_errors
        )
        - set(baseline_errors)
    )

    stable_control = (
        baseline_control_similarity >= 0.85
    )

    quote_behavior_change = (
        baseline_quote_similarity <= 0.70
        or quote_length_delta >= 0.30
        or quote_probe["status"] != baseline["status"]
    )

    boolean_behavior_change = (
        true_false_similarity <= 0.70
        or true_false_length_delta >= 0.30
        or true_probe["status"] != false_probe["status"]
    )

    score = 0
    reasons = []

    if stable_control:
        score += 1
        reasons.append(
            "Baseline and ordinary control responses were stable."
        )

    if new_error_markers:
        score += 3
        reasons.append(
            "Database-related error indicators appeared only after altered input."
        )

    if quote_behavior_change:
        score += 2
        reasons.append(
            "Quote-based altered input produced a significant response change."
        )

    if boolean_behavior_change:
        score += 3
        reasons.append(
            "True/false comparison inputs produced materially different responses."
        )

    if not stable_control:
        reasons.append(
            "The application response was unstable during control testing."
        )

    if score >= 6 and stable_control:
        status = "STRONGLY INDICATED"
        confidence = "HIGH"
        severity = "HIGH"

    elif score >= 3 and stable_control:
        status = "BEHAVIORALLY INDICATED"
        confidence = "MEDIUM"
        severity = "MEDIUM"

    elif score >= 1:
        status = "INCONCLUSIVE"
        confidence = "LOW"
        severity = "INFO"

    else:
        status = "NOT INDICATED"
        confidence = "LOW"
        severity = "INFO"

    return {
        "title": "Differential Injection Verification",
        "category": "Injection Verification",
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "port": port,
        "source_page": finding.get(
            "page",
            "/",
        ),
        "endpoint": finding.get(
            "endpoint",
            "/",
        ),
        "method": finding.get(
            "method",
            "GET",
        ),
        "parameter": finding.get(
            "parameter",
            "Unknown",
        ),
        "score": score,
        "reasons": reasons,
        "database_error_markers": new_error_markers,
        "metrics": {
            "baseline_status": baseline["status"],
            "baseline_length": baseline["length"],
            "control_status": control["status"],
            "control_length": control["length"],
            "quote_status": quote_probe["status"],
            "quote_length": quote_probe["length"],
            "true_status": true_probe["status"],
            "true_length": true_probe["length"],
            "false_status": false_probe["status"],
            "false_length": false_probe["length"],
            "baseline_control_similarity": round(
                baseline_control_similarity * 100,
                2,
            ),
            "baseline_quote_similarity": round(
                baseline_quote_similarity * 100,
                2,
            ),
            "true_false_similarity": round(
                true_false_similarity * 100,
                2,
            ),
        },
        "disclaimer": (
            "Behavioral verification is not proof of exploitation. "
            "Manual authorized validation is still required."
        ),
    }


def verify_injection_hypotheses(
    target,
    web_recon_results,
    web_detection_results,
):
    verification_results = {}

    for port, findings in web_detection_results.items():
        inputs = web_recon_results.get(
            port,
            {},
        ).get(
            "inputs",
            [],
        )

        port_results = []

        for finding in findings:
            if finding.get("title") != "Possible Injection Surface":
                continue

            page = finding.get(
                "page",
                "/",
            )

            endpoint = finding.get(
                "endpoint",
                page,
            )

            method = finding.get(
                "method",
                "GET",
            )

            parameter = finding.get(
                "parameter",
                "",
            )

            if not parameter:
                continue

            probe_values = {
                "baseline": "bhishma",
                "control": "bhishma-control",
                "quote": "bhishma'",
                "true": "' OR '1'='1' -- ",
                "false": "' OR '1'='2' -- ",
            }

            responses = {}

            for probe_name, probe_value in probe_values.items():
                parameters = _build_parameters(
                    inputs,
                    page,
                    parameter,
                    probe_value,
                )

                responses[probe_name] = _send_http_request(
                    target,
                    port,
                    endpoint,
                    method=method,
                    parameters=parameters,
                )

            port_results.append(
                _verification_result(
                    finding,
                    port,
                    responses["baseline"],
                    responses["control"],
                    responses["quote"],
                    responses["true"],
                    responses["false"],
                )
            )

        verification_results[port] = port_results

    return verification_results
