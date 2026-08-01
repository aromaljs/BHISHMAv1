import socket
import ssl


SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS header",
    "content-security-policy": "Missing Content-Security-Policy header",
    "x-frame-options": "Missing X-Frame-Options header",
    "x-content-type-options": "Missing X-Content-Type-Options header",
    "referrer-policy": "Missing Referrer-Policy header",
}


def _http_request(target, port, use_ssl=False, method="HEAD", path="/"):
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)

        if use_ssl:
            context = ssl._create_unverified_context()
            s = context.wrap_socket(raw, server_hostname=target)
        else:
            s = raw

        s.connect((target, int(port)))

        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: BHISHMA-ConfigAudit/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.send(request.encode())
        response = b""

        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 20000:
                break

        s.close()
        return response.decode(errors="ignore")

    except Exception as e:
        return f"ERROR: {e}"


def _parse_headers(response):
    headers = {}

    header_block = response.split("\r\n\r\n")[0]

    for line in header_block.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    return headers


def audit_http_service(target, port, banner=""):
    findings = []

    use_ssl = port in [443, 8443]
    response = _http_request(target, port, use_ssl=use_ssl, method="GET", path="/")
    headers = _parse_headers(response)

    if "server" in headers:
        findings.append({
            "title": "Server Version Disclosure",
            "finding_type": "Configuration",
            "severity": "LOW",
            "cvss": 3.1,
            "confidence": "HIGH",
            "evidence": f"Server: {headers.get('server')}",
            "description": "The server exposes software/version details through HTTP headers.",
            "remediation": "Disable or reduce server banner disclosure using ServerTokens/ServerSignature or equivalent settings.",
        })

    for header, title in SECURITY_HEADERS.items():
        if header not in headers:
            severity = "MEDIUM" if header in ["content-security-policy", "x-frame-options"] else "LOW"
            findings.append({
                "title": title,
                "finding_type": "Configuration",
                "severity": severity,
                "cvss": 4.0 if severity == "MEDIUM" else 3.0,
                "confidence": "HIGH",
                "evidence": f"{header} header not present",
                "description": f"The HTTP response does not include the {header} security header.",
                "remediation": f"Configure the web server/application to send the {header} header.",
            })

    body_low = response.lower()

    if "apache2 debian default page" in body_low or "it works" in body_low:
        findings.append({
            "title": "Default Web Server Page Exposed",
            "finding_type": "Configuration",
            "severity": "LOW",
            "cvss": 3.0,
            "confidence": "HIGH",
            "evidence": "Default Apache/Debian page detected",
            "description": "A default web server page is exposed, which may reveal technology stack information.",
            "remediation": "Replace default pages with production content or restrict access.",
        })

    if "index of /" in body_low:
        findings.append({
            "title": "Directory Listing May Be Enabled",
            "finding_type": "Configuration",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "confidence": "MEDIUM",
            "evidence": "Index of / detected",
            "description": "Directory listing may expose files and sensitive paths.",
            "remediation": "Disable autoindex/directory listing on the web server.",
        })

    return findings


def audit_smb_service(target, port, banner=""):
    findings = []

    findings.append({
        "title": "SMB Service Requires Hardening Review",
        "finding_type": "Configuration",
        "severity": "MEDIUM",
        "cvss": 5.0,
        "confidence": "MEDIUM",
        "evidence": str(banner),
        "description": "SMB is exposed. Signing, SMBv1 status, guest access, and share permissions should be reviewed.",
        "remediation": "Disable SMBv1, enforce SMB signing, restrict access to trusted hosts, and review share permissions.",
    })

    return findings


def audit_webmin_service(target, port, banner=""):
    findings = []

    findings.append({
        "title": "Administrative Web Interface Exposed",
        "finding_type": "Configuration",
        "severity": "HIGH",
        "cvss": 7.0,
        "confidence": "HIGH",
        "evidence": str(banner),
        "description": "A Webmin/Usermin-style administrative interface appears reachable over the network.",
        "remediation": "Restrict admin interface access by VPN/IP allowlist and enforce strong authentication.",
    })

    return findings


def run_config_audit(target, port, banner):
    banner_low = str(banner).lower()

    if port in [80, 443, 8080, 8443] or "apache" in banner_low or "http" in banner_low:
        return audit_http_service(target, port, banner)

    if port in [10000, 20000] or "webmin" in banner_low or "miniserv" in banner_low:
        return audit_webmin_service(target, port, banner)

    if port in [139, 445] or "smb" in banner_low or "samba" in banner_low:
        return audit_smb_service(target, port, banner)

    return []
