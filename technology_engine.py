import re
import socket
import ssl


def _safe_get(target, port, use_ssl=False):
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)

        if use_ssl:
            context = ssl._create_unverified_context()
            s = context.wrap_socket(raw, server_hostname=target)
        else:
            s = raw

        s.connect((target, int(port)))

        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: BHISHMA-TechDetect/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.send(req.encode())
        data = b""

        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 50000:
                break

        s.close()
        return data.decode(errors="ignore")

    except Exception:
        return ""


def _add(found, name, category, version, confidence, evidence, source):
    key = f"{name}:{version}:{source}"
    if key in found:
        return

    found[key] = {
        "name": name,
        "category": category,
        "version": version or "Unknown",
        "confidence": confidence,
        "evidence": evidence[:300],
        "source": source,
    }


def detect_technologies(target, port, banner):
    found = {}
    text = str(banner)
    combined = text

    if port in [80, 443, 8080, 8443, 10000, 20000] and target:
        combined += "\n" + _safe_get(target, port, use_ssl=port in [443, 8443])

    low = combined.lower()

    patterns = [
        ("Apache HTTP Server", "Web Server", r"apache/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("Nginx", "Web Server", r"nginx/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("PHP", "Programming Language", r"php/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("OpenSSL", "TLS Library", r"openssl/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("MiniServ/Webmin", "Admin Panel", r"miniserv/?([0-9]+\.[0-9]+)"),
        ("Webmin", "Admin Panel", r"webmin(?:\s+|/)([0-9]+\.[0-9]+)"),
        ("Samba", "File Sharing", r"samba\s+smbd\s+([0-9]+(?:\.[0-9]+)+)"),
        ("jQuery", "JavaScript Library", r"jquery[-.]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("Bootstrap", "Frontend Framework", r"bootstrap[-.]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("React", "JavaScript Framework", r"react(?:\.production)?(?:\.min)?\.js"),
        ("Angular", "JavaScript Framework", r"angular(?:\.min)?\.js"),
        ("Express", "Node.js Framework", r"x-powered-by:\s*express"),
        ("Node.js", "Runtime", r"node\.js|nodejs"),
        ("WordPress", "CMS", r"wp-content|wp-includes|wordpress"),
        ("Laravel", "PHP Framework", r"laravel|x-powered-by:\s*laravel"),
    ]

    for name, category, pattern in patterns:
        match = re.search(pattern, low, re.I)
        if match:
            version = match.group(1) if match.groups() else "Detected"
            _add(found, name, category, version, "HIGH", match.group(0), "banner/http")

    if "debian" in low:
        _add(found, "Debian Linux", "Operating System", "Unknown", "HIGH", "Debian detected", "banner/header")

    if "ubuntu" in low:
        _add(found, "Ubuntu Linux", "Operating System", "Unknown", "HIGH", "Ubuntu detected", "banner/header")

    if "set-cookie:" in low:
        cookies = re.findall(r"set-cookie:\s*([^=;\r\n]+)", combined, re.I)
        for cookie in cookies[:5]:
            _add(found, f"Cookie: {cookie}", "Cookie", "Unknown", "MEDIUM", cookie, "set-cookie")

    return list(found.values())


def format_technology_summary(technologies):
    if not technologies:
        return "No technologies detected."

    lines = []
    for tech in technologies:
        lines.append(
            f"- {tech['name']} {tech['version']} "
            f"({tech['category']}, {tech['confidence']}) via {tech['source']}"
        )

    return "\n".join(lines)
