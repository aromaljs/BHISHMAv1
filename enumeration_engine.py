import socket
import ssl
import subprocess
import re

from asset_model import Service
from fingerprint_engine import fingerprint_service


SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    10000: "webmin",
    20000: "webmin",
}


def _clean_text(text):
    text = str(text).replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:700] if text else ""


def _recv_banner(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, int(port)))

        try:
            banner = s.recv(2048).decode(errors="ignore").strip()
        except Exception:
            banner = ""

        s.close()
        return banner

    except Exception:
        return ""


def _http_probe(target, port, use_ssl=False):
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(4)

        if use_ssl:
            context = ssl._create_unverified_context()
            s = context.wrap_socket(raw, server_hostname=target)
        else:
            s = raw

        s.connect((target, int(port)))

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: BHISHMA/2.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.send(request.encode())
        response = s.recv(4096).decode(errors="ignore")
        s.close()

        useful = []

        for line in response.splitlines():
            line_low = line.lower().strip()

            if line_low.startswith("http/"):
                useful.append(line.strip())
            elif line_low.startswith("server:"):
                useful.append(line.strip())
            elif line_low.startswith("x-powered-by:"):
                useful.append(line.strip())
            elif line_low.startswith("set-cookie:"):
                useful.append(line.strip())

        if useful:
            return " | ".join(useful)

        return response[:200]

    except Exception:
        return ""


def _nmap_version_probe(target, port):
    try:
        cmd = [
            "nmap",
            "-Pn",
            "-sV",
            "--version-light",
            "-p",
            str(port),
            target,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=25,
        )

        output = result.stdout + result.stderr

        useful_lines = []

        for line in output.splitlines():
            if f"{port}/tcp" in line and "open" in line:
                useful_lines.append(line.strip())

            if "Service Info:" in line:
                useful_lines.append(line.strip())

            if "CPE:" in line:
                useful_lines.append(line.strip())

            if "Server:" in line:
                useful_lines.append(line.strip())

        if useful_lines:
            return " | ".join(useful_lines)

        return "Open (No Version Detected)"

    except subprocess.TimeoutExpired:
        return "Open (Nmap Version Probe Timeout)"

    except Exception as e:
        return f"Open (Nmap Probe Error: {e})"


def _probe_service(target, port):
    service_hint = SERVICE_MAP.get(port, "unknown")
    banner = ""

    if port in [80, 8080, 8000]:
        banner = _http_probe(target, port, use_ssl=False)

    elif port in [443, 8443]:
        banner = _http_probe(target, port, use_ssl=True)

    elif port in [10000, 20000]:
        banner = _http_probe(target, port, use_ssl=True)

        if not banner:
            banner = _http_probe(target, port, use_ssl=False)

    elif port in [21, 22, 25, 110, 143]:
        banner = _recv_banner(target, port)

    if not banner:
        banner = _nmap_version_probe(target, port)

    return f"{service_hint.upper()} | {_clean_text(banner)}"


def _sanitize_ports(ports):
    sanitized = []

    for p in ports:
        try:
            if isinstance(p, str):
                if "[+]" in p:
                    p = p.replace("[+]", "").strip().split("|")[0].strip()
                else:
                    p = p.strip()

            sanitized.append(int(p))

        except Exception:
            continue

    return sorted(set(sanitized))


def run_enumeration(target, ports, structured=False):
    """
    Main enumeration function.

    structured=False:
        returns old-compatible format:
        {
            80: "HTTP | Server: Apache/2.4.51"
        }

    structured=True:
        returns new intelligence format:
        {
            80: {
                "port": 80,
                "service": "Apache HTTP Server",
                "vendor": "...",
                ...
            }
        }
    """

    results = {}
    sanitized_ports = _sanitize_ports(ports)

    for port in sanitized_ports:
        raw_banner = _probe_service(target, port)
        fingerprint = fingerprint_service(port, raw_banner)

        service_obj = Service(
            port=port,
            protocol="tcp",
            state="open",
            service=fingerprint.get("service", "Unknown Service"),
            vendor=fingerprint.get("vendor", "Unknown"),
            product=fingerprint.get("product", "unknown"),
            version=fingerprint.get("version", "Unknown"),
            cpe=fingerprint.get("cpe", "Unknown"),
            confidence=fingerprint.get("confidence", 0),
            quality=fingerprint.get("quality", "UNKNOWN"),
            os_hint=fingerprint.get("os_hint", "Unknown"),
            evidence=fingerprint.get("evidence", raw_banner),
            reason=fingerprint.get("reason", ""),
        )

        if structured:
            results[port] = service_obj.to_dict()
        else:
            results[port] = (
                f"{service_obj.service} | "
                f"Vendor: {service_obj.vendor} | "
                f"Version: {service_obj.version} | "
                f"CPE: {service_obj.cpe} | "
                f"Confidence: {service_obj.confidence}% | "
                f"Quality: {service_obj.quality} | "
                f"OS Hint: {service_obj.os_hint} | "
                f"Evidence: {_clean_text(service_obj.evidence)}"
            )

    return results
