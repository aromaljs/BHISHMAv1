import re


SERVICE_PORT_HINTS = {
    21: ("FTP Service", "ftp"),
    22: ("SSH Service", "ssh"),
    25: ("SMTP Service", "smtp"),
    53: ("DNS Service", "dns"),
    80: ("HTTP Service", "http"),
    139: ("NetBIOS/SMB Service", "smb"),
    443: ("HTTPS Service", "https"),
    445: ("SMB Service", "smb"),
    3306: ("MySQL Database", "mysql"),
    3389: ("Remote Desktop", "rdp"),
    5432: ("PostgreSQL Database", "postgresql"),
    5900: ("VNC Service", "vnc"),
    6379: ("Redis Service", "redis"),
    8080: ("HTTP Alternate", "http"),
    8443: ("HTTPS Alternate", "https"),
    10000: ("Webmin Admin Panel", "webmin"),
    20000: ("Usermin/Webmin Panel", "webmin"),
}


FINGERPRINT_PATTERNS = [
    {
        "service": "Apache HTTP Server",
        "vendor": "Apache Software Foundation",
        "product": "apache",
        "regex": r"apache/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "cpe_template": "cpe:/a:apache:http_server:{version}",
    },
    {
        "service": "OpenSSH",
        "vendor": "OpenBSD",
        "product": "openssh",
        "regex": r"openssh[_/-]?([0-9]+\.[0-9]+(?:p[0-9]+)?)",
        "cpe_template": "cpe:/a:openbsd:openssh:{version}",
    },
    {
        "service": "Samba",
        "vendor": "Samba Team",
        "product": "samba",
        "regex": r"samba\s+smbd\s+([0-9]+(?:\.[0-9]+)+)",
        "cpe_template": "cpe:/a:samba:samba:{version}",
    },
    {
        "service": "Webmin",
        "vendor": "Webmin",
        "product": "webmin",
        "regex": r"webmin.*?([0-9]+\.[0-9]+)",
        "cpe_template": "cpe:/a:webmin:webmin:{version}",
    },
    {
        "service": "MiniServ/Webmin",
        "vendor": "Webmin",
        "product": "webmin",
        "regex": r"miniserv/?\s*([0-9]+\.[0-9]+)",
        "cpe_template": "cpe:/a:webmin:webmin:{version}",
    },
    {
        "service": "Nginx",
        "vendor": "F5 / Nginx",
        "product": "nginx",
        "regex": r"nginx/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "cpe_template": "cpe:/a:nginx:nginx:{version}",
    },
    {
        "service": "vsftpd",
        "vendor": "vsftpd",
        "product": "vsftpd",
        "regex": r"vsftpd\s*([0-9]+\.[0-9]+\.[0-9]+)",
        "cpe_template": "cpe:/a:vsftpd:vsftpd:{version}",
    },
    {
        "service": "MySQL",
        "vendor": "Oracle",
        "product": "mysql",
        "regex": r"mysql.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "cpe_template": "cpe:/a:mysql:mysql:{version}",
    },
    {
        "service": "MariaDB",
        "vendor": "MariaDB Foundation",
        "product": "mariadb",
        "regex": r"mariadb.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "cpe_template": "cpe:/a:mariadb:mariadb:{version}",
    },
    {
        "service": "Redis",
        "vendor": "Redis",
        "product": "redis",
        "regex": r"redis.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "cpe_template": "cpe:/a:redis:redis:{version}",
    },
]


SOFT_KEYWORDS = [
    ("Apache HTTP Server", "Apache Software Foundation", "apache", ["apache"]),
    ("OpenSSH", "OpenBSD", "openssh", ["openssh", "ssh"]),
    ("Samba", "Samba Team", "samba", ["samba", "smb", "netbios"]),
    ("Webmin", "Webmin", "webmin", ["webmin", "miniserv"]),
    ("Nginx", "F5 / Nginx", "nginx", ["nginx"]),
    ("FTP Service", "Unknown", "ftp", ["ftp"]),
]


def _detect_os_hint(banner: str) -> str:
    text = banner.lower()

    if "debian" in text:
        return "Debian Linux"
    if "ubuntu" in text:
        return "Ubuntu Linux"
    if "centos" in text:
        return "CentOS Linux"
    if "red hat" in text or "rhel" in text:
        return "Red Hat Enterprise Linux"
    if "windows" in text or "microsoft" in text:
        return "Microsoft Windows"

    return "Unknown"


def fingerprint_service(port: int, banner: str) -> dict:
    text = str(banner)
    text_low = text.lower()

    for item in FINGERPRINT_PATTERNS:
        match = re.search(item["regex"], text_low)
        if match:
            version = match.group(1)
            return {
                "port": port,
                "service": item["service"],
                "vendor": item["vendor"],
                "product": item["product"],
                "version": version,
                "cpe": item["cpe_template"].format(version=version),
                "confidence": 99,
                "quality": "EXCELLENT",
                "os_hint": _detect_os_hint(text),
                "evidence": text,
                "reason": "Exact product and version detected from banner.",
            }

    for service, vendor, product, keywords in SOFT_KEYWORDS:
        if any(k in text_low for k in keywords):
            return {
                "port": port,
                "service": service,
                "vendor": vendor,
                "product": product,
                "version": "Unknown",
                "cpe": "Unknown",
                "confidence": 65,
                "quality": "LIMITED",
                "os_hint": _detect_os_hint(text),
                "evidence": text,
                "reason": "Product detected, but exact version was not exposed.",
            }

    service_hint, product_hint = SERVICE_PORT_HINTS.get(
        port,
        ("Unknown Service", "unknown")
    )

    return {
        "port": port,
        "service": service_hint,
        "vendor": "Unknown",
        "product": product_hint,
        "version": "Unknown",
        "cpe": "Unknown",
        "confidence": 40 if product_hint != "unknown" else 20,
        "quality": "PORT_HINT" if product_hint != "unknown" else "UNKNOWN",
        "os_hint": _detect_os_hint(text),
        "evidence": text,
        "reason": "Service inferred mainly from port number or weak banner.",
    }
