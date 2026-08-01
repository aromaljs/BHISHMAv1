import re


CURATED_CVES = [
    {
        "product": "apache",
        "affected_versions": ["2.4.49"],
        "cve": "CVE-2021-41773",
        "title": "Apache Path Traversal and File Disclosure",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache HTTP Server 2.4.49 is affected by path traversal when misconfigured.",
        "remediation": "Upgrade Apache to 2.4.51 or later.",
    },
    {
        "product": "apache",
        "affected_versions": ["2.4.50"],
        "cve": "CVE-2021-42013",
        "title": "Apache Path Traversal and Possible RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache HTTP Server 2.4.50 is affected by path traversal and possible remote code execution.",
        "remediation": "Upgrade Apache immediately.",
    },
    {
        "product": "vsftpd",
        "affected_versions": ["2.3.4"],
        "cve": "CVE-2011-2523",
        "title": "Backdoored vsftpd Version Detected",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "vsftpd 2.3.4 contains a known malicious backdoor.",
        "remediation": "Remove this version and install a trusted package.",
    },
    {
        "product": "webmin",
        "affected_versions": ["1.890"],
        "cve": "CVE-2019-15107",
        "title": "Webmin Remote Command Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Webmin 1.890 is associated with a known remote command execution vulnerability.",
        "remediation": "Upgrade Webmin to a patched version.",
    },
]


def extract_product_version(banner):
    text = str(banner).lower()

    patterns = [
        ("Apache HTTP Server", "apache", r"apache/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("OpenSSH", "openssh", r"openssh[_/-]?([0-9]+\.[0-9]+(?:p[0-9]+)?)"),
        ("Samba", "samba", r"samba\s+smbd\s+([0-9]+(?:\.[0-9]+)+)"),
        ("Webmin", "webmin", r"webmin.*?([0-9]+\.[0-9]+)"),
        ("MiniServ/Webmin", "webmin", r"miniserv/?\s*([0-9]+\.[0-9]+)"),
        ("Nginx", "nginx", r"nginx/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("vsftpd", "vsftpd", r"vsftpd\s*([0-9]+\.[0-9]+\.[0-9]+)"),
        ("MySQL", "mysql", r"mysql.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("MariaDB", "mariadb", r"mariadb.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("Redis", "redis", r"redis.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("MongoDB", "mongodb", r"mongodb.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
        ("Tomcat", "tomcat", r"tomcat/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ]

    for display_name, product_key, pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return {
                "service": display_name,
                "product_key": product_key,
                "version": match.group(1),
                "confidence": 99,
                "quality": "EXCELLENT",
                "reason": "Exact product and version detected from service banner.",
            }

    soft_matches = [
        ("Apache HTTP Server", "apache", ["apache"]),
        ("OpenSSH", "openssh", ["openssh", "ssh"]),
        ("Samba", "samba", ["samba", "smb", "netbios"]),
        ("Webmin", "webmin", ["webmin", "miniserv"]),
        ("Nginx", "nginx", ["nginx"]),
        ("FTP Service", "ftp", ["ftp"]),
    ]

    for display_name, product_key, keywords in soft_matches:
        if any(k in text for k in keywords):
            return {
                "service": display_name,
                "product_key": product_key,
                "version": "Unknown",
                "confidence": 65,
                "quality": "LIMITED",
                "reason": "Product detected, but exact version was not exposed.",
            }

    return {
        "service": "Unknown Service",
        "product_key": None,
        "version": "Unknown",
        "confidence": 20,
        "quality": "UNKNOWN",
        "reason": "Unable to extract product or version from banner.",
    }


def lookup_cves_from_banner(banner):
    fp = extract_product_version(banner)

    result = {
        "fingerprint": fp,
        "cves": [],
        "cve_status": "UNKNOWN",
        "message": "",
    }

    product = fp["product_key"]
    version = fp["version"]

    if not product:
        result["cve_status"] = "UNKNOWN_SERVICE"
        result["message"] = "No reliable product fingerprint. CVE matching skipped."
        return result

    if version == "Unknown":
        result["cve_status"] = "VERSION_UNKNOWN"
        result["message"] = f"{fp['service']} detected, but exact version is unknown. CVE matching skipped to prevent false positives."
        return result

    for item in CURATED_CVES:
        if item["product"] != product:
            continue

        if version in item["affected_versions"]:
            result["cves"].append({
                **item,
                "source": "curated-strict",
                "matched_version": version,
            })

    if result["cves"]:
        result["cve_status"] = "MATCH_FOUND"
        result["message"] = f"Exact vulnerable version match found for {fp['service']} {version}."
    else:
        result["cve_status"] = "NO_STRICT_MATCH"
        result["message"] = f"{fp['service']} {version} detected. No strict CVE match in curated database."

    return result
