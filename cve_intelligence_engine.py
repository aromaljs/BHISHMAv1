import json
import os
import re
from typing import Dict, List, Any


DB_PATH = os.path.join("intelligence", "cves.json")


def _load_cve_db() -> Dict[str, Any]:
    if not os.path.exists(DB_PATH):
        return {
            "metadata": {},
            "cves": [],
        }

    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "metadata": {},
            "cves": [],
        }


def normalize_version(version: str) -> str:
    if not version:
        return "Unknown"

    version = str(version).strip()

    match = re.search(r"([0-9]+(?:\.[0-9]+){1,3}(?:p[0-9]+)?)", version)
    if match:
        return match.group(1)

    return version


def extract_product_version(banner: str) -> Dict[str, Any]:
    text = str(banner)
    text_low = text.lower()

    patterns = [
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
            "service": "MiniServ/Webmin",
            "vendor": "Webmin",
            "product": "webmin",
            "regex": r"miniserv/([0-9]+\.[0-9]+)",
            "cpe_template": "cpe:/a:webmin:webmin:{version}",
        },
        {
            "service": "Webmin",
            "vendor": "Webmin",
            "product": "webmin",
            "regex": r"webmin(?:\s+|/)([0-9]+\.[0-9]+)",
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
        }
    ]

    for item in patterns:
        match = re.search(item["regex"], text_low)
        if match:
            version = normalize_version(match.group(1))
            return {
                "service": item["service"],
                "vendor": item["vendor"],
                "product": item["product"],
                "version": version,
                "cpe": item["cpe_template"].format(version=version),
                "confidence": 99,
                "quality": "EXCELLENT",
                "reason": "Exact product and version detected from service evidence.",
            }

    soft_matches = [
        ("Apache HTTP Server", "Apache Software Foundation", "apache", ["apache"]),
        ("OpenSSH", "OpenBSD", "openssh", ["openssh", "ssh"]),
        ("Samba", "Samba Team", "samba", ["samba", "smb", "netbios"]),
        ("Webmin", "Webmin", "webmin", ["webmin", "miniserv"]),
        ("Nginx", "F5 / Nginx", "nginx", ["nginx"]),
        ("FTP Service", "Unknown", "ftp", ["ftp"]),
    ]

    for service, vendor, product, keywords in soft_matches:
        if any(k in text_low for k in keywords):
            return {
                "service": service,
                "vendor": vendor,
                "product": product,
                "version": "Unknown",
                "cpe": "Unknown",
                "confidence": 65,
                "quality": "LIMITED",
                "reason": "Product detected, but exact version was not exposed.",
            }

    return {
        "service": "Unknown Service",
        "vendor": "Unknown",
        "product": None,
        "version": "Unknown",
        "cpe": "Unknown",
        "confidence": 20,
        "quality": "UNKNOWN",
        "reason": "Unable to identify product or version from available evidence.",
    }


def _version_matches(version: str, affected_versions: List[str]) -> bool:
    version = normalize_version(version)

    for affected in affected_versions:
        affected = normalize_version(affected)

        if version == affected:
            return True

    return False


def lookup_cves_from_banner(banner: str) -> Dict[str, Any]:
    fingerprint = extract_product_version(banner)
    db = _load_cve_db()

    result = {
        "fingerprint": fingerprint,
        "cves": [],
        "cve_status": "UNKNOWN",
        "message": "",
        "reason": "",
        "database_version": db.get("metadata", {}).get("version", "unknown"),
    }

    product = fingerprint.get("product")
    version = fingerprint.get("version", "Unknown")
    service_name = fingerprint.get("service", "Unknown Service")

    if not product:
        result["cve_status"] = "UNKNOWN_SERVICE"
        result["message"] = "CVE intelligence skipped."
        result["reason"] = "No reliable product fingerprint was identified."
        return result

    matching_product_cves = [
        cve for cve in db.get("cves", [])
        if cve.get("product") == product
    ]

    if version == "Unknown":
        result["cve_status"] = "VERSION_UNKNOWN"
        result["message"] = f"{service_name} detected, but exact version is unknown."
        result["reason"] = (
            "BHISHMA skipped CVE matching to avoid false positives. "
            "Improve fingerprinting or run deeper version detection."
        )
        return result

    for cve in matching_product_cves:
        if _version_matches(version, cve.get("affected_versions", [])):
            result["cves"].append(cve)

    if result["cves"]:
        result["cve_status"] = "MATCH_FOUND"
        result["message"] = f"Strict CVE match found for {service_name} {version}."
        result["reason"] = "Detected version exactly matches an affected version in the local intelligence database."
    else:
        result["cve_status"] = "NO_STRICT_MATCH"
        result["message"] = f"No strict CVE match found for {service_name} {version}."
        result["reason"] = (
            "Detected version does not match affected versions in the local intelligence database. "
            "This does not prove the service is fully secure; continue with configuration audit."
        )

    return result


def explain_cve_status(status: str) -> str:
    explanations = {
        "MATCH_FOUND": "A known affected version was detected.",
        "NO_STRICT_MATCH": "No matching affected version was found in the local intelligence database.",
        "VERSION_UNKNOWN": "Product detected, but exact version is unknown. CVE matching skipped.",
        "UNKNOWN_SERVICE": "Service fingerprint is too weak for CVE matching.",
        "UNKNOWN": "CVE status could not be determined.",
    }

    return explanations.get(status, "CVE status explanation unavailable.")
