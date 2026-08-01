from core.models import TargetAsset, Service


def build_asset_from_enumeration(target: str, enum_results: dict) -> TargetAsset:
    asset = TargetAsset(target=target)

    for port, data in enum_results.items():
        if isinstance(data, dict):
            service = Service(
                port=int(port),
                protocol=data.get("protocol", "tcp"),
                state=data.get("state", "open"),
                service_name=data.get("service", "Unknown Service"),
                vendor=data.get("vendor", "Unknown"),
                product=data.get("product", "unknown"),
                version=data.get("version", "Unknown"),
                cpe=data.get("cpe", "Unknown"),
                os_hint=data.get("os_hint", "Unknown"),
                fingerprint_confidence=int(data.get("confidence", 0)),
                fingerprint_quality=data.get("quality", "UNKNOWN"),
            )
            service.add_evidence(
                "enumeration",
                data.get("evidence", ""),
                service.fingerprint_confidence,
            )
        else:
            service = Service(
                port=int(port),
                service_name="Unknown Service",
            )
            service.add_evidence("legacy_banner", str(data), 40)

        asset.add_service(service)

    asset.os_guess = _guess_asset_os(asset)
    asset.summary = summarize_asset(asset)

    return asset


def _guess_asset_os(asset: TargetAsset) -> str:
    hints = []

    for service in asset.services:
        if service.os_hint != "Unknown":
            hints.append(service.os_hint)

    if not hints:
        return "Unknown"

    return max(set(hints), key=hints.count)


def summarize_asset(asset: TargetAsset) -> dict:
    services = len(asset.services)

    exposed_high_value = 0

    for service in asset.services:
        if service.port in [21, 22, 80, 443, 445, 139, 3306, 5432, 6379, 9200, 10000, 20000]:
            exposed_high_value += 1

    return {
        "service_count": services,
        "high_value_exposed_services": exposed_high_value,
        "known_products": len([s for s in asset.services if s.product != "unknown"]),
        "exact_versions": len([s for s in asset.services if s.version != "Unknown"]),
    }
