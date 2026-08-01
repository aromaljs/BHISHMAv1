from core.pipeline import build_asset_from_enumeration


def run_asset_intelligence(target: str, enum_results: dict):
    """
    Converts enumeration results into a structured TargetAsset object.

    This is the beginning of the BHISHMA v2 intelligence pipeline.
    Later, this same pipeline will add:
    - CVE intelligence
    - Configuration audit
    - Risk scoring
    - Attack surface analysis
    - Verification results
    """

    asset = build_asset_from_enumeration(target, enum_results)

    asset.attack_surface_score = calculate_attack_surface_score(asset)
    asset.overall_risk_score = calculate_initial_risk_score(asset)

    asset.summary.update({
        "attack_surface_score": asset.attack_surface_score,
        "overall_risk_score": asset.overall_risk_score,
        "risk_label": risk_label(asset.overall_risk_score),
    })

    return asset


def calculate_attack_surface_score(asset):
    score = 0

    for service in asset.services:
        if service.port in [80, 443, 8080, 8443]:
            score += 10

        elif service.port in [139, 445]:
            score += 20

        elif service.port in [10000, 20000]:
            score += 25

        elif service.port in [3306, 5432, 6379, 27017, 9200]:
            score += 25

        elif service.port in [21, 22]:
            score += 8

        else:
            score += 5

        if service.fingerprint_quality == "UNKNOWN":
            score += 5

    return min(score, 100)


def calculate_initial_risk_score(asset):
    score = 0

    for service in asset.services:
        if service.port in [139, 445]:
            score += 18

        elif service.port in [10000, 20000]:
            score += 20

        elif service.port in [80, 443, 8080, 8443]:
            score += 8

        elif service.port in [3306, 5432, 6379, 27017, 9200]:
            score += 22

        elif service.port == 21:
            score += 10

        elif service.port == 22:
            score += 5

        if service.version == "Unknown":
            score += 4

    return min(score, 100)


def risk_label(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "MINIMAL"
