class ExecutiveWriter:
    def __init__(self, app):
        self.app = app

    def generate(self):
        app = self.app

        target = app.current_target if app.current_target else "No target selected"
        ports = len(app.open_ports_found)
        risk = int(app.stat_risk.get()) if str(app.stat_risk.get()).isdigit() else 0
        techs = app._dashboard_technologies()
        sev = app._dashboard_severity_counts()
        attack_surface = app._dashboard_attack_surface_score()

        if risk >= 80:
            risk_label = "critical"
        elif risk >= 60:
            risk_label = "high"
        elif risk >= 35:
            risk_label = "medium"
        elif risk > 0:
            risk_label = "low"
        else:
            risk_label = "pending"

        tech_text = ", ".join(techs[:5]) if techs else "technology detection pending"

        if not app.current_target:
            return "Enter a target IP and run reconnaissance to begin the BHISHMA assessment workflow."

        return (
            f"Target {target} exposes {ports} reachable service(s). "
            f"Current risk is {risk_label.upper()} with score {risk}/100. "
            f"Attack surface score is {attack_surface}/100. "
            f"Detected technologies include {tech_text}. "
            f"Findings summary: {sev['CRITICAL']} critical, {sev['HIGH']} high, "
            f"{sev['MEDIUM']} medium, and {sev['LOW']} low. "
            f"Recommended next action: review exposed management interfaces, "
            f"configuration findings, and verification results first."
        )
