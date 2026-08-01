class AttackSurfaceWriter:
    def __init__(self, app):
        self.app = app

    def generate(self):
        app = self.app

        if not app.current_target:
            return [
                "No assessment available.",
                "Run reconnaissance to generate an attack surface profile."
            ]

        score = app._dashboard_attack_surface_score()
        techs = app._dashboard_technologies()
        ports = app.open_ports_found

        items = []

        items.append(f"Attack Surface Score : {score}/100")
        items.append(f"Open Services        : {len(ports)}")
        items.append(f"Detected Tech        : {len(techs)}")

        if ports:
            items.append("")
            items.append("Exposed Services:")

            for port in ports[:8]:
                items.append(f"  • TCP/{port}")

        if techs:
            items.append("")
            items.append("Technology Stack:")

            for tech in techs[:6]:
                items.append(f"  • {tech}")

        return items
