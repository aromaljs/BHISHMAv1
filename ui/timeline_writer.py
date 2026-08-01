from datetime import datetime


class TimelineWriter:
    def __init__(self, app):
        self.app = app

    def generate(self):
        app = self.app
        now = datetime.now().strftime("%H:%M")

        events = []

        if not app.current_target:
            return [f"{now}  ○ Waiting for target input"]

        events.append(f"{now}  ✓ Target selected: {app.current_target}")

        if app.recon_results:
            events.append(f"{now}  ✓ Reconnaissance completed")
            events.append(f"{now}  ✓ {len(app.open_ports_found)} open service(s) discovered")

        if app.enum_results:
            events.append(f"{now}  ✓ Service fingerprinting completed")

        if app._dashboard_technologies():
            events.append(f"{now}  ✓ Technology stack identified")

        if app.exploit_results:
            events.append(f"{now}  ✓ CVE/configuration intelligence completed")
            events.append(f"{now}  ✓ Risk score calculated: {app.stat_risk.get()}/100")

        if app.verification_results:
            events.append(f"{now}  ✓ Safe verification completed")

        return events
