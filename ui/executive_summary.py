import customtkinter as ctk


class ExecutiveSummary:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        app = self.app

        panel = ctk.CTkFrame(
            parent,
            fg_color="#0F1117",
            border_width=2,
            border_color="#274D7E",
            corner_radius=16,
            height=210,
        )
        panel.grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 12))
        panel.grid_propagate(False)

        ctk.CTkLabel(
            panel,
            text="EXECUTIVE SUMMARY",
            font=("Helvetica", 15, "bold"),
            text_color="#FFFFFF",
        ).pack(anchor="w", padx=16, pady=(14, 4))

        ctk.CTkFrame(
            panel,
            fg_color="#00B8FF",
            height=2,
            corner_radius=2,
        ).pack(fill="x", padx=16, pady=(0, 10))

        body = ctk.CTkFrame(panel, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        risk = int(app.stat_risk.get()) if str(app.stat_risk.get()).isdigit() else 0
        risk_label = app._dashboard_risk_label(risk)
        risk_color = app._dashboard_risk_color(risk)

        status_text = "ASSESSMENT READY" if app.current_target else "WAITING FOR TARGET"
        status_color = "#00E676" if app.current_target else "#8B949E"

        chip = ctk.CTkFrame(
            body,
            fg_color="#0B1220",
            border_width=1,
            border_color=status_color,
            corner_radius=999,
        )
        chip.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            chip,
            text=f"● {status_text}",
            font=("Helvetica", 10, "bold"),
            text_color=status_color,
        ).pack(padx=10, pady=4)

        target = app.current_target if app.current_target else "No target selected"
        ports = len(app.open_ports_found)
        techs = app._dashboard_technologies()
        tech_text = ", ".join(techs[:4]) if techs else "Pending"
        sev = app._dashboard_severity_counts()

        lines = [
            f"Target: {target}",
            f"Open Services: {ports}",
            f"Risk: {risk_label} ({risk}/100)",
            f"Technologies: {tech_text}",
            f"Findings: {sev['CRITICAL']} Critical / {sev['HIGH']} High / {sev['MEDIUM']} Medium / {sev['LOW']} Low",
            "Recommended Action: Review exposed web, remote access, and management interfaces first.",
        ]

        for line in lines:
            ctk.CTkLabel(
                body,
                text=f"• {line}",
                font=("Helvetica", 11, "bold"),
                text_color=risk_color if line.startswith("Risk:") else "#D8DCE5",
                wraplength=900,
                justify="left",
            ).pack(anchor="w", pady=2)
