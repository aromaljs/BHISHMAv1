import customtkinter as ctk
from ui.components import MetricCard


class KPICards:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        app = self.app

        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="ew", padx=22, pady=(16, 10))

        for i in range(5):
            frame.grid_columnconfigure(i, weight=1)

        cards = [
            ("🛡", "Status", app.stat_status.get(), "Assessment State", "#00E676"),
            ("🎯", "Target", app.current_target if app.current_target else "--", "Selected Asset", "#00B8FF"),
            ("⚠", "Risk", app.stat_risk.get(), "Overall Risk", "#FF3D57"),
            ("📋", "Findings", app.stat_vectors.get(), "Total Findings", "#FFB300"),
            ("💻", "Tech", len(app._dashboard_technologies()), "Detected Stack", "#6F5BFF"),
        ]

        for col, (icon, title, value, subtitle, color) in enumerate(cards):
            card = MetricCard(
                frame,
                icon=icon,
                title=title,
                value=value,
                subtitle=subtitle,
                accent=color,
            )
            card.grid(row=0, column=col, sticky="nsew", padx=6)
