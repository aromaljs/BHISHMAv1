import customtkinter as ctk
from ui.components import EnterprisePanel, Badge


class TechnologyPanel:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        app = self.app

        panel = EnterprisePanel(
            parent,
            title="TECHNOLOGY STACK",
            accent="#00E5FF",
            height=150,
        )

        panel.grid(
            row=5,
            column=0,
            sticky="ew",
            padx=22,
            pady=(0, 12),
        )

        body = panel.body

        techs = app._dashboard_technologies()

        if not techs:
            Badge(
                body,
                "Run Enumeration",
                accent="#8B949E",
            ).pack(side="left", padx=4, pady=4)
            return

        for tech in techs:
            Badge(
                body,
                tech,
                accent="#00E5FF",
            ).pack(side="left", padx=4, pady=4)
