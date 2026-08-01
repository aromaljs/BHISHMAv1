import customtkinter as ctk


class InsightPanels:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        app = self.app

        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=5, column=0, sticky="ew", padx=22, pady=(0, 16))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        self._technology_panel(frame)
        self._verification_panel(frame)

    def _technology_panel(self, parent):
        app = self.app
        techs = app._dashboard_technologies()

        card = ctk.CTkFrame(
            parent,
            fg_color="#111827",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=14,
        )
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        ctk.CTkLabel(
            card,
            text="TECHNOLOGY STACK",
            font=("Helvetica", 13, "bold"),
            text_color="#00E5FF",
        ).pack(anchor="w", padx=16, pady=(14, 6))

        if techs:
            for tech in techs:
                ctk.CTkLabel(
                    card,
                    text=f"● {tech}",
                    font=("Helvetica", 12, "bold"),
                    text_color="#FFFFFF",
                ).pack(anchor="w", padx=18, pady=2)
        else:
            ctk.CTkLabel(
                card,
                text="Run Exploit Engine to identify technologies.",
                font=("Helvetica", 11),
                text_color="#8B949E",
            ).pack(anchor="w", padx=18, pady=(4, 16))

    def _verification_panel(self, parent):
        app = self.app

        total = sum(len(v) for v in app.verification_results.values()) if app.verification_results else 0

        card = ctk.CTkFrame(
            parent,
            fg_color="#111827",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=14,
        )
        card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        ctk.CTkLabel(
            card,
            text="VERIFICATION STATUS",
            font=("Helvetica", 13, "bold"),
            text_color="#00B8FF",
        ).pack(anchor="w", padx=16, pady=(14, 6))

        ctk.CTkLabel(
            card,
            text="OBSERVED" if total else "NOT RUN",
            font=("Helvetica", 24, "bold"),
            text_color="#00E676" if total else "#8B949E",
        ).pack(anchor="w", padx=18, pady=(4, 0))

        ctk.CTkLabel(
            card,
            text=f"{total} verification checks recorded",
            font=("Helvetica", 11),
            text_color="#8B949E",
        ).pack(anchor="w", padx=18, pady=(4, 16))
