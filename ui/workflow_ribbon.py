import customtkinter as ctk


class WorkflowRibbon:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        app = self.app

        frame = ctk.CTkFrame(
            parent,
            fg_color="#05070D",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=16,
            height=86,
        )
        frame.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 12))
        frame.grid_propagate(False)

        stages = [
            ("RECON", bool(app.recon_results), "#00E676"),
            ("ENUM", bool(app.enum_results), "#00B8FF"),
            ("TECH", bool(app._dashboard_technologies()), "#6F5BFF"),
            ("INTEL", bool(app.exploit_results), "#FFB300"),
            ("VERIFY", bool(app.verification_results), "#D8DCE5"),
        ]

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=18, pady=14)

        for i in range(len(stages)):
            inner.grid_columnconfigure(i, weight=1)

        for col, (name, complete, color) in enumerate(stages):
            box = ctk.CTkFrame(inner, fg_color="transparent")
            box.grid(row=0, column=col, sticky="nsew")

            dot = "●" if complete else "○"
            state = "COMPLETE" if complete else "READY"

            ctk.CTkLabel(
                box,
                text=dot,
                font=("Helvetica", 22, "bold"),
                text_color=color if complete else "#4B5563",
            ).pack()

            ctk.CTkLabel(
                box,
                text=name,
                font=("Helvetica", 11, "bold"),
                text_color="#FFFFFF",
            ).pack()

            ctk.CTkLabel(
                box,
                text=state,
                font=("Helvetica", 9, "bold"),
                text_color=color if complete else "#8B949E",
            ).pack()
