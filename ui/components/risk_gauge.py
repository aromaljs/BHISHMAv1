import customtkinter as ctk


class RiskGauge(ctk.CTkFrame):
    def __init__(self, parent, score=0, label="STANDBY", accent="#00B8FF", **kwargs):
        super().__init__(
            parent,
            fg_color="#0B1220",
            border_width=1,
            border_color=accent,
            corner_radius=14,
            **kwargs
        )

        score = max(0, min(int(score or 0), 100))

        ctk.CTkLabel(
            self,
            text="ATTACK SURFACE",
            font=("Helvetica", 11, "bold"),
            text_color="#8B949E",
        ).pack(pady=(16, 4))

        ctk.CTkProgressBar(
            self,
            width=220,
            height=14,
            progress_color=accent,
        ).pack(pady=(6, 8))

        self.bar = self.winfo_children()[-1]
        self.bar.set(score / 100)

        ctk.CTkLabel(
            self,
            text=f"{score}/100",
            font=("Helvetica", 34, "bold"),
            text_color=accent,
        ).pack()

        ctk.CTkLabel(
            self,
            text=label,
            font=("Helvetica", 13, "bold"),
            text_color=accent,
        ).pack(pady=(0, 16))
