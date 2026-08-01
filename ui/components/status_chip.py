import customtkinter as ctk


class StatusChip(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        text,
        status="info",
        **kwargs
    ):
        colors = {
            "success": "#00E676",
            "info": "#00B8FF",
            "warning": "#FFB300",
            "danger": "#FF3D57",
            "muted": "#8B949E",
        }

        accent = colors.get(status, "#00B8FF")

        super().__init__(
            parent,
            fg_color="#0B1220",
            border_width=1,
            border_color=accent,
            corner_radius=999,
            **kwargs
        )

        ctk.CTkLabel(
            self,
            text=f"● {text}",
            font=("Helvetica", 10, "bold"),
            text_color=accent,
        ).pack(padx=10, pady=4)
