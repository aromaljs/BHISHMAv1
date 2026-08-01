import customtkinter as ctk


class MetricCard(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        icon="●",
        title="TITLE",
        value="0",
        subtitle="",
        accent="#00B8FF",
        **kwargs
    ):
        super().__init__(
            parent,
            fg_color="#111827",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=14,
            height=120,
            **kwargs
        )

        self.grid_propagate(False)

        # =============================
        # HEADER
        # =============================
        header = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        header.pack(fill="x", padx=14, pady=(12, 6))

        ctk.CTkLabel(
            header,
            text=icon,
            font=("Segoe UI Emoji", 17),
            text_color=accent,
        ).pack(side="left")

        ctk.CTkLabel(
            header,
            text=title.upper(),
            font=("Helvetica", 10, "bold"),
            text_color="#8B949E",
        ).pack(side="left", padx=8)

        # =============================
        # VALUE
        # =============================
        ctk.CTkLabel(
            self,
            text=str(value),
            font=("Helvetica", 32, "bold"),
            text_color=accent,
        ).pack(anchor="w", padx=14)

        # =============================
        # SUBTITLE
        # =============================
        ctk.CTkLabel(
            self,
            text=subtitle,
            font=("Helvetica", 10),
            text_color="#8B949E",
        ).pack(anchor="w", padx=14)

        # =============================
        # ACCENT LINE
        # =============================
        ctk.CTkFrame(
            self,
            fg_color=accent,
            height=3,
            corner_radius=10,
        ).pack(fill="x", padx=14, pady=(10, 0))
