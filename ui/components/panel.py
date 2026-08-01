import customtkinter as ctk


class EnterprisePanel(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        title="",
        accent="#00B8FF",
        **kwargs
    ):
        super().__init__(
            parent,
            fg_color="#111827",
            border_width=2,
            border_color="#274D7E",
            corner_radius=16,
            **kwargs
        )

        self.grid_propagate(False)

        # ===========================
        # Header
        # ===========================

        self.header = ctk.CTkFrame(
            self,
            fg_color="transparent",
            height=48,
        )
        self.header.pack(fill="x", padx=16, pady=(12, 2))
        self.header.pack_propagate(False)

        ctk.CTkLabel(
            self.header,
            text=title.upper(),
            font=("Helvetica", 15, "bold"),
            text_color="#FFFFFF",
        ).pack(anchor="w")

        # ===========================
        # Accent Divider
        # ===========================

        ctk.CTkFrame(
            self,
            fg_color=accent,
            height=2,
            corner_radius=2,
        ).pack(fill="x", padx=16)

        # ===========================
        # Body
        # ===========================

        self.body = ctk.CTkFrame(
            self,
            fg_color="transparent",
        )
        self.body.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=(12, 16),
        )
