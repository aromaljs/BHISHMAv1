import customtkinter as ctk


class SectionTitle(ctk.CTkFrame):

    def __init__(
        self,
        parent,
        title,
        subtitle="",
        accent="#00B8FF",
        **kwargs
    ):
        super().__init__(
            parent,
            fg_color="transparent",
            **kwargs
        )

        left = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        left.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            left,
            text=title.upper(),
            font=("Helvetica", 15, "bold"),
            text_color="#FFFFFF",
        ).pack(anchor="w")

        if subtitle:
            ctk.CTkLabel(
                left,
                text=subtitle,
                font=("Helvetica", 10),
                text_color="#8B949E",
            ).pack(anchor="w")

        line = ctk.CTkFrame(
            self,
            fg_color=accent,
            height=2,
            width=60,
            corner_radius=2,
        )
        line.pack(side="right", padx=8, pady=12)
