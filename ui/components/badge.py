import customtkinter as ctk


class Badge(ctk.CTkFrame):
    def __init__(
        self,
        parent,
        text,
        accent="#00B8FF",
        **kwargs
    ):
        super().__init__(
            parent,
            fg_color="#0B1220",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=8,
            **kwargs
        )

        ctk.CTkLabel(
            self,
            text=str(text),
            font=("Helvetica", 10, "bold"),
            text_color=accent,
        ).pack(padx=9, pady=4)
