import customtkinter as ctk


class ExposureBar(ctk.CTkFrame):

    def __init__(self, parent, name, value, color="#00B8FF"):
        super().__init__(
            parent,
            fg_color="transparent"
        )

        ctk.CTkLabel(
            self,
            text=name,
            width=70,
            anchor="w",
            font=("Helvetica",10,"bold"),
            text_color="#FFFFFF",
        ).pack(side="left")

        bar = ctk.CTkProgressBar(
            self,
            width=140,
            progress_color=color,
            fg_color="#1F2A3D",
        )
        bar.pack(side="left", padx=8)
        bar.set(value)

        ctk.CTkLabel(
            self,
            text=f"{int(value*100)}%",
            width=40,
            text_color=color,
        ).pack(side="left")
