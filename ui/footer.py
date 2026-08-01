import customtkinter as ctk


class DashboardFooter:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        frame = ctk.CTkFrame(
            parent,
            fg_color="#05070D",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=0,
            height=34,
        )
        frame.grid(row=6, column=0, sticky="ew")
        frame.grid_propagate(False)

        ctk.CTkLabel(
            frame,
            text="BHISHMA Security Labs  •  Enterprise v1.0",
            font=("Helvetica", 10, "bold"),
            text_color="#8B949E",
        ).pack(side="left", padx=22)

        ctk.CTkLabel(
            frame,
            text="SEE EVERYTHING. KNOW EVERYTHING. SECURE EVERYTHING.",
            font=("Helvetica", 10, "bold"),
            text_color="#00E5FF",
        ).pack(side="right", padx=22)
