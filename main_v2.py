import customtkinter as ctk

from ui.theme import (
    apply_theme,
    BG_MAIN,
    BG_SIDEBAR,
    BG_PANEL,
    TXT_WHITE,
    TXT_MUTED,
    TXT_DIM,
    ACCENT,
    BORDER,
)

from ui.widgets import section_header


class BhishmaV2App(ctk.CTk):
    def __init__(self):
        super().__init__()

        apply_theme()

        self.title("BHISHMA v2.0 Alpha // Attack Surface Intelligence Platform")
        self.geometry("1500x900")
        self.minsize(1200, 720)
        self.configure(fg_color=BG_MAIN)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.current_target = ""
        self.open_ports_found = []
        self.recon_results = []
        self.enum_results = {}
        self.exploit_results = {}
        self.verification_results = {}

        self._build_sidebar()

        self.main_content = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew")

        self.show_dashboard()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self,
            width=230,
            corner_radius=0,
            fg_color=BG_SIDEBAR,
            border_width=1,
            border_color=BORDER,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=18, pady=(28, 0))

        ctk.CTkLabel(
            logo_frame,
            text="⚡",
            font=("Helvetica", 24),
            text_color=ACCENT,
        ).pack(side="left")

        ctk.CTkLabel(
            logo_frame,
            text=" BHISHMA",
            font=("Helvetica", 19, "bold"),
            text_color=TXT_WHITE,
        ).pack(side="left")

        ctk.CTkLabel(
            self.sidebar,
            text="Attack Surface Intelligence",
            font=("Helvetica", 10),
            text_color=TXT_MUTED,
        ).pack(padx=18, anchor="w", pady=(3, 28))

        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER).pack(
            fill="x", padx=14
        )

        ctk.CTkLabel(
            self.sidebar,
            text="MODULES",
            font=("Helvetica", 10, "bold"),
            text_color=TXT_DIM,
        ).pack(padx=18, pady=(18, 6), anchor="w")

        nav_items = [
            ("  ◈  Dashboard", self.show_dashboard),
            ("  ◉  Enumeration", self.show_placeholder_enumeration),
            ("  ⬡  Intelligence", self.show_placeholder_intelligence),
            ("  ⬟  Verification", self.show_placeholder_verification),
            ("  ◧  Reports", self.show_placeholder_reports),
            ("  ◫  History", self.show_placeholder_history),
        ]

        for text, command in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                anchor="w",
                fg_color="transparent",
                text_color=TXT_MUTED,
                hover_color="#1A1A2E",
                corner_radius=8,
                height=38,
                font=("Helvetica", 13),
                command=command,
            )
            btn.pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(
            self.sidebar,
            text="v2.0 Alpha",
            font=("Helvetica", 10, "bold"),
            text_color=ACCENT,
        ).pack(side="bottom", padx=18, pady=(0, 8), anchor="w")

        ctk.CTkLabel(
            self.sidebar,
            text="Detection only • No exploitation",
            font=("Helvetica", 9),
            text_color=TXT_DIM,
        ).pack(side="bottom", padx=18, pady=(0, 12), anchor="w")

    def clear_main(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        self.clear_main()

        section_header(
            self.main_content,
            "BHISHMA v2.0 Alpha",
            "Attack Surface Intelligence Platform",
        )

        card = ctk.CTkFrame(
            self.main_content,
            fg_color=BG_PANEL,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
        )
        card.pack(fill="both", expand=True, padx=28, pady=20)

        ctk.CTkLabel(
            card,
            text="Sprint 1 Foundation Loaded",
            font=("Helvetica", 28, "bold"),
            text_color=TXT_WHITE,
        ).pack(pady=(40, 10))

        ctk.CTkLabel(
            card,
            text=(
                "This is the new modular BHISHMA v2 shell.\n\n"
                "Old main.py is still safe.\n"
                "Next we will move Dashboard, Enumeration, Intelligence,\n"
                "Verification, Reports, and History into separate UI modules."
            ),
            font=("Helvetica", 15),
            text_color=TXT_MUTED,
            justify="center",
        ).pack(pady=10)

        ctk.CTkLabel(
            card,
            text="Current Sprint: Architecture Refactor + Fingerprint Intelligence",
            font=("Helvetica", 14, "bold"),
            text_color=ACCENT,
        ).pack(pady=20)

    def _placeholder(self, title, subtitle):
        self.clear_main()
        section_header(self.main_content, title, subtitle)

        box = ctk.CTkFrame(
            self.main_content,
            fg_color=BG_PANEL,
            corner_radius=12,
            border_width=1,
            border_color=BORDER,
        )
        box.pack(fill="both", expand=True, padx=28, pady=20)

        ctk.CTkLabel(
            box,
            text=f"{title} module coming next",
            font=("Helvetica", 24, "bold"),
            text_color=TXT_WHITE,
        ).pack(pady=(40, 10))

        ctk.CTkLabel(
            box,
            text="This tab will be split into its own clean UI file.",
            font=("Helvetica", 14),
            text_color=TXT_MUTED,
        ).pack(pady=10)

    def show_placeholder_enumeration(self):
        self._placeholder("Enumeration", "Service Fingerprint Intelligence")

    def show_placeholder_intelligence(self):
        self._placeholder("Intelligence", "CVE, CPE, Configuration and Risk")

    def show_placeholder_verification(self):
        self._placeholder("Verification", "Safe Confirmation Engine")

    def show_placeholder_reports(self):
        self._placeholder("Reports", "Executive HTML Reports")

    def show_placeholder_history(self):
        self._placeholder("History", "Scan Inventory and Timeline")


if __name__ == "__main__":
    app = BhishmaV2App()
    app.mainloop()
