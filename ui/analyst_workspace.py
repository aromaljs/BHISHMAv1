import customtkinter as ctk
from ui.attack_surface_writer import AttackSurfaceWriter
from ui.components import RiskGauge
from ui.timeline_writer import TimelineWriter

class AnalystWorkspace:
    def __init__(self, app):
        self.app = app

    def render(self, parent):
        app = self.app

        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=4, column=0, sticky="nsew", padx=22, pady=(0, 16))

        parent.grid_rowconfigure(4, weight=1)
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=2)
        frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            frame,
            text="LIVE ASSESSMENT CONSOLE",
            font=("Helvetica", 13, "bold"),
            text_color="#FFFFFF",
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(0, 6))

        ctk.CTkLabel(
            frame,
            text="ATTACK SURFACE COMMAND CENTER",
            font=("Helvetica", 12, "bold"),
            text_color="#FF3D57",
        ).grid(row=0, column=1, sticky="w", padx=(12, 4), pady=(0, 6))

        app.console = app._module_textbox(frame)
        app.console.grid(row=1, column=0, sticky="nsew", padx=(0, 8))

        right_panel = ctk.CTkFrame(
            frame,
            fg_color="#0F1117",
            border_width=2,
            border_color="#274D7E",
            corner_radius=16,
        )
        right_panel.grid(row=1, column=1, sticky="nsew", padx=(8, 0))
        right_panel.grid_rowconfigure(2, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        score = app._dashboard_attack_surface_score()
        label = app._dashboard_risk_label(score)
        color = app._dashboard_risk_color(score)

        RiskGauge(
            right_panel,
            score=score,
            label=label,
            accent=color,
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        
                exposure_box = ctk.CTkFrame(
            right_panel,
            fg_color="#0B1220",
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=12,
        )
        exposure_box.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))

        ports = app.open_ports_found

        exposure_items = [
            ("WEB", 0.85 if any(p in ports for p in [80, 443, 8080, 8443]) else 0.10, "#00B8FF"),
            ("REMOTE", 0.65 if any(p in ports for p in [22, 3389, 5985]) else 0.10, "#6F5BFF"),
            ("SMB", 0.70 if any(p in ports for p in [139, 445]) else 0.10, "#FFB300"),
            ("MGMT", 0.80 if any(p in ports for p in [10000, 20000]) else 0.10, "#FF3D57"),
        ]

        for name, value, bar_color in exposure_items:
            row = ctk.CTkFrame(exposure_box, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=4)

            ctk.CTkLabel(
                row,
                text=name,
                width=70,
                anchor="w",
                font=("Helvetica", 10, "bold"),
                text_color="#FFFFFF",
            ).pack(side="left")

            bar = ctk.CTkProgressBar(
                row,
                width=140,
                progress_color=bar_color,
                fg_color="#1F2A3D",
            )
            bar.pack(side="left", padx=8)
            bar.set(value)

            ctk.CTkLabel(
                row,
                text=f"{int(value * 100)}%",
                width=40,
                font=("Helvetica", 10, "bold"),
                text_color=bar_color,
            ).pack(side="left")

        app.findings = ctk.CTkTextbox(
            right_panel,
            fg_color="#0B1220",
            text_color="#FFFFFF",
            font=("Consolas", 12, "bold"),
            border_width=1,
            border_color="#1F2A3D",
            corner_radius=12,
        )
        app.findings.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))

        app.console.delete("0.0", "end")
        app.findings.delete("0.0", "end")

        app._update_dashboard_after_scan()
        app.console.insert("end", "\nLIVE ASSESSMENT TIMELINE\n")
        app.console.insert("end", "─" * 34 + "\n")

        for line in TimelineWriter(app).generate():
            app.console.insert("end", line + "\n")

        for line in AttackSurfaceWriter(app).generate():
            app.findings.insert("end", line + "\n")
