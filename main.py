import customtkinter as ctk
import threading
from PIL import Image

import recon_engine
import enumeration_engine
import exploit_engine
import web_recon_engine
import web_detection_engine
import web_verification_engine
import roadmap_engine
import correlation_engine
import report_engine
import database_engine
import migration_engine
import exploit_poc
from ui.dashboard_v2 import DashboardV2

BG_MAIN = "#090B10"
BG_PANEL = "#0F1117"
BG_CARD = "#111827"
BG_INPUT = "#0B1220"
BG_SIDEBAR = "#05070D"

TXT_WHITE = "#FFFFFF"
TXT_MUTED = "#8B949E"
TXT_DIM = "#4B5563"

ACCENT = "#00B8FF"
ACCENT_HOVER = "#33C9FF"
RED = "#FF3D57"
GREEN = "#00E676"
AMBER = "#FFB300"
CYAN = "#00E5FF"
BORDER = "#1F2A3D"
BORDER_BRIGHT = "#00B8FF"
RED_DIM = "#2A1010"
GOLD = "#D8DCE5"

ctk.set_appearance_mode("dark")


def _tagged_insert(textbox, text, tag=None):
    try:
        if textbox is None or not textbox.winfo_exists():
            return

        widget = textbox._textbox

        if tag:
            widget.insert("end", str(text) + "\n", tag)
        else:
            widget.insert("end", str(text) + "\n")

        textbox.see("end")

    except Exception:
        return


def _configure_tags(textbox):
    w = textbox._textbox
    w.tag_config("green", foreground=GREEN)
    w.tag_config("red", foreground=RED)
    w.tag_config("amber", foreground=AMBER)
    w.tag_config("cyan", foreground=CYAN)
    w.tag_config("muted", foreground=TXT_MUTED)
    w.tag_config("white", foreground=TXT_WHITE)


def _auto_tag(line):
    line = str(line)
    l = line.lower()

    if "critical" in l or "confirmed" in l:
        return "red"
    if "high" in l or "[!]" in line:
        return "red"
    if "medium" in l:
        return "amber"
    if "low" in l or "info" in l:
        return "cyan"
    if "[+]" in line or "open" in l:
        return "green"
    if "closed" in l or "not_confirmed" in l:
        return "muted"
    return "white"


class BhishmaApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("BHISHMA Enterprise v1.0 — Attack Surface Intelligence Platform")
        self.geometry("1500x900")
        self.minsize(1200, 720)
        self.configure(fg_color=BG_MAIN)
        # self.withdraw()
        # self.splash = None
	
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.current_target = ""
        self.open_ports_found = []
        self.recon_results = []
        self.enum_results = {}
        self.web_recon_results = {}
        self.web_detection_results = {}
        self.web_verification_results = {}
        self.correlation_results = []
        self.roadmap_results = {
            "summary": {},
            "items": [],
            "disclaimer": "",
        }
        self.exploit_results = {}
        self.verification_results = {}
        self.creds = ""
        self.dashboard_view = None
        
        self.stat_status = ctk.StringVar(value="STANDBY")
        self.stat_targets = ctk.StringVar(value="0")
        self.stat_vectors = ctk.StringVar(value="0")
        self.stat_hits = ctk.StringVar(value="0")
        self.stat_risk = ctk.StringVar(value="0")

        database_engine.init_db()
        migration_engine.migrate_database()
	
        self._build_sidebar()

        self.main_content = ctk.CTkScrollableFrame(
            self,
            fg_color=BG_MAIN,
            corner_radius=0,
            scrollbar_button_color=ACCENT,
            scrollbar_button_hover_color=ACCENT_HOVER,
        )
        self.main_content.grid(
            row=0,
            column=1,
            sticky="nsew",
        )

        self.show_dashboard()
        # self._show_splash_screen()
        # self.after(2500, self._finish_splash)
        
    def _show_splash_screen(self):
        self.splash = ctk.CTkToplevel(self)
        self.splash.title("BHISHMA")
        self.splash.geometry("620x430")
        self.splash.resizable(False, False)
        self.splash.configure(fg_color=BG_MAIN)

        self.splash.update_idletasks()
        x = (self.splash.winfo_screenwidth() // 2) - 310
        y = (self.splash.winfo_screenheight() // 2) - 215
        self.splash.geometry(f"620x430+{x}+{y}")

        box = ctk.CTkFrame(
            self.splash,
            fg_color=BG_PANEL,
            border_width=1,
            border_color=ACCENT,
            corner_radius=18,
        )
        box.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            box,
            text="BHISHMA",
            font=("Helvetica", 42, "bold"),
            text_color=TXT_WHITE,
        ).pack(pady=(42, 4))

        ctk.CTkLabel(
            box,
            text="ATTACK SURFACE INTELLIGENCE PLATFORM",
            font=("Helvetica", 13, "bold"),
            text_color=ACCENT,
        ).pack(pady=(0, 28))

        loading_items = [
            "Initializing Intelligence Core...",
            "Loading Technology Detection...",
            "Loading Configuration Audit...",
            "Loading Verification Engine...",
        ]

        for item in loading_items:
            ctk.CTkLabel(
                box,
                text=item,
                font=("Consolas", 13),
                text_color=TXT_MUTED,
            ).pack(anchor="w", padx=90, pady=4)

            bar = ctk.CTkProgressBar(
                box,
                width=420,
                height=8,
                progress_color=ACCENT,
            )
            bar.set(1)
            bar.pack(pady=(0, 8))

        ctk.CTkLabel(
            box,
            text="READY",
            font=("Helvetica", 22, "bold"),
            text_color=GREEN,
        ).pack(pady=(12, 8))

        ctk.CTkLabel(
            box,
            text="SEE EVERYTHING. KNOW EVERYTHING. SECURE EVERYTHING.",
            font=("Helvetica", 10, "bold"),
            text_color=CYAN,
        ).pack(pady=(4, 0))

    def _finish_splash(self):
        try:
            if self.splash and self.splash.winfo_exists():
                self.splash.destroy()
        except Exception:
            pass

        self.deiconify()
	
    def _load_logo_image(self, size=(60, 60)):
        try:
            return ctk.CTkImage(
                light_image=Image.open("branding/logo.png"),
                dark_image=Image.open("branding/logo.png"),
                size=size,
            )
        except Exception as e:
            print(f"[Logo] {e}")
            return None
	
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self,
            width=245,
            corner_radius=0,
            fg_color=BG_SIDEBAR,
            border_width=1,
            border_color=BORDER,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand_box = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_box.pack(fill="x", padx=18, pady=(24, 8))

        self.sidebar_logo = self._load_logo_image(size=(320, 250))

        if self.sidebar_logo:
            ctk.CTkLabel(
                brand_box,
                image=self.sidebar_logo,
                text="",
            ).pack(anchor="w", pady=(0, 8))
        else:
            ctk.CTkLabel(
                brand_box,
                text="⬢",
                font=("Helvetica", 36, "bold"),
                text_color=ACCENT,
            ).pack(anchor="w", pady=(0, 8))

        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER).pack(
            fill="x", padx=16, pady=(14, 16)
        )

        ctk.CTkLabel(
            self.sidebar,
            text="COMMAND CENTER",
            font=("Helvetica", 13, "bold"),
            text_color=ACCENT,
        ).pack(padx=18, pady=(0, 8), anchor="w")

        nav_items = [
            ("  ◈  Dashboard", "dash", self.show_dashboard),
            ("  ◉  Enumeration", "enum", self.show_enumeration),
            ("  ⬡  Intelligence", "exploit", self.show_exploit_engine),
            ("  ⬟  Verification", "verify", self.show_verification),
            ("  ◧  Reports", "report", self.show_report_generator),
            ("  ◫  History", "history", self.show_history),
        ]

        self._nav_btns = {}

        for text, key, cmd in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                anchor="w",
                fg_color="transparent",
                text_color=TXT_MUTED,
                hover_color="#062A46",
                border_width=1,
                border_color="#0B1220",
                corner_radius=10,
                height=42,
                font=("Helvetica", 13, "bold"),
                command=lambda c=cmd, k=key: self._nav(c, k),
            )
            btn.pack(fill="x", padx=12, pady=3)
            self._nav_btns[key] = btn

        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER).pack(
            fill="x", padx=16, pady=(0, 12)
        )

        ctk.CTkLabel(
            self.sidebar,
            text="BHISHMA ENTERPRISE",
            font=("Helvetica", 10, "bold"),
            text_color=ACCENT,
        ).pack(padx=18, anchor="w")

        ctk.CTkLabel(
            self.sidebar,
            text="v1.0",
            font=("Helvetica", 9, "bold"),
            text_color=TXT_MUTED,
            justify="left",
        ).pack(padx=18, pady=(4, 16), anchor="w")

    def _nav(self, cmd, key):
        for k, btn in self._nav_btns.items():
            if k == key:
                btn.configure(fg_color="#071B2E", text_color=ACCENT, border_color=ACCENT,)
            else:
                btn.configure(fg_color="transparent", text_color=TXT_MUTED, border_color="#0B1220",)
        cmd()

    def clear_main(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()

    def _set_stat(self, status=None, targets=None, vectors=None, hits=None, risk=None):
        def _do():
            if status is not None:
                self.stat_status.set(status)
            if targets is not None:
                self.stat_targets.set(str(targets))
            if vectors is not None:
                self.stat_vectors.set(str(vectors))
            if hits is not None:
                self.stat_hits.set(str(hits))
            if risk is not None:
                self.stat_risk.set(str(risk))

        self.after(0, _do)

    def _parse_open_ports(self, results):
        ports = []

        for line in results:
            if "[+]" not in line:
                continue

            parts = line.replace("[+]", "").strip().split("|")
            if not parts:
                continue

            port_part = parts[0].strip()

            try:
                ports.append(int(port_part))
            except ValueError:
                continue

        return sorted(list(set(ports)))

    def _section_header(self, parent, title, subtitle=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=28, pady=(24, 6))

        ctk.CTkLabel(
            frame,
            text=title,
            font=("Helvetica", 26, "bold"),
            text_color=TXT_WHITE,
        ).pack(side="left")

        if subtitle:
            ctk.CTkLabel(
                frame,
                text=f"  //  {subtitle}",
                font=("Helvetica", 16, "italic"),
                text_color=ACCENT,
            ).pack(side="left", pady=(4, 0))

    def _stat_card(self, parent, col, title, var, accent_color):
        icon_map = {
            "STATUS": "●",
            "TARGETS": "⌖",
            "FINDINGS": "◇",
            "VECTORS": "◇",
            "OPEN PORTS": "◉",
            "HITS": "◉",
            "RISK": "⚠",
            "RISK SCORE": "⚠",
        }

        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            border_width=1,
            border_color=BORDER_BRIGHT,
            corner_radius=14,
        )
        card.grid(row=0, column=col, sticky="nsew", padx=7, pady=4)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(12, 4))

        ctk.CTkLabel(
            top,
            text=icon_map.get(title, "◆"),
            font=("Helvetica", 16, "bold"),
            text_color=accent_color,
        ).pack(side="left")

        ctk.CTkLabel(
            top,
            text=f"  {title}",
            font=("Helvetica", 10, "bold"),
            text_color=TXT_MUTED,
        ).pack(side="left")

        ctk.CTkLabel(
            card,
            textvariable=var,
            font=("Helvetica", 26, "bold"),
            text_color=accent_color,
        ).pack(anchor="w", padx=14, pady=(0, 8))

        ctk.CTkFrame(
            card,
            height=3,
            fg_color=accent_color,
            corner_radius=3,
        ).pack(fill="x", padx=14, pady=(0, 12))

    def _module_textbox(self, parent, height=None):
        textbox_kwargs = {
            "fg_color": BG_PANEL,
            "text_color": TXT_WHITE,
            "font": ("Consolas", 12),
            "border_width": 1,
            "border_color": BORDER_BRIGHT,
            "corner_radius": 8,
        }

        if height is not None:
            textbox_kwargs["height"] = height

        textbox = ctk.CTkTextbox(
            parent,
            **textbox_kwargs,
        )

        _configure_tags(textbox)
        return textbox

    def _action_btn(self, parent, text, color, cmd):
        return ctk.CTkButton(
            parent,
            text=text,
            fg_color=color,
            hover_color=ACCENT_HOVER,
            corner_radius=8,
            height=38,
            font=("Helvetica", 13, "bold"),
            command=cmd,
        )

    def _dashboard_risk_label(self, score):
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "STANDBY"

    def _dashboard_risk_color(self, score):
        if score >= 60:
            return RED
        if score >= 35:
            return AMBER
        if score > 0:
            return GREEN
        return TXT_MUTED

    def _dashboard_attack_surface_score(self):
        best = 0
        for findings in self.exploit_results.values():
            for finding in findings:
                if finding.get("finding_type") == "Attack Surface":
                    evidence = str(finding.get("evidence", ""))
                    for line in evidence.splitlines():
                        if "Attack Surface Score:" in line:
                            try:
                                score = int(line.split(":")[1].split("/")[0].strip())
                                best = max(best, score)
                            except Exception:
                                pass
        return best

    def _dashboard_technologies(self):
        """
        Returns up to 6 unique technologies for the dashboard.
        Preference:
            1. Enumeration results
            2. Intelligence Technology findings
        """

        techs = []

        # ---------- Enumeration ----------
        for service in self.enum_results.values():

            if not isinstance(service, dict):
                continue

            candidates = [
                service.get("product"),
                service.get("service"),
                service.get("vendor"),
                service.get("os_hint"),
            ]

            for item in candidates:

                if not item:
                    continue

                item = str(item).strip()

                if (
                    not item
                    or item.lower() == "unknown"
                    or item.lower() == "none"
                ):
                    continue

                if item not in techs:
                    techs.append(item)

        # ---------- Intelligence ----------
        for findings in self.exploit_results.values():

            for finding in findings:

                if finding.get("finding_type") != "Technology":
                    continue

                evidence = str(
                    finding.get("evidence", "")
                )

                for line in evidence.splitlines():

                    clean = (
                        line.replace("-", "")
                        .split("(")[0]
                        .strip()
                    )

                    if (
                        clean
                        and clean not in techs
                    ):
                        techs.append(clean)

        return techs[:6]

    def _dashboard_severity_counts(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for findings in self.exploit_results.values():
            for finding in findings:
                sev = finding.get("severity", "").upper()
                if sev in counts:
                    counts[sev] += 1
        return counts

    def show_dashboard(self):
        self.dashboard_view = DashboardV2(self)
        self.dashboard_view.render()
        return
        
        self.clear_main()

        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(4, weight=1)

        risk_value = int(self.stat_risk.get()) if str(self.stat_risk.get()).isdigit() else 0
        attack_score = self._dashboard_attack_surface_score()
        techs = self._dashboard_technologies()
        tech_text = ", ".join(techs) if techs else "Run Exploit Engine"
        target_text = self.current_target if self.current_target else "No target selected"
        services_text = ", ".join(str(p) for p in self.open_ports_found[:8]) if self.open_ports_found else "No services yet"

        # HEADER
        topbar = ctk.CTkFrame(
            self.main_content,
            fg_color=BG_PANEL,
            border_width=1,
            border_color=BORDER,
            corner_radius=0,
            height=82,
        )
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)

        brand = ctk.CTkFrame(topbar, fg_color="transparent")
        brand.pack(side="left", padx=26, pady=14)

        ctk.CTkLabel(
            brand,
            text="BHISHMA",
            font=("Helvetica", 30, "bold"),
            text_color=TXT_WHITE,
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand,
            text="// ADVANCED SECURITY ENGINE    Attack Surface Intelligence Platform",
            font=("Helvetica", 11, "bold"),
            text_color=ACCENT,
        ).pack(anchor="w")

        right = ctk.CTkFrame(topbar, fg_color="transparent")
        right.pack(side="right", padx=22)

        self.cred_entry = ctk.CTkEntry(
            right,
            placeholder_text="SSH user:pass optional",
            width=180,
            height=36,
            fg_color=BG_INPUT,
            border_color=BORDER_BRIGHT,
            text_color=TXT_WHITE,
            placeholder_text_color=TXT_MUTED,
        )
        self.cred_entry.pack(side="left", padx=6)

        self.ip_entry = ctk.CTkEntry(
            right,
            placeholder_text="Target IP...",
            width=150,
            height=36,
            fg_color=BG_INPUT,
            border_color=BORDER_BRIGHT,
            text_color=TXT_WHITE,
            placeholder_text_color=TXT_MUTED,
        )
        self.ip_entry.pack(side="left", padx=6)

        ctk.CTkLabel(right, text="Scan Mode:", font=("Helvetica", 10), text_color=TXT_MUTED).pack(side="left", padx=(10, 4))

        ctk.CTkSegmentedButton(
            right,
            values=["QUICK", "STANDARD", "DEEP"],
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=BG_INPUT,
            unselected_hover_color=BG_CARD,
            width=180,
        ).pack(side="left", padx=6)

        ctk.CTkLabel(right, text="Throttle", font=("Helvetica", 10), text_color=TXT_MUTED).pack(side="left", padx=(8, 2))

        self.throttle_slider = ctk.CTkSlider(
            right,
            from_=0,
            to=0.5,
            width=80,
            button_color=ACCENT,
            progress_color=ACCENT,
        )
        self.throttle_slider.set(0.01)
        self.throttle_slider.pack(side="left", padx=4)

        self.full_scan_var = ctk.BooleanVar(value=False)

        ctk.CTkSwitch(
            right,
            text="65k",
            variable=self.full_scan_var,
            text_color=TXT_WHITE,
            button_color=ACCENT,
            progress_color=ACCENT,
        ).pack(side="left", padx=10)

        self.run_btn = ctk.CTkButton(
            right,
            text="  ▶  ENGAGE TARGET",
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            corner_radius=8,
            height=38,
            font=("Helvetica", 13, "bold"),
            command=self.handle_run,
        )
        self.run_btn.pack(side="left", padx=6)

        # WORKFLOW RIBBON
        ribbon = ctk.CTkFrame(
            self.main_content,
            fg_color=BG_PANEL,
            border_width=1,
            border_color=BORDER_BRIGHT,
            corner_radius=10,
            height=88,
        )
        ribbon.grid(row=1, column=0, sticky="ew", padx=20, pady=(14, 10))
        ribbon.grid_propagate(False)
        ribbon.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)

        stages = [
            ("01", "RECON", "COMPLETE" if self.recon_results else "READY", GREEN),
            ("02", "ENUMERATION", "COMPLETE" if self.enum_results else "READY", CYAN),
            ("03", "TECHNOLOGY", "COMPLETE" if techs else "READY", CYAN),
            ("04", "CONFIGURATION", "COMPLETE" if self.exploit_results else "READY", ACCENT),
            ("05", "INTELLIGENCE", "COMPLETE" if self.exploit_results else "READY", AMBER),
            ("06", "VERIFICATION", "COMPLETE" if self.verification_results else "READY", GOLD if "GOLD" in globals() else AMBER),
            ("07", "REPORT", "READY", TXT_MUTED),
        ]

        for i, (num, name, state, color) in enumerate(stages):
            active = state == "COMPLETE"

            box = ctk.CTkFrame(
                ribbon,
                fg_color="#101C2B" if active else "transparent",
                border_width=1 if active else 0,
                border_color=color if active else BORDER,
                corner_radius=10,
            )
            box.grid(row=0, column=i, sticky="nsew", padx=6, pady=10)

            ctk.CTkLabel(
                box,
                text=num,
                font=("Helvetica", 13, "bold"),
                text_color=color,
            ).pack(anchor="w", padx=10, pady=(8, 0))

            ctk.CTkLabel(
                box,
                text=name,
                font=("Helvetica", 11, "bold"),
                text_color=TXT_WHITE,
            ).pack(anchor="w", padx=10)

            ctk.CTkLabel(
                box,
                text="● " + state,
                font=("Helvetica", 9, "bold"),
                text_color=color if active else TXT_MUTED,
            ).pack(anchor="w", padx=10, pady=(0, 8))

        # KPI CARDS
        cards = ctk.CTkFrame(self.main_content, fg_color="transparent")
        cards.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))
        cards.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self._stat_card(cards, 0, "STATUS", self.stat_status, GREEN)
        self._stat_card(cards, 1, "TARGETS", self.stat_targets, CYAN)
        self._stat_card(cards, 2, "FINDINGS", self.stat_vectors, AMBER)
        self._stat_card(cards, 3, "OPEN PORTS", self.stat_hits, GREEN)
        self._stat_card(cards, 4, "RISK SCORE", self.stat_risk, RED)

        # SUMMARY PANEL
        summary = ctk.CTkFrame(
            self.main_content,
            fg_color=BG_CARD,
            border_width=1,
            border_color=BORDER_BRIGHT,
            corner_radius=12,
        )
        summary.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 12))
        summary.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        ctk.CTkLabel(
            summary,
            text="SECURITY ASSESSMENT SUMMARY",
            font=("Helvetica", 11, "bold"),
            text_color=ACCENT,
        ).grid(row=0, column=0, columnspan=6, sticky="w", padx=18, pady=(12, 4))

        summary_items = [
            ("TARGET", target_text, "IPv4 Address", CYAN),
            ("STATUS", "ONLINE" if self.current_target else "STANDBY", "Host assessment state", GREEN if self.current_target else TXT_MUTED),
            ("OPERATING SYSTEM", "Debian Linux" if "Debian" in tech_text else "Unknown", "OS Hint", AMBER),
            ("ATTACK SURFACE", f"{attack_score}/100" if attack_score else "Pending", self._dashboard_risk_label(attack_score), self._dashboard_risk_color(attack_score)),
            ("TECHNOLOGIES", tech_text, f"{len(techs)} identified", CYAN),
            ("SERVICES", services_text, f"{len(self.open_ports_found)} open ports", GREEN),
        ]

        for i, (title, value, sub, color) in enumerate(summary_items):
            item = ctk.CTkFrame(summary, fg_color="transparent")
            item.grid(row=1, column=i, sticky="nsew", padx=10, pady=(8, 14))

            ctk.CTkLabel(item, text=title, font=("Helvetica", 10, "bold"), text_color=TXT_MUTED).pack(anchor="w")
            ctk.CTkLabel(item, text=value, font=("Helvetica", 15, "bold"), text_color=color, wraplength=180, justify="left").pack(anchor="w")
            ctk.CTkLabel(item, text=sub, font=("Helvetica", 10), text_color=TXT_MUTED).pack(anchor="w")

        # MAIN SPLIT
        split = ctk.CTkFrame(self.main_content, fg_color="transparent")
        split.grid(row=4, column=0, sticky="nsew", padx=20, pady=(0, 16))
        split.grid_columnconfigure(0, weight=3)
        split.grid_columnconfigure(1, weight=2)
        split.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            split,
            text="LIVE ASSESSMENT CONSOLE",
            font=("Helvetica", 11, "bold"),
            text_color=ACCENT,
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(0, 4))

        ctk.CTkLabel(
            split,
            text="ATTACK SURFACE SNAPSHOT",
            font=("Helvetica", 11, "bold"),
            text_color=RED,
        ).grid(row=0, column=1, sticky="w", padx=(12, 4), pady=(0, 4))

        self.console = self._module_textbox(split)
        self.console.grid(row=1, column=0, sticky="nsew", padx=(0, 6))

        self.findings = ctk.CTkTextbox(
            split,
            fg_color=BG_PANEL,
            text_color=TXT_WHITE,
            font=("Consolas", 12, "bold"),
            border_width=1,
            border_color=RED_DIM,
            corner_radius=8,
        )
        self.findings.grid(row=1, column=1, sticky="nsew", padx=(6, 0))
        _configure_tags(self.findings)

        self._update_dashboard_after_scan()

        if hasattr(self, "findings") and self.findings.winfo_exists() and self.exploit_results:
            severity_counts = self._dashboard_severity_counts()

            _tagged_insert(self.findings, "\nATTACK SURFACE", "red")
            _tagged_insert(self.findings, "─" * 28, "muted")
            _tagged_insert(self.findings, f"Risk Level: {self._dashboard_risk_label(risk_value)}", self._dashboard_risk_color(risk_value))
            _tagged_insert(self.findings, f"Attack Surface: {attack_score}/100", "amber")
            _tagged_insert(self.findings, f"Critical: {severity_counts['CRITICAL']}", "red")
            _tagged_insert(self.findings, f"High: {severity_counts['HIGH']}", "red")
            _tagged_insert(self.findings, f"Medium: {severity_counts['MEDIUM']}", "amber")
            _tagged_insert(self.findings, f"Low: {severity_counts['LOW']}", "green")

    def _refresh_dashboard_if_visible(self):
        try:
            if self.dashboard_view is not None:
                self.dashboard_view.refresh()
        except Exception:
            pass

    def _update_dashboard_after_scan(self):
        if hasattr(self, "console") and self.console.winfo_exists():
            self.console.delete("0.0", "end")
            for line in self.recon_results:
                _tagged_insert(self.console, line, _auto_tag(line))

        if hasattr(self, "findings") and self.findings.winfo_exists():
            self.findings.delete("0.0", "end")

            if self.exploit_results:
                risk_value = int(self.stat_risk.get()) if str(self.stat_risk.get()).isdigit() else 0

                critical = high = medium = low = 0
                attack_score = 0

                for findings in self.exploit_results.values():
                    for finding in findings:
                        sev = finding.get("severity", "").upper()

                        if sev == "CRITICAL":
                            critical += 1
                        elif sev == "HIGH":
                            high += 1
                        elif sev == "MEDIUM":
                            medium += 1
                        elif sev == "LOW":
                            low += 1

                        if finding.get("finding_type") == "Attack Surface":
                            evidence = str(finding.get("evidence", ""))
                            for line in evidence.splitlines():
                                if "Attack Surface Score:" in line:
                                    try:
                                        score = int(line.split(":")[1].split("/")[0].strip())
                                        attack_score = max(attack_score, score)
                                    except Exception:
                                        pass

                risk_label = "CRITICAL" if risk_value >= 80 else "HIGH" if risk_value >= 60 else "MEDIUM" if risk_value >= 35 else "LOW" if risk_value > 0 else "STANDBY"

                _tagged_insert(self.findings, "ATTACK SURFACE SNAPSHOT", "red")
                _tagged_insert(self.findings, "─" * 32, "muted")
                _tagged_insert(self.findings, f"Risk Level      : {risk_label}", "red" if risk_value >= 60 else "amber")
                _tagged_insert(self.findings, f"Risk Score      : {risk_value}/100", "red" if risk_value >= 60 else "amber")
                _tagged_insert(self.findings, f"Attack Surface  : {attack_score}/100", "amber")
                _tagged_insert(self.findings, "", "white")
                _tagged_insert(self.findings, "FINDINGS BY SEVERITY", "cyan")
                _tagged_insert(self.findings, "─" * 32, "muted")
                _tagged_insert(self.findings, f"Critical        : {critical}", "red")
                _tagged_insert(self.findings, f"High            : {high}", "red")
                _tagged_insert(self.findings, f"Medium          : {medium}", "amber")
                _tagged_insert(self.findings, f"Low             : {low}", "green")
                _tagged_insert(self.findings, "", "white")
                _tagged_insert(self.findings, "OPEN SERVICES", "cyan")
                _tagged_insert(self.findings, "─" * 32, "muted")

                for port in self.open_ports_found:
                    _tagged_insert(self.findings, f"▶ Port {port} OPEN", "green")

            elif self.open_ports_found:
                _tagged_insert(self.findings, "OPEN PORTS", "red")
                _tagged_insert(self.findings, "─" * 24, "muted")

                for port in self.open_ports_found:
                    _tagged_insert(self.findings, f"▶ Port {port} OPEN", "green")

            else:
                _tagged_insert(self.findings, "No open ports found.", "muted")

    def show_enumeration(self):
        self.clear_main()
        self._section_header(self.main_content, "Enumeration", "Service Fingerprinting")

        btn_row = ctk.CTkFrame(self.main_content, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 14))

        self._action_btn(
            btn_row,
            "  ◉  Enumerate Open Ports",
            ACCENT,
            self._run_enum_threaded,
        ).pack(side="left")

        ctk.CTkLabel(
            btn_row,
            text="  Grabs banners from discovered open ports",
            font=("Helvetica", 11),
            text_color=TXT_MUTED,
        ).pack(side="left", padx=12)

        self.results_area = self._module_textbox(self.main_content, height=650)
        self.results_area.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        if self.enum_results:
            self._display_enum_results()

    def _display_enum_results(self):
        if not hasattr(self, "results_area") or not self.results_area.winfo_exists():
            return

        self.results_area.delete("0.0", "end")

        _tagged_insert(
            self.results_area,
            "SERVICE ENUMERATION RESULTS",
            "cyan",
        )

        _tagged_insert(
            self.results_area,
            "═" * 70,
            "muted",
        )

        for port, service in self.enum_results.items():
            if not isinstance(service, dict):
                _tagged_insert(
                    self.results_area,
                    f"Port {port}: {service}",
                    "white",
                )
                continue

            _tagged_insert(
                self.results_area,
                f"PORT {port}/TCP",
                "green",
            )

            _tagged_insert(
                self.results_area,
                f"Service      : {service.get('service', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Vendor       : {service.get('vendor', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Product      : {service.get('product', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Version      : {service.get('version', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"CPE          : {service.get('cpe', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                (
                    f"Confidence   : {service.get('confidence', 0)}% "
                    f"({service.get('quality', 'UNKNOWN')})"
                ),
                "cyan",
            )

            _tagged_insert(
                self.results_area,
                f"OS Hint      : {service.get('os_hint', 'Unknown')}",
                "amber",
            )

            _tagged_insert(
                self.results_area,
                "Evidence",
                "green",
            )

            _tagged_insert(
                self.results_area,
                str(service.get("evidence", "None")),
                "white",
            )

            _tagged_insert(
                self.results_area,
                "Reason",
                "green",
            )

            _tagged_insert(
                self.results_area,
                str(service.get("reason", "None")),
                "white",
            )

            _tagged_insert(
                self.results_area,
                "─" * 70,
                "muted",
            )

        if not self.web_recon_results:
            return

        _tagged_insert(
            self.results_area,
            "",
            "white",
        )

        _tagged_insert(
            self.results_area,
            "WEB APPLICATION INTELLIGENCE",
            "cyan",
        )

        _tagged_insert(
            self.results_area,
            "═" * 70,
            "muted",
        )

        for port, result in self.web_recon_results.items():
            _tagged_insert(
                self.results_area,
                f"WEB SERVICE — PORT {port}/TCP",
                "green",
            )

            _tagged_insert(
                self.results_area,
                f"Server       : {result.get('server', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Powered By   : {result.get('powered_by', 'Unknown')}",
                "white",
            )
            
            auth_forms = sum(
                1
                for form in result.get(
                    "form_classifications",
                    [],
                )
                if form.get("type") == "Authentication Form"
            )

            search_forms = sum(
                1
                for form in result.get(
                    "form_classifications",
                    [],
                )
                if form.get("type") == "Search Form"
            )

            upload_forms = sum(
                1
                for form in result.get(
                    "form_classifications",
                    [],
                )
                if form.get("type") == "File Upload Form"
            )

            pages = result.get(
                "pages_crawled",
                [],
            )

            inputs = result.get(
                "inputs",
                [],
            )

            resources = result.get(
                "interesting_links",
                [],
            )

            cookies = result.get(
                "cookies",
                [],
            )

            _tagged_insert(
                self.results_area,
                "",
                "white",
            )

            _tagged_insert(
                self.results_area,
                "WEB INTELLIGENCE SUMMARY",
                "green",
            )

            _tagged_insert(
                self.results_area,
                f"Pages Crawled          : {len(pages)}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Authentication Forms   : {auth_forms}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Search Forms           : {search_forms}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Upload Forms           : {upload_forms}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Input Parameters       : {len(inputs)}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Interesting Resources  : {len(resources)}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Cookies                : {len(cookies)}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                "─" * 70,
                "muted",
            )
            
            management = any(
                item.get("classification") == "Management"
                for item in resources
            )

            authentication = auth_forms > 0

            if management and authentication:
                overall = "HIGH"
                color = "red"

            elif management or authentication:
                overall = "MEDIUM"
                color = "amber"

            else:
                overall = "LOW"
                color = "green"

            _tagged_insert(
                self.results_area,
                "EXPOSURE ASSESSMENT",
                color,
            )

            _tagged_insert(
                self.results_area,
                (
                    f"Management Surface     : "
                    f"{'HIGH' if management else 'LOW'}"
                ),
                "white",
            )

            _tagged_insert(
                self.results_area,
                (
                    f"Authentication Surface : "
                    f"{'HIGH' if authentication else 'LOW'}"
                ),
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Overall Web Exposure   : {overall}",
                color,
            )

            _tagged_insert(
                self.results_area,
                "═" * 70,
                "muted",
            )            
            
            pages = result.get("pages_crawled", [])

            _tagged_insert(
                self.results_area,
                f"Pages Crawled: {len(pages)}",
                "cyan",
            )

            if pages:
                for page in pages:
                    _tagged_insert(
                        self.results_area,
                        f"  • {page}",
                        "white",
                    )

            titles = result.get("titles", [])

            if titles:
                _tagged_insert(
                    self.results_area,
                    "Page Titles",
                    "amber",
                )

                for item in titles:
                    _tagged_insert(
                        self.results_area,
                        (
                            f"  • {item.get('path', '/')} → "
                            f"{item.get('title', 'Unknown')}"
                        ),
                        "white",
                    )

            classified_forms = result.get(
                "form_classifications",
                [],
            )

            if classified_forms:
                _tagged_insert(
                    self.results_area,
                    "Form Intelligence",
                    "amber",
                )

                for form in classified_forms:
                    page = form.get("page", "/")
                    form_type = form.get(
                        "type",
                        "General Form",
                    )
                    method = form.get(
                        "method",
                        "GET",
                    )
                    action = form.get(
                        "action",
                        "",
                    ) or "/"

                    _tagged_insert(
                        self.results_area,
                        (
                            f"  • [{form_type}] {page} | "
                            f"{method} → {action}"
                        ),
                        "white",
                    )

            inputs = result.get("inputs", [])

            if inputs:
                _tagged_insert(
                    self.results_area,
                    "Input Fields",
                    "amber",
                )

                for field in inputs:
                    _tagged_insert(
                        self.results_area,
                        f"  • {field.get('page', '/')} | {field.get('field', '')}",
                        "white",
                    )

            comments = result.get("comments", [])

            if comments:
                _tagged_insert(
                    self.results_area,
                    "HTML Comments",
                    "amber",
                )

                for comment in comments:
                    _tagged_insert(
                        self.results_area,
                        (
                            f"  • {comment.get('page', '/')} | "
                            f"{comment.get('comment', '')}"
                        ),
                        "white",
                    )

            links = result.get("interesting_links", [])

            if links:
                _tagged_insert(
                    self.results_area,
                    "Interesting Resources",
                    "amber",
                )

                for item in links:
                    classification = item.get(
                        "classification",
                        "Resource",
                    )

                    path = item.get(
                        "path",
                        "",
                    )

                    status = item.get(
                        "status_code",
                        "",
                    )

                    if status:
                        text = f"  • [{classification}] {path} ({status})"
                    else:
                        text = f"  • [{classification}] {path}"

                    _tagged_insert(
                        self.results_area,
                        text,
                        "white",
                    )

            cookies = result.get("cookies", [])

            if cookies:
                _tagged_insert(
                    self.results_area,
                    "Cookies",
                    "amber",
                )

                for cookie in cookies:
                    if isinstance(cookie, dict):
                        text = cookie.get("cookie", "")
                        page = cookie.get("page", "/")

                        _tagged_insert(
                            self.results_area,
                            f"  • {page} | {text}",
                            "white",
                        )
                    else:
                        _tagged_insert(
                            self.results_area,
                            f"  • {cookie}",
                            "white",
                        )

            robots_found = result.get("robots_found", False)

            _tagged_insert(
                self.results_area,
                (
                    "robots.txt   : Found"
                    if robots_found
                    else "robots.txt   : Not found"
                ),
                "green" if robots_found else "muted",
            )

            if robots_found and result.get("robots_preview"):
                _tagged_insert(
                    self.results_area,
                    str(result.get("robots_preview")),
                    "white",
                )

            sitemap_found = result.get("sitemap_found", False)

            _tagged_insert(
                self.results_area,
                (
                    "sitemap.xml  : Found"
                    if sitemap_found
                    else "sitemap.xml  : Not found"
                ),
                "green" if sitemap_found else "muted",
            )

            if sitemap_found and result.get("sitemap_preview"):
                _tagged_insert(
                    self.results_area,
                    str(result.get("sitemap_preview")),
                    "white",
                )

            _tagged_insert(
                self.results_area,
                "─" * 70,
                "muted",
            )
            
        if not self.web_detection_results:
            return

        _tagged_insert(
            self.results_area,
            "",
            "white",
        )

        _tagged_insert(
            self.results_area,
            "WEB DETECTION INTELLIGENCE",
            "cyan",
        )

        _tagged_insert(
            self.results_area,
            "═" * 70,
            "muted",
        )

        for port, findings in self.web_detection_results.items():
            _tagged_insert(
                self.results_area,
                f"WEB SERVICE — PORT {port}/TCP",
                "green",
            )

            if not findings:
                _tagged_insert(
                    self.results_area,
                    "No detection hypotheses generated.",
                    "muted",
                )

                _tagged_insert(
                    self.results_area,
                    "─" * 70,
                    "muted",
                )

                continue

            for finding in findings:
                severity = str(
                    finding.get("severity", "INFO")
                ).upper()

                if severity == "HIGH":
                    severity_color = "red"

                elif severity == "MEDIUM":
                    severity_color = "amber"

                elif severity == "LOW":
                    severity_color = "green"

                else:
                    severity_color = "cyan"

                _tagged_insert(
                    self.results_area,
                    (
                        f"[{severity}] "
                        f"{finding.get('title', 'Detection Hypothesis')}"
                    ),
                    severity_color,
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Category     : "
                        f"{finding.get('category', 'Unknown')}"
                    ),
                    "white",
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Status       : "
                        f"{finding.get('status', 'HYPOTHESIS')}"
                    ),
                    "amber",
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Confidence   : "
                        f"{finding.get('confidence', 'UNKNOWN')}"
                    ),
                    "cyan",
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Source Page  : "
                        f"{finding.get('page', '/')}"
                    ),
                    "white",
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Endpoint     : "
                        f"{finding.get('endpoint', '/')}"
                    ),
                    "white",
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Method       : "
                        f"{finding.get('method', 'GET')}"
                    ),
                    "white",
                )

                _tagged_insert(
                    self.results_area,
                    (
                        f"Parameter    : "
                        f"{finding.get('parameter', 'N/A')}"
                    ),
                    "white",
                )

                _tagged_insert(
                    self.results_area,
                    "Reason",
                    "green",
                )

                _tagged_insert(
                    self.results_area,
                    str(finding.get("reason", "No reason provided.")),
                    "white",
                )

                hypotheses = finding.get(
                    "hypotheses",
                    [],
                )

                if hypotheses:
                    _tagged_insert(
                        self.results_area,
                        "Investigation Hypotheses",
                        "amber",
                    )

                    for hypothesis in hypotheses:
                        _tagged_insert(
                            self.results_area,
                            f"  • {hypothesis}",
                            "white",
                        )

                _tagged_insert(
                    self.results_area,
                    "─" * 70,
                    "muted",
                )
                
        if self.web_verification_results:
            _tagged_insert(
                self.results_area,
                "",
                "white",
            )

            _tagged_insert(
                self.results_area,
                "DIFFERENTIAL WEB VERIFICATION",
                "cyan",
            )

            _tagged_insert(
                self.results_area,
                "═" * 70,
                "muted",
            )

            for port, findings in self.web_verification_results.items():
                for finding in findings:
                    status = finding.get(
                        "status",
                        "INCONCLUSIVE",
                    )

                    severity = finding.get(
                        "severity",
                        "INFO",
                    )

                    if severity == "HIGH":
                        color = "red"
                    elif severity == "MEDIUM":
                        color = "amber"
                    else:
                        color = "cyan"

                    _tagged_insert(
                        self.results_area,
                        f"[{status}] {finding.get('title')}",
                        color,
                    )

                    _tagged_insert(
                        self.results_area,
                        f"Endpoint     : {finding.get('endpoint')}",
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        f"Method       : {finding.get('method')}",
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        f"Parameter    : {finding.get('parameter')}",
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        f"Confidence   : {finding.get('confidence')}",
                        "cyan",
                    )

                    metrics = finding.get(
                        "metrics",
                        {},
                    )

                    _tagged_insert(
                        self.results_area,
                        "Response Comparison",
                        "green",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • Baseline  : "
                            f"HTTP {metrics.get('baseline_status')} | "
                            f"{metrics.get('baseline_length')} bytes"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • Control   : "
                            f"HTTP {metrics.get('control_status')} | "
                            f"{metrics.get('control_length')} bytes"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • Quote     : "
                            f"HTTP {metrics.get('quote_status')} | "
                            f"{metrics.get('quote_length')} bytes"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • True Test : "
                            f"HTTP {metrics.get('true_status')} | "
                            f"{metrics.get('true_length')} bytes"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • False Test: "
                            f"HTTP {metrics.get('false_status')} | "
                            f"{metrics.get('false_length')} bytes"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        "Similarity",
                        "green",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • Baseline / Control: "
                            f"{metrics.get('baseline_control_similarity')}%"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • Baseline / Quote  : "
                            f"{metrics.get('baseline_quote_similarity')}%"
                        ),
                        "white",
                    )

                    _tagged_insert(
                        self.results_area,
                        (
                            "  • True / False      : "
                            f"{metrics.get('true_false_similarity')}%"
                        ),
                        "white",
                    )

                    reasons = finding.get(
                        "reasons",
                        [],
                    )

                    if reasons:
                        _tagged_insert(
                            self.results_area,
                            "Verification Reasons",
                            "amber",
                        )

                        for reason in reasons:
                            _tagged_insert(
                                self.results_area,
                                f"  • {reason}",
                                "white",
                            )

                    markers = finding.get(
                        "database_error_markers",
                        [],
                    )

                    if markers:
                        _tagged_insert(
                            self.results_area,
                            "Database Error Indicators",
                            "red",
                        )

                        for marker in markers:
                            _tagged_insert(
                                self.results_area,
                                f"  • {marker}",
                                "white",
                            )

                    _tagged_insert(
                        self.results_area,
                        finding.get(
                            "disclaimer",
                            "",
                        ),
                        "muted",
                    )

                    _tagged_insert(
                        self.results_area,
                        "─" * 70,
                        "muted",
                    )
                
        if not self.correlation_results:
            return

        _tagged_insert(
            self.results_area,
            "",
            "white",
        )

        _tagged_insert(
            self.results_area,
            "CORRELATED ATTACK-PATH INTELLIGENCE",
            "cyan",
        )

        _tagged_insert(
            self.results_area,
            "═" * 70,
            "muted",
        )

        for finding in self.correlation_results:
            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            if severity == "HIGH":
                color = "red"
            elif severity == "MEDIUM":
                color = "amber"
            elif severity == "LOW":
                color = "green"
            else:
                color = "cyan"

            _tagged_insert(
                self.results_area,
                (
                    f"[{severity}] "
                    f"{finding.get('title', 'Correlation Finding')}"
                ),
                color,
            )

            _tagged_insert(
                self.results_area,
                (
                    f"Category     : "
                    f"{finding.get('category', 'Unknown')}"
                ),
                "white",
            )

            _tagged_insert(
                self.results_area,
                (
                    f"Status       : "
                    f"{finding.get('status', 'CORRELATED HYPOTHESIS')}"
                ),
                "amber",
            )

            _tagged_insert(
                self.results_area,
                (
                    f"Confidence   : "
                    f"{finding.get('confidence', 'UNKNOWN')}"
                ),
                "cyan",
            )

            evidence = finding.get(
                "evidence",
                [],
            )

            if evidence:
                _tagged_insert(
                    self.results_area,
                    "Correlated Evidence",
                    "green",
                )

                for item in evidence:
                    _tagged_insert(
                        self.results_area,
                        f"  • {item}",
                        "white",
                    )

            hypotheses = finding.get(
                "hypotheses",
                [],
            )

            if hypotheses:
                _tagged_insert(
                    self.results_area,
                    "Attack-Path Hypotheses",
                    "amber",
                )

                for item in hypotheses:
                    _tagged_insert(
                        self.results_area,
                        f"  • {item}",
                        "white",
                    )

            recommendations = finding.get(
                "recommendations",
                [],
            )

            if recommendations:
                _tagged_insert(
                    self.results_area,
                    "Recommended Investigation",
                    "green",
                )

                for item in recommendations:
                    _tagged_insert(
                        self.results_area,
                        f"  • {item}",
                        "white",
                    )

            _tagged_insert(
                self.results_area,
                "─" * 70,
                "muted",
            )
            
        self._display_roadmap_results()

    def _display_roadmap_results(self):
        """
        Display the final analyst investigation workflow.
        """

        roadmap = getattr(
            self,
            "roadmap_results",
            {},
        )

        items = roadmap.get(
            "items",
            [],
        )

        if not items:
            return

        _tagged_insert(
            self.results_area,
            "",
            "white",
        )

        _tagged_insert(
            self.results_area,
            "ANALYST INVESTIGATION WORKFLOW",
            "cyan",
        )

        _tagged_insert(
            self.results_area,
            "═" * 70,
            "muted",
        )

        for item in items:

            severity = str(
                item.get(
                    "severity",
                    "INFO",
                )
            ).upper()

            if severity in ("CRITICAL", "HIGH"):
                color = "red"
            elif severity == "MEDIUM":
                color = "amber"
            elif severity == "LOW":
                color = "green"
            else:
                color = "cyan"

            _tagged_insert(
                self.results_area,
                f"STEP {item.get('priority', '-')}",
                "cyan",
            )

            _tagged_insert(
                self.results_area,
                f"Priority     : {severity}",
                color,
            )

            _tagged_insert(
                self.results_area,
                f"Category     : {item.get('category', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                f"Finding      : {item.get('title', 'Unknown')}",
                "white",
            )

            _tagged_insert(
                self.results_area,
                "Evidence",
                "green",
            )

            for evidence in item.get("evidence", []):
                _tagged_insert(
                    self.results_area,
                    f"  • {evidence}",
                    "white",
                )

            _tagged_insert(
                self.results_area,
                "Recommended Actions",
                "amber",
            )

            for action in item.get("actions", []):
                _tagged_insert(
                    self.results_area,
                    f"  • {action}",
                    "white",
                )

            _tagged_insert(
                self.results_area,
                "Objective",
                "green",
            )

            _tagged_insert(
                self.results_area,
                item.get(
                    "objective",
                    "",
                ),
                "white",
            )

            _tagged_insert(
                self.results_area,
                "─" * 70,
                "muted",
            )

        disclaimer = roadmap.get(
            "disclaimer",
            "",
        )

        if disclaimer:

            _tagged_insert(
                self.results_area,
                disclaimer,
                "muted",
            )

    def _run_enum_threaded(self):
        if not self.open_ports_found:
            _tagged_insert(
                self.results_area,
                "[-] No open ports found. Run Recon first.",
                "amber",
            )
            return

        self.results_area.delete("0.0", "end")
        _tagged_insert(
            self.results_area,
            f"[*] Enumerating {len(self.open_ports_found)} open ports...",
            "cyan",
        )

        threading.Thread(target=self._do_enumeration, daemon=True).start()

    def _do_enumeration(self):
        self.enum_results = enumeration_engine.run_enumeration(
            self.current_target,
            self.open_ports_found,
            structured=True,
        )

        self.web_recon_results = web_recon_engine.run_web_recon(
            self.current_target,
            self.open_ports_found,
        )

        self.web_detection_results = web_detection_engine.analyze_web_recon(
            self.web_recon_results,
        )

        self.web_verification_results = (
            web_verification_engine.verify_injection_hypotheses(
                self.current_target,
                self.web_recon_results,
                self.web_detection_results,
            )
        )

        self.correlation_results = correlation_engine.correlate_findings(
            self.recon_results,
            self.web_recon_results,
            self.web_detection_results,
        )

        self.roadmap_results = (
            roadmap_engine.build_investigation_roadmap(
                self.recon_results,
                self.web_detection_results,
                self.web_verification_results,
                self.correlation_results,
                self.exploit_results,
            )
        )

        self.after(0, self._display_enum_results)
        self.after(0, self._refresh_dashboard_if_visible)

    def show_exploit_engine(self):
        self.clear_main()
        self._section_header(self.main_content, "Exploit Engine", "CVE + Risk Analysis")

        btn_row = ctk.CTkFrame(self.main_content, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 14))

        self._action_btn(
            btn_row,
            "  ⬡  Analyze Vulnerabilities",
            RED,
            self._run_exploit_threaded,
        ).pack(side="left")

        ctk.CTkLabel(
            btn_row,
            text="  Evidence-based CVE and risk mapping",
            font=("Helvetica", 11),
            text_color=TXT_MUTED,
        ).pack(side="left", padx=12)

        self.exploit_area = self._module_textbox(self.main_content, height=650)
        self.exploit_area.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        if self.exploit_results:
            self._display_exploit_results()

    def _display_exploit_results(self):
        if not hasattr(self, "exploit_area") or not self.exploit_area.winfo_exists():
            return

        self.exploit_area.delete("0.0", "end")

        risk_score = exploit_engine.calculate_risk_score(self.exploit_results)

        _tagged_insert(self.exploit_area, f"Risk Score: {risk_score}/100", "red")
        _tagged_insert(self.exploit_area, "─" * 60, "muted")

        for port, findings in self.exploit_results.items():
            self._insert_exploit_port_result(port, findings)

    def _insert_exploit_port_result(self, port, findings):
        if not hasattr(self, "exploit_area") or not self.exploit_area.winfo_exists():
            return

        _tagged_insert(self.exploit_area, f"\nPORT {port}", "amber")
        _tagged_insert(self.exploit_area, "─" * 50, "muted")

        for finding in findings:
            service = finding.get("service", "Unknown Service")
            version = finding.get("version", "Unknown")
            ftype = finding.get("finding_type", "Finding")
            cve_status = finding.get("cve_status", "UNKNOWN")
            severity = finding.get("severity", "INFO")
            title = finding.get("title", "")
            cve = finding.get("cve", "N/A")
            cvss = finding.get("cvss", 0)
            fp_conf = finding.get("fingerprint_confidence", 0)
            fp_quality = finding.get("fingerprint_quality", "UNKNOWN")
            evidence = finding.get("evidence", "")
            description = finding.get("description", "")
            remediation = finding.get("remediation", "")

            if cve_status == "MATCH_FOUND":
                cve_line = f"CVE Status: MATCH FOUND → {cve}"
            elif cve_status == "NO_STRICT_MATCH":
                cve_line = "CVE Status: NO STRICT MATCH"
            elif cve_status == "VERSION_UNKNOWN":
                cve_line = "CVE Status: VERSION UNKNOWN"
            elif cve_status == "UNKNOWN_SERVICE":
                cve_line = "CVE Status: UNKNOWN SERVICE"
            else:
                cve_line = f"CVE Status: {cve_status}"

            lines = [
                f"[{severity}] {title}",
                f"Finding Type: {ftype}",
                f"Service: {service}",
                f"Version: {version}",
                f"Fingerprint Quality: {fp_quality}",
                f"Fingerprint Confidence: {fp_conf}%",
                cve_line,
                f"CVSS: {cvss}",
                f"Evidence: {evidence}",
                f"Reason: {description}",
                f"Recommended Next Action: {remediation}",
            ]

            for line in lines:
                _tagged_insert(self.exploit_area, "  " + line, _auto_tag(line))

            _tagged_insert(self.exploit_area, "", "white")

    def _run_exploit_threaded(self):
        if not self.enum_results:
            _tagged_insert(
                self.exploit_area,
                "[-] No enumeration data. Run Enumeration first.",
                "amber",
            )
            return

        self.exploit_area.delete("0.0", "end")
        _tagged_insert(self.exploit_area, "[*] Analyzing vulnerabilities...", "cyan")
        _tagged_insert(self.exploit_area, "[*] CVE intelligence lookup may take time on first run.", "cyan")
        _tagged_insert(self.exploit_area, "─" * 60, "muted")

        threading.Thread(target=self._do_exploit, daemon=True).start()

    def _do_exploit(self):
        self.exploit_results = {}

        try:
            total = len(self.enum_results)
            done = 0

            for port, banner in self.enum_results.items():
                port_int = int(port)

                vulns = exploit_engine.get_vulnerabilities(
                    port_int,
                    str(banner),
                    self.current_target,
                )

                self.exploit_results[port_int] = vulns
                done += 1

                self._set_stat(
                    status=f"ANALYZING {done}/{total}",
                    vectors=sum(len(v) for v in self.exploit_results.values()),
                )

                self.after(
                    0,
                    lambda p=port_int, f=vulns: self._insert_exploit_port_result(p, f),
                )

            risk_score = exploit_engine.calculate_risk_score(self.exploit_results)

            database_engine.save_scan(
                self.current_target,
                self.recon_results,
                self.enum_results,
                self.exploit_results,
                risk_score,
            )

            self._set_stat(
                status="ANALYSIS DONE",
                vectors=sum(len(v) for v in self.exploit_results.values()),
                risk=risk_score,
            )

            self.after(
                0,
                self._refresh_dashboard_if_visible,
            )


            def _final_update():
                if hasattr(self, "exploit_area") and self.exploit_area.winfo_exists():
                    _tagged_insert(self.exploit_area, "─" * 60, "muted")
                    _tagged_insert(
                        self.exploit_area,
                        f"[+] Analysis Complete | Risk Score: {risk_score}/100",
                        "green",
                    )

            self.after(0, _final_update)

        except Exception as e:
            def _show_error():
                if hasattr(self, "exploit_area") and self.exploit_area.winfo_exists():
                    _tagged_insert(
                        self.exploit_area,
                        f"[!] Exploit analysis failed: {e}",
                        "red",
                    )

            self.after(0, _show_error)
            self._set_stat(status="ERROR")

    def show_verification(self):
        self.clear_main()
        self._section_header(self.main_content, "Verification", "Safe NSE Confirmation")

        btn_row = ctk.CTkFrame(self.main_content, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 14))

        self._action_btn(
            btn_row,
            "  ⬟  Run Verification",
            "#00AA55",
            self._run_verify_threaded,
        ).pack(side="left")

        ctk.CTkLabel(
            btn_row,
            text="  Confirms selected findings using safe Nmap scripts",
            font=("Helvetica", 11),
            text_color=TXT_MUTED,
        ).pack(side="left", padx=12)

        self.verify_area = self._module_textbox(self.main_content, height=650)
        self.verify_area.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        if self.verification_results:
            self._display_verification_results()

    def _display_verification_results(self):
        if not hasattr(self, "verify_area") or not self.verify_area.winfo_exists():
            return

        self.verify_area.delete("0.0", "end")
        _tagged_insert(self.verify_area, "[+] Previous Verification Results", "green")
        _tagged_insert(self.verify_area, "─" * 60, "muted")

        for port, results in self.verification_results.items():
            _tagged_insert(self.verify_area, f"\nPORT {port}", "amber")
            _tagged_insert(self.verify_area, "─" * 40, "muted")

            for result in results:
                status = result.get("status", "unknown")
                summary = result.get("summary", "")
                output = result.get("output", "")

                tag = "red" if status in ["confirmed", "confirmed_misconfiguration"] else "cyan"

                _tagged_insert(self.verify_area, f"Status: {status}", tag)

                if summary:
                    _tagged_insert(self.verify_area, summary, tag)

                if output:
                    _tagged_insert(self.verify_area, output[:3000], "white")

                _tagged_insert(self.verify_area, "─" * 60, "muted")

    def _run_verify_threaded(self):
        if not self.exploit_results:
            _tagged_insert(
                self.verify_area,
                "[-] Run Exploit Engine first.",
                "amber",
            )
            return

        self.verify_area.delete("0.0", "end")
        _tagged_insert(self.verify_area, "[*] Starting safe verification...", "cyan")
        threading.Thread(target=self._do_verify, daemon=True).start()

    def _do_verify(self):
        self.verification_results = {}

        for port, findings in self.exploit_results.items():
            self.verification_results[port] = []

            for finding in findings:
                severity = finding.get("severity", "").upper()

                if severity not in ["CRITICAL", "HIGH", "MEDIUM"]:
                    continue

                title = finding.get("title", "Unknown Finding")

                self.after(
                    0,
                    lambda p=port, t=title: _tagged_insert(
                        self.verify_area,
                        f"\n[*] Testing Port {p} → {t}",
                        "amber",
                    ),
                )

                result = exploit_poc.run_poc(self.current_target, port, finding)
                self.verification_results[port].append(result)

                status = result.get("status", "unknown")
                output = result.get("output", result.get("summary", ""))

                tag = "red" if status == "confirmed" else "cyan"
                display_text = f"Status: {status}\n{output[:3000]}"

                self.after(
                    0,
                    lambda text=display_text, tg=tag: _tagged_insert(
                        self.verify_area,
                        text,
                        tg,
                    ),
                )

                self.after(
                    0,
                    lambda: _tagged_insert(self.verify_area, "─" * 60, "muted"),
                )

        self.after(
            0,
            lambda: _tagged_insert(
                self.verify_area,
                "\n[+] Verification Complete.",
                "green",
            ),
        )
        
        self.after(
            0,
            self._refresh_dashboard_if_visible,
        )        
        

    def show_report_generator(self):
        self.clear_main()
        self._section_header(self.main_content, "Report Generator", "HTML Export")

        btn_row = ctk.CTkFrame(self.main_content, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 14))

        self._action_btn(
            btn_row,
            "  ◧  Generate HTML Report",
            ACCENT,
            self._run_report_threaded,
        ).pack(side="left")

        ctk.CTkLabel(
            btn_row,
            text="  Exports professional HTML report",
            font=("Helvetica", 11),
            text_color=TXT_MUTED,
        ).pack(side="left", padx=12)

        self.report_area = self._module_textbox(self.main_content)
        self.report_area.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    def _run_report_threaded(self):
        if not self.current_target:
            _tagged_insert(self.report_area, "[-] No target selected.", "amber")
            return

        _tagged_insert(self.report_area, "[*] Generating HTML report...", "cyan")
        threading.Thread(target=self._do_report, daemon=True).start()

    def _do_report(self):
        filename = report_engine.generate_report(
            self.current_target,
            self.recon_results,
            self.enum_results,
            self.exploit_results,
            self.web_recon_results,
            self.web_detection_results,
            self.web_verification_results,
            self.correlation_results,
            self.roadmap_results,
        )

        self.after(
            0,
            lambda: _tagged_insert(
                self.report_area,
                f"[+] Report saved: {filename}",
                "green",
            ),
        )

    def show_history(self):
        self.clear_main()

        self._section_header(
            self.main_content,
            "Scan History",
            "Stored Assessments",
        )

        history_area = self._module_textbox(
            self.main_content,
            height=650,
        )
        history_area.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=(0, 20),
        )

        history_data = database_engine.get_history()

        if not history_data:
            _tagged_insert(
                history_area,
                "No scan history available.",
                "muted",
            )
            return

        _tagged_insert(
            history_area,
            "BHISHMA ENTERPRISE - SCAN HISTORY",
            "cyan",
        )

        _tagged_insert(
            history_area,
            "═" * 80,
            "muted",
        )

        for scan in history_data:

            if len(scan) == 4:
                scan_id, target, timestamp, risk = scan
            else:
                scan_id, target, timestamp = scan
                risk = 0

            if risk >= 80:
                risk_tag = "CRITICAL"
                risk_color = "red"

            elif risk >= 60:
                risk_tag = "HIGH"
                risk_color = "red"

            elif risk >= 35:
                risk_tag = "MEDIUM"
                risk_color = "amber"

            else:
                risk_tag = "LOW"
                risk_color = "green"

            _tagged_insert(
                history_area,
                f"Assessment #{scan_id}",
                "cyan",
            )

            _tagged_insert(
                history_area,
                f"Target      : {target}",
                "white",
            )

            _tagged_insert(
                history_area,
                f"Scan Time   : {timestamp}",
                "white",
            )

            _tagged_insert(
                history_area,
                f"Risk Score  : {risk}/100 ({risk_tag})",
                risk_color,
            )

            _tagged_insert(
                history_area,
                "─" * 80,
                "muted",
            )

    def handle_run(self):
        if self.run_btn.cget("text").strip().endswith("ENGAGE TARGET"):
            target = self.ip_entry.get().strip()

            if not target:
                return

            self.current_target = target
            self.creds = self.cred_entry.get().strip()

            self.recon_results = []
            self.open_ports_found = []
            self.enum_results = {}
            self.web_recon_results = {}
            self.web_detection_results = {}
            self.web_verification_results = {}
            self.correlation_results = []
            self.roadmap_results = {
                "summary": {},
                "items": [],
                "disclaimer": "",
            }
            self.exploit_results = {}
            self.verification_results = {}

            self.run_btn.configure(
                text="  ■  STOP SCAN",
                fg_color=RED,
            )

            self._set_stat(
                status="RECON RUNNING",
                targets=1,
                vectors=0,
                hits=0,
                risk=0,
            )

            self._refresh_dashboard_if_visible()

            threading.Thread(
                target=self._do_recon,
                daemon=True,
            ).start()

        else:
            recon_engine.stop()

            self.run_btn.configure(
                text="▶ ENGAGE TARGET",
                fg_color=ACCENT,
            )

            self._set_stat(status="CANCELLED")
            self._refresh_dashboard_if_visible()

    def _do_recon(self):
        self.recon_results = recon_engine.start_recon_sequence(
            self.current_target,
            full_scan=self.full_scan_var.get(),
            throttle=self.throttle_slider.get(),
        )

        self.recon_results = list(dict.fromkeys(self.recon_results))
        self.open_ports_found = self._parse_open_ports(self.recon_results)

        self._set_stat(
            status="COMPLETED",
            targets=1,
            vectors=len(self.recon_results),
            hits=len(self.open_ports_found),
            risk=0,
        )

        def _stream_console_lines(index=0):
            if not hasattr(self, "console") or not self.console.winfo_exists():
                return

            if index == 0:
                self.console.delete("0.0", "end")
                _tagged_insert(self.console, "BHISHMA LIVE OPERATIONS STREAM", "cyan")
                _tagged_insert(self.console, "─" * 46, "muted")

            if index >= len(self.recon_results):
                _tagged_insert(self.console, "[DONE] Reconnaissance completed", "green")
                return

            line = self.recon_results[index]
            _tagged_insert(self.console, f"[LIVE] {line}", _auto_tag(line))

            self.after(
                80,
                lambda: _stream_console_lines(index + 1),
            )

        def _finish():
            if hasattr(self, "run_btn") and self.run_btn.winfo_exists():
                self.run_btn.configure(text="  ▶  Engage Target", fg_color=ACCENT)

            self._refresh_dashboard_if_visible()
            _stream_console_lines()

        self.after(0, _finish)


if __name__ == "__main__":
    app = BhishmaApp()
    app.mainloop()
