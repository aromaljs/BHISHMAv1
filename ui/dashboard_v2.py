import customtkinter as ctk


class DashboardV2:
    def __init__(self, app):
        self.app = app
        self.metric_labels = []

    def render(self):
        app = self.app
        app.clear_main()

        app.main_content.grid_columnconfigure(0, weight=1)

        app.main_content.grid_rowconfigure(0, weight=0)
        app.main_content.grid_rowconfigure(1, weight=0)
        app.main_content.grid_rowconfigure(2, weight=0)
        app.main_content.grid_rowconfigure(3, weight=1)
        app.main_content.grid_rowconfigure(4, weight=2)
        app.main_content.grid_rowconfigure(5, weight=1)
        app.main_content.grid_rowconfigure(6, weight=0)

        self._header()
        self._kpi_cards()
        self._workflow()
        self._executive_row()
        self._workspace()
        self._bottom_row()
        self._footer()

    def _risk_color(self, score):
        if score >= 80:
            return "#FF3D57"
        if score >= 60:
            return "#FF3D57"
        if score >= 35:
            return "#FFB300"
        if score > 0:
            return "#00E676"
        return "#8B949E"

    def _panel(
        self,
        parent,
        title,
        row,
        col,
        rowspan=1,
        colspan=1,
        accent="#00B8FF",
        height=None,
    ):
        panel_kwargs = {
            "fg_color": "#0D1117",
            "border_width": 2,
            "border_color": "#1D5FA8",
            "corner_radius": 18,
        }

        if height is not None:
            panel_kwargs["height"] = height

        panel = ctk.CTkFrame(
            parent,
            **panel_kwargs,
        )

        panel.grid(
            row=row,
            column=col,
            rowspan=rowspan,
            columnspan=colspan,
            sticky="nsew",
            padx=8,
            pady=8,
        )

        if height is not None:
            panel.grid_propagate(False)

        header = ctk.CTkFrame(
            panel,
            fg_color="transparent",
            height=36,
        )
        header.pack(fill="x", padx=16, pady=(12, 0))
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text=title.upper(),
            font=("Helvetica", 13, "bold"),
            text_color="#FFFFFF",
        ).pack(side="left")

        glow = ctk.CTkFrame(
            panel,
            fg_color=accent,
            height=3,
            corner_radius=10,
        )
        glow.pack(fill="x", padx=16, pady=(4, 10))

        body = ctk.CTkFrame(
            panel,
            fg_color="transparent",
        )
        body.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=(2, 14),
        )

        return body

    def _header(self):
        app = self.app

        header = ctk.CTkFrame(
            app.main_content,
            fg_color="#05070D",
            border_width=2,
            border_color="#274D7E",
            corner_radius=16,
            height=110,
        )
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(14, 10))
        header.grid_propagate(False)

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.pack(fill="both", expand=True, padx=20, pady=18)

        for i in range(6):
            controls.grid_columnconfigure(i, weight=1)

        def label(text, col):
            ctk.CTkLabel(
                controls,
                text=text,
                font=("Helvetica", 10, "bold"),
                text_color="#FFFFFF",
            ).grid(row=0, column=col, sticky="w", padx=8, pady=(0, 4))

        label("TARGET IP / DOMAIN", 0)
        label("SSH USER", 1)
        label("SCAN MODE", 2)
        label("THROTTLE", 3)
        label("MAX PORTS", 4)

        app.ip_entry = ctk.CTkEntry(
            controls,
            placeholder_text="Enter target IP or domain",
            width=230,
            height=38,
            fg_color="#0B1220",
            border_color="#274D7E",
            text_color="#FFFFFF",
            placeholder_text_color="#8B949E",
        )
        app.ip_entry.grid(row=1, column=0, sticky="ew", padx=8)

        app.cred_entry = ctk.CTkEntry(
            controls,
            placeholder_text="username@target optional",
            width=230,
            height=38,
            fg_color="#0B1220",
            border_color="#274D7E",
            text_color="#FFFFFF",
            placeholder_text_color="#8B949E",
        )
        app.cred_entry.grid(row=1, column=1, sticky="ew", padx=8)

        app.scan_profile = ctk.CTkSegmentedButton(
            controls,
            values=["QUICK", "STANDARD", "DEEP"],
            selected_color="#00B8FF",
            selected_hover_color="#33C9FF",
            unselected_color="#0B1220",
            unselected_hover_color="#111827",
        )
        app.scan_profile.grid(row=1, column=2, sticky="ew", padx=8)
        app.scan_profile.set("STANDARD")

        app.throttle_slider = ctk.CTkSlider(
            controls,
            from_=0,
            to=0.5,
            width=120,
            button_color="#00B8FF",
            progress_color="#00B8FF",
        )
        app.throttle_slider.set(0.01)
        app.throttle_slider.grid(row=1, column=3, sticky="ew", padx=8)

        app.full_scan_var = ctk.BooleanVar(value=False)

        ctk.CTkSwitch(
            controls,
            text="65K Ports",
            variable=app.full_scan_var,
            text_color="#FFFFFF",
            button_color="#00B8FF",
            progress_color="#00B8FF",
        ).grid(row=1, column=4, sticky="w", padx=8)

        app.run_btn = ctk.CTkButton(
            controls,
            text="▶ ENGAGE TARGET",
            fg_color="#00B8FF",
            hover_color="#4DD2FF",
            border_width=2,
            border_color="#A5ECFF",
            height=48,
            width=190,
            corner_radius=14,
            font=("Helvetica", 13, "bold"),
            text_color="#FFFFFF",
            command=app.handle_run,
        )
        app.run_btn.grid(row=1, column=5, sticky="e", padx=8)

        ctk.CTkLabel(
            header,
            text="● ENGINE STATUS: ONLINE",
            font=("Helvetica", 10, "bold"),
            text_color="#00E676",
        ).place(relx=0.985, rely=0.18, anchor="e")

    def _metric(self, parent, col, icon, title, value, sub, color):

        card = ctk.CTkFrame(
            parent,
            fg_color="#111827",
            border_width=2,
            border_color="#1D5FA8",
            corner_radius=18,
            height=126,
        )
        card.grid(
            row=0,
            column=col,
            sticky="nsew",
            padx=6,
        )
        card.grid_propagate(False)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 6))

        ctk.CTkLabel(
            top,
            text=icon,
            font=("Segoe UI Emoji", 18),
            text_color=color,
        ).pack(side="left")

        ctk.CTkLabel(
            top,
            text=title.upper(),
            font=("Helvetica", 10, "bold"),
            text_color="#8B949E",
        ).pack(side="left", padx=8)

        value_label = ctk.CTkLabel(
            card,
            text="0",
            font=("Helvetica", 32, "bold"),
            text_color=color,
        )
        value_label.pack(anchor="w", padx=16)

        ctk.CTkLabel(
            card,
            text=sub,
            font=("Helvetica", 10),
            text_color="#8B949E",
        ).pack(anchor="w", padx=16)

        ctk.CTkFrame(
            card,
            fg_color=color,
            height=4,
            corner_radius=10,
        ).pack(
            fill="x",
            padx=16,
            pady=(12, 0),
        )

        try:
            target = int(value)
            self.metric_labels.append((value_label, target))
        except Exception:
            value_label.configure(text=str(value))

    def _animate_metrics(self):

        for label, target in self.metric_labels:

            def counter(lbl=label, tgt=target, value=0):

                if value >= tgt:
                    lbl.configure(text=str(tgt))
                    return

                step = max(1, tgt // 20)

                lbl.configure(text=str(value))

                lbl.after(
                    15,
                    lambda: counter(
                        lbl,
                        tgt,
                        min(value + step, tgt)
                    )
                )

            counter()

    def _kpi_cards(self):
        app = self.app

        frame = ctk.CTkFrame(app.main_content, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="ew", padx=22, pady=(16, 10))

        for i in range(6):
            frame.grid_columnconfigure(i, weight=1)

        self.metric_labels.clear()

        self._metric(frame, 0, "🛡", "Status", app.stat_status.get(), "Assessment State", "#00E676")
        self._metric(frame, 1, "🎯", "Target", app.current_target if app.current_target else "--", "Selected Asset", "#00B8FF")
        self._metric(frame, 2, "⚠", "Risk", app.stat_risk.get(), "Overall Risk", "#FF3D57")
        self._metric(frame, 3, "📋", "Findings", app.stat_vectors.get(), "Total Findings", "#FFB300")
        self._metric(frame, 4, "🌐", "Ports", len(app.open_ports_found), "Open Services", "#00E5FF")
        self._metric(frame, 5, "💻", "Tech", len(app._dashboard_technologies()), "Detected Stack", "#6F5BFF")

        self._animate_metrics()

    def _workflow(self):
        app = self.app
        self.workflow_widgets = {}

        frame = ctk.CTkFrame(
            app.main_content,
            fg_color="#05070D",
            border_width=2,
            border_color="#1D5FA8",
            corner_radius=16,
            height=92,
        )
        frame.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 10))
        frame.grid_propagate(False)

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=20, pady=10)

        stages = [
            ("RECON", "#00E676"),
            ("ENUM", "#00B8FF"),
            ("TECH", "#6F5BFF"),
            ("INTEL", "#FFB300"),
            ("VERIFY", "#00E676"),
        ]

        for i in range(len(stages)):
            inner.grid_columnconfigure(i, weight=1)

        for i, (title, color) in enumerate(stages):
            cell = ctk.CTkFrame(inner, fg_color="transparent")
            cell.grid(row=0, column=i, sticky="nsew")

            top = ctk.CTkFrame(cell, fg_color="transparent")
            top.pack(fill="x")

            dot = ctk.CTkLabel(
                top,
                text="●",
                font=("Helvetica", 18, "bold"),
                text_color="#4B5563",
            )
            dot.pack(side="left")

            connector = None

            if i < len(stages) - 1:
                connector = ctk.CTkFrame(
                    top,
                    fg_color="#1F2A3D",
                    height=2,
                )
                connector.pack(
                    side="left",
                    fill="x",
                    expand=True,
                    padx=(6, 0),
                    pady=10,
                )

            title_label = ctk.CTkLabel(
                cell,
                text=title,
                font=("Helvetica", 11, "bold"),
                text_color="#FFFFFF",
            )
            title_label.pack(pady=(6, 2))

            state_label = ctk.CTkLabel(
                cell,
                text="READY",
                font=("Helvetica", 9, "bold"),
                text_color="#8B949E",
            )
            state_label.pack()

            self.workflow_widgets[title] = {
                "dot": dot,
                "connector": connector,
                "state": state_label,
                "color": color,
            }

        self._refresh_workflow()
        
    def _refresh_workflow(self):
        app = self.app

        status = str(app.stat_status.get()).upper()

        states = {
            "RECON": bool(app.recon_results),
            "ENUM": bool(app.enum_results),
            "TECH": bool(app._dashboard_technologies()),
            "INTEL": bool(app.exploit_results),
            "VERIFY": bool(app.verification_results),
        }

        active_stage = None

        if "RECON" in status:
            active_stage = "RECON"
        elif "ENUM" in status:
            active_stage = "ENUM"
        elif "ANALYZING" in status:
            active_stage = "INTEL"
        elif "VERIFY" in status:
            active_stage = "VERIFY"

        for name, complete in states.items():
            widget = self.workflow_widgets.get(name)

            if not widget:
                continue

            color = widget["color"]

            if complete:
                dot_text = "✔"
                dot_color = color
                state_text = "COMPLETE"
                state_color = color

            elif name == active_stage:
                dot_text = "●"
                dot_color = color
                state_text = "RUNNING"
                state_color = "#FFFFFF"

            else:
                dot_text = "○"
                dot_color = "#4B5563"
                state_text = "PENDING"
                state_color = "#8B949E"

            widget["dot"].configure(
                text=dot_text,
                text_color=dot_color,
            )

            widget["state"].configure(
                text=state_text,
                text_color=state_color,
            )

            if widget["connector"]:

                if complete:
                    connector_color = color

                elif name == active_stage:
                    connector_color = "#3A7BFF"

                else:
                    connector_color = "#1F2A3D"

                widget["connector"].configure(
                    fg_color=connector_color,
                )

    def _executive_row(self):
        app = self.app

        row = ctk.CTkFrame(app.main_content, fg_color="transparent")
        row.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 8))
        row.grid_columnconfigure(0, weight=3)
        row.grid_columnconfigure(1, weight=2)
        row.grid_columnconfigure(2, weight=2)

        self._executive_summary(row)
        self._attack_score(row)
        self._breakdown(row)

    def _executive_summary(self, parent):
        app = self.app

        body = self._panel(
            parent,
            "Executive Summary",
            0,
            0,
            accent="#00B8FF",
            height=210,
        )

        target = app.current_target if app.current_target else "No Target Selected"

        risk = (
            int(app.stat_risk.get())
            if str(app.stat_risk.get()).isdigit()
            else 0
        )

        techs = app._dashboard_technologies()
        sev = app._dashboard_severity_counts()

        chip_text = (
            "ASSESSMENT READY"
            if app.current_target
            else "WAITING FOR TARGET"
        )

        chip_color = (
            "#00E676"
            if app.current_target
            else "#8B949E"
        )

        chip = ctk.CTkFrame(
            body,
            fg_color="#0B1220",
            border_width=2,
            border_color=chip_color,
            corner_radius=999,
        )
        chip.pack(anchor="w", pady=(0, 12))

        ctk.CTkLabel(
            chip,
            text=f"● {chip_text}",
            font=("Helvetica", 10, "bold"),
            text_color=chip_color,
        ).pack(
            padx=12,
            pady=5,
        )

        summary = (
            f"Target: {target}\n\n"
            f"Open Services : {len(app.open_ports_found)}\n"
            f"Risk Score    : {risk}/100\n"
            f"Critical      : {sev['CRITICAL']}\n"
            f"High          : {sev['HIGH']}\n"
            f"Medium        : {sev['MEDIUM']}\n"
            f"Low           : {sev['LOW']}\n\n"
            f"Technology    : "
            f"{', '.join(techs[:4]) if techs else 'Pending'}"
        )

        ctk.CTkLabel(
            body,
            text=summary,
            font=("Consolas", 12),
            text_color="#D8DCE5",
            justify="left",
            anchor="w",
        ).pack(
            anchor="w",
            fill="x",
        )

    def _attack_score(self, parent):
        app = self.app
        score = app._dashboard_attack_surface_score()
        color = self._risk_color(score)

        body = self._panel(
            parent,
            "Attack Surface Score",
            0,
            1,
            accent=color,
            height=210,
        )

        gauge = ctk.CTkCanvas(
            body,
            width=260,
            height=120,
            bg="#0D1117",
            highlightthickness=0,
        )
        gauge.pack(pady=(8, 0))

        gauge.create_arc(
            25,
            20,
            235,
            210,
            start=180,
            extent=-180,
            style="arc",
            outline="#1F2A3D",
            width=14,
        )

        active_arc = gauge.create_arc(
            25,
            20,
            235,
            210,
            start=180,
            extent=0,
            style="arc",
            outline=color,
            width=14,
        )
        
        self.attack_canvas = gauge
        self.attack_arc = active_arc

        score_label = ctk.CTkLabel(
            body,
            text="0",
            font=("Helvetica", 44, "bold"),
            text_color=color,
        )
        score_label.pack(pady=(0, 0))
        self.score_label = score_label

        risk_label = ctk.CTkLabel(
            body,
            text=f"{app._dashboard_risk_label(score)}  •  {score}/100",
            font=("Helvetica", 13, "bold"),
            text_color=color,
        )
        risk_label.pack(pady=(0, 8))
        self.risk_label = risk_label

        def animate(value=0):
            if value >= score:
                gauge.itemconfig(
                    active_arc,
                    extent=-(180 * score / 100),
                )
                score_label.configure(text=str(score))
                return

            step = max(1, score // 25)

            gauge.itemconfig(
                active_arc,
                extent=-(180 * value / 100),
            )
            score_label.configure(text=str(value))

            gauge.after(
                15,
                lambda: animate(min(value + step, score)),
            )

        animate()

    def _breakdown(self, parent):
        app = self.app
        body = self._panel(parent, "Exposure Breakdown", 0, 2, accent="#00E5FF", height=210)

        ports = app.open_ports_found
        web = 0.85 if any(p in ports for p in [80, 443, 8080, 8443]) else 0.15
        remote = 0.65 if any(p in ports for p in [22, 3389, 5985]) else 0.10
        smb = 0.70 if any(p in ports for p in [139, 445]) else 0.10
        mgmt = 0.80 if any(p in ports for p in [10000, 20000]) else 0.10

        for name, value, color in [
            ("WEB", web, "#00B8FF"),
            ("REMOTE", remote, "#6F5BFF"),
            ("SMB", smb, "#FFB300"),
            ("MGMT", mgmt, "#FF3D57"),
        ]:
            line = ctk.CTkFrame(body, fg_color="transparent")
            line.pack(fill="x", pady=4)

            ctk.CTkLabel(line, text=name, width=70, anchor="w", font=("Helvetica", 10, "bold"), text_color="#FFFFFF").pack(side="left")

            bar = ctk.CTkProgressBar(line, width=160, progress_color=color, fg_color="#1F2A3D")
            bar.pack(side="left", padx=8)
            bar.set(value)

            ctk.CTkLabel(line, text=f"{int(value * 100)}%", width=40, font=("Helvetica", 10, "bold"), text_color=color).pack(side="left")

    def _workspace(self):
        app = self.app

        work = ctk.CTkFrame(app.main_content, fg_color="transparent")
        work.grid(row=4, column=0, sticky="nsew", padx=14, pady=(0, 8))
        work.grid_columnconfigure(0, weight=3)
        work.grid_columnconfigure(1, weight=2)
        work.grid_columnconfigure(2, weight=2)
        work.grid_rowconfigure(0, weight=1)

        self._console_panel(work)
        self._timeline_panel(work)
        self._verification_panel(work)

    def _console_panel(self, parent):
        app = self.app

        body = self._panel(
            parent,
            "Live Assessment Console",
            0,
            0,
            accent="#00B8FF",
        )

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(
            header,
            text="● LIVE",
            font=("Helvetica", 11, "bold"),
            text_color="#00E676",
        ).pack(side="left")

        ctk.CTkLabel(
            header,
            text="SOC assessment stream",
            font=("Helvetica", 10),
            text_color="#8B949E",
        ).pack(side="left", padx=10)

        app.console = app._module_textbox(body)
        app.console.configure(
            border_width=2,
            border_color="#00B8FF",
            font=("Consolas", 13, "bold"),
        )
        app.console.pack(fill="both", expand=True)

        app.console.delete("0.0", "end")

        if app.recon_results:
            for line in app.recon_results:
                app.console.insert("end", f"[LIVE]  {line}\n")
        else:
            startup_lines = [
                "[READY]  BHISHMA Enterprise console initialized",
                "[INFO]   Waiting for target input",
                "[MODE]   Quick / Standard / Deep profiles available",
                "[SAFE]   Detection and verification only",
                "[NEXT]   Enter target and click ENGAGE TARGET",
            ]

            app.console.insert("end", "BHISHMA LIVE OPERATIONS STREAM\n")
            app.console.insert("end", "─" * 46 + "\n\n")

            for line in startup_lines:
                app.console.insert("end", line + "\n")

    def _timeline_panel(self, parent):
        app = self.app

        body = self._panel(
            parent,
            "Assessment Timeline",
            0,
            1,
            accent="#6F5BFF",
        )

        events = []

        if app.current_target:
            events.append(("TARGET", f"Selected target: {app.current_target}", "#00B8FF"))
        else:
            events.append(("WAITING", "Target input required", "#8B949E"))

        if app.recon_results:
            events.append(("RECON", f"Recon completed • {len(app.open_ports_found)} open port(s)", "#00E676"))
        else:
            events.append(("RECON", "Reconnaissance pending", "#8B949E"))

        if app.enum_results:
            techs = app._dashboard_technologies()
            tech_text = ", ".join(techs[:3]) if techs else "Services fingerprinted"
            events.append(("ENUM", f"Fingerprinting completed • {tech_text}", "#00B8FF"))
        else:
            events.append(("ENUM", "Service fingerprinting pending", "#8B949E"))

        if app.exploit_results:
            findings = sum(len(v) for v in app.exploit_results.values())
            events.append(("INTEL", f"CVE intelligence completed • {findings} finding(s)", "#FFB300"))
        else:
            events.append(("INTEL", "Risk intelligence pending", "#8B949E"))

        if app.verification_results:
            checks = sum(len(v) for v in app.verification_results.values())
            events.append(("VERIFY", f"Verification completed • {checks} check(s)", "#00E676"))
        else:
            events.append(("VERIFY", "Safe verification pending", "#8B949E"))

        for index, (title, desc, color) in enumerate(events):
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", pady=3)

            marker = ctk.CTkFrame(row, fg_color="transparent", width=34)
            marker.pack(side="left", fill="y")
            marker.pack_propagate(False)

            ctk.CTkLabel(
                marker,
                text="●",
                font=("Helvetica", 16, "bold"),
                text_color=color,
            ).pack(anchor="n")

            if index < len(events) - 1:
                ctk.CTkFrame(
                    marker,
                    fg_color=color if color != "#8B949E" else "#1F2A3D",
                    width=2,
                    height=26,
                ).pack(anchor="n")

            text_area = ctk.CTkFrame(row, fg_color="transparent")
            text_area.pack(side="left", fill="x", expand=True)

            ctk.CTkLabel(
                text_area,
                text=title,
                font=("Helvetica", 11, "bold"),
                text_color=color,
            ).pack(anchor="w")

            ctk.CTkLabel(
                text_area,
                text=desc,
                font=("Helvetica", 11),
                text_color="#D8DCE5",
                wraplength=300,
                justify="left",
            ).pack(anchor="w")

    def _verification_panel(self, parent):
        app = self.app
        body = self._panel(parent, "Verification Status", 0, 2, accent="#00E676")

        total = sum(len(v) for v in app.verification_results.values()) if app.verification_results else 0

        confirmed = 0
        observed = 0
        pending = 0

        if app.verification_results:
            for results in app.verification_results.values():
                for result in results:
                    status = str(result.get("status", "")).lower()

                    if "confirmed" in status:
                        confirmed += 1
                    elif "observed" in status:
                        observed += 1
                    else:
                        pending += 1

        status_text = "ACTIVE" if total else "NOT RUN"
        status_color = "#00E676" if total else "#8B949E"

        ctk.CTkLabel(
            body,
            text="🛡",
            font=("Segoe UI Emoji", 34),
            text_color=status_color,
        ).pack(anchor="w", pady=(4, 2))

        ctk.CTkLabel(
            body,
            text=status_text,
            font=("Helvetica", 28, "bold"),
            text_color=status_color,
        ).pack(anchor="w")

        progress = ctk.CTkProgressBar(
            body,
            width=220,
            height=12,
            progress_color=status_color,
            fg_color="#1F2A3D",
        )
        progress.pack(anchor="w", pady=(10, 12))
        progress.set(1 if total else 0)

        rows = [
            ("CONFIRMED", confirmed, "#00E676"),
            ("OBSERVED", observed, "#00B8FF"),
            ("PENDING", pending, "#FFB300"),
            ("TOTAL CHECKS", total, "#D8DCE5"),
        ]

        for name, value, color in rows:
            line = ctk.CTkFrame(body, fg_color="transparent")
            line.pack(fill="x", pady=2)

            ctk.CTkLabel(
                line,
                text=name,
                width=120,
                anchor="w",
                font=("Helvetica", 10, "bold"),
                text_color="#8B949E",
            ).pack(side="left")

            ctk.CTkLabel(
                line,
                text=str(value),
                font=("Helvetica", 12, "bold"),
                text_color=color,
            ).pack(side="right")

    def _bottom_row(self):
        app = self.app

        row = ctk.CTkFrame(app.main_content, fg_color="transparent")
        row.grid(row=5, column=0, sticky="ew", padx=14, pady=(0, 8))
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=1)

        self._technology_stack(row)
        self._recent_activity(row)

    def _technology_stack(self, parent):
        app = self.app

        body = self._panel(
            parent,
            "Technology Stack",
            0,
            0,
            accent="#00E5FF",
            height=150,
        )

        techs = app._dashboard_technologies()

        if not techs:
            techs = [
                "Enumeration Pending",
                "Intelligence Pending",
            ]

        grid = ctk.CTkFrame(
            body,
            fg_color="transparent",
        )
        grid.pack(anchor="w", fill="x")

        colors = [
            "#00E5FF",
            "#00B8FF",
            "#6F5BFF",
            "#00E676",
            "#FFB300",
            "#D8DCE5",
        ]

        for i, tech in enumerate(techs[:8]):
            color = colors[i % len(colors)]

            chip = ctk.CTkFrame(
                grid,
                fg_color="#08111F",
                border_width=2,
                border_color=color,
                corner_radius=999,
            )
            chip.grid(
                row=i // 4,
                column=i % 4,
                sticky="w",
                padx=6,
                pady=6,
            )

            ctk.CTkLabel(
                chip,
                text=f"●  {tech}",
                font=("Helvetica", 10, "bold"),
                text_color=color,
            ).pack(
                padx=12,
                pady=7,
            )

    def _recent_activity(self, parent):
        app = self.app

        body = self._panel(
            parent,
            "Recent Activity",
            0,
            1,
            accent="#FFB300",
            height=150,
        )

        events = []

        if app.current_target:
            events.append(("●", f"Target: {app.current_target}", "#00B8FF"))

        if app.recon_results:
            events.append(("✓", "Reconnaissance completed", "#00E676"))

        if app.enum_results:
            events.append(("✓", "Service fingerprinting completed", "#6F5BFF"))

        if app.exploit_results:
            events.append(("✓", f"Risk Score: {app.stat_risk.get()}/100", "#FFB300"))

        if app.verification_results:
            events.append(("✓", "Verification completed", "#00E676"))

        if not events:
            events.append(("○", "Waiting for assessment...", "#8B949E"))

        for icon, text, color in events:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", pady=3)

            ctk.CTkLabel(
                row,
                text=icon,
                font=("Helvetica", 12, "bold"),
                text_color=color,
                width=18,
            ).pack(side="left")

            ctk.CTkLabel(
                row,
                text=text,
                font=("Helvetica", 10, "bold"),
                text_color="#D8DCE5",
            ).pack(side="left")

    def refresh(self):
        app = self.app

        score = app._dashboard_attack_surface_score()
        color = self._risk_color(score)

        self._refresh_workflow()

        # -------------------------------
        # Animate Attack Surface Gauge
        # -------------------------------
        if hasattr(self, "attack_canvas") and hasattr(self, "attack_arc"):

            current_extent = self.attack_canvas.itemcget(
                self.attack_arc,
                "extent",
            )

            try:
                current_extent = float(current_extent)
            except Exception:
                current_extent = 0

            target_extent = -(180 * score / 100)

            def animate_arc(ext=current_extent):

                if abs(ext - target_extent) < 2:
                    self.attack_canvas.itemconfig(
                        self.attack_arc,
                        extent=target_extent,
                        outline=color,
                    )
                    return

                ext += (target_extent - ext) * 0.20

                self.attack_canvas.itemconfig(
                    self.attack_arc,
                    extent=ext,
                    outline=color,
                )

                self.attack_canvas.after(
                    16,
                    lambda: animate_arc(ext),
                )

            animate_arc()

        # -------------------------------
        # Animate Score Counter
        # -------------------------------
        if hasattr(self, "score_label"):

            try:
                current_score = int(self.score_label.cget("text"))
            except Exception:
                current_score = 0

            def animate_score(value=current_score):

                if value == score:
                    self.score_label.configure(
                        text=str(score),
                        text_color=color,
                    )
                    return

                step = 1 if value < score else -1

                value += step

                self.score_label.configure(
                    text=str(value),
                    text_color=color,
                )

                self.score_label.after(
                    12,
                    lambda: animate_score(value),
                )

            animate_score()

        if hasattr(self, "risk_label"):
            self.risk_label.configure(
                text=f"{app._dashboard_risk_label(score)}  •  {score}/100",
                text_color=color,
            )

        try:
            app._update_dashboard_after_scan()
        except Exception:
            pass

    def _footer(self):
        app = self.app

        footer = ctk.CTkFrame(
            app.main_content,
            fg_color="#05070D",
            border_width=1,
            border_color="#1D5FA8",
            corner_radius=0,
            height=34,
        )
        footer.grid(row=6, column=0, sticky="ew")
        footer.grid_propagate(False)

        ctk.CTkLabel(
            footer,
            text="BHISHMA Enterprise v1.0",
            font=("Helvetica", 10, "bold"),
            text_color="#00E5FF",
        ).pack(side="left", padx=22)

        ctk.CTkLabel(
            footer,
            text="Attack Surface Intelligence Platform  |  Detection • Enumeration • Intelligence • Verification",
            font=("Helvetica", 10, "bold"),
            text_color="#8B949E",
        ).pack(side="right", padx=22)
