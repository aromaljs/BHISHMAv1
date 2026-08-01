import customtkinter as ctk
from ui.theme import (
    BG_CARD,
    BG_PANEL,
    BORDER_BRIGHT,
    TXT_WHITE,
    TXT_MUTED,
    ACCENT_HOVER,
    GREEN,
    RED,
    AMBER,
    CYAN,
)


def configure_text_tags(textbox):
    w = textbox._textbox
    w.tag_config("green", foreground=GREEN)
    w.tag_config("red", foreground=RED)
    w.tag_config("amber", foreground=AMBER)
    w.tag_config("cyan", foreground=CYAN)
    w.tag_config("muted", foreground=TXT_MUTED)
    w.tag_config("white", foreground=TXT_WHITE)


def tagged_insert(textbox, text, tag=None):
    widget = textbox._textbox

    if tag:
        widget.insert("end", str(text) + "\n", tag)
    else:
        widget.insert("end", str(text) + "\n")

    textbox.see("end")


def auto_tag(line):
    line = str(line)
    lower = line.lower()

    if "critical" in lower or "confirmed" in lower:
        return "red"
    if "high" in lower or "[!]" in line:
        return "red"
    if "medium" in lower:
        return "amber"
    if "low" in lower or "info" in lower:
        return "cyan"
    if "[+]" in line or "open" in lower or "observed" in lower:
        return "green"
    if "closed" in lower or "not_confirmed" in lower:
        return "muted"

    return "white"


def module_textbox(parent):
    textbox = ctk.CTkTextbox(
        parent,
        fg_color=BG_PANEL,
        text_color=TXT_WHITE,
        font=("Consolas", 12),
        border_width=1,
        border_color=BORDER_BRIGHT,
        corner_radius=8,
    )
    configure_text_tags(textbox)
    return textbox


def action_button(parent, text, color, command):
    return ctk.CTkButton(
        parent,
        text=text,
        fg_color=color,
        hover_color=ACCENT_HOVER,
        corner_radius=8,
        height=38,
        font=("Helvetica", 13, "bold"),
        command=command,
    )


def stat_card(parent, col, title, variable, accent_color):
    card = ctk.CTkFrame(
        parent,
        fg_color=BG_CARD,
        border_width=1,
        border_color=BORDER_BRIGHT,
        corner_radius=10,
    )
    card.grid(row=0, column=col, sticky="nsew", padx=6, pady=4)

    stripe = ctk.CTkFrame(card, width=3, fg_color=accent_color, corner_radius=2)
    stripe.pack(side="left", fill="y", padx=(8, 0), pady=10)

    inner = ctk.CTkFrame(card, fg_color="transparent")
    inner.pack(side="left", fill="both", expand=True, padx=12, pady=10)

    ctk.CTkLabel(
        inner,
        text=title,
        font=("Helvetica", 10, "bold"),
        text_color=TXT_MUTED,
    ).pack(anchor="w")

    ctk.CTkLabel(
        inner,
        textvariable=variable,
        font=("Helvetica", 22, "bold"),
        text_color=accent_color,
    ).pack(anchor="w")

    return card


def section_header(parent, title, subtitle=""):
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
            text_color="#6C47FF",
        ).pack(side="left", pady=(4, 0))

    return frame
