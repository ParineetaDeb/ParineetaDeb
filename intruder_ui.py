# intruder_ui.py
# INTRUDER ALERT UI SCREENS — SentinelsVault
#
# This file contains all the visual screens for the Intruder Alert system.
# It is imported by app_ui.py and mixed into SentinelsVaultApp.
#
# Screens provided:
# 1. show_intruder_alert_screen()  — Full-screen red warning on lockout
# 2. show_lockout_countdown()      — Countdown timer during lockout
# 3. show_intruder_history()       — Full history of all intrusion events
# 4. show_db_tamper_warning()      — Alert when DB is modified externally

import os
import datetime
import customtkinter as ctk
try:
    import customtkinter as ctk  # type: ignore
except (ImportError, ModuleNotFoundError):
    import tkinter as ctk  # type: ignore
from tkinter import messagebox

COLORS = {
    "bg":      "#0D1117",
    "sidebar": "#161B22",
    "card":    "#1C2128",
    "accent":  "#00D4FF",
    "red":     "#FF4444",
    "green":   "#00C851",
    "orange":  "#FF8C00",
    "gold":    "#FFD700",
    "text":    "#E6EDF3",
    "subtext": "#8B949E",
    "purple":  "#C084FC",
}


def show_intruder_alert_screen(app, lockout_info: dict):
    """
    Full-screen red intruder alert displayed when 5 failed attempts
    are detected. Completely replaces the login screen.

    This screen:
    - Shows a bold red warning banner
    - Displays who tried to get in (system info)
    - Shows a live countdown until lockout expires
    - Provides a Recovery Code bypass for the legitimate owner
    - Logs the display event

    app:          The SentinelsVaultApp instance
    lockout_info: Dict returned by record_failed_attempt()
    """
    app.clear_screen()

    # ── Full screen dark red background ──
    main = ctk.CTkFrame(app, fg_color="#1A0000")
    main.pack(fill="both", expand=True)

    # ── Pulsing red top bar ──
    ctk.CTkFrame(main, fg_color=COLORS["red"],
                 height=6, corner_radius=0).pack(fill="x")

    # ── Alert icon and title ──
    ctk.CTkLabel(main, text="INTRUDER ALERT",
                 font=("Segoe UI", 48, "bold"),
                 text_color=COLORS["red"]).pack(pady=(60, 4))

    ctk.CTkLabel(main,
                 text="UNAUTHORISED ACCESS ATTEMPT DETECTED",
                 font=("Segoe UI", 18),
                 text_color=COLORS["orange"]).pack(pady=(0, 30))

    # ── Alert details card ──
    details_card = ctk.CTkFrame(main, fg_color="#2A0000",
                                 corner_radius=16,
                                 border_width=2,
                                 border_color=COLORS["red"])
    details_card.pack(padx=100, pady=(0, 20), fill="x")

    ctk.CTkFrame(details_card, fg_color=COLORS["red"],
                 height=3).pack(fill="x")

    ctk.CTkLabel(details_card,
                 text="VAULT LOCKED — SECURITY BREACH ATTEMPT",
                 font=("Segoe UI", 16, "bold"),
                 text_color=COLORS["red"]).pack(pady=(16, 8))

    # Detail rows
    details = [
        ("Failed Attempts Detected",
         f"{lockout_info.get('total_attempts', 5)} attempts"),
        ("Vault Status",
         "LOCKED"),
        ("Locked Until",
         lockout_info.get("lockout_until", "30 minutes from now")),
        ("Action Taken",
         "Vault sealed. All keys wiped from memory."),
        ("Evidence",
         "Full log saved to intruder_alert.log"),
    ]

    for label, value in details:
        row = ctk.CTkFrame(details_card, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=3)
        ctk.CTkLabel(row, text=label,
                     font=("Segoe UI", 12),
                     text_color=COLORS["subtext"],
                     width=240, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=value,
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["red"]).pack(side="left")

    ctk.CTkFrame(details_card, height=16,
                 fg_color="transparent").pack()

    # ── Countdown timer ──
    timer_frame = ctk.CTkFrame(main, fg_color=COLORS["card"],
                                corner_radius=12)
    timer_frame.pack(padx=100, pady=(0, 20), fill="x")

    ctk.CTkLabel(timer_frame,
                 text="VAULT UNLOCKS IN",
                 font=("Segoe UI", 12),
                 text_color=COLORS["subtext"]).pack(pady=(12, 4))

    countdown_label = ctk.CTkLabel(timer_frame, text="30:00",
                                    font=("Segoe UI", 42, "bold"),
                                    text_color=COLORS["orange"])
    countdown_label.pack()

    countdown_bar = ctk.CTkProgressBar(
        timer_frame, width=600, height=10, corner_radius=5,
        fg_color="#1A0000", progress_color=COLORS["orange"])
    countdown_bar.pack(pady=(4, 12))
    countdown_bar.set(1.0)

    ctk.CTkLabel(timer_frame,
                 text="The vault will automatically unlock when the "
                      "timer reaches zero.",
                 font=("Segoe UI", 10),
                 text_color=COLORS["subtext"]).pack(pady=(0, 12))

    # Start the live countdown
    _run_lockout_countdown(
        app, countdown_label, countdown_bar)

    # ── Recovery bypass section ──
    recovery_frame = ctk.CTkFrame(main, fg_color=COLORS["sidebar"],
                                   corner_radius=12, border_width=1,
                                   border_color=COLORS["orange"])
    recovery_frame.pack(padx=100, pady=(0, 20), fill="x")

    ctk.CTkLabel(recovery_frame,
                 text="Are you the legitimate owner?",
                 font=("Segoe UI", 13, "bold"),
                 text_color=COLORS["orange"]).pack(pady=(16, 4))
    ctk.CTkLabel(recovery_frame,
                 text="Enter your Recovery Code to bypass the lockout "
                      "immediately.",
                 font=("Segoe UI", 11),
                 text_color=COLORS["subtext"]).pack(pady=(0, 8))

    rec_entry = ctk.CTkEntry(
        recovery_frame,
        placeholder_text="Enter Recovery Code",
        show="●", width=360, height=44,
        font=("Segoe UI", 13))
    rec_entry.pack(pady=(0, 8))

    bypass_status = ctk.CTkLabel(
        recovery_frame, text="",
        font=("Segoe UI", 11), text_color=COLORS["red"])
    bypass_status.pack()

    def attempt_bypass():
        """
        Allows the legitimate owner to unlock immediately
        using their Recovery Code — no need to wait 30 minutes.
        """
        code = rec_entry.get().strip()
        if not code:
            bypass_status.configure(
                text="Enter your Recovery Code.")
            return
        # Delegate to the app's recovery logic
        if hasattr(app, '_attempt_recovery_bypass'):
            app._attempt_recovery_bypass(code, bypass_status)
        else:
            # Fallback — just go to recovery screen
            app.show_recovery_screen()

    ctk.CTkButton(recovery_frame,
                  text="Bypass Lockout with Recovery Code",
                  command=attempt_bypass,
                  width=360, height=42,
                  fg_color=COLORS["orange"],
                  text_color=COLORS["bg"],
                  font=("Segoe UI", 12, "bold")).pack(pady=(0, 16))

    # ── Bottom notice ──
    ctk.CTkFrame(main, fg_color=COLORS["red"],
                 height=3, corner_radius=0).pack(
        fill="x", side="bottom")
    ctk.CTkLabel(main,
                 text="This incident has been logged to intruder_alert.log  "
                      "|  SentinelsVault Security System",
                 font=("Segoe UI", 9),
                 text_color=COLORS["subtext"]).pack(
        side="bottom", pady=8)


def _run_lockout_countdown(app, label, bar):
    """
    Updates the countdown timer every second.
    When the timer reaches 0, redirects to the login screen.
    """
    is_locked, secs = app.intruder_system.is_locked_out()

    if not is_locked:
        # Lockout expired — go back to login
        app.show_login_screen()
        return

    # Format as MM:SS
    mins = secs // 60
    sec  = secs % 60
    label.configure(text=f"{mins:02d}:{sec:02d}")

    # Update progress bar (1.0 = full, 0.0 = empty)
    bar.set(secs / 1800)

    # Color changes as time decreases
    if secs < 300:    # Last 5 minutes — red
        label.configure(text_color=COLORS["red"])
        bar.configure(progress_color=COLORS["red"])
    elif secs < 600:  # Last 10 minutes — orange
        label.configure(text_color=COLORS["orange"])
        bar.configure(progress_color=COLORS["orange"])

    # Schedule next update in 1 second
    app.after(1000, lambda: _run_lockout_countdown(app, label, bar))


def show_intruder_history_screen(app):
    """
    Displays the complete history of all intrusion events.
    Accessible from the Security section in the sidebar.

    Shows:
    - Every lockout event with timestamp
    - Every DB tampering detection
    - Photos taken (if any)
    - Total statistics
    """
    app.clear_content()

    header = ctk.CTkFrame(app.content,
                           fg_color=COLORS["sidebar"], height=60)
    header.pack(fill="x")
    header.pack_propagate(False)

    ctk.CTkLabel(header,
                 text="Intruder Alert History",
                 font=("Segoe UI", 18, "bold"),
                 text_color=COLORS["red"]).pack(
        side="left", padx=20, pady=16)

    # Clear history button
    def clear_history():
        confirm = messagebox.askyesno(
            "Clear History",
            "Clear all intruder alert records?\n\n"
            "This does NOT affect the intruder_alert.log file.")
        if confirm:
            app.intruder_system.clear_history()
            show_intruder_history_screen(app)  # Refresh

    ctk.CTkButton(header, text="Clear History",
                  command=clear_history,
                  width=120, height=32,
                  fg_color=COLORS["card"],
                  hover_color="#2A1010",
                  text_color=COLORS["red"],
                  font=("Segoe UI", 11)).pack(
        side="right", padx=20, pady=14)

    scroll = ctk.CTkScrollableFrame(
        app.content, fg_color=COLORS["bg"])
    scroll.pack(fill="both", expand=True, padx=20, pady=20)

    summary = app.intruder_system.get_summary()
    history = app.intruder_system.get_alert_history()

    # ── Summary stats ──
    stats_frame = ctk.CTkFrame(scroll, fg_color="transparent")
    stats_frame.pack(fill="x", pady=(0, 16))

    stats = [
        ("Total Intrusion Events",
         str(summary["total_intrusions"]), COLORS["red"]),
        ("Current Failed Attempts",
         str(summary["current_attempts"]), COLORS["orange"]),
        ("Vault Status",
         "LOCKED" if summary["is_locked"] else "SECURE",
         COLORS["red"] if summary["is_locked"] else COLORS["green"]),
        ("Alert Records",
         str(summary["alert_history_count"]), COLORS["accent"]),
    ]

    for i, (label, value, color) in enumerate(stats):
        s = ctk.CTkFrame(stats_frame, fg_color=COLORS["sidebar"],
                         corner_radius=10, border_width=1,
                         border_color=color)
        s.grid(row=0, column=i, padx=5, sticky="ew")
        stats_frame.columnconfigure(i, weight=1)
        ctk.CTkLabel(s, text=value,
                     font=("Segoe UI", 22, "bold"),
                     text_color=color).pack(pady=(10, 0))
        ctk.CTkLabel(s, text=label,
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 10))

    # ── History list ──
    if not history:
        ctk.CTkLabel(scroll,
                     text="No intrusion events recorded.\n\n"
                          "Your vault has not been attacked yet.",
                     font=("Segoe UI", 14),
                     text_color=COLORS["subtext"],
                     justify="center").pack(pady=40)
        return

    ctk.CTkLabel(scroll, text="Intrusion Event Log",
                 font=("Segoe UI", 14, "bold"),
                 text_color=COLORS["text"]).pack(
        anchor="w", pady=(0, 8))

    for event in history:
        event_type = event.get("type", "UNKNOWN")

        # Color-code by event type
        if "LOCKOUT" in event_type:
            border_color = COLORS["red"]
            icon         = "ALERT"
        elif "TAMPER" in event_type:
            border_color = COLORS["orange"]
            icon         = "TAMPER"
        else:
            border_color = COLORS["gold"]
            icon         = "INFO"

        card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                            corner_radius=10, border_width=1,
                            border_color=border_color)
        card.pack(fill="x", pady=4)

        # Left color bar
        ctk.CTkFrame(card, fg_color=border_color,
                     width=4, corner_radius=2).pack(
            side="left", fill="y", padx=(0, 12))

        info = ctk.CTkFrame(card, fg_color="transparent")
        info.pack(side="left", fill="both",
                  expand=True, pady=10)

        # Type and timestamp
        top = ctk.CTkFrame(info, fg_color="transparent")
        top.pack(fill="x")
        ctk.CTkLabel(top,
                     text=f"[{icon}]  {event_type.replace('_', ' ')}",
                     font=("Segoe UI", 12, "bold"),
                     text_color=border_color).pack(side="left")
        ctk.CTkLabel(top, text=event.get("timestamp", ""),
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(side="right")

        # Event details
        details_text = ""
        if "attempts" in event:
            details_text += f"Failed attempts: {event['attempts']}  |  "
        if "username" in event:
            details_text += f"User: {event['username']}  |  "
        if "hostname" in event:
            details_text += f"Machine: {event['hostname']}  |  "
        if "locked_until" in event:
            details_text += f"Locked until: {event['locked_until']}  |  "
        if "elapsed" in event:
            details_text += f"Time since snapshot: {event['elapsed']}  |  "
        if "photo" in event:
            details_text += f"Photo: {os.path.basename(event['photo'])}"

        details_text = details_text.rstrip("  |  ")

        if details_text:
            ctk.CTkLabel(info, text=details_text,
                         font=("Segoe UI", 10),
                         text_color=COLORS["text"],
                         wraplength=600,
                         justify="left").pack(anchor="w", pady=(2, 0))

        # Show photo button if photo was captured
        if "photo" in event and os.path.exists(event["photo"]):
            ctk.CTkButton(info,
                          text="View Intruder Photo",
                          width=160, height=28,
                          fg_color=COLORS["card"],
                          hover_color=COLORS["red"],
                          text_color=COLORS["orange"],
                          font=("Segoe UI", 10),
                          command=lambda p=event["photo"]:
                              os.startfile(p)
                          ).pack(anchor="w", pady=(4, 0))

    # ── Log file link ──
    log_card = ctk.CTkFrame(scroll, fg_color=COLORS["card"],
                             corner_radius=8)
    log_card.pack(fill="x", pady=(16, 0))
    ctk.CTkLabel(log_card,
                 text="Full detailed log saved to: intruder_alert.log",
                 font=("Segoe UI", 11),
                 text_color=COLORS["subtext"]).pack(
        side="left", padx=16, pady=10)
    ctk.CTkButton(log_card, text="Open Log File",
                  command=lambda: os.startfile("intruder_alert.log")
                  if os.path.exists("intruder_alert.log") else None,
                  width=120, height=30,
                  fg_color=COLORS["accent"],
                  text_color=COLORS["bg"],
                  font=("Segoe UI", 10)).pack(
        side="right", padx=16, pady=10)


def show_db_tamper_warning(app, tamper_info: dict):
    """
    Shows a warning popup when the database was modified externally.
    Called on app startup if check_db_integrity() detects a mismatch.
    """
    popup = ctk.CTkToplevel(app)
    popup.title("Database Integrity Alert")
    popup.geometry("540x380")
    popup.configure(fg_color=COLORS["sidebar"])
    popup.grab_set()

    ctk.CTkFrame(popup, fg_color=COLORS["orange"],
                 height=4).pack(fill="x")

    ctk.CTkLabel(popup,
                 text="DATABASE INTEGRITY WARNING",
                 font=("Segoe UI", 20, "bold"),
                 text_color=COLORS["orange"]).pack(pady=(20, 6))

    ctk.CTkLabel(popup,
                 text="Your vault database was modified while "
                      "SentinelsVault was closed.",
                 font=("Segoe UI", 12),
                 text_color=COLORS["text"]).pack(pady=(0, 12))

    details_card = ctk.CTkFrame(popup, fg_color=COLORS["card"],
                                 corner_radius=8)
    details_card.pack(fill="x", padx=30, pady=(0, 12))

    rows = [
        ("Expected Hash",
         tamper_info.get("old_hash", "N/A")[:32] + "..."),
        ("Detected Hash",
         tamper_info.get("new_hash", "N/A")[:32] + "..."),
        ("Time Since Last Session",
         tamper_info.get("time_elapsed", "Unknown")),
        ("Risk",
         "Someone may have modified your encrypted database."),
    ]

    for label, value in rows:
        row = ctk.CTkFrame(details_card, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=3)
        ctk.CTkLabel(row, text=label,
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"],
                     width=200, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=value,
                     font=("Segoe UI", 10, "bold"),
                     text_color=COLORS["orange"],
                     wraplength=250).pack(side="left")

    ctk.CTkLabel(popup,
                 text="The AES-256-GCM authentication tag will detect any\n"
                      "tampered data when you try to decrypt it.",
                 font=("Segoe UI", 10),
                 text_color=COLORS["subtext"],
                 justify="center").pack(pady=(0, 8))

    btn_frame = ctk.CTkFrame(popup, fg_color="transparent")
    btn_frame.pack(pady=(0, 20))

    ctk.CTkButton(btn_frame, text="Proceed (I understand the risk)",
                  command=popup.destroy,
                  width=220, height=38,
                  fg_color=COLORS["orange"],
                  text_color=COLORS["bg"],
                  font=("Segoe UI", 12, "bold")).pack(
        side="left", padx=6)

    ctk.CTkButton(btn_frame, text="View Alert Log",
                  command=lambda: [
                      popup.destroy(),
                      show_intruder_history_screen(app)],
                  width=160, height=38,
                  fg_color=COLORS["card"],
                  text_color=COLORS["accent"],
                  font=("Segoe UI", 11)).pack(side="left", padx=6)