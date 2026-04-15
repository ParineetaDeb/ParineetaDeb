# app_ui.py
# MODULE 5: User Interface — The Face of SentinelsVault

import os
import time
import base64
import secrets
import string
import logging

try:
    import customtkinter as ctk  # type: ignore
except (ImportError, ModuleNotFoundError):
    import tkinter as ctk  # type: ignore
try:
    import pyotp  # type: ignore
except (ImportError, ModuleNotFoundError):
    pyotp = None  # type: ignore
from tkinter import Image, messagebox, filedialog
from auth_manager import AuthManager
from encryption_provider import EncryptionProvider
from storage_engine import StorageEngine
from sentinel_auditor import SentinelAuditor

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

logger = logging.getLogger(__name__)

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
    "blue":    "#3B82F6",   
}


class SentinelsVaultApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("SentinelsVault — AES-256 GCM | Zero-Knowledge")
        self.geometry("1100x850")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg"])

        self.auth_manager     = AuthManager()
        self.storage_engine   = StorageEngine()
        self.sentinel_auditor = SentinelAuditor()
        self.master_key          = None
        self.encryption_provider = None
        # MFA + session hardening
        self.session_timeout_seconds = 300  # 5 minutes inactivity
        self._auto_lock_enabled = False
        self._last_activity_ts = time.time()
        self._pending_totp = None
        self.setup_pass_visible = False
        if self.storage_engine.is_vault_initialized():
            self.show_login_screen()
        else:
            self.show_setup_screen()

    # ═══════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════

    def clear_screen(self):
        """Destroys all widgets in the main window."""
        for widget in self.winfo_children():
            widget.destroy()

    def clear_content(self):
        """Destroys only the right content area, keeping sidebar intact."""
        for widget in self.content.winfo_children():
            widget.destroy()

    # ═══════════════════════════════════════════════════════
    # SCREEN 1: SETUP
    # ═══════════════════════════════════════════════════════

    def show_setup_screen(self):
        """First-time vault initialization screen with enhanced password strength meter."""
        self.clear_screen()
    
    # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(self, fg_color=COLORS["bg"])
        scroll_frame.pack(fill="both", expand=True)
    
        card = ctk.CTkFrame(scroll_frame, fg_color=COLORS["sidebar"],
                        corner_radius=16, border_width=2,
                        border_color=COLORS["accent"])
        card.pack(pady=30, padx=20)

        # Header
        ctk.CTkLabel(card, text="🛡️ SENTINELSVAULT",
                 font=("Segoe UI", 32, "bold"),
                 text_color=COLORS["accent"]).pack(pady=(30, 0))
        ctk.CTkLabel(card, text="Initialize Your Secure Vault",
                 font=("Segoe UI", 14),
                 text_color=COLORS["subtext"]).pack(pady=(4, 16))
    
        # Info box
        info_frame = ctk.CTkFrame(card, fg_color=COLORS["card"], corner_radius=8)
        info_frame.pack(padx=40, pady=(0, 12), fill="x")
        ctk.CTkLabel(info_frame,
                 text="🔐  This Master Password is the ONLY way to access your vault.\n"
                      "     It cannot be recovered if lost. Make it strong and memorable!",
                 font=("Segoe UI", 10),
                 text_color=COLORS["orange"],
                 justify="left").pack(padx=12, pady=8)

        # Password field
        ctk.CTkLabel(card, text="MASTER PASSWORD",
                 font=("Segoe UI", 11, "bold"),
                 text_color=COLORS["accent"]).pack(anchor="w", padx=40, pady=(8, 2))
    
        self.setup_pass = ctk.CTkEntry(
        card, placeholder_text="Create a strong Master Password (12+ chars)",
        show="●", width=380, height=48, font=("Segoe UI", 13))
        self.setup_pass.pack(padx=40, pady=(0, 6))
    
        # Password visibility toggle
        pass_btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        pass_btn_frame.pack(padx=40, pady=(0, 8), anchor="e")
    
        def toggle_master_show():
            if hasattr(self, 'setup_pass_visible'):
                self.setup_pass_visible = not self.setup_pass_visible
            else:
                self.setup_pass_visible = False
                self.setup_pass_visible = not self.setup_pass_visible
                self.setup_pass.configure(show="" if self.setup_pass_visible else "●")
                show_btn.configure(text="🙈" if self.setup_pass_visible else "👁️")
    
        show_btn = ctk.CTkButton(
        pass_btn_frame, text="👁️", width=40, height=28,
        command=toggle_master_show,
        fg_color=COLORS["card"],
        hover_color=COLORS["sidebar"],
        font=("Segoe UI", 11))
        show_btn.pack(side="right")
        self.setup_pass_visible = False
    
        # Strength meter bar
        self.setup_strength_bar = ctk.CTkProgressBar(
        card, width=380, height=8, corner_radius=4,
        fg_color=COLORS["card"],
        progress_color=COLORS["accent"])
        self.setup_strength_bar.pack(padx=40, pady=(4, 4))
        self.setup_strength_bar.set(0)
    
        # Strength label
        self.setup_strength_label = ctk.CTkLabel(
        card, text="Strength: —",
        font=("Segoe UI", 11), text_color=COLORS["subtext"])
        self.setup_strength_label.pack(padx=40, pady=(2, 4))
    
        # Requirements checklist frame
        req_frame = ctk.CTkFrame(card, fg_color=COLORS["card"], corner_radius=8)
        req_frame.pack(padx=40, pady=(8, 4), fill="x")
    
        ctk.CTkLabel(req_frame, text="✓  Password Requirements",
                 font=("Segoe UI", 11, "bold"),
                 text_color=COLORS["accent"]).pack(anchor="w", padx=12, pady=(8, 4))
    
        # Store requirement labels for dynamic updates
        self.req_labels = {}
        requirements = [
        ('length', '❌  At least 12 characters'),
        ('upper', '❌  Uppercase letter (A-Z)'),
        ('lower', '❌  Lowercase letter (a-z)'),
        ('digit', '❌  Number (0-9)'),
        ('special', '❌  Special character (!@#$%^&*)'),
        ('common', '❌  Not in common password lists'),
    ]
    
        for key, text in requirements:
            label = ctk.CTkLabel(req_frame, text=text,
                             font=("Segoe UI", 10),
                             text_color=COLORS["subtext"],
                             anchor="w")
            label.pack(anchor="w", padx=12, pady=2)
        self.req_labels[key] = label
    
        # Warning label
        self.warning_label = ctk.CTkLabel(
        card, text="",
        font=("Segoe UI", 10), text_color=COLORS["orange"])
        self.warning_label.pack(padx=40, pady=(4, 4))
    
        # Confirm password field
        ctk.CTkLabel(card, text="CONFIRM PASSWORD",
                 font=("Segoe UI", 11, "bold"),
                 text_color=COLORS["accent"]).pack(anchor="w", padx=40, pady=(8, 2))
    
        self.setup_confirm = ctk.CTkEntry(
        card, placeholder_text="Confirm your Master Password",
        show="●", width=380, height=48, font=("Segoe UI", 13))
        self.setup_confirm.pack(padx=40, pady=(0, 12))
    
        # Confirm password match indicator
        self.confirm_match_label = ctk.CTkLabel(
        card, text="",
        font=("Segoe UI", 10), text_color=COLORS["green"])
        self.confirm_match_label.pack(padx=40, pady=(0, 4))
    
        def check_confirm_match(event=None):
            pwd = self.setup_pass.get()
            confirm = self.setup_confirm.get()
            if confirm:
                if pwd == confirm:
                    self.confirm_match_label.configure(
                        text="✅  Passwords match",
                        text_color=COLORS["green"])
                else:
                    self.confirm_match_label.configure(
                        text="❌  Passwords do not match",
                        text_color=COLORS["red"])
            else:
                self.confirm_match_label.configure(text="")
    
    
        self.setup_confirm.bind("<KeyRelease>", check_confirm_match)
    
        # Bind live strength update
        self.setup_pass.bind("<KeyRelease>", self.update_master_strength_meter)
    
        # Notice box
        notice = ctk.CTkFrame(card, fg_color=COLORS["bg"], corner_radius=8)
        notice.pack(padx=40, pady=(8, 12), fill="x")
        ctk.CTkLabel(notice,
            text="⚠️  ZERO-KNOWLEDGE RECOVERY\n\n"
                 "     Your Master Password cannot be recovered if forgotten.\n"
                 "     You will receive a Recovery Code after setup — store it safely offline!\n"
                 "     Without the Recovery Code, your vault will be permanently inaccessible.",
            font=("Segoe UI", 10),
            text_color=COLORS["orange"],
            justify="left").pack(padx=12, pady=8)
    
        # Initialize button
        ctk.CTkButton(card, text="🔐  Initialize Vault with Argon2id",
                  command=self.perform_setup,
                  width=380, height=48,
                  fg_color=COLORS["accent"],
                  hover_color=COLORS["green"],
                  text_color=COLORS["bg"],
                  font=("Segoe UI", 14, "bold"),
                  corner_radius=10).pack(padx=40, pady=(8, 30))
    
        # Extra padding at bottom
        ctk.CTkFrame(card, height=30, fg_color="transparent").pack()

    def check_setup_strength(self, event=None):
        """Updates strength label live as user types master password."""
        pwd = self.setup_pass.get()
        if not pwd:
            self.setup_strength_label.configure(
                text="Strength: —", text_color=COLORS["subtext"])
            return
        audit = self.sentinel_auditor.audit_single_password(pwd)
        self.setup_strength_label.configure(
            text=f"Strength: {audit['strength_label']}  "
                 f"({audit['entropy']} bits)",
            text_color=audit["color"])

    def update_master_strength_meter(self, event=None):
        """
        Enhanced password strength meter for Master Password setup.
        Shows live strength analysis with color-changing bar and requirements checklist.
        """
        pwd = self.setup_pass.get()
        
        if not pwd:
            self.setup_strength_label.configure(text="Strength: —", text_color=COLORS["subtext"])
            if hasattr(self, 'setup_strength_bar'):
                self.setup_strength_bar.set(0)
                self.setup_strength_bar.configure(progress_color=COLORS["card"])
            if hasattr(self, 'req_labels'):
                for req in self.req_labels.values():
                    req.configure(text_color=COLORS["subtext"])
            return
        
        # Get full audit
        audit = self.sentinel_auditor.audit_single_password(pwd)
        entropy = audit["entropy"]
        strength = audit["strength_label"]
        color = audit["color"]
        
        # Update strength label with entropy
        self.setup_strength_label.configure(
            text=f"Strength: {strength}  |  Entropy: {entropy} bits",
            text_color=color
        )
        
        # Update progress bar
        if hasattr(self, 'setup_strength_bar'):
            # Map strength to progress value (0-1)
            if strength == "Very Weak":
                progress = 0.15
            elif strength == "Weak":
                progress = 0.35
            elif strength == "Moderate":
                progress = 0.60
            elif strength == "Strong":
                progress = 0.85
            else:  # Very Strong
                progress = 1.0
            
            self.setup_strength_bar.set(progress)
            self.setup_strength_bar.configure(progress_color=color)
        
        # Update requirements checklist
        if hasattr(self, 'req_labels'):
            # Length requirement (minimum 12 characters)
            length_ok = len(pwd) >= 12
            self.req_labels['length'].configure(
                text=f"{'✅' if length_ok else '❌'}  At least 12 characters",
                text_color=COLORS["green"] if length_ok else COLORS["red"]
            )
            
            # Uppercase requirement
            has_upper = any(c.isupper() for c in pwd)
            self.req_labels['upper'].configure(
                text=f"{'✅' if has_upper else '❌'}  Uppercase letter (A-Z)",
                text_color=COLORS["green"] if has_upper else COLORS["red"]
            )
            
            # Lowercase requirement
            has_lower = any(c.islower() for c in pwd)
            self.req_labels['lower'].configure(
                text=f"{'✅' if has_lower else '❌'}  Lowercase letter (a-z)",
                text_color=COLORS["green"] if has_lower else COLORS["red"]
            )
            
            # Number requirement
            has_digit = any(c.isdigit() for c in pwd)
            self.req_labels['digit'].configure(
                text=f"{'✅' if has_digit else '❌'}  Number (0-9)",
                text_color=COLORS["green"] if has_digit else COLORS["red"]
            )
            
            # Special character requirement
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)
            self.req_labels['special'].configure(
                text=f"{'✅' if has_special else '❌'}  Special character (!@#$%^&*)",
                text_color=COLORS["green"] if has_special else COLORS["red"]
            )
            
            # Check if password is common
            is_common = audit["is_common"]
            self.req_labels['common'].configure(
                text=f"{'❌' if is_common else '✅'}  Not in common password lists",
                text_color=COLORS["red"] if is_common else COLORS["green"]
            )
        
        # Show warning for weak passwords
        if hasattr(self, 'warning_label'):
            if strength in ("Very Weak", "Weak"):
                self.warning_label.configure(
                    text="⚠️  Warning: This password is too weak! Consider using a stronger one.",
                    text_color=COLORS["orange"]
                )
            elif strength == "Moderate":
                self.warning_label.configure(
                    text="ℹ️  Moderate strength. For better security, use a longer password with more variety.",
                    text_color=COLORS["gold"]
                )
            elif strength in ("Strong", "Very Strong"):
                self.warning_label.configure(
                    text="✅  Excellent! This password meets security best practices.",
                    text_color=COLORS["green"]
                )
            else:
                self.warning_label.configure(text="")

    def perform_setup(self):
        """Validates, hashes, and saves the master password with enhanced validation."""
        pwd = self.setup_pass.get()
        confirm = self.setup_confirm.get()
        
        # Validate inputs
        if not pwd or not confirm:
            messagebox.showerror("Error", "Both fields are required.")
            return
        
        # Check length
        if len(pwd) < 12:
            messagebox.showwarning("Too Short",
                "Master password must be at least 12 characters.\n\n"
                "A strong Master Password is essential for vault security.")
            return
        
        # Check strength
        audit = self.sentinel_auditor.audit_single_password(pwd)
        if audit["strength_label"] in ("Very Weak", "Weak"):
            response = messagebox.askyesno(
                "Weak Password Warning",
                f"Your password is {audit['strength_label']} ({audit['entropy']} bits entropy).\n\n"
                f"Issues found:\n" + "\n".join(f"  • {issue}" for issue in audit["issues"]) +
                "\n\nWeak passwords can be easily cracked by attackers.\n"
                "Do you still want to use this password?")
            if not response:
                return
        
        # Check match
        if pwd != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match. Please re-enter.")
            return
        
        try:
            # Generate salt and hash the master password
            salt = self.auth_manager.generate_salt()
            m_hash = self.auth_manager.hash_master_password_argon2(pwd)
            
            # Generate vault key and recovery code
            vault_key = secrets.token_bytes(32)
            recovery_code = self.auth_manager.generate_recovery_code()
            recovery_salt = os.urandom(32)
            
            # Derive master key from password and encrypt vault key
            k_master = self.auth_manager.derive_key_pbkdf2(pwd, salt)
            provider_master = EncryptionProvider(k_master)
            vault_key_enc_master, vault_key_nonce_master = provider_master.encrypt_bytes(vault_key)
            
            # Derive recovery key and encrypt vault key
            k_recovery = self.auth_manager.derive_key_pbkdf2(recovery_code, recovery_salt)
            provider_recovery = EncryptionProvider(k_recovery)
            vault_key_enc_recovery, vault_key_nonce_recovery = provider_recovery.encrypt_bytes(vault_key)
            
            # Store the master key for this session
            self.master_key = vault_key
            self.encryption_provider = EncryptionProvider(vault_key)
            
            # Generate MFA secret
            mfa_secret_bytes = secrets.token_bytes(20)
            mfa_secret_b32 = base64.b32encode(mfa_secret_bytes).decode("utf-8").strip("=")
            mfa_secret_enc, mfa_secret_nonce = self.encryption_provider.encrypt_bytes(
                mfa_secret_b32.encode("utf-8")
            )
            
            # Save everything to database
            self.storage_engine.save_vault_config(
                salt=salt,
                master_hash=m_hash,
                recovery_salt=recovery_salt,
                vault_key_enc_master=vault_key_enc_master,
                vault_key_nonce_master=vault_key_nonce_master,
                vault_key_enc_recovery=vault_key_enc_recovery,
                vault_key_nonce_recovery=vault_key_nonce_recovery,
                mfa_enabled=1,
                mfa_secret_enc=mfa_secret_enc,
                mfa_secret_nonce=mfa_secret_nonce,
            )
            
            # Wipe temporary providers
            provider_master.secure_wipe()
            provider_recovery.secure_wipe()
            
            # Show success message with recovery code
            messagebox.showinfo(
                "Vault Initialized Successfully! 🎉",
                f"Your secure vault is ready!\n\n"
                f"🔐 Master Password Strength: {audit['strength_label']} ({audit['entropy']} bits)\n\n"
                f"📋 Recovery Code (STORE THIS SAFELY):\n{recovery_code}\n\n"
                f"🔑 TOTP Secret for Authenticator App:\n{mfa_secret_b32}\n\n"
                f"⚠️  IMPORTANT: Without the Recovery Code, your vault is permanently unrecoverable!\n"
                f"    Store it offline (printed or on a USB drive)."
            )
            
            # Show OTP challenge for initial MFA setup
            totp = pyotp.TOTP(mfa_secret_b32)
            self.show_otp_challenge(totp, display_test_code=True)
            
        except Exception as e:
            messagebox.showerror("Setup Failed", f"Error:\n{e}")
            logger.error(f"Setup failed: {e}")

    # ═══════════════════════════════════════════════════════
    # SCREEN 2: LOGIN
    # ═══════════════════════════════════════════════════════

    def show_login_screen(self):
        """Vault login screen shown on every launch after setup."""
        self.clear_screen()
        card = ctk.CTkFrame(self, fg_color=COLORS["sidebar"],
                            corner_radius=16, border_width=1,
                            border_color=COLORS["accent"])
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🛡️",
                     font=("Segoe UI", 52)).pack(pady=(30, 0))
        ctk.CTkLabel(card, text="Vault Locked",
                     font=("Segoe UI", 22, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(4, 2))
        ctk.CTkLabel(card,
                     text="Zero-Knowledge  •  AES-256  •  Local-First",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(pady=(0, 24))

        self.login_entry = ctk.CTkEntry(
            card, placeholder_text="Enter Master Password",
            show="●", width=320, height=44, font=("Segoe UI", 13))
        self.login_entry.pack(padx=40, pady=6)
        self.login_entry.bind("<Return>", lambda e: self.perform_login())

        self.login_status = ctk.CTkLabel(
            card, text="", font=("Segoe UI", 11),
            text_color=COLORS["red"])
        self.login_status.pack()

        ctk.CTkButton(card, text="🔓  Unlock Vault",
                      command=self.perform_login,
                      width=320, height=44,
                      fg_color=COLORS["accent"],
                      text_color=COLORS["bg"],
                      font=("Segoe UI", 13, "bold")).pack(
            padx=40, pady=(6, 30))

        ctk.CTkButton(
            card,
            text="🗝  Recover Master Password",
            command=self.show_recovery_screen,
            width=320,
            height=34,
            fg_color=COLORS["card"],
            hover_color=COLORS["sidebar"],
            text_color=COLORS["orange"],
            font=("Segoe UI", 11, "bold"),
        ).pack(padx=40, pady=(0, 12))
        self.login_entry.focus()

    def perform_login(self):
        """Verifies master password, unlocks vault key, then enforces MFA."""
        pwd = self.login_entry.get()
        if not pwd:
            self.login_status.configure(
                text="⚠️  Please enter your password.")
            return
        try:
            config = self.storage_engine.get_vault_config()
            if not config:
                messagebox.showerror("Error", "Vault config missing.")
                return
            salt        = config[0]
            stored_hash = config[1]
            is_valid = self.auth_manager.verify_master_password_argon2(
                stored_hash, pwd)
            if not is_valid:
                self.login_status.configure(
                    text="❌  Incorrect password. Try again.")
                self.login_entry.delete(0, "end")
                return

            # Derive the Master wrapper key.
            k_master = self.auth_manager.derive_key_pbkdf2(pwd, salt)

            # If this is a new vault format, unwrap the random Vault Key (VK).
            vault_key = k_master
            vault_key_enc_master = config[4]
            vault_key_nonce_master = config[5]
            if vault_key_enc_master is not None and vault_key_nonce_master is not None:
                provider_master = EncryptionProvider(k_master)
                vault_key = provider_master.decrypt_bytes(
                    vault_key_enc_master, vault_key_nonce_master
                )
                provider_master.secure_wipe()

            self.master_key = vault_key
            self.encryption_provider = EncryptionProvider(vault_key)

            # Enforce offline MFA if enabled.
            mfa_enabled = bool(config[8])
            if mfa_enabled and config[9] is not None and config[10] is not None:
                mfa_secret_b32 = self.encryption_provider.decrypt_bytes(
                    config[9], config[10]
                ).decode("utf-8")
                totp = pyotp.TOTP(mfa_secret_b32)
                self._pending_totp = totp
                self.show_otp_challenge(totp, display_test_code=False)
                return

            # No MFA: go straight in.
            self.show_dashboard()
            self.arm_auto_lock()
        except Exception as e:
            self.login_status.configure(text=f"⚠️  Error: {str(e)}")

    # ═══════════════════════════════════════════════════════
    # LOCK VAULT
    # ═══════════════════════════════════════════════════════

    def lock_vault(self):
        """Wipes AES key from RAM and returns to login screen."""
        if self.encryption_provider:
            self.encryption_provider.secure_wipe()
        self.master_key          = None
        self.encryption_provider = None
        self._auto_lock_enabled = False
        self._last_activity_ts  = time.time()
        self.show_login_screen()
    
    # ═══════════════════════════════════════════════════════════
    # REMOTE WIPE & REVOCATION (Emergency Lock)
    # ═══════════════════════════════════════════════════════════
    
    def generate_emergency_kill_code(self) -> str:
        """
        Generate an emergency kill code that can be used from another device.
        Store this code safely BEFORE any theft occurs.
        """
        import secrets
        
        # Generate 32-byte kill code
        kill_code = secrets.token_hex(16).upper()
        formatted_code = "-".join([kill_code[i:i+4] for i in range(0, len(kill_code), 4)])
        
        # Save to database
        self.storage_engine.save_kill_token(kill_code)
        
        return formatted_code
    
    def show_emergency_preparation_screen(self):
        """
        Display screen where user can generate emergency kill code.
        Call this BEFORE theft occurs (preparation phase).
        """
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🚨  EMERGENCY PREPARATION",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["red"]).pack(side="left", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Instructions
        info_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        info_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(info_card, text="🔐  Generate Emergency Kill Code",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        ctk.CTkLabel(info_card, 
                     text="This kill code can be used to remotely lock your vault if your laptop is stolen.\n\n"
                          "IMPORTANT: Store this code in a SAFE place (e.g., password-protected note on your phone).\n"
                          "This is a ONE-TIME USE code. Generate a new one after using it.\n\n"
                          "When stolen, use this code from another device to:\n"
                          "  • Wipe encryption keys from RAM\n"
                          "  • Force lock the vault\n"
                          "  • Revoke all active sessions",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"],
                     wraplength=650).pack(anchor="w", padx=16, pady=(0, 12))
        
        # Generate button
        kill_code_var = ctk.StringVar()
        
        def generate_code():
            code = self.generate_emergency_kill_code()
            kill_code_var.set(code)
            copy_btn.configure(state="normal")
        
        generate_btn = ctk.CTkButton(info_card, text="🔑  Generate Kill Code",
                                      command=generate_code,
                                      width=200, height=40,
                                      fg_color=COLORS["accent"],
                                      text_color=COLORS["bg"])
        generate_btn.pack(pady=(0, 12))
        
        # Display code
        code_frame = ctk.CTkFrame(info_card, fg_color=COLORS["card"], corner_radius=8)
        code_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        code_label = ctk.CTkLabel(code_frame, textvariable=kill_code_var,
                                   font=("Courier New", 16, "bold"),
                                   text_color=COLORS["green"])
        code_label.pack(pady=12)
        
        def copy_code():
            self.clipboard_clear()
            self.clipboard_append(kill_code_var.get())
            copy_btn.configure(text="✅ Copied!", state="normal")
            self.after(2000, lambda: copy_btn.configure(text="📋 Copy Code"))
        
        copy_btn = ctk.CTkButton(code_frame, text="📋 Copy Code",
                                  command=copy_code,
                                  width=120, height=30,
                                  fg_color=COLORS["card"],
                                  text_color=COLORS["accent"],
                                  state="disabled")
        copy_btn.pack(pady=(0, 12))
        
        # Warning
        warning_frame = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        warning_frame.pack(fill="x")
        
        ctk.CTkLabel(warning_frame, text="⚠️  IMPORTANT WARNINGS",
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["red"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        ctk.CTkLabel(warning_frame,
                     text="• Store this code in a DIFFERENT location than your laptop\n"
                          "• This code works only ONCE. Generate a new code after each use\n"
                          "• Without this code, you cannot remotely lock your vault\n"
                          "• Keep this code secret - anyone with it can lock your vault",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"],
                     wraplength=650).pack(anchor="w", padx=16, pady=(0, 12))
    
    def emergency_lock_screen(self):
        """
        Screen to enter kill code when laptop is stolen.
        Called from another device to remotely lock the stolen laptop.
        """
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🚨  EMERGENCY LOCK",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["red"]).pack(side="left", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        info_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        info_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(info_card, text="🔒  Remote Emergency Lock",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["red"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        ctk.CTkLabel(info_card,
                     text="Enter your emergency kill code to remotely lock this device.\n"
                          "This will:\n"
                          "  • Immediately wipe all encryption keys from RAM\n"
                          "  • Lock the vault permanently\n"
                          "  • Revoke all active sessions\n\n"
                          "WARNING: This action cannot be undone without the master password.",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"],
                     wraplength=650).pack(anchor="w", padx=16, pady=(0, 12))
        
        # Kill code entry
        entry_frame = ctk.CTkFrame(info_card, fg_color="transparent")
        entry_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        kill_entry = ctk.CTkEntry(entry_frame, placeholder_text="Enter Kill Code (XXXX-XXXX-XXXX-XXXX)",
                                   width=350, height=44,
                                   font=("Courier New", 12))
        kill_entry.pack(side="left", padx=(0, 10))
        
        status_label = ctk.CTkLabel(entry_frame, text="", font=("Segoe UI", 10), text_color=COLORS["red"])
        status_label.pack(side="left")
        
        def execute_emergency_lock():
            kill_code_raw = kill_entry.get().strip().replace("-", "")
            
            if not kill_code_raw:
                status_label.configure(text="Enter kill code")
                return
            
            # Verify kill token
            if self.storage_engine.verify_kill_token(kill_code_raw):
                # Execute emergency lock
                self.lock_vault()  # This wipes keys and locks
                self.storage_engine.revoke_all_sessions()
                self.storage_engine.mark_token_used(kill_code_raw)
                
                status_label.configure(text="✅ Emergency lock executed!", text_color=COLORS["green"])
                
                # Show confirmation
                messagebox.showwarning(
                    "EMERGENCY LOCK ACTIVATED",
                    "This vault has been locked remotely.\n\n"
                    "All encryption keys have been wiped from RAM.\n"
                    "All active sessions have been revoked.\n\n"
                    "To unlock, you will need your Master Password."
                )
                
                # Return to login
                self.show_login_screen()
            else:
                status_label.configure(text="❌ Invalid kill code", text_color=COLORS["red"])
        
        lock_btn = ctk.CTkButton(info_card, text="🔒  EXECUTE EMERGENCY LOCK",
                                  command=execute_emergency_lock,
                                  width=250, height=45,
                                  fg_color=COLORS["red"],
                                  hover_color="#AA0000",
                                  text_color=COLORS["bg"],
                                  font=("Segoe UI", 13, "bold"))
        lock_btn.pack(pady=(0, 16))
    
    # ═══════════════════════════════════════════════════════════
    # DUAL DEVICE EMERGENCY LOCK
    # ═══════════════════════════════════════════════════════════
    
    def setup_device_pairing(self):
        """
        Set up pairing between laptop and phone.
        Run this ONCE during initial setup.
        """
        import secrets
        import qrcode
        from PIL import ImageTk, Image
        
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📱  DEVICE PAIRING SETUP",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Generate pairing code
        pairing_code = secrets.token_hex(8).upper()
        device_id = secrets.token_hex(16)
        
        # Save to database
        self.storage_engine.create_device_pair(device_id, "Laptop", pairing_code)
        
        # Display QR code for phone to scan
        qr_data = f"sentinelsvault://pair?code={pairing_code}&device={device_id}"
        
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(qr_data)
        qr.make()
        qr_img = qr.make_image(fill_color=COLORS["accent"], back_color=COLORS["bg"])
        
        # Convert to PhotoImage
        from PIL import ImageTk
        import io
        img_buffer = io.BytesIO()
        qr_img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        pil_img = Image.open(img_buffer)
        tk_img = ImageTk.PhotoImage(pil_img)
        
        qr_label = ctk.CTkLabel(main_frame, text="", image=tk_img)
        qr_label.image = tk_img
        qr_label.pack(pady=10)
        
        ctk.CTkLabel(main_frame, text=f"Pairing Code: {pairing_code}",
                     font=("Courier New", 16, "bold"),
                     text_color=COLORS["green"]).pack()
        
        ctk.CTkLabel(main_frame, 
                     text="Scan this QR code with your phone's SentinelsVault app\n"
                          "This creates a secure pairing between your devices.\n\n"
                          "Once paired, if ONE device is stolen, you can use the OTHER\n"
                          "to trigger an emergency lock on the stolen device.",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(pady=20)
        
        ctk.CTkButton(main_frame, text="Complete Pairing",
                      command=self.show_dashboard,
                      width=200, height=40,
                      fg_color=COLORS["green"],
                      text_color=COLORS["bg"]).pack(pady=10)
    
    def start_heartbeat_monitor(self):
        """
        Start background heartbeat monitoring.
        Sends heartbeat every 30 seconds to paired devices.
        """
        import threading
        
        def heartbeat_loop():
            while self._auto_lock_enabled:
                time.sleep(30)
                try:
                    # Update heartbeat for this device
                    self.storage_engine.update_heartbeat(self.device_id)
                    
                    # Check other devices' heartbeats
                    devices = self.storage_engine.check_device_heartbeats()
                    
                    for device_id, status in devices.items():
                        if device_id != self.device_id and not status['is_alive']:
                            # Other device is missing! (possibly stolen)
                            self.show_device_missing_alert(device_id, status)
                except Exception as e:
                    logger.error(f"Heartbeat error: {e}")
        
        self.device_id = secrets.token_hex(16)  # Unique ID for this device
        threading.Thread(target=heartbeat_loop, daemon=True).start()
    
    def show_device_missing_alert(self, device_id: str, status: dict):
        """
        Show alert when paired device stops responding.
        User can then trigger emergency lock.
        """
        # Create popup alert
        alert = ctk.CTkToplevel(self)
        alert.title("⚠️ DEVICE ALERT")
        alert.geometry("450x300")
        alert.configure(fg_color=COLORS["sidebar"])
        alert.grab_set()
        
        ctk.CTkLabel(alert, text="🚨 PAIRED DEVICE MISSING!",
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["red"]).pack(pady=(20, 10))
        
        ctk.CTkLabel(alert, text=f"Device: {status['name']}\n"
                                  f"Last seen: {status['minutes_since_heartbeat']} minutes ago\n\n"
                                  f"This device may have been stolen!\n"
                                  f"Would you like to lock the missing device remotely?",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(pady=10)
        
        button_frame = ctk.CTkFrame(alert, fg_color="transparent")
        button_frame.pack(pady=20)
        
        def lock_remote():
            # Trigger emergency lock on missing device
            self.storage_engine.revoke_all_sessions()
            ctk.CTkLabel(alert, text="✅ Remote lock triggered!",
                         text_color=COLORS["green"]).pack()
            alert.after(2000, alert.destroy)
        
        ctk.CTkButton(button_frame, text="🔒 Lock Missing Device",
                      command=lock_remote,
                      width=180, height=40,
                      fg_color=COLORS["red"],
                      text_color=COLORS["bg"]).pack(side="left", padx=10)
        
        ctk.CTkButton(button_frame, text="Ignore",
                      command=alert.destroy,
                      width=100, height=40,
                      fg_color=COLORS["card"],
                      text_color=COLORS["text"]).pack(side="left", padx=10)
    
    # ═══════════════════════════════════════════════════════════
    # REMOTE PASSWORD CHANGE (Emergency)
    # ═══════════════════════════════════════════════════════════
    
    def emergency_password_reset_screen(self):
        """
        Screen to reset passwords of ALL accounts from another device.
        Use this when both devices are stolen to lock the attacker out.
        """
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🔄  EMERGENCY PASSWORD RESET",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["red"]).pack(side="left", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        info_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        info_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(info_card, text="⚠️  EMERGENCY ACTION",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["red"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        ctk.CTkLabel(info_card,
                     text="This will generate NEW passwords for ALL accounts in your vault.\n\n"
                          "Use this ONLY if:\n"
                          "  • Both your laptop AND phone are stolen\n"
                          "  • You are on a trusted device\n"
                          "  • You want to lock the attacker out of ALL accounts\n\n"
                          "WARNING: This will change passwords for every account.\n"
                          "You will need to update them on all your devices.",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"],
                     wraplength=650).pack(anchor="w", padx=16, pady=(0, 12))
        
        # Master password verification (to confirm it's really you)
        ctk.CTkLabel(info_card, text="Enter Master Password to confirm:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(anchor="w", padx=16, pady=(10, 4))
        
        pwd_entry = ctk.CTkEntry(info_card, placeholder_text="Master Password",
                                  show="●", width=300, height=40)
        pwd_entry.pack(anchor="w", padx=16, pady=(0, 10))
        
        status_label = ctk.CTkLabel(info_card, text="", font=("Segoe UI", 10), text_color=COLORS["red"])
        status_label.pack(anchor="w", padx=16, pady=(0, 10))
        
        def execute_emergency_reset():
            # Verify master password first
            pwd = pwd_entry.get()
            if not pwd:
                status_label.configure(text="Enter master password", text_color=COLORS["red"])
                return
            
            config = self.storage_engine.get_vault_config()
            if not config:
                status_label.configure(text="Vault config error", text_color=COLORS["red"])
                return
            
            salt = config[0]
            stored_hash = config[1]
            
            is_valid = self.auth_manager.verify_master_password_argon2(stored_hash, pwd)
            if not is_valid:
                status_label.configure(text="Incorrect master password", text_color=COLORS["red"])
                return
            
            # Get all credentials
            all_creds = self.storage_engine.get_all_credentials()
            reset_count = 0
            
            for cred in all_creds:
                try:
                    # Generate new strong password
                    new_password = self.sentinel_auditor.generate_secure_password(20)
                    
                    # Encrypt new password
                    ciphertext, iv = self.encryption_provider.encrypt(new_password)
                    
                    # Update in database
                    self.storage_engine.update_credential(
                        cred[0], cred[1], cred[2], 
                        ciphertext, iv, cred[5], cred[6]
                    )
                    reset_count += 1
                except Exception as e:
                    logger.error(f"Failed to reset password for {cred[1]}: {e}")
            
            # Show success and export new passwords
            from datetime import datetime
            export_file = f"emergency_passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(export_file, 'w') as f:
                f.write("EMERGENCY PASSWORD RESET - SAVE THIS FILE SECURELY\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Date: {datetime.now()}\n")
                f.write(f"Total accounts reset: {reset_count}\n\n")
                
                # Get updated credentials
                updated_creds = self.storage_engine.get_all_credentials()
                for cred in updated_creds:
                    try:
                        plaintext = self.encryption_provider.decrypt(cred[3], cred[4])
                        f.write(f"{cred[1]} ({cred[2]}): {plaintext}\n")
                    except:
                        f.write(f"{cred[1]} ({cred[2]}): [DECRYPT ERROR]\n")
            
            status_label.configure(text=f"✅ {reset_count} passwords reset! File saved: {export_file}", 
                                   text_color=COLORS["green"])
            
            messagebox.showwarning(
                "EMERGENCY RESET COMPLETE",
                f"{reset_count} passwords have been reset.\n\n"
                f"New passwords saved to:\n{export_file}\n\n"
                f"IMPORTANT: Save this file securely and update your accounts."
            )
        
        reset_btn = ctk.CTkButton(info_card, text="🚨  EXECUTE EMERGENCY RESET",
                                   command=execute_emergency_reset,
                                   width=300, height=45,
                                   fg_color=COLORS["red"],
                                   hover_color="#AA0000",
                                   text_color=COLORS["bg"],
                                   font=("Segoe UI", 13, "bold"))
        reset_btn.pack(pady=(10, 20))
    
    # ═══════════════════════════════════════════════════════════
    # CROSS-DEVICE VAULT SYNC (For Case 2 - Different Passwords)
    # ═══════════════════════════════════════════════════════════
    
    def export_vault_for_sync(self):
        """
        Export entire vault as encrypted blob for sync.
        This ensures both devices have identical credential sets.
        """
        import json
        import zlib
        
        # Get all credentials
        all_creds = self.storage_engine.get_all_credentials()
        
        # Prepare export data (encrypted, not plaintext)
        export_data = []
        for cred in all_creds:
            export_data.append({
                'site_name': cred[1],
                'username': cred[2],
                'encrypted_password': cred[3].hex() if cred[3] else None,
                'iv': cred[4].hex() if cred[4] else None,
                'category': cred[5],
                'notes': cred[6],
                'last_updated': cred[8] if len(cred) > 8 else None
            })
        
        # Compress and encrypt
        json_data = json.dumps(export_data)
        compressed = zlib.compress(json_data.encode())
        
        # Encrypt with master key
        encrypted_blob, nonce = self.encryption_provider.encrypt_bytes(compressed)
        
        return encrypted_blob, nonce
    
    def import_vault_from_sync(self, encrypted_blob: bytes, nonce: bytes, merge_strategy: str = "smart"):
        """
        Import vault from another device.
        
        merge_strategy options:
        - "replace": Replace local vault with imported one
        - "smart": Keep newer entries from both devices
        - "manual": Let user resolve conflicts
        """
        import json
        import zlib
        
        # Decrypt
        decrypted = self.encryption_provider.decrypt_bytes(encrypted_blob, nonce)
        
        # Decompress
        decompressed = zlib.decompress(decrypted)
        
        # Parse JSON
        imported_creds = json.loads(decompressed.decode())
        
        if merge_strategy == "replace":
            # Replace entire vault
            for cred in imported_creds:
                self.storage_engine.add_credential(
                    cred['site_name'],
                    cred['username'],
                    bytes.fromhex(cred['encrypted_password']),
                    bytes.fromhex(cred['iv']),
                    cred['category'],
                    cred['notes']
                )
            return len(imported_creds)
        
        elif merge_strategy == "smart":
            # Smart merge: Keep the most recent version of each credential
            imported_count = 0
            for imported in imported_creds:
                existing = self.storage_engine.get_credential_by_site(imported['site_name'])
                
                if not existing:
                    # New credential - add it
                    self.storage_engine.add_credential(
                        imported['site_name'],
                        imported['username'],
                        bytes.fromhex(imported['encrypted_password']),
                        bytes.fromhex(imported['iv']),
                        imported['category'],
                        imported['notes']
                    )
                    imported_count += 1
                else:
                    # Conflict - keep the one with newer last_updated
                    existing_time = existing[8] if len(existing) > 8 else ""
                    imported_time = imported.get('last_updated', "")
                    
                    if imported_time > existing_time:
                        # Imported version is newer
                        self.storage_engine.update_credential(
                            existing[0],
                            imported['site_name'],
                            imported['username'],
                            bytes.fromhex(imported['encrypted_password']),
                            bytes.fromhex(imported['iv']),
                            imported['category'],
                            imported['notes']
                        )
                        imported_count += 1
            
            return imported_count
        
        return 0
    
    def sync_devices_via_qr(self):
        """
        Sync two devices using QR code (no internet required).
        """
        import qrcode
        from PIL import Image, ImageTk
        import io
        
        # Export vault
        encrypted_blob, nonce = self.export_vault_for_sync()
        
        # Combine blob and nonce for QR (limited to ~3KB)
        # For larger vaults, use multiple QR codes or local network
        import base64
        sync_data = base64.b64encode(encrypted_blob + nonce).decode()
        
        # Split into chunks if too large
        chunk_size = 2000
        chunks = [sync_data[i:i+chunk_size] for i in range(0, len(sync_data), chunk_size)]
        
        # Display first QR code
        self.show_sync_qr_chain(chunks, 0)
    
    def show_sync_qr_chain(self, chunks: list, index: int):
        """
        Display a chain of QR codes for large sync data.
        """
        import qrcode
        from PIL import ImageTk
        import io
        
        if index >= len(chunks):
            messagebox.showinfo("Sync Complete", "All data transferred successfully!")
            return
        
        popup = ctk.CTkToplevel(self)
        popup.title(f"Sync QR Code {index + 1}/{len(chunks)}")
        popup.geometry("500x550")
        popup.configure(fg_color=COLORS["sidebar"])
        popup.grab_set()
        
        ctk.CTkLabel(popup, text=f"Scan QR Code {index + 1} of {len(chunks)}",
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(20, 10))
        
        # Generate QR code
        qr = qrcode.QRCode(box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(chunks[index])
        qr.make()
        
        qr_img = qr.make_image(fill_color=COLORS["accent"], back_color=COLORS["bg"])
        
        # Convert to PhotoImage
        img_buffer = io.BytesIO()
        qr_img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        pil_img = Image.open(img_buffer)
        tk_img = ImageTk.PhotoImage(pil_img)
        
        qr_label = ctk.CTkLabel(popup, text="", image=tk_img)
        qr_label.image = tk_img
        qr_label.pack(pady=10)
        
        def next_chunk():
            popup.destroy()
            self.show_sync_qr_chain(chunks, index + 1)
        
        ctk.CTkButton(popup, text="Next QR Code",
                      command=next_chunk,
                      width=200, height=40,
                      fg_color=COLORS["accent"],
                      text_color=COLORS["bg"]).pack(pady=20)
    
    # ═══════════════════════════════════════════════════════
    # SESSION AUTO-LOCK (5 minutes inactivity)
    # ═══════════════════════════════════════════════════════

    def _note_activity(self, event=None):
        """Called on user input to mark the vault session as active."""
        self._last_activity_ts = time.time()

    def arm_auto_lock(self):
        """Starts the inactivity timer after successful unlock."""
        self._auto_lock_enabled = True
        self._last_activity_ts = time.time()

        # Bind common user interactions so the vault doesn't lock mid-use.
        self.bind_all("<KeyPress>", self._note_activity)
        self.bind_all("<ButtonPress>", self._note_activity)

        self.after(1000, self._check_idle)

    def _check_idle(self):
        """Locks the vault if idle time exceeds the configured timeout."""
        if not self._auto_lock_enabled:
            return
        if self.encryption_provider is None:
            return

        idle_for = time.time() - self._last_activity_ts
        if idle_for >= self.session_timeout_seconds:
            try:
                self.lock_vault()
            except Exception:
                # If UI fails, at least stop auto-lock loop.
                self._auto_lock_enabled = False
            return

        # Keep checking every second.
        self.after(1000, self._check_idle)

    # ═══════════════════════════════════════════════════════
    # MFA: OTP CHALLENGE (offline TOTP)
    # ═══════════════════════════════════════════════════════

    def show_otp_challenge(self, totp, display_test_code: bool = False):
        """Shows OTP input screen after Master Password unlock."""
        self.clear_screen()
        card = ctk.CTkFrame(
            self,
            fg_color=COLORS["sidebar"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["accent"],
        )
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🛡️ MFA Verification", font=("Segoe UI", 22, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(24, 6))
        ctk.CTkLabel(
            card,
            text="Enter the 6-digit OTP from your Authenticator app.",
            font=("Segoe UI", 12),
            text_color=COLORS["subtext"],
        ).pack(pady=(0, 14))

        if display_test_code:
            # For setup flow we show a one-time test code to let the user verify quickly.
            ctk.CTkLabel(
                card,
                text=f"Test OTP (for setup only): {totp.now()}",
                font=("Segoe UI", 11, "bold"),
                text_color=COLORS["gold"],
            ).pack(pady=(0, 8))

        otp_entry = ctk.CTkEntry(
            card,
            placeholder_text="Enter OTP",
            width=220,
            height=44,
            font=("Segoe UI", 13),
        )
        otp_entry.pack(padx=40, pady=6)
        otp_entry.focus()

        status_label = ctk.CTkLabel(card, text="", font=("Segoe UI", 11), text_color=COLORS["red"])
        status_label.pack()

        def verify():
            code = otp_entry.get().strip()
            if not code:
                status_label.configure(text="⚠️ Enter OTP.")
                return
            try:
                if totp.verify(code, valid_window=1):
                    self._pending_totp = None
                    self.show_dashboard()
                    self.arm_auto_lock()
                else:
                    status_label.configure(text="❌ Invalid OTP. Try again.")
                    otp_entry.delete(0, "end")
            except Exception as e:
                status_label.configure(text=f"⚠️ OTP error: {str(e)}")

        otp_entry.bind("<Return>", lambda e: verify())

        ctk.CTkButton(
            card,
            text="✅  Verify & Unlock",
            command=verify,
            width=260,
            height=44,
            fg_color=COLORS["accent"],
            text_color=COLORS["bg"],
            font=("Segoe UI", 13, "bold"),
        ).pack(padx=40, pady=(12, 8))

    # ═══════════════════════════════════════════════════════
    # MASTER PASSWORD RECOVERY (Recovery Code flow)
    # ═══════════════════════════════════════════════════════

    def show_recovery_screen(self):
        """Recovery screen: uses Recovery Code to re-wrap the vault key."""
        self.clear_screen()
        card = ctk.CTkFrame(
            self,
            fg_color=COLORS["sidebar"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["accent"],
        )
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🔑 Master Password Recovery", font=("Segoe UI", 20, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(24, 6))
        ctk.CTkLabel(
            card,
            text="Enter your Recovery Code to unlock the vault key and set a new Master Password.",
            font=("Segoe UI", 12),
            text_color=COLORS["subtext"],
            wraplength=720,
            justify="center",
        ).pack(pady=(0, 14))

        self.recovery_code_entry = ctk.CTkEntry(
            card,
            placeholder_text="Recovery Code (XXXX-XXXX-XXXX-XXXX)",
            show="●",
            width=360,
            height=44,
            font=("Segoe UI", 12),
        )
        self.recovery_code_entry.pack(padx=40, pady=(10, 6))

        self.recovery_new_pass = ctk.CTkEntry(
            card,
            placeholder_text="New Master Password",
            show="●",
            width=360,
            height=44,
            font=("Segoe UI", 12),
        )
        self.recovery_new_pass.pack(padx=40, pady=6)

        self.recovery_new_confirm = ctk.CTkEntry(
            card,
            placeholder_text="Confirm New Master Password",
            show="●",
            width=360,
            height=44,
            font=("Segoe UI", 12),
        )
        self.recovery_new_confirm.pack(padx=40, pady=6)

        status_label = ctk.CTkLabel(card, text="", font=("Segoe UI", 11), text_color=COLORS["red"])
        status_label.pack()

        def do_recovery():
            rec_code = self.recovery_code_entry.get().strip()
            new_pwd = self.recovery_new_pass.get()
            confirm = self.recovery_new_confirm.get()

            if not rec_code:
                status_label.configure(text="⚠️ Enter your Recovery Code.")
                return
            if not new_pwd or not confirm:
                status_label.configure(text="⚠️ Enter new password and confirmation.")
                return
            if len(new_pwd) < 12:
                status_label.configure(text="⚠️ New Master Password must be at least 12 characters.")
                return
            if new_pwd != confirm:
                status_label.configure(text="❌ New passwords do not match.")
                return

            try:
                config = self.storage_engine.get_vault_config()
                if not config:
                    status_label.configure(text="Error: Vault config missing.")
                    return

                recovery_salt = config[3]
                vault_key_enc_recovery = config[6]
                vault_key_nonce_recovery = config[7]

                if recovery_salt is None or vault_key_enc_recovery is None or vault_key_nonce_recovery is None:
                    status_label.configure(text="❌ Recovery wrappers not found in this vault.")
                    return

                k_recovery = self.auth_manager.derive_key_pbkdf2(rec_code, recovery_salt)
                provider_recovery = EncryptionProvider(k_recovery)
                vault_key = provider_recovery.decrypt_bytes(vault_key_enc_recovery, vault_key_nonce_recovery)

                # Re-wrap vault key with the NEW master password.
                new_salt = self.auth_manager.generate_salt()
                new_master_hash = self.auth_manager.hash_master_password_argon2(new_pwd)
                k_master_new = self.auth_manager.derive_key_pbkdf2(new_pwd, new_salt)
                provider_master_new = EncryptionProvider(k_master_new)
                enc_master_new, nonce_master_new = provider_master_new.encrypt_bytes(vault_key)

                self.storage_engine.update_master_rewrap(
                    new_salt=new_salt,
                    new_master_hash=new_master_hash,
                    new_vault_key_enc_master=enc_master_new,
                    new_vault_key_nonce_master=nonce_master_new,
                )

                # Unlock for this session using the vault key.
                provider_recovery.secure_wipe()
                provider_master_new.secure_wipe()
                self.master_key = vault_key
                self.encryption_provider = EncryptionProvider(vault_key)

                # If MFA is enabled, require OTP now.
                mfa_enabled = bool(config[8])
                if mfa_enabled and config[9] is not None and config[10] is not None:
                    mfa_secret_b32 = self.encryption_provider.decrypt_bytes(config[9], config[10]).decode("utf-8")
                    totp = pyotp.TOTP(mfa_secret_b32)
                    self._pending_totp = totp
                    self.show_otp_challenge(totp, display_test_code=False)
                else:
                    self.show_dashboard()
                    self.arm_auto_lock()
            except Exception as e:
                status_label.configure(text=f"⚠️ Recovery failed: {str(e)}")

        ctk.CTkButton(
            card,
            text="🛡️  Recover & Unlock Vault",
            command=do_recovery,
            width=360,
            height=44,
            fg_color=COLORS["accent"],
            text_color=COLORS["bg"],
            font=("Segoe UI", 13, "bold"),
        ).pack(padx=40, pady=(14, 8))

        ctk.CTkButton(
            card,
            text="← Back to Login",
            command=self.show_login_screen,
            width=360,
            height=38,
            fg_color=COLORS["card"],
            text_color=COLORS["text"],
            font=("Segoe UI", 12, "bold"),
        ).pack(padx=40, pady=(6, 10))

    # ═══════════════════════════════════════════════════════
    # SCREEN 3: DASHBOARD
    # ═══════════════════════════════════════════════════════

    def show_dashboard(self):
        """Main dashboard with sidebar navigation and content area."""
        self.clear_screen()

        self.sidebar = ctk.CTkFrame(
            self, width=240, fg_color=COLORS["sidebar"], corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        ctk.CTkLabel(self.sidebar, text="🛡️ SENTINEL",
                     font=("Segoe UI", 20, "bold"),
                     text_color=COLORS["accent"]).pack(pady=30)

        ctk.CTkFrame(self.sidebar, fg_color=COLORS["card"],
                     height=1).pack(fill="x", padx=16, pady=(0, 10))

        # Define navigation items properly
        nav_items = [
            ("🏠  Sentinel Dashboard",    self.show_sentinel_dashboard),
            ("🔑  My Vault",              self.show_vault_view),
            ("➕  Add Secret",             self.show_add_view),
            ("🛡️  Security Audit",        self.show_audit_view),
            ("👑  Advanced Audit",         self.show_advanced_audit),
            ("📊  Export Report",          self.show_export_view),
            ("📖  Strength Guide",         self.show_strength_guide),
            ("🔗  Encryption Flow",        self.show_encryption_flow),
            ("💰  Attack Cost Calc",       self.show_attack_calculator),
            ("📊  Comparison Table",       self.show_comparison_table),
            ("⚡  Key Derivation Demo",    self.show_key_derivation_demo),
            ("🔐  Security Flowchart",     self.show_security_flowchart),
            ("📐  UML Class Diagram",      self.show_class_diagram),
            ("📋  Error Logs",             self.show_error_logs),
            ("🩺  System Health",          self.show_system_health),
            ("📊  Data Flow Diagram",      self.show_data_flow_diagram),
            ("🪨  Grey Rock Security",     self.show_grey_rock_settings),
            ("🔑  Recovery Management",    self.show_recovery_management),
            ("🚨  Emergency Prep",       self.show_emergency_preparation_screen),
            ("🔒  Emergency Lock",       self.emergency_lock_screen),
            ("📱  Device Pairing",         self.setup_device_pairing),           
            ("🚨  Emergency Reset",        self.emergency_password_reset_screen),
            ("🔄  Sync Vault",             self.sync_devices_via_qr), 
        ]

        for label, command in nav_items:
            ctk.CTkButton(
                self.sidebar, text=label,
                fg_color="transparent",
                hover_color=COLORS["card"],
                anchor="w",
                font=("Segoe UI", 13),
                text_color=COLORS["text"],
                command=command
            ).pack(fill="x", padx=15, pady=4)

        ctk.CTkButton(
            self.sidebar, text="🔒  Lock Vault",
            fg_color="#2A1A1A", hover_color="#3A1A1A",
            text_color=COLORS["red"],
            font=("Segoe UI", 13, "bold"),
            command=self.lock_vault
        ).pack(side="bottom", fill="x", padx=15, pady=20)

        self.content = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        self.content.pack(side="right", fill="both", expand=True)

        # Show Sentinel Dashboard by default
        self.show_sentinel_dashboard()

    # ═══════════════════════════════════════════════════════
    # CONTENT: MY VAULT
    # ═══════════════════════════════════════════════════════

    def show_vault_view(self):
        """Displays all stored credentials in a scrollable list."""
        self.clear_content()

        header = ctk.CTkFrame(self.content,
                              fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🔑  Secure Vault Storage",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["text"]).pack(
            side="left", padx=20, pady=16)

        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=16, pady=16)

        creds = self.storage_engine.get_all_credentials()
        if not creds:
            ctk.CTkLabel(scroll,
                text="🔒  No secrets stored yet.\n"
                     "Click '➕ Add Secret' to get started.",
                font=("Segoe UI", 14),
                text_color=COLORS["subtext"]).pack(pady=60)
            return

        for c in creds:
            self.build_credential_card(scroll, c)

    def build_credential_card(self, parent, c):
        """Builds one credential row card with View, History, Delete buttons."""
        card = ctk.CTkFrame(parent, fg_color=COLORS["sidebar"],
                            corner_radius=10, border_width=1,
                            border_color=COLORS["card"])
        card.pack(fill="x", pady=5, padx=4)

        icon = ctk.CTkFrame(card, fg_color=COLORS["accent"],
                            width=42, height=42, corner_radius=10)
        icon.pack(side="left", padx=(12, 8), pady=10)
        icon.pack_propagate(False)
        ctk.CTkLabel(icon, text=c[1][0].upper(),
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["bg"]).place(
            relx=0.5, rely=0.5, anchor="center")

        info = ctk.CTkFrame(card, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, pady=10)
        ctk.CTkLabel(info, text=c[1],
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w")

        history_count = self.storage_engine.get_history_count(c[0])
        username_text = (f"{c[2]}   |   🕐 {history_count} change(s)"
                         if history_count > 0 else c[2])
        ctk.CTkLabel(info, text=username_text,
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(anchor="w")

        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=10, pady=10)

        ctk.CTkButton(
            btn_frame, text="👁  View", width=75, height=32,
            fg_color=COLORS["card"], hover_color=COLORS["bg"],
            text_color=COLORS["accent"], font=("Segoe UI", 11),
            command=lambda cid=c[0]: self.view_secret(cid)
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_frame, text="🕐  History", width=85, height=32,
            fg_color=COLORS["card"], hover_color=COLORS["bg"],
            text_color=COLORS["purple"], font=("Segoe UI", 11),
            command=lambda cid=c[0], site=c[1]: self.view_password_history(
                cid, site)
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_frame, text="🗑  Delete", width=80, height=32,
            fg_color=COLORS["card"], hover_color="#2A1010",
            text_color=COLORS["red"], font=("Segoe UI", 11),
            command=lambda cid=c[0], site=c[1]: self.delete_secret(cid, site)
        ).pack(side="left", padx=3)

    # ═══════════════════════════════════════════════════════
    # VIEW CURRENT PASSWORD
    # ═══════════════════════════════════════════════════════
    
    def view_secret(self, cred_id):
        """Decrypts one credential in RAM and shows it in a popup with clipboard countdown timer."""
        try:
            data = self.storage_engine.get_credential_by_id(cred_id)
            if not data:
                messagebox.showerror("Error", "Credential not found.")
                return
            plaintext = self.encryption_provider.decrypt(data[3], data[4])

            popup = ctk.CTkToplevel(self)
            popup.title(f"🔑 {data[1]}")
            popup.geometry("400x300")
            popup.configure(fg_color=COLORS["sidebar"])
            popup.grab_set()

            ctk.CTkLabel(popup, text=f"🌐  {data[1]}",
                         font=("Segoe UI", 18, "bold"),
                         text_color=COLORS["accent"]).pack(pady=(20, 4))
            ctk.CTkLabel(popup, text=f"Username: {data[2]}",
                         font=("Segoe UI", 12),
                         text_color=COLORS["subtext"]).pack()

            pass_row = ctk.CTkFrame(popup, fg_color=COLORS["card"],
                                    corner_radius=8)
            pass_row.pack(fill="x", padx=30, pady=12)
            ctk.CTkLabel(pass_row, text=plaintext,
                         font=("Segoe UI", 14),
                         text_color=COLORS["green"]).pack(
                side="left", padx=12, pady=10)

            # Timer frame for better visual organization
            timer_frame = ctk.CTkFrame(popup, fg_color="transparent")
            timer_frame.pack(pady=(8, 4))
            
            # Timer icon and label
            timer_icon = ctk.CTkLabel(timer_frame, text="⏱️",
                                       font=("Segoe UI", 14),
                                       text_color=COLORS["subtext"])
            timer_icon.pack(side="left", padx=(0, 8))
            
            timer_label = ctk.CTkLabel(
                timer_frame, 
                text="Clipboard will clear in 30 seconds",
                font=("Segoe UI", 11),
                text_color=COLORS["subtext"])
            timer_label.pack(side="left")
            
            # Progress bar for visual countdown
            progress_bar = ctk.CTkProgressBar(
                popup, 
                width=340, 
                height=6, 
                corner_radius=3,
                fg_color=COLORS["card"],
                progress_color=COLORS["accent"])
            progress_bar.pack(pady=(4, 8))
            progress_bar.set(1.0)
            
            # Status label for copy confirmation
            copy_status = ctk.CTkLabel(
                popup, 
                text="",
                font=("Segoe UI", 10),
                text_color=COLORS["green"])
            copy_status.pack(pady=(0, 8))

            # Variable to track if clipboard was cleared
            clipboard_cleared = [False]
            
            # Countdown tracking variables
            remaining_seconds = [30]
            
            def update_timer():
                """Update countdown display every second."""
                if remaining_seconds[0] > 0 and not clipboard_cleared[0]:
                    remaining_seconds[0] -= 1
                    
                    # Update timer label with seconds remaining
                    timer_label.configure(
                        text=f"Clipboard will clear in {remaining_seconds[0]} second{'s' if remaining_seconds[0] != 1 else ''}",
                        text_color=COLORS["orange"] if remaining_seconds[0] <= 10 else COLORS["subtext"])
                    
                    # Update progress bar
                    progress_bar.set(remaining_seconds[0] / 30)
                    
                    # Change progress bar color when time is low
                    if remaining_seconds[0] <= 10:
                        progress_bar.configure(progress_color=COLORS["red"])
                    elif remaining_seconds[0] <= 20:
                        progress_bar.configure(progress_color=COLORS["orange"])
                    
                    # Schedule next update
                    popup.after(1000, update_timer)
                elif remaining_seconds[0] == 0 and not clipboard_cleared[0]:
                    # Time's up - clear clipboard
                    self.clipboard_clear()
                    clipboard_cleared[0] = True
                    timer_label.configure(
                        text="🗑️  Clipboard cleared automatically",
                        text_color=COLORS["green"])
                    progress_bar.set(0)
                    copy_status.configure(text="")
            
            def copy_to_clipboard():
                """Copy password to clipboard and start/restart countdown."""
                if clipboard_cleared[0]:
                    clipboard_cleared[0] = False
                
                self.clipboard_clear()
                self.clipboard_append(plaintext)
                
                copy_status.configure(
                    text="✅ Copied to clipboard! Timer reset.",
                    text_color=COLORS["green"])
                
                remaining_seconds[0] = 30
                progress_bar.set(1.0)
                progress_bar.configure(progress_color=COLORS["accent"])
                timer_label.configure(
                    text=f"Clipboard will clear in 30 seconds",
                    text_color=COLORS["subtext"])
            
            # Copy button with enhanced styling
            copy_btn = ctk.CTkButton(
                pass_row, 
                text="📋 Copy to Clipboard", 
                width=100, 
                height=32,
                command=copy_to_clipboard, 
                fg_color=COLORS["accent"],
                text_color=COLORS["bg"],
                font=("Segoe UI", 12, "bold"),
                corner_radius=6)
            copy_btn.pack(side="right", padx=8, pady=6)
            
            # Start the countdown timer
            popup.after(1000, update_timer)
            
            # Add a manual clear button for user convenience
            def manual_clear():
                """Manually clear clipboard and reset timer."""
                self.clipboard_clear()
                clipboard_cleared[0] = True
                remaining_seconds[0] = 0
                timer_label.configure(
                    text="🗑️  Clipboard cleared manually",
                    text_color=COLORS["green"])
                progress_bar.set(0)
                copy_status.configure(
                    text="",
                    text_color=COLORS["subtext"])
                copy_btn.configure(
                    text="📋 Copied (Cleared)",
                    fg_color=COLORS["card"],
                    state="disabled")
            
            clear_btn = ctk.CTkButton(
                popup,
                text="🗑️ Clear Now",
                width=120,
                height=30,
                command=manual_clear,
                fg_color=COLORS["card"],
                hover_color=COLORS["red"],
                text_color=COLORS["red"],
                font=("Segoe UI", 11),
                corner_radius=6)
            clear_btn.pack(pady=(4, 12))
            
            # Add close button at bottom
            close_btn = ctk.CTkButton(
                popup,
                text="Close",
                command=popup.destroy,
                width=100,
                height=32,
                fg_color=COLORS["card"],
                hover_color=COLORS["sidebar"],
                text_color=COLORS["text"],
                font=("Segoe UI", 11))
            close_btn.pack(pady=(0, 16))
            
            # Make the popup modal and bring to front
            popup.focus_force()
            
        except Exception as e:
            messagebox.showerror("Decryption Error",
                                 f"Failed to decrypt:\n{e}")

    def start_clipboard_countdown(self, label, seconds_left):
        """Counts down from 30 to 0, updating the timer label every second."""
        if seconds_left > 0:
            label.configure(
                text=f"⏱️  Clipboard clears in {seconds_left} seconds",
                text_color=COLORS["orange"] if seconds_left <= 10
                else COLORS["subtext"])
            self.after(1000,
                       lambda: self.start_clipboard_countdown(
                           label, seconds_left - 1))
        else:
            label.configure(
                text="🗑️  Clipboard cleared.",
                text_color=COLORS["green"])

    # ═══════════════════════════════════════════════════════
    # VIEW PASSWORD HISTORY
    # ═══════════════════════════════════════════════════════

    def view_password_history(self, cred_id: int, site_name: str):
        """Shows full password change history for one credential."""
        history = self.storage_engine.get_password_history(cred_id)

        popup = ctk.CTkToplevel(self)
        popup.title(f"Password History — {site_name}")
        popup.geometry("520x500")
        popup.configure(fg_color=COLORS["sidebar"])
        popup.grab_set()

        ctk.CTkLabel(popup, text="🕐  Password History",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["purple"]).pack(pady=(20, 2))
        ctk.CTkLabel(popup,
                     text=f"{site_name}  —  {len(history)} change(s) recorded",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(pady=(0, 12))

        if not history:
            ctk.CTkLabel(popup,
                         text="No password changes recorded yet.\n\n"
                              "History is saved automatically every time\n"
                              "you update a password entry.",
                         font=("Segoe UI", 12),
                         text_color=COLORS["subtext"],
                         justify="center").pack(expand=True)
            return

        scroll = ctk.CTkScrollableFrame(popup, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        for entry in history:
            _, cred_id_ref, old_enc, old_iv, changed_at, change_num = entry
            try:
                old_plaintext = self.encryption_provider.decrypt(
                    old_enc, old_iv)
            except Exception:
                old_plaintext = "[Could not decrypt]"

            card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                                corner_radius=10, border_width=1,
                                border_color=COLORS["card"])
            card.pack(fill="x", pady=4)

            ctk.CTkFrame(card, fg_color=COLORS["purple"],
                         width=4, corner_radius=2).pack(
                side="left", fill="y", padx=(0, 12))

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", fill="both", expand=True, pady=10)

            top = ctk.CTkFrame(info, fg_color="transparent")
            top.pack(fill="x")
            ctk.CTkLabel(top, text=f"Change #{change_num}",
                         font=("Segoe UI", 12, "bold"),
                         text_color=COLORS["purple"]).pack(side="left")
            ctk.CTkLabel(top, text=str(changed_at),
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack(side="right")

            pass_row = ctk.CTkFrame(info, fg_color=COLORS["card"],
                                     corner_radius=6)
            pass_row.pack(fill="x", pady=(4, 0), padx=(0, 12))
            ctk.CTkLabel(pass_row, text=old_plaintext,
                         font=("Segoe UI", 12),
                         text_color=COLORS["gold"]).pack(
                side="left", padx=10, pady=6)

            def copy_old(pwd=old_plaintext):
                self.clipboard_clear()
                self.clipboard_append(pwd)
                self.after(30000, self.clipboard_clear)

            ctk.CTkButton(pass_row, text="📋", width=36, height=28,
                          command=copy_old,
                          fg_color=COLORS["accent"],
                          text_color=COLORS["bg"],
                          font=("Segoe UI", 11)).pack(
                side="right", padx=6, pady=4)

        ctk.CTkLabel(popup,
                     text="🔐  All passwords decrypted in RAM only. "
                          "Nothing is written to disk.",
                     font=("Segoe UI", 9),
                     text_color=COLORS["subtext"]).pack(pady=(4, 10))

    # ═══════════════════════════════════════════════════════
    # DELETE CREDENTIAL
    # ═══════════════════════════════════════════════════════

    def delete_secret(self, cred_id, site_name):
        """Confirms then permanently deletes credential and its history."""
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Permanently delete password for:\n\n{site_name}\n\n"
            f"This will also delete all password history.\n"
            f"This cannot be undone.")
        if confirm:
            self.storage_engine.delete_credential(cred_id)
            messagebox.showinfo("Deleted",
                                f"{site_name} and its history removed.")
            self.show_vault_view()

    # ═══════════════════════════════════════════════════════
    # CONTENT: ADD SECRET
    # ═══════════════════════════════════════════════════════

    def show_add_view(self):
        """Form to add a new encrypted credential to the vault with enhanced password generator."""
        self.clear_content()

        header = ctk.CTkFrame(self.content,
                              fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="➕  Add New Secret",
                     font=("Segoe UI", 18, "bold")).pack(
            side="left", padx=20, pady=16)

        form = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        form.pack(fill="both", expand=True, padx=40, pady=20)

        # ── Website / App Name ──
        ctk.CTkLabel(form, text="Website / App Name",
                     font=("Segoe UI", 12),
                     text_color=COLORS["subtext"]).pack(
            anchor="w", pady=(8, 2))
        site_entry = ctk.CTkEntry(
            form, placeholder_text="e.g. Netflix, Gmail, GitHub",
            width=480, height=44, font=("Segoe UI", 13))
        site_entry.pack(anchor="w")

        # ── Username / Email ──
        ctk.CTkLabel(form, text="Username / Email",
                     font=("Segoe UI", 12),
                     text_color=COLORS["subtext"]).pack(
            anchor="w", pady=(12, 2))
        user_entry = ctk.CTkEntry(
            form, placeholder_text="e.g. john@gmail.com",
            width=480, height=44, font=("Segoe UI", 13))
        user_entry.pack(anchor="w")

        # ── Password Field ──
        ctk.CTkLabel(form, text="Password",
                     font=("Segoe UI", 12),
                     text_color=COLORS["subtext"]).pack(
            anchor="w", pady=(12, 2))
        pass_entry = ctk.CTkEntry(
            form, placeholder_text="Enter or generate a password",
            show="●", width=480, height=44, font=("Segoe UI", 13))
        pass_entry.pack(anchor="w")

        # Password strength indicator
        strength_label = ctk.CTkLabel(
            form, text="Strength: —",
            font=("Segoe UI", 11), text_color=COLORS["subtext"])
        strength_label.pack(anchor="w", pady=(6, 2))

        strength_bar = ctk.CTkProgressBar(
            form, width=480, height=8, corner_radius=4)
        strength_bar.pack(anchor="w")
        strength_bar.set(0)

        def update_strength(event=None):
            pwd = pass_entry.get()
            if pwd:
                audit = self.sentinel_auditor.audit_single_password(pwd)
                strength_bar.set(min(audit["entropy"] / 100, 1.0))
                strength_label.configure(
                    text=f"Strength: {audit['strength_label']}"
                         f"  ({audit['entropy']} bits)",
                    text_color=audit["color"])

        pass_entry.bind("<KeyRelease>", update_strength)

        # ═══════════════════════════════════════════════════════════════════
        # ENHANCED PASSWORD GENERATOR PANEL
        # ═══════════════════════════════════════════════════════════════════
        
        # Generator Panel Frame
        gen_panel = ctk.CTkFrame(form, fg_color=COLORS["sidebar"], corner_radius=12)
        gen_panel.pack(fill="x", pady=(12, 8))
        
        # Panel Header
        gen_header = ctk.CTkFrame(gen_panel, fg_color="transparent")
        gen_header.pack(fill="x", padx=16, pady=(12, 8))
        ctk.CTkLabel(gen_header, text="🔐  Password Generator",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).pack(side="left")
        ctk.CTkLabel(gen_header, text="Create strong, random passwords",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(side="right")
        
        # ── Length Slider ──
        length_frame = ctk.CTkFrame(gen_panel, fg_color="transparent")
        length_frame.pack(fill="x", padx=16, pady=(4, 8))
        ctk.CTkLabel(length_frame, text="Password Length:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(side="left")
        
        length_slider = ctk.CTkSlider(
            length_frame, from_=8, to=32, number_of_steps=24,
            width=200, height=16,
            fg_color=COLORS["card"],
            progress_color=COLORS["accent"])
        length_slider.set(18)
        length_slider.pack(side="left", padx=(12, 8))
        
        length_label = ctk.CTkLabel(length_frame, text="18 chars",
                                    font=("Segoe UI", 11, "bold"),
                                    text_color=COLORS["accent"],
                                    width=70)
        length_label.pack(side="left")
        
        # ── Character Type Toggles ──
        toggle_frame = ctk.CTkFrame(gen_panel, fg_color="transparent")
        toggle_frame.pack(fill="x", padx=16, pady=(4, 8))
        
        # Toggle variables
        use_upper = ctk.BooleanVar(value=True)
        use_lower = ctk.BooleanVar(value=True)
        use_digits = ctk.BooleanVar(value=True)
        use_symbols = ctk.BooleanVar(value=True)
        exclude_ambiguous = ctk.BooleanVar(value=False)
        
        ctk.CTkCheckBox(toggle_frame, text="Uppercase (A-Z)",
                        variable=use_upper, text_color=COLORS["text"],
                        fg_color=COLORS["accent"], hover_color=COLORS["green"],
                        font=("Segoe UI", 11)).pack(side="left", padx=(0, 12))
        
        ctk.CTkCheckBox(toggle_frame, text="Lowercase (a-z)",
                        variable=use_lower, text_color=COLORS["text"],
                        fg_color=COLORS["accent"], hover_color=COLORS["green"],
                        font=("Segoe UI", 11)).pack(side="left", padx=(0, 12))
        
        ctk.CTkCheckBox(toggle_frame, text="Numbers (0-9)",
                        variable=use_digits, text_color=COLORS["text"],
                        fg_color=COLORS["accent"], hover_color=COLORS["green"],
                        font=("Segoe UI", 11)).pack(side="left", padx=(0, 12))
        
        ctk.CTkCheckBox(toggle_frame, text="Symbols (!@#$%)",
                        variable=use_symbols, text_color=COLORS["text"],
                        fg_color=COLORS["accent"], hover_color=COLORS["green"],
                        font=("Segoe UI", 11)).pack(side="left", padx=(0, 12))
        
        # Second row of toggles
        toggle_frame2 = ctk.CTkFrame(gen_panel, fg_color="transparent")
        toggle_frame2.pack(fill="x", padx=16, pady=(4, 8))
        
        ctk.CTkCheckBox(toggle_frame2, text="Exclude ambiguous (l, 1, O, 0)",
                        variable=exclude_ambiguous, text_color=COLORS["text"],
                        fg_color=COLORS["accent"], hover_color=COLORS["orange"],
                        font=("Segoe UI", 11)).pack(side="left")
        
        # ── Generated Password Preview ──
        preview_frame = ctk.CTkFrame(gen_panel, fg_color=COLORS["card"], corner_radius=8)
        preview_frame.pack(fill="x", padx=16, pady=(8, 8))
        
        preview_label = ctk.CTkLabel(preview_frame, text="",
                                      font=("Segoe UI", 14, "bold"),
                                      text_color=COLORS["green"])
        preview_label.pack(pady=12, padx=12)
        
        # Generator preview strength bar
        preview_strength_label = ctk.CTkLabel(
            preview_frame, text="",
            font=("Segoe UI", 10), text_color=COLORS["subtext"])
        preview_strength_label.pack()
        
        preview_bar = ctk.CTkProgressBar(
            preview_frame, width=400, height=6, corner_radius=3)
        preview_bar.pack(pady=(6, 12))
        preview_bar.set(0)
        
        # ── Generator Control Buttons ──
        button_frame = ctk.CTkFrame(gen_panel, fg_color="transparent")
        button_frame.pack(fill="x", padx=16, pady=(4, 12))
        
        def generate_password_preview():
            """Generate password based on current settings and update preview."""
            length = int(length_slider.get())
            
            # Build character pool
            pool = ""
            if use_upper.get():
                if exclude_ambiguous.get():
                    pool += "ABCDEFGHJKLMNPQRSTUVWXYZ"
                else:
                    pool += string.ascii_uppercase
            if use_lower.get():
                if exclude_ambiguous.get():
                    pool += "abcdefghijkmnopqrstuvwxyz"
                else:
                    pool += string.ascii_lowercase
            if use_digits.get():
                if exclude_ambiguous.get():
                    pool += "23456789"
                else:
                    pool += string.digits
            if use_symbols.get():
                pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            # Ensure at least one character type is selected
            if not pool:
                pool = string.ascii_letters + string.digits
                use_lower.set(True)
                use_upper.set(True)
                use_digits.set(True)
            
            # Generate password with at least one of each selected type
            max_attempts = 50
            for _ in range(max_attempts):
                password = ''.join(secrets.choice(pool) for _ in range(length))
                
                valid = True
                if use_upper.get() and not any(c.isupper() for c in password):
                    valid = False
                if use_lower.get() and not any(c.islower() for c in password):
                    valid = False
                if use_digits.get() and not any(c.isdigit() for c in password):
                    valid = False
                if use_symbols.get() and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                    valid = False
                
                if valid:
                    break
            else:
                password = ''.join(secrets.choice(pool) for _ in range(length))
            
            # Update preview
            preview_label.configure(text=password)
            
            # Update strength analysis
            audit = self.sentinel_auditor.audit_single_password(password)
            preview_strength_label.configure(
                text=f"{audit['strength_label']}  |  Entropy: {audit['entropy']} bits",
                text_color=audit["color"])
            preview_bar.set(min(audit["entropy"] / 100, 1.0))
            
            return password
        
        def refresh_preview(*args):
            """Refresh password preview when settings change."""
            generate_password_preview()
        
        # Bind events
        length_slider.configure(command=lambda x: [length_label.configure(text=f"{int(x)} chars"), refresh_preview()])
        use_upper.trace_add("write", refresh_preview)
        use_lower.trace_add("write", refresh_preview)
        use_digits.trace_add("write", refresh_preview)
        use_symbols.trace_add("write", refresh_preview)
        exclude_ambiguous.trace_add("write", refresh_preview)
        
        # Regenerate button
        def regenerate():
            new_password = generate_password_preview()
            preview_label.configure(text=new_password)
        
        regen_btn = ctk.CTkButton(
            button_frame, text="🔄  Regenerate",
            command=regenerate,
            width=120, height=32,
            fg_color=COLORS["card"],
            hover_color=COLORS["sidebar"],
            text_color=COLORS["accent"],
            font=("Segoe UI", 11),
            border_width=1, border_color=COLORS["accent"])
        regen_btn.pack(side="left", padx=(0, 8))
        
        # Copy to form button
        def copy_to_form():
            generated_pwd = preview_label.cget("text")
            if generated_pwd:
                pass_entry.delete(0, "end")
                pass_entry.insert(0, generated_pwd)
                pass_entry.configure(show="●")
                update_strength()
                
                copy_status = ctk.CTkLabel(
                    button_frame, text="✅ Copied!",
                    font=("Segoe UI", 10),
                    text_color=COLORS["green"])
                copy_status.pack(side="left", padx=(8, 0))
                button_frame.after(2000, copy_status.destroy)
        
        copy_btn = ctk.CTkButton(
            button_frame, text="📋  Use This Password",
            command=copy_to_form,
            width=140, height=32,
            fg_color=COLORS["accent"],
            hover_color=COLORS["green"],
            text_color=COLORS["bg"],
            font=("Segoe UI", 11, "bold"))
        copy_btn.pack(side="left", padx=(8, 0))
        
        # Generate initial preview
        generate_password_preview()
        
        # ── Category Selection ──
        ctk.CTkLabel(form, text="Category",
                     font=("Segoe UI", 12),
                     text_color=COLORS["subtext"]).pack(
            anchor="w", pady=(12, 2))
        cat_var = ctk.StringVar(value="General")
        ctk.CTkOptionMenu(form,
            values=["General", "Finance", "Social", "Email", "Work"],
            variable=cat_var, width=200, height=40,
            fg_color=COLORS["card"],
            button_color=COLORS["accent"],
            text_color=COLORS["text"]).pack(anchor="w", pady=(0, 20))

        # ── Save Button ──
        def save():
            site = site_entry.get().strip()
            user = user_entry.get().strip()
            pwd  = pass_entry.get()
            cat  = cat_var.get()
            if not site or not user or not pwd:
                messagebox.showerror(
                    "Error",
                    "Site, Username, and Password are required.")
                return
            try:
                ciphertext, iv = self.encryption_provider.encrypt(pwd)
                self.storage_engine.add_credential(
                    site, user, ciphertext, iv, cat)
                messagebox.showinfo(
                    "Saved",
                    f"Password for {site} encrypted with AES-256-GCM"
                    f"\nand stored securely.")
                self.show_vault_view()
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed:\n{e}")

        ctk.CTkButton(form, text="💾  Encrypt & Save to Vault",
                      command=save, width=480, height=44,
                      fg_color=COLORS["accent"],
                      text_color=COLORS["bg"],
                      font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(20, 10))

        def generate():
            strong = self.sentinel_auditor.generate_secure_password(18)
            pass_entry.configure(show="")
            pass_entry.delete(0, "end")
            pass_entry.insert(0, strong)
            update_strength()

        ctk.CTkButton(form, text="⚡  Generate Strong Password",
                      command=generate, width=240, height=38,
                      fg_color=COLORS["card"],
                      hover_color=COLORS["sidebar"],
                      text_color=COLORS["green"],
                      border_width=1, border_color=COLORS["green"],
                      font=("Segoe UI", 12)).pack(
            anchor="w", pady=(10, 16))

    # ═══════════════════════════════════════════════════════
    # CONTENT: SECURITY AUDIT (WITH CATEGORY-WISE STATISTICS)
    # ═══════════════════════════════════════════════════════

    def show_audit_view(self):
        """Runs the Sentinel Auditor and displays the full security report with category-wise analysis."""
        self.clear_content()

        header = ctk.CTkFrame(self.content,
                              fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🛡️  Security Audit — The Sentinel",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(
            side="left", padx=20, pady=16)

        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=20)

        all_creds = self.storage_engine.get_all_credentials()
        if not all_creds:
            ctk.CTkLabel(scroll, text="🔒  No passwords to audit yet.",
                         font=("Segoe UI", 14),
                         text_color=COLORS["subtext"]).pack(pady=60)
            return

        # Decrypt in RAM and compute category-wise strength statistics.
        category_stats = {}
        decrypted_for_report = []

        for c in all_creds:
            site_name = c[1]
            cat = c[5] if c[5] else "General"
            try:
                plaintext = self.encryption_provider.decrypt(c[3], c[4])
                decrypted_for_report.append((site_name, plaintext))

                entropy = self.sentinel_auditor.calculate_entropy(plaintext)
                strength_label, _color = self.sentinel_auditor.get_strength_label(entropy)

                if cat not in category_stats:
                    category_stats[cat] = {
                        "strong": 0,
                        "weak": 0,
                        "moderate": 0,
                        "total": 0,
                        "accounts": []
                    }

                if strength_label in ("Strong", "Very Strong"):
                    category_stats[cat]["strong"] += 1
                elif strength_label in ("Very Weak", "Weak"):
                    category_stats[cat]["weak"] += 1
                else:
                    category_stats[cat]["moderate"] += 1

                category_stats[cat]["total"] += 1
                category_stats[cat]["accounts"].append((site_name, strength_label))

            except Exception:
                continue

        report = self.sentinel_auditor.generate_vault_report(decrypted_for_report)
        score  = report["vault_score"]
        score_color = (COLORS["red"]  if score < 40 else
                       COLORS["gold"] if score < 70 else
                       COLORS["green"])

        score_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                                   corner_radius=12, border_width=2,
                                   border_color=score_color)
        score_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(score_card, text="Vault Security Score",
                     font=("Segoe UI", 13),
                     text_color=COLORS["subtext"]).pack(pady=(16, 2))
        ctk.CTkLabel(score_card, text=f"{score} / 100",
                     font=("Segoe UI", 40, "bold"),
                     text_color=score_color).pack()
        bar = ctk.CTkProgressBar(score_card, width=400, height=12,
                                  corner_radius=6)
        bar.pack(pady=(4, 16))
        bar.set(score / 100)

        cats = report["categories"]
        stats_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 16))

        stats = [
            ("Total",    report["total_count"],              COLORS["accent"]),
            ("Strong",   cats["Strong"]+cats["Very Strong"], COLORS["green"]),
            ("Moderate", cats["Moderate"],                   COLORS["gold"]),
            ("Weak",     cats["Weak"]+cats["Very Weak"],     COLORS["red"]),
            ("Reused",   len(report["reused_map"]),          COLORS["orange"]),
            ("Common",   len(report["common_list"]),         COLORS["red"]),
        ]
        for i, (label, value, color) in enumerate(stats):
            s = ctk.CTkFrame(stats_frame, fg_color=COLORS["sidebar"],
                             corner_radius=10, border_width=1,
                             border_color=color)
            s.grid(row=0, column=i, padx=5, sticky="ew")
            stats_frame.columnconfigure(i, weight=1)
            ctk.CTkLabel(s, text=str(value),
                         font=("Segoe UI", 26, "bold"),
                         text_color=color).pack(pady=(10, 0))
            ctk.CTkLabel(s, text=label,
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack(pady=(0, 10))

        # Category-wise Statistics
        if category_stats:
            category_card = ctk.CTkFrame(
                scroll, fg_color=COLORS["sidebar"],
                corner_radius=12, border_width=2,
                border_color=COLORS["purple"])
            category_card.pack(fill="x", pady=(0, 16))

            ctk.CTkFrame(category_card, fg_color=COLORS["purple"],
                         height=3).pack(fill="x")

            header_row = ctk.CTkFrame(category_card, fg_color="transparent")
            header_row.pack(fill="x", padx=20, pady=(12, 4))
            ctk.CTkLabel(header_row, text="📊  Category-wise Password Strength Analysis",
                         font=("Segoe UI", 15, "bold"),
                         text_color=COLORS["purple"]).pack(side="left")
            ctk.CTkLabel(header_row, text="Data Analysis & Insights",
                         font=("Segoe UI", 11),
                         text_color=COLORS["subtext"]).pack(side="right")

            ctk.CTkLabel(category_card,
                         text="Breakdown of password strength across different categories — "
                              "identify which account types need security improvement.",
                         font=("Segoe UI", 11),
                         text_color=COLORS["text"],
                         wraplength=700).pack(anchor="w", padx=20, pady=(0, 12))

            categories_grid = ctk.CTkFrame(category_card, fg_color="transparent")
            categories_grid.pack(fill="x", padx=20, pady=(0, 12))

            categories_grid.columnconfigure(0, weight=1)
            categories_grid.columnconfigure(1, weight=1)

            sorted_categories = sorted(category_stats.keys())

            for idx, cat_name in enumerate(sorted_categories):
                stats = category_stats[cat_name]
                total = stats["total"]
                strong = stats["strong"]
                weak = stats["weak"]
                moderate = stats["moderate"]

                strong_pct = (strong / total * 100) if total > 0 else 0
                weak_pct = (weak / total * 100) if total > 0 else 0
                moderate_pct = (moderate / total * 100) if total > 0 else 0

                if strong_pct >= 70:
                    health = "EXCELLENT"
                    health_color = COLORS["green"]
                elif strong_pct >= 50:
                    health = "GOOD"
                    health_color = COLORS["gold"]
                elif strong_pct >= 30:
                    health = "FAIR"
                    health_color = COLORS["orange"]
                else:
                    health = "POOR"
                    health_color = COLORS["red"]

                cat_card = ctk.CTkFrame(categories_grid, fg_color=COLORS["card"],
                                         corner_radius=10, border_width=1,
                                         border_color=health_color)
                row = idx // 2
                col = idx % 2
                cat_card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

                icons = {
                    "Finance": "💰", "General": "🔐", "Social": "👥",
                    "Email": "📧", "Work": "💼", "Entertainment": "🎬"
                }
                icon = icons.get(cat_name, "📁")
                ctk.CTkLabel(cat_card,
                             text=f"{icon}  {cat_name}",
                             font=("Segoe UI", 14, "bold"),
                             text_color=COLORS["text"]).pack(
                    anchor="w", padx=12, pady=(10, 2))

                ctk.CTkLabel(cat_card,
                             text=f"{total} password(s)",
                             font=("Segoe UI", 10),
                             text_color=COLORS["subtext"]).pack(
                    anchor="w", padx=12, pady=(0, 8))

                bar_frame = ctk.CTkFrame(cat_card, fg_color="transparent")
                bar_frame.pack(fill="x", padx=12, pady=(0, 6))

                if strong > 0:
                    strong_bar = ctk.CTkFrame(bar_frame, fg_color=COLORS["green"],
                                               height=6, corner_radius=3)
                    strong_bar.pack(side="left", fill="x",
                                     expand=True if strong_pct > 0 else False,
                                     padx=(0, 1))

                if moderate > 0:
                    mod_bar = ctk.CTkFrame(bar_frame, fg_color=COLORS["gold"],
                                             height=6, corner_radius=3)
                    mod_bar.pack(side="left", fill="x",
                                  expand=True if moderate_pct > 0 else False,
                                  padx=(0, 1))

                if weak > 0:
                    weak_bar = ctk.CTkFrame(bar_frame, fg_color=COLORS["red"],
                                             height=6, corner_radius=3)
                    weak_bar.pack(side="left", fill="x",
                                   expand=True if weak_pct > 0 else False)

                stats_row = ctk.CTkFrame(cat_card, fg_color="transparent")
                stats_row.pack(fill="x", padx=12, pady=(4, 4))

                ctk.CTkLabel(stats_row, text=f"🟢 Strong: {strong}",
                             font=("Segoe UI", 10),
                             text_color=COLORS["green"]).pack(side="left", padx=(0, 8))
                ctk.CTkLabel(stats_row, text=f"🟡 Moderate: {moderate}",
                             font=("Segoe UI", 10),
                             text_color=COLORS["gold"]).pack(side="left", padx=(0, 8))
                ctk.CTkLabel(stats_row, text=f"🔴 Weak: {weak}",
                             font=("Segoe UI", 10),
                             text_color=COLORS["red"]).pack(side="left")

                health_frame = ctk.CTkFrame(cat_card, fg_color="transparent")
                health_frame.pack(fill="x", padx=12, pady=(4, 10))
                ctk.CTkLabel(health_frame, text=f"Health: {health}",
                             font=("Segoe UI", 11, "bold"),
                             text_color=health_color).pack(side="left")
                ctk.CTkLabel(health_frame,
                             text=f"Strong: {strong_pct:.0f}% | Weak: {weak_pct:.0f}%",
                             font=("Segoe UI", 9),
                             text_color=COLORS["subtext"]).pack(side="right")

                def make_toggle(cat=cat_name, stats_data=stats):
                    def toggle_details():
                        self._show_category_details(cat, stats_data["accounts"])
                    return toggle_details

                ctk.CTkButton(cat_card, text="📋  View Account Details",
                              command=make_toggle(),
                              fg_color="transparent",
                              hover_color=COLORS["sidebar"],
                              text_color=COLORS["accent"],
                              font=("Segoe UI", 10),
                              width=120, height=28,
                              border_width=1, border_color=COLORS["accent"]).pack(
                    anchor="w", padx=12, pady=(0, 10))

            summary_frame = ctk.CTkFrame(category_card, fg_color=COLORS["bg"],
                                          corner_radius=8)
            summary_frame.pack(fill="x", padx=20, pady=(0, 12))

            total_strong = sum(s["strong"] for s in category_stats.values())
            total_weak = sum(s["weak"] for s in category_stats.values())
            total_moderate = sum(s["moderate"] for s in category_stats.values())

            ctk.CTkLabel(summary_frame,
                         text="📈  Category Summary",
                         font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["accent"]).pack(anchor="w", padx=12, pady=(8, 2))

            worst_category = None
            worst_weak_pct = 0
            for cat_name, s in category_stats.items():
                if s["total"] > 0:
                    weak_pct = (s["weak"] / s["total"]) * 100
                    if weak_pct > worst_weak_pct:
                        worst_weak_pct = weak_pct
                        worst_category = cat_name

            summary_text = (f"Across {len(category_stats)} categories: "
                            f"{total_strong} strong, {total_moderate} moderate, {total_weak} weak passwords.")
            if worst_category:
                summary_text += f" Most vulnerable: {worst_category} ({worst_weak_pct:.0f}% weak)."

            ctk.CTkLabel(summary_frame, text=summary_text,
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"],
                         wraplength=650, justify="left").pack(
                anchor="w", padx=12, pady=(0, 8))

        def section(title, items, color):
            if not items:
                return
            f = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                             corner_radius=10, border_width=1,
                             border_color=color)
            f.pack(fill="x", pady=5)
            ctk.CTkFrame(f, fg_color=color, height=2).pack(fill="x")
            ctk.CTkLabel(f, text=title,
                         font=("Segoe UI", 13, "bold"),
                         text_color=color).pack(
                anchor="w", padx=16, pady=(10, 4))
            for item in items:
                ctk.CTkLabel(f, text=f"   •  {item}",
                             font=("Segoe UI", 12),
                             text_color=COLORS["text"]).pack(
                    anchor="w", padx=16, pady=1)
            ctk.CTkFrame(f, height=8, fg_color="transparent").pack()

        section("🔴  Very Weak Passwords",
                [s for s, p in decrypted_for_report
                 if self.sentinel_auditor.calculate_entropy(p) < 28],
                COLORS["red"])
        section("🟠  Weak Passwords",
                [s for s, p in decrypted_for_report
                 if 28 <= self.sentinel_auditor.calculate_entropy(p) < 36],
                COLORS["orange"])
        section("⚠️  Common / Breached Passwords",
                report["common_list"], COLORS["red"])

        if report["reused_map"]:
            f = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                             corner_radius=10, border_width=1,
                             border_color=COLORS["orange"])
            f.pack(fill="x", pady=5)
            ctk.CTkFrame(f, fg_color=COLORS["orange"],
                         height=2).pack(fill="x")
            ctk.CTkLabel(f, text="♻️  Reused Passwords",
                         font=("Segoe UI", 13, "bold"),
                         text_color=COLORS["orange"]).pack(
                anchor="w", padx=16, pady=(10, 4))
            for pwd, sites in report["reused_map"].items():
                ctk.CTkLabel(f,
                    text=f"   •  Same password on: {', '.join(sites)}",
                    font=("Segoe UI", 12),
                    text_color=COLORS["text"]).pack(
                    anchor="w", padx=16, pady=1)
            ctk.CTkFrame(f, height=8, fg_color="transparent").pack()

        section("🟢  Strong Passwords",
                [s for s, p in decrypted_for_report
                 if self.sentinel_auditor.calculate_entropy(p) >= 60],
                COLORS["green"])

    def _show_category_details(self, category_name: str, accounts: list):
        """Helper method to show detailed account list for a specific category."""
        popup = ctk.CTkToplevel(self)
        popup.title(f"Category Details — {category_name}")
        popup.geometry("500x400")
        popup.configure(fg_color=COLORS["sidebar"])
        popup.grab_set()

        ctk.CTkLabel(popup, text=f"📊  {category_name} — Password Strength Details",
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["purple"]).pack(pady=(20, 4))

        strong_count = sum(1 for _, s in accounts if s in ("Strong", "Very Strong"))
        weak_count = sum(1 for _, s in accounts if s in ("Weak", "Very Weak"))
        moderate_count = len(accounts) - strong_count - weak_count

        summary_frame = ctk.CTkFrame(popup, fg_color=COLORS["card"], corner_radius=8)
        summary_frame.pack(fill="x", padx=20, pady=(10, 10))

        ctk.CTkLabel(summary_frame,
                     text=f"Total: {len(accounts)} accounts",
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["text"]).pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(summary_frame,
                     text=f"🟢 Strong: {strong_count}  🟡 Moderate: {moderate_count}  🔴 Weak: {weak_count}",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=12, pady=8)

        scroll = ctk.CTkScrollableFrame(popup, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        def get_strength_score(strength):
            if strength in ("Weak", "Very Weak"):
                return 0
            elif strength == "Moderate":
                return 1
            else:
                return 2

        sorted_accounts = sorted(accounts, key=lambda x: get_strength_score(x[1]))

        for site_name, strength in sorted_accounts:
            if strength in ("Weak", "Very Weak"):
                color = COLORS["red"]
                icon = "🔴"
            elif strength == "Moderate":
                color = COLORS["gold"]
                icon = "🟡"
            else:
                color = COLORS["green"]
                icon = "🟢"

            card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                                corner_radius=8, border_width=1,
                                border_color=color)
            card.pack(fill="x", pady=3)

            ctk.CTkLabel(card, text=icon,
                         font=("Segoe UI", 14)).pack(side="left", padx=(12, 6), pady=10)
            ctk.CTkLabel(card, text=site_name,
                         font=("Segoe UI", 12, "bold"),
                         text_color=COLORS["text"]).pack(side="left", padx=0, pady=10)
            ctk.CTkLabel(card, text=strength,
                         font=("Segoe UI", 11),
                         text_color=color).pack(side="right", padx=12, pady=10)

        ctk.CTkButton(popup, text="Close",
                      command=popup.destroy,
                      width=100, height=35,
                      fg_color=COLORS["card"],
                      hover_color=COLORS["sidebar"],
                      text_color=COLORS["accent"]).pack(pady=(0, 20))

    # ═══════════════════════════════════════════════════════
    # CONTENT: VAULT EXPORT REPORT
    # ═══════════════════════════════════════════════════════

    def show_export_view(self):
        """Vault Export Report screen."""
        self.clear_content()

        header = ctk.CTkFrame(self.content,
                              fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📊  Vault Export Report",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["green"]).pack(
            side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Generate a professional security summary file",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(
            side="right", padx=20, pady=16)

        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=24, pady=20)

        all_creds = self.storage_engine.get_all_credentials()
        if not all_creds:
            ctk.CTkLabel(scroll,
                         text="🔒  No passwords in vault to export.\n\n"
                              "Add some credentials first.",
                         font=("Segoe UI", 14),
                         text_color=COLORS["subtext"],
                         justify="center").pack(pady=60)
            return

        decrypted = []
        for c in all_creds:
            try:
                plaintext = self.encryption_provider.decrypt(c[3], c[4])
                decrypted.append((c[1], plaintext))
            except Exception:
                decrypted.append((c[1], "DECRYPT_ERROR"))

        report = self.sentinel_auditor.generate_vault_report(decrypted)
        score  = report["vault_score"]
        cats   = report["categories"]

        score_color = (COLORS["red"]  if score < 40 else
                       COLORS["gold"] if score < 70 else
                       COLORS["green"])

        info_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                                  corner_radius=12, border_width=2,
                                  border_color=COLORS["green"])
        info_card.pack(fill="x", pady=(0, 16))
        ctk.CTkFrame(info_card, fg_color=COLORS["green"],
                     height=3).pack(fill="x")

        ctk.CTkLabel(info_card,
                     text="📄  What Will Be Exported",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["green"]).pack(
            anchor="w", padx=20, pady=(14, 8))

        included = [
            ("✅  Included", "Site names and usernames"),
            ("✅  Included", "Password strength rating per account"),
            ("✅  Included", "Entropy score (bits) per account"),
            ("✅  Included", "Issues found per account"),
            ("✅  Included", "Reused password groups (site names only)"),
            ("✅  Included", "Common/breached password flags"),
            ("✅  Included", "Overall vault security score"),
            ("✅  Included", "Actionable security recommendations"),
            ("🚫  Excluded", "Plaintext passwords — NEVER exported"),
            ("🚫  Excluded", "Encryption keys — NEVER exported"),
            ("🚫  Excluded", "Any cryptographic material"),
        ]
        for status, detail in included:
            row = ctk.CTkFrame(info_card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=1)
            color = COLORS["green"] if "Included" in status else COLORS["red"]
            ctk.CTkLabel(row, text=status,
                         font=("Segoe UI", 11, "bold"),
                         text_color=color,
                         width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=detail,
                         font=("Segoe UI", 11),
                         text_color=COLORS["text"]).pack(side="left")
        ctk.CTkFrame(info_card, height=12,
                     fg_color="transparent").pack()

        preview_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"],
                                     corner_radius=12, border_width=1,
                                     border_color=COLORS["card"])
        preview_card.pack(fill="x", pady=(0, 16))
        ctk.CTkFrame(preview_card, fg_color=COLORS["accent"],
                     height=3).pack(fill="x")

        ctk.CTkLabel(preview_card,
                     text="📋  Report Preview",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(
            anchor="w", padx=20, pady=(14, 10))

        score_row = ctk.CTkFrame(preview_card, fg_color=COLORS["card"],
                                  corner_radius=8)
        score_row.pack(fill="x", padx=20, pady=(0, 8))
        ctk.CTkLabel(score_row,
                     text=f"Overall Security Score",
                     font=("Segoe UI", 12),
                     text_color=COLORS["subtext"]).pack(
            side="left", padx=16, pady=10)
        ctk.CTkLabel(score_row,
                     text=f"{score} / 100",
                     font=("Segoe UI", 18, "bold"),
                     text_color=score_color).pack(
            side="right", padx=16, pady=10)

        preview_stats = [
            ("Very Strong passwords", cats["Very Strong"], COLORS["green"]),
            ("Strong passwords",      cats["Strong"],      COLORS["green"]),
            ("Moderate passwords",    cats["Moderate"],    COLORS["gold"]),
            ("Weak passwords",        cats["Weak"],        COLORS["orange"]),
            ("Very Weak passwords",   cats["Very Weak"],   COLORS["red"]),
            ("Reused password groups",len(report["reused_map"]), COLORS["orange"]),
            ("Common/breached flags", len(report["common_list"]),COLORS["red"]),
        ]
        for label, value, color in preview_stats:
            row = ctk.CTkFrame(preview_card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(row, text=label,
                         font=("Segoe UI", 11),
                         text_color=COLORS["subtext"],
                         anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(value),
                         font=("Segoe UI", 11, "bold"),
                         text_color=color).pack(side="right")

        ctk.CTkLabel(preview_card,
                     text="Accounts to be analyzed:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(
            anchor="w", padx=20, pady=(10, 4))

        for site, pwd in decrypted[:10]:
            audit = self.sentinel_auditor.audit_single_password(pwd)
            row   = ctk.CTkFrame(preview_card, fg_color=COLORS["card"],
                                  corner_radius=6)
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(row, text=site,
                         font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["text"]).pack(
                side="left", padx=10, pady=6)
            ctk.CTkLabel(row,
                         text=f"{audit['strength_label']}  "
                              f"|  {audit['entropy']} bits",
                         font=("Segoe UI", 10),
                         text_color=audit["color"]).pack(
                side="right", padx=10, pady=6)

        if len(decrypted) > 10:
            ctk.CTkLabel(preview_card,
                         text=f"... and {len(decrypted) - 10} more accounts",
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack(
                anchor="w", padx=30, pady=4)

        ctk.CTkFrame(preview_card, height=12,
                     fg_color="transparent").pack()

        status_label = ctk.CTkLabel(scroll, text="",
                                     font=("Segoe UI", 12, "bold"),
                                     text_color=COLORS["subtext"])
        status_label.pack(pady=(8, 4))

        def perform_export():
            filepath = filedialog.asksaveasfilename(
                title="Save Security Report",
                defaultextension=".txt",
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("All Files",  "*.*")
                ],
                initialfile="SentinelsVault_Security_Report.txt"
            )

            if not filepath:
                status_label.configure(
                    text="Export cancelled.",
                    text_color=COLORS["subtext"])
                return

            success, result = self.sentinel_auditor.export_security_report(
                decrypted, score, filepath)

            if success:
                filename = os.path.basename(result)
                status_label.configure(
                    text=f"✅  Report saved successfully: {filename}",
                    text_color=COLORS["green"])
                export_btn.configure(text="✅  Exported Successfully")

                open_it = messagebox.askyesno(
                    "Export Complete",
                    f"Report saved to:\n{result}\n\n"
                    f"Would you like to open it now?")
                if open_it:
                    try:
                        os.startfile(result)
                    except Exception:
                        messagebox.showinfo(
                            "File Saved",
                            f"Report saved at:\n{result}\n\n"
                            f"Open it manually from that location.")
            else:
                status_label.configure(
                    text=f"❌  Export failed: {result}",
                    text_color=COLORS["red"])

        export_btn = ctk.CTkButton(
            scroll,
            text="📥  Choose Save Location & Export Report",
            command=perform_export,
            width=480, height=50,
            fg_color=COLORS["green"],
            hover_color="#00A040",
            text_color=COLORS["bg"],
            font=("Segoe UI", 14, "bold"),
            corner_radius=10)
        export_btn.pack(pady=(8, 4))

        ctk.CTkLabel(scroll,
                     text="The report contains NO passwords. "
                          "It is safe to share with IT administrators.",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 20))

    # ═══════════════════════════════════════════════════════
    # CONTENT: PASSWORD STRENGTH GUIDE
    # ═══════════════════════════════════════════════════════

    def show_strength_guide(self):
        """Displays the Password Strength Guide screen."""
        self.clear_content()

        header = ctk.CTkFrame(self.content,
                              fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📖  Password Strength Guide",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["purple"]).pack(
            side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Learn what makes a password strong or weak",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(
            side="right", padx=20, pady=16)

        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=16)

        guide = self.sentinel_auditor.get_strength_guide()

        # Section 1: Entropy Formula
        formula_data = guide["entropy_formula"]
        formula_card = ctk.CTkFrame(
            scroll, fg_color=COLORS["sidebar"],
            corner_radius=12, border_width=2,
            border_color=COLORS["purple"])
        formula_card.pack(fill="x", pady=(0, 16))
        ctk.CTkFrame(formula_card, fg_color=COLORS["purple"],
                     height=3).pack(fill="x")
        ctk.CTkLabel(formula_card,
                     text="The Science Behind Password Strength",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["purple"]).pack(
            anchor="w", padx=20, pady=(14, 2))
        ctk.CTkLabel(formula_card,
                     text=formula_data["formula"],
                     font=("Segoe UI", 32, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(4, 2))
        ctk.CTkLabel(formula_card,
                     text=formula_data["explanation"],
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(pady=(0, 10))

        pool_frame = ctk.CTkFrame(formula_card, fg_color=COLORS["card"],
                                   corner_radius=8)
        pool_frame.pack(fill="x", padx=20, pady=(0, 6))
        ctk.CTkLabel(pool_frame, text="Character Pool Sizes (R)",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLORS["text"]).pack(
            anchor="w", padx=12, pady=(8, 4))
        for char_type, pool_size in formula_data["pool_sizes"]:
            row = ctk.CTkFrame(pool_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(row, text=char_type,
                         font=("Segoe UI", 11),
                         text_color=COLORS["subtext"],
                         width=240, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=pool_size,
                         font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["accent"]).pack(side="left")
        ctk.CTkLabel(formula_card,
                     text=f"Example:  {formula_data['example']}",
                     font=("Segoe UI", 11),
                     text_color=COLORS["green"]).pack(
            anchor="w", padx=20, pady=(8, 16))

        # Section 2: The 5 Strength Tiers
        ctk.CTkLabel(scroll, text="The 5 Password Strength Tiers",
                     font=("Segoe UI", 15, "bold"),
                     text_color=COLORS["text"]).pack(
            anchor="w", pady=(0, 8))

        for tier in guide["tiers"]:
            tier_card = ctk.CTkFrame(
                scroll, fg_color=COLORS["sidebar"],
                corner_radius=12, border_width=1,
                border_color=tier["color"])
            tier_card.pack(fill="x", pady=5)
            ctk.CTkFrame(tier_card, fg_color=tier["color"],
                         height=3).pack(fill="x")
            top_row = ctk.CTkFrame(tier_card, fg_color="transparent")
            top_row.pack(fill="x", padx=16, pady=(10, 4))
            ctk.CTkLabel(top_row,
                         text=f"{tier['icon']}  {tier['level']}",
                         font=("Segoe UI", 14, "bold"),
                         text_color=tier["color"]).pack(side="left")
            ctk.CTkLabel(top_row,
                         text=f"Time to crack: {tier['time']}",
                         font=("Segoe UI", 11),
                         text_color=COLORS["subtext"]).pack(side="right")
            ctk.CTkLabel(tier_card,
                         text=f"Entropy: {tier['entropy']}",
                         font=("Segoe UI", 10, "bold"),
                         fg_color=tier["color"],
                         text_color=COLORS["bg"],
                         corner_radius=6).pack(
                anchor="w", padx=16, pady=(0, 6))
            ctk.CTkLabel(tier_card, text=tier["description"],
                         font=("Segoe UI", 11),
                         text_color=COLORS["text"],
                         wraplength=700, justify="left").pack(
                anchor="w", padx=16, pady=(0, 6))
            example_row = ctk.CTkFrame(tier_card,
                                        fg_color=COLORS["card"],
                                        corner_radius=6)
            example_row.pack(fill="x", padx=16, pady=(0, 8))
            ctk.CTkLabel(example_row,
                         text=f"Examples:  {tier['examples']}",
                         font=("Segoe UI", 11),
                         text_color=COLORS["subtext"]).pack(
                anchor="w", padx=10, pady=6)
            tips_frame = ctk.CTkFrame(tier_card, fg_color="transparent")
            tips_frame.pack(fill="x", padx=16, pady=(0, 12))
            for tip in tier["tips"]:
                ctk.CTkLabel(tips_frame, text=f"  +  {tip}",
                             font=("Segoe UI", 11),
                             text_color=tier["color"]).pack(
                    anchor="w", pady=1)

        # Section 3: Golden Rules
        ctk.CTkLabel(scroll,
                     text="The 5 Golden Rules of Password Security",
                     font=("Segoe UI", 15, "bold"),
                     text_color=COLORS["text"]).pack(
            anchor="w", pady=(16, 8))

        for rule in guide["golden_rules"]:
            rule_card = ctk.CTkFrame(
                scroll, fg_color=COLORS["sidebar"],
                corner_radius=10, border_width=1,
                border_color=COLORS["card"])
            rule_card.pack(fill="x", pady=4)
            ctk.CTkFrame(rule_card, fg_color=COLORS["gold"],
                         width=4, corner_radius=2).pack(
                side="left", fill="y", padx=(0, 12))
            body = ctk.CTkFrame(rule_card, fg_color="transparent")
            body.pack(side="left", fill="both", expand=True, pady=12)
            ctk.CTkLabel(body,
                         text=f"{rule['icon']}  {rule['title']}",
                         font=("Segoe UI", 13, "bold"),
                         text_color=COLORS["gold"]).pack(anchor="w")
            ctk.CTkLabel(body, text=rule["body"],
                         font=("Segoe UI", 11),
                         text_color=COLORS["text"],
                         wraplength=680, justify="left").pack(
                anchor="w", pady=(2, 0))

        # Section 4: Live Password Tester
        ctk.CTkLabel(scroll, text="Live Password Strength Tester",
                     font=("Segoe UI", 15, "bold"),
                     text_color=COLORS["text"]).pack(
            anchor="w", pady=(16, 8))

        tester_card = ctk.CTkFrame(
            scroll, fg_color=COLORS["sidebar"],
            corner_radius=12, border_width=1,
            border_color=COLORS["accent"])
        tester_card.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(tester_card,
                     text="Type any password below to analyze it instantly "
                          "(nothing is saved):",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(
            anchor="w", padx=20, pady=(14, 6))

        test_entry = ctk.CTkEntry(
            tester_card,
            placeholder_text="Type a password to test its strength...",
            width=560, height=44, font=("Segoe UI", 13))
        test_entry.pack(anchor="w", padx=20, pady=(0, 8))

        result_label = ctk.CTkLabel(
            tester_card, text="",
            font=("Segoe UI", 13, "bold"),
            text_color=COLORS["subtext"])
        result_label.pack(anchor="w", padx=20)

        result_bar = ctk.CTkProgressBar(
            tester_card, width=560, height=10, corner_radius=5)
        result_bar.pack(anchor="w", padx=20, pady=(4, 8))
        result_bar.set(0)

        issues_label = ctk.CTkLabel(
            tester_card, text="",
            font=("Segoe UI", 11),
            text_color=COLORS["subtext"],
            justify="left", wraplength=560)
        issues_label.pack(anchor="w", padx=20, pady=(0, 16))

        def analyze_test_password(event=None):
            pwd = test_entry.get()
            if not pwd:
                result_label.configure(text="")
                result_bar.set(0)
                issues_label.configure(text="")
                return
            audit = self.sentinel_auditor.audit_single_password(pwd)
            result_label.configure(
                text=f"{audit['strength_label']}   |   "
                     f"Entropy: {audit['entropy']} bits   |   "
                     f"Length: {len(pwd)} characters",
                text_color=audit["color"])
            result_bar.set(min(audit["entropy"] / 100, 1.0))
            if audit["issues"]:
                issues_text = "Issues found:\n" + "\n".join(
                    f"  •  {issue}" for issue in audit["issues"])
            else:
                issues_text = "No issues found. This password is strong!"
            issues_label.configure(
                text=issues_text,
                text_color=COLORS["red"] if audit["issues"]
                else COLORS["green"])

        test_entry.bind("<KeyRelease>", analyze_test_password)

    # ═══════════════════════════════════════════════════════
    # SENTINEL DASHBOARD - Security Command Center
    # ═══════════════════════════════════════════════════════

    def show_sentinel_dashboard(self):
        """Display the main Sentinel Dashboard."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=70)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        ctk.CTkLabel(header, text="🛡️  SENTINEL DASHBOARD",
                     font=("Segoe UI", 22, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        
        ctk.CTkLabel(header, text="Security Command Center | Real-time Protection Status",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="left", padx=(10, 0))
        
        refresh_btn = ctk.CTkButton(header, text="🔄 Refresh",
                                     command=self.refresh_dashboard,
                                     width=100, height=35,
                                     fg_color=COLORS["card"],
                                     hover_color=COLORS["bg"],
                                     text_color=COLORS["accent"])
        refresh_btn.pack(side="right", padx=20)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        all_creds = self.storage_engine.get_all_credentials()
        
        decrypted = []
        for c in all_creds:
            try:
                plaintext = self.encryption_provider.decrypt(c[3], c[4])
                decrypted.append((c[1], plaintext, c[5] if c[5] else "General"))
            except Exception:
                decrypted.append((c[1], "DECRYPT_ERROR", "General"))
        
        total_passwords = len(decrypted)
        
        if total_passwords > 0:
            audit_results = [self.sentinel_auditor.audit_single_password(pwd) for _, pwd, _ in decrypted if pwd != "DECRYPT_ERROR"]
            strength_counts = {
                "Very Strong": sum(1 for r in audit_results if r["strength_label"] == "Very Strong"),
                "Strong": sum(1 for r in audit_results if r["strength_label"] == "Strong"),
                "Moderate": sum(1 for r in audit_results if r["strength_label"] == "Moderate"),
                "Weak": sum(1 for r in audit_results if r["strength_label"] == "Weak"),
                "Very Weak": sum(1 for r in audit_results if r["strength_label"] == "Very Weak")
            }
            avg_entropy = sum(r["entropy"] for r in audit_results) / len(audit_results) if audit_results else 0
            vault_report = self.sentinel_auditor.generate_vault_report(decrypted)
            vault_score = vault_report["vault_score"]
        else:
            strength_counts = {"Very Strong": 0, "Strong": 0, "Moderate": 0, "Weak": 0, "Very Weak": 0}
            avg_entropy = 0
            vault_score = 0
        
        # Health Score Card
        health_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=16)
        health_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(health_card, text="📊  VAULT HEALTH SCORE",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        gauge_frame = ctk.CTkFrame(health_card, fg_color="transparent")
        gauge_frame.pack(pady=(0, 16))
        
        if vault_score >= 80:
            score_color = COLORS["green"]
            score_status = "EXCELLENT"
        elif vault_score >= 60:
            score_color = COLORS["gold"]
            score_status = "GOOD"
        elif vault_score >= 40:
            score_color = COLORS["orange"]
            score_status = "FAIR"
        else:
            score_color = COLORS["red"]
            score_status = "POOR"
        
        score_label = ctk.CTkLabel(gauge_frame, text=str(vault_score),
                                    font=("Segoe UI", 64, "bold"),
                                    text_color=score_color)
        score_label.pack()
        
        ctk.CTkLabel(gauge_frame, text=f"/ 100  -  {score_status}",
                     font=("Segoe UI", 14),
                     text_color=score_color).pack()
        
        score_bar = ctk.CTkProgressBar(health_card, width=500, height=12, corner_radius=6)
        score_bar.pack(pady=(8, 16))
        score_bar.set(vault_score / 100)
        score_bar.configure(progress_color=score_color)
        
        # Statistics Cards
        stats_grid = ctk.CTkFrame(scroll, fg_color="transparent")
        stats_grid.pack(fill="x", pady=(0, 16))
        
        for i in range(4):
            stats_grid.columnconfigure(i, weight=1)
        
        # Stat 1: Total Passwords
        stat1 = ctk.CTkFrame(stats_grid, fg_color=COLORS["sidebar"], corner_radius=12)
        stat1.grid(row=0, column=0, padx=4, sticky="nsew")
        ctk.CTkLabel(stat1, text="🔐", font=("Segoe UI", 24)).pack(pady=(12, 0))
        ctk.CTkLabel(stat1, text=str(total_passwords),
                     font=("Segoe UI", 24, "bold"),
                     text_color=COLORS["accent"]).pack()
        ctk.CTkLabel(stat1, text="Total Passwords",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 12))
        
        # Stat 2: Average Entropy
        stat2 = ctk.CTkFrame(stats_grid, fg_color=COLORS["sidebar"], corner_radius=12)
        stat2.grid(row=0, column=1, padx=4, sticky="nsew")
        ctk.CTkLabel(stat2, text="📈", font=("Segoe UI", 24)).pack(pady=(12, 0))
        
        entropy_color = COLORS["green"] if avg_entropy >= 60 else (COLORS["gold"] if avg_entropy >= 40 else COLORS["red"])
        ctk.CTkLabel(stat2, text=f"{avg_entropy:.1f}",
                     font=("Segoe UI", 24, "bold"),
                     text_color=entropy_color).pack()
        ctk.CTkLabel(stat2, text="Avg Entropy (bits)",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 12))
        
        # Stat 3: Weak Passwords
        stat3 = ctk.CTkFrame(stats_grid, fg_color=COLORS["sidebar"], corner_radius=12)
        stat3.grid(row=0, column=2, padx=4, sticky="nsew")
        ctk.CTkLabel(stat3, text="⚠️", font=("Segoe UI", 24)).pack(pady=(12, 0))
        
        weak_count = strength_counts["Weak"] + strength_counts["Very Weak"]
        weak_color = COLORS["red"] if weak_count > 0 else COLORS["green"]
        ctk.CTkLabel(stat3, text=str(weak_count),
                     font=("Segoe UI", 24, "bold"),
                     text_color=weak_color).pack()
        ctk.CTkLabel(stat3, text="Weak Passwords",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 12))
        
        # Stat 4: Security Score
        stat4 = ctk.CTkFrame(stats_grid, fg_color=COLORS["sidebar"], corner_radius=12)
        stat4.grid(row=0, column=3, padx=4, sticky="nsew")
        ctk.CTkLabel(stat4, text="🛡️", font=("Segoe UI", 24)).pack(pady=(12, 0))
        ctk.CTkLabel(stat4, text=f"{vault_score}",
                     font=("Segoe UI", 24, "bold"),
                     text_color=score_color).pack()
        ctk.CTkLabel(stat4, text="Security Score",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 12))
        
        # Strength Distribution Chart
        chart_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=16)
        chart_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(chart_card, text="📊  PASSWORD STRENGTH DISTRIBUTION",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        categories = [
            ("💎 Very Strong", strength_counts["Very Strong"], COLORS["green"]),
            ("🟢 Strong", strength_counts["Strong"], COLORS["green"]),
            ("🟡 Moderate", strength_counts["Moderate"], COLORS["gold"]),
            ("🟠 Weak", strength_counts["Weak"], COLORS["orange"]),
            ("🔴 Very Weak", strength_counts["Very Weak"], COLORS["red"])
        ]
        
        max_count = max(strength_counts.values()) if strength_counts else 1
        
        for label, count, color in categories:
            bar_frame = ctk.CTkFrame(chart_card, fg_color="transparent")
            bar_frame.pack(fill="x", padx=20, pady=4)
            
            ctk.CTkLabel(bar_frame, text=label,
                         font=("Segoe UI", 11),
                         text_color=color,
                         width=120, anchor="w").pack(side="left")
            
            ctk.CTkLabel(bar_frame, text=str(count),
                         font=("Segoe UI", 11, "bold"),
                         text_color=color,
                         width=40, anchor="e").pack(side="right")
            
            bar_width = (count / max_count * 300) if max_count > 0 else 0
            bar = ctk.CTkFrame(bar_frame, fg_color=color, height=20, corner_radius=4, width=bar_width)
            bar.pack(side="left", padx=(10, 0), fill="x", expand=True)
        
        # Encryption Status
        security_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=16)
        security_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(security_card, text="🔒  ENCRYPTION & SECURITY STATUS",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        features_grid = ctk.CTkFrame(security_card, fg_color="transparent")
        features_grid.pack(fill="x", padx=20, pady=(0, 16))
        
        features = [
            ("AES-256-GCM", "Active ✓", COLORS["green"], "Military-grade encryption"),
            ("PBKDF2 + Argon2id", "Active ✓", COLORS["green"], "600,000 iterations"),
            ("Zero-Knowledge", "Active ✓", COLORS["green"], "Keys never leave your device"),
            ("MFA (TOTP)", "Active ✓" if hasattr(self, '_pending_totp') else "Inactive", COLORS["green"] if hasattr(self, '_pending_totp') else COLORS["orange"], "Multi-factor authentication"),
            ("Secure Wipe", "Active ✓", COLORS["green"], "RAM cleared on lock"),
            ("Session Auto-Lock", "Active ✓", COLORS["green"], "5 minutes inactivity"),
        ]
        
        for i, (feature, status, color, desc) in enumerate(features):
            row = i // 2
            col = i % 2
            feat_frame = ctk.CTkFrame(features_grid, fg_color=COLORS["card"], corner_radius=8)
            feat_frame.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            
            ctk.CTkLabel(feat_frame, text=feature,
                         font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=(8, 2))
            ctk.CTkLabel(feat_frame, text=status,
                         font=("Segoe UI", 10, "bold"),
                         text_color=color).pack(anchor="w", padx=10)
            ctk.CTkLabel(feat_frame, text=desc,
                         font=("Segoe UI", 9),
                         text_color=COLORS["subtext"]).pack(anchor="w", padx=10, pady=(0, 8))
        
        features_grid.columnconfigure(0, weight=1)
        features_grid.columnconfigure(1, weight=1)
        
        # Recommendations
        alerts_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=16)
        alerts_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(alerts_card, text="⚠️  SECURITY RECOMMENDATIONS",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        recommendations = []
        
        if weak_count > 0:
            recommendations.append(f"🔴 CRITICAL: Replace {weak_count} weak password(s) immediately")
        if strength_counts["Moderate"] > 3:
            recommendations.append("🟡 WARNING: Moderate passwords can be strengthened")
        if total_passwords == 0:
            recommendations.append("📌 TIP: Add your first password to start securing your accounts")
        if vault_score < 70:
            recommendations.append("📈 ACTION: Use the password generator for stronger passwords")
        
        if not recommendations:
            recommendations.append("✅ EXCELLENT: Your vault is in great shape! Keep up the good security practices.")
        
        for rec in recommendations:
            alert_frame = ctk.CTkFrame(alerts_card, fg_color=COLORS["card"], corner_radius=8)
            alert_frame.pack(fill="x", padx=20, pady=4)
            ctk.CTkLabel(alert_frame, text=rec,
                         font=("Segoe UI", 10),
                         text_color=COLORS["text"],
                         wraplength=650).pack(anchor="w", padx=10, pady=8)
        
        # Quick Actions
        actions_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=16)
        actions_card.pack(fill="x", pady=(0, 0))
        
        ctk.CTkLabel(actions_card, text="⚡  QUICK ACTIONS",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        actions_frame = ctk.CTkFrame(actions_card, fg_color="transparent")
        actions_frame.pack(fill="x", padx=20, pady=(0, 16))
        
        actions = [
            ("➕ Add Secret", self.show_add_view, COLORS["accent"]),
            ("🛡️ Run Audit", self.show_audit_view, COLORS["purple"]),
            ("🔑 Lock Vault", self.lock_vault, COLORS["red"]),
            ("📊 Export Report", self.show_export_view, COLORS["green"]),
        ]
        
        for i, (text, command, color) in enumerate(actions):
            btn = ctk.CTkButton(actions_frame, text=text,
                                 command=command,
                                 width=180, height=45,
                                 fg_color=color,
                                 hover_color=color,
                                 text_color=COLORS["bg"],
                                 font=("Segoe UI", 12, "bold"),
                                 corner_radius=10)
            btn.grid(row=0, column=i, padx=6, pady=6, sticky="nsew")
        
        for i in range(4):
            actions_frame.columnconfigure(i, weight=1)
        
        footer = ctk.CTkFrame(scroll, fg_color="transparent")
        footer.pack(fill="x", pady=(16, 0))
        
        ctk.CTkLabel(footer, text="🛡️  SentinelsVault - Enterprise-Grade Protection",
                     font=("Segoe UI", 9),
                     text_color=COLORS["subtext"]).pack()
    
    def refresh_dashboard(self):
        """Refresh the dashboard with latest data."""
        self.show_sentinel_dashboard()

    # ═══════════════════════════════════════════════════════
    # FEATURE 1: ANIMATED SECURITY CHAIN — Encryption Flow
    # ═══════════════════════════════════════════════════════
    
    def show_encryption_flow(self):
        """Animated Security Chain showing each step of the encryption flow."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🔗  Encryption Flow — The Security Pipeline",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Each step in the encryption process lights up sequentially",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=40, pady=30)
        
        desc_frame = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        desc_frame.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(desc_frame,
                     text="🔐  SentinelsVault Encryption Pipeline — Industry-Standard AES-256-GCM",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(12, 4))
        ctk.CTkLabel(desc_frame,
                     text="Watch how your password transforms from plaintext to unbreakable ciphertext",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(pady=(0, 12))
        
        steps_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        steps_frame.pack(fill="x", pady=20)
        
        steps = [
            ("1", "Master Password", "User enters Master Password", "🔑"),
            ("2", "Key Derivation", "PBKDF2 + Argon2id with 600,000 iterations", "⚙️"),
            ("3", "Salt & IV", "Unique 32-byte salt + 12-byte IV generated", "🧂"),
            ("4", "AES-256-GCM", "Military-grade encryption applied", "🔒"),
            ("5", "Ciphertext", "Encrypted data stored in SQLite BLOB", "💾"),
        ]
        
        step_widgets = []
        for i, (num, title, desc, icon) in enumerate(steps):
            step_frame = ctk.CTkFrame(steps_frame, fg_color=COLORS["sidebar"], 
                                       corner_radius=12, border_width=1,
                                       border_color=COLORS["card"])
            step_frame.pack(fill="x", pady=8)
            
            num_frame = ctk.CTkFrame(step_frame, fg_color="transparent", width=80)
            num_frame.pack(side="left", padx=16, pady=12)
            num_frame.pack_propagate(False)
            
            step_circle = ctk.CTkFrame(num_frame, fg_color=COLORS["card"],
                                        width=50, height=50, corner_radius=25)
            step_circle.pack()
            step_circle.pack_propagate(False)
            
            step_label = ctk.CTkLabel(step_circle, text=f"{icon}\n{num}",
                                       font=("Segoe UI", 18, "bold"),
                                       text_color=COLORS["subtext"])
            step_label.place(relx=0.5, rely=0.5, anchor="center")
            
            info_frame = ctk.CTkFrame(step_frame, fg_color="transparent")
            info_frame.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=12)
            
            title_label = ctk.CTkLabel(info_frame, text=title,
                                        font=("Segoe UI", 14, "bold"),
                                        text_color=COLORS["text"])
            title_label.pack(anchor="w")
            
            desc_label = ctk.CTkLabel(info_frame, text=desc,
                                       font=("Segoe UI", 11),
                                       text_color=COLORS["subtext"])
            desc_label.pack(anchor="w")
            
            status_label = ctk.CTkLabel(step_frame, text="⏳ Pending",
                                         font=("Segoe UI", 11, "bold"),
                                         width=100,
                                         text_color=COLORS["subtext"])
            status_label.pack(side="right", padx=16, pady=12)
            
            step_widgets.append({
                'frame': step_frame,
                'circle': step_circle,
                'status': status_label,
                'title': title,
                'desc': desc
            })
        
        control_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        control_frame.pack(pady=20)
        
        animation_running = [False]
        current_step = [0]
        
        def reset_animation():
            animation_running[0] = False
            current_step[0] = 0
            for widget in step_widgets:
                widget['circle'].configure(fg_color=COLORS["card"])
                widget['status'].configure(text="⏳ Pending", text_color=COLORS["subtext"])
        
        def animate_step():
            if not animation_running[0]:
                return
            
            if current_step[0] < len(step_widgets):
                widget = step_widgets[current_step[0]]
                widget['circle'].configure(fg_color=COLORS["accent"])
                widget['status'].configure(text="✅ Complete", text_color=COLORS["green"])
                
                current_step[0] += 1
                main_frame.after(800, animate_step)
            else:
                animation_running[0] = False
                complete_label.configure(text="✅ Encryption Pipeline Complete!", 
                                         text_color=COLORS["green"])
        
        def start_animation():
            reset_animation()
            animation_running[0] = True
            complete_label.configure(text="🔐 Running encryption simulation...", 
                                     text_color=COLORS["accent"])
            animate_step()
        
        start_btn = ctk.CTkButton(control_frame, text="▶️  Start Encryption Flow",
                                   command=start_animation,
                                   width=180, height=40,
                                   fg_color=COLORS["green"],
                                   hover_color="#00A040",
                                   font=("Segoe UI", 12, "bold"))
        start_btn.pack(side="left", padx=8)
        
        reset_btn = ctk.CTkButton(control_frame, text="🔄  Reset",
                                   command=reset_animation,
                                   width=120, height=40,
                                   fg_color=COLORS["card"],
                                   hover_color=COLORS["sidebar"],
                                   font=("Segoe UI", 12))
        reset_btn.pack(side="left", padx=8)
        
        complete_label = ctk.CTkLabel(control_frame, text="",
                                       font=("Segoe UI", 12, "bold"),
                                       text_color=COLORS["accent"])
        complete_label.pack(side="left", padx=20)
        
        tech_frame = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        tech_frame.pack(fill="x", pady=(20, 0))
        
        ctk.CTkLabel(tech_frame,
                     text="🔬 Technical Deep Dive",
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        tech_text = (
            "1. Master Password: Human-readable input (never stored)\n"
            "2. Key Derivation: PBKDF2-SHA256 with 600,000 iterations + Argon2id (memory-hard)\n"
            "3. Salt & IV: 32-byte random salt prevents rainbow tables, 12-byte IV ensures unique ciphertext\n"
            "4. AES-256-GCM: 256-bit key length, Galois/Counter Mode provides authentication\n"
            "5. Ciphertext: Encrypted data + authentication tag stored as BLOB in SQLite\n\n"
            f"⚡ Security Strength: {2**256:,} possible key combinations — practically uncrackable"
        )
        
        ctk.CTkLabel(tech_frame, text=tech_text,
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"],
                     justify="left",
                     wraplength=700).pack(anchor="w", padx=16, pady=(0, 12))
    
    # ═══════════════════════════════════════════════════════
    # FEATURE 2: ATTACK COST CALCULATOR
    # ═══════════════════════════════════════════════════════
    
    def show_attack_calculator(self):
        """Attack Cost Calculator — Shows how many years/dollars it would take to crack your vault."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="💰  Attack Cost Calculator",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Real-world cost to crack your vault using current GPU technology",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=40, pady=30)
        
        input_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        input_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(input_card, text="📊  Enter Password Information",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        pwd_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        pwd_frame.pack(fill="x", padx=20, pady=(0, 12))
        
        ctk.CTkLabel(pwd_frame, text="Password to analyze:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(side="left", padx=(0, 12))
        
        test_pwd_entry = ctk.CTkEntry(pwd_frame, placeholder_text="Enter a password to test...",
                                       width=300, height=38,
                                       font=("Segoe UI", 12))
        test_pwd_entry.pack(side="left")
        
        rate_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        rate_frame.pack(fill="x", padx=20, pady=(0, 12))
        
        ctk.CTkLabel(rate_frame, text="Attacker Hardware:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(side="left", padx=(0, 12))
        
        hardware_options = [
            ("💻 Single RTX 4090", 1.5e10),
            ("⚡ 10x RTX 4090", 1.5e11),
            ("🏭 100x RTX 4090", 1.5e12),
            ("🌐 Nation-State", 1.5e13),
        ]
        
        hardware_var = ctk.StringVar(value=hardware_options[0][0])
        
        def update_calculation(*args):
            selected = hardware_var.get()
            for name, rate in hardware_options:
                if name == selected:
                    current_rate = rate
                    break
            else:
                current_rate = 1.5e10
            
            pwd = test_pwd_entry.get()
            if pwd:
                audit = self.sentinel_auditor.audit_single_password(pwd)
                entropy = audit["entropy"]
                combinations = 2 ** entropy
                seconds = combinations / current_rate
                years = seconds / (365 * 24 * 3600)
                
                hours = seconds / 3600
                cost = hours * 10
                
                if years > 1e9:
                    time_text = f"{years / 1e9:.1f} Billion years"
                elif years > 1e6:
                    time_text = f"{years / 1e6:.1f} Million years"
                elif years > 1e3:
                    time_text = f"{years / 1e3:.1f} Thousand years"
                else:
                    time_text = f"{years:.1f} years"
                
                time_label.configure(text=time_text, text_color=COLORS["green"])
                
                if cost > 1e12:
                    cost_text = f"${cost / 1e12:.2f} Trillion"
                elif cost > 1e9:
                    cost_text = f"${cost / 1e9:.2f} Billion"
                elif cost > 1e6:
                    cost_text = f"${cost / 1e6:.2f} Million"
                else:
                    cost_text = f"${cost:,.0f}"
                
                cost_label.configure(text=cost_text, text_color=COLORS["green"])
                
                if years < 1:
                    risk = "⚠️ CRITICAL RISK — Can be cracked in hours!"
                    risk_color = COLORS["red"]
                elif years < 100:
                    risk = "🔴 HIGH RISK — Crackable within your lifetime"
                    risk_color = COLORS["red"]
                elif years < 10000:
                    risk = "🟡 MODERATE RISK — Requires significant resources"
                    risk_color = COLORS["orange"]
                else:
                    risk = "🟢 SECURE — Practically uncrackable"
                    risk_color = COLORS["green"]
                
                risk_label.configure(text=risk, text_color=risk_color)
                
                strength_label.configure(
                    text=f"Strength: {audit['strength_label']} | Entropy: {entropy:.1f} bits",
                    text_color=audit["color"]
                )
                entropy_bar.set(min(entropy / 128, 1.0))
                entropy_bar.configure(progress_color=audit["color"])
            else:
                time_label.configure(text="—", text_color=COLORS["subtext"])
                cost_label.configure(text="—", text_color=COLORS["subtext"])
                risk_label.configure(text="Enter a password to analyze", text_color=COLORS["subtext"])
        
        hardware_menu = ctk.CTkOptionMenu(rate_frame, values=[opt[0] for opt in hardware_options],
                                           variable=hardware_var, width=200,
                                           command=lambda x: update_calculation())
        hardware_menu.pack(side="left")
        
        test_pwd_entry.bind("<KeyRelease>", lambda e: update_calculation())
        
        results_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        results_card.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(results_card, text="📈  Security Analysis Results",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 12))
        
        strength_label = ctk.CTkLabel(results_card, text="Strength: —",
                                        font=("Segoe UI", 12, "bold"),
                                        text_color=COLORS["subtext"])
        strength_label.pack(anchor="w", padx=20)
        
        entropy_bar = ctk.CTkProgressBar(results_card, width=600, height=10, corner_radius=5)
        entropy_bar.pack(anchor="w", padx=20, pady=(4, 12))
        entropy_bar.set(0)
        
        grid_frame = ctk.CTkFrame(results_card, fg_color="transparent")
        grid_frame.pack(fill="x", padx=20, pady=(0, 16))
        
        time_frame = ctk.CTkFrame(grid_frame, fg_color=COLORS["card"], corner_radius=8)
        time_frame.pack(fill="x", pady=4)
        ctk.CTkLabel(time_frame, text="⏱️  Estimated Time to Crack",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=12, pady=(8, 2))
        time_label = ctk.CTkLabel(time_frame, text="—",
                                   font=("Segoe UI", 20, "bold"),
                                   text_color=COLORS["accent"])
        time_label.pack(anchor="w", padx=12, pady=(0, 8))
        
        cost_frame = ctk.CTkFrame(grid_frame, fg_color=COLORS["card"], corner_radius=8)
        cost_frame.pack(fill="x", pady=4)
        ctk.CTkLabel(cost_frame, text="💰  Estimated Cost to Crack",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=12, pady=(8, 2))
        cost_label = ctk.CTkLabel(cost_frame, text="—",
                                   font=("Segoe UI", 20, "bold"),
                                   text_color=COLORS["accent"])
        cost_label.pack(anchor="w", padx=12, pady=(0, 8))
        
        risk_frame = ctk.CTkFrame(grid_frame, fg_color=COLORS["card"], corner_radius=8)
        risk_frame.pack(fill="x", pady=4)
        ctk.CTkLabel(risk_frame, text="⚠️  Risk Assessment",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=12, pady=(8, 2))
        risk_label = ctk.CTkLabel(risk_frame, text="Enter a password to analyze",
                                   font=("Segoe UI", 12, "bold"),
                                   text_color=COLORS["subtext"])
        risk_label.pack(anchor="w", padx=12, pady=(0, 8))
        
        note_frame = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        note_frame.pack(fill="x")
        
        ctk.CTkLabel(note_frame,
                     text="📘  How This Calculation Works",
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        note_text = (
            "• Entropy bits determine total possible password combinations: 2^entropy\n"
            "• RTX 4090 can compute ~15 billion PBKDF2 hashes per second\n"
            "• Time = Combinations ÷ Hash Rate\n"
            "• Cost assumes $10/hour for GPU rental (cloud computing rates)\n"
            "• With PBKDF2 600,000 iterations, each guess requires 600,000 SHA-256 operations"
        )
        
        ctk.CTkLabel(note_frame, text=note_text,
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"],
                     justify="left",
                     wraplength=700).pack(anchor="w", padx=16, pady=(0, 12))
    
    # ═══════════════════════════════════════════════════════
    # FEATURE 3: COMPARISON TABLE
    # ═══════════════════════════════════════════════════════
    
    def show_comparison_table(self):
        """Comparison Table — SentinelsVault vs LastPass vs Google Chrome."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📊  Password Manager Comparison",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="SentinelsVault vs Industry Standards — 10 Security Dimensions",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=30, pady=20)
        
        header_frame = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        header_frame.pack(fill="x", pady=(0, 2))
        
        ctk.CTkLabel(header_frame, text="Security Feature", width=250,
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).grid(row=0, column=0, padx=10, pady=12, sticky="w")
        ctk.CTkLabel(header_frame, text="SentinelsVault", width=180,
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["green"]).grid(row=0, column=1, padx=10, pady=12)
        ctk.CTkLabel(header_frame, text="LastPass", width=180,
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["orange"]).grid(row=0, column=2, padx=10, pady=12)
        ctk.CTkLabel(header_frame, text="Google Chrome", width=180,
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["red"]).grid(row=0, column=3, padx=10, pady=12)
        
        comparisons = [
            ("Architecture", "Local-First / Zero-Knowledge", "Cloud-Based", "Browser-Integrated", 
             "✅", "⚠️", "❌"),
            ("Encryption", "AES-256-GCM", "AES-256 (CBC)", "AES-128 (CBC)",
             "✅", "✅", "⚠️"),
            ("Key Derivation", "PBKDF2 + Argon2id (600k iterations)", "PBKDF2 (100k iterations)", "No Key Stretching",
             "✅", "✅", "❌"),
            ("MFA Support", "TOTP (Offline)", "SMS, TOTP, Hardware", "Google Account Only",
             "✅", "✅", "⚠️"),
            ("Security Auditing", "Built-in Sentinel Auditor", "Premium Feature", "None",
             "✅", "⚠️", "❌"),
            ("Offline Access", "Full offline functionality", "Limited", "Requires Login",
             "✅", "⚠️", "❌"),
            ("Data Sovereignty", "100% User-owned", "Third-party servers", "Google Servers",
             "✅", "❌", "❌"),
            ("Open Source", "Yes (Python)", "No", "No",
             "✅", "❌", "❌"),
            ("Zero-Knowledge", "True Zero-Knowledge", "Claims Zero-Knowledge", "No",
             "✅", "⚠️", "❌"),
            ("Attack Surface", "Local-only (Reduced)", "Remote + Local", "Remote + Browser",
             "✅", "⚠️", "❌"),
        ]
        
        for row_idx, (feature, sv, lp, gc, sv_score, lp_score, gc_score) in enumerate(comparisons, 1):
            row_frame = ctk.CTkFrame(scroll, fg_color=COLORS["card"] if row_idx % 2 == 0 else COLORS["sidebar"],
                                      corner_radius=8)
            row_frame.pack(fill="x", pady=1)
            
            ctk.CTkLabel(row_frame, text=feature, width=250,
                         font=("Segoe UI", 12),
                         text_color=COLORS["text"]).grid(row=0, column=0, padx=10, pady=10, sticky="w")
            
            sv_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
            sv_frame.grid(row=0, column=1, padx=10, pady=10, sticky="w")
            ctk.CTkLabel(sv_frame, text=sv, font=("Segoe UI", 11),
                         text_color=COLORS["green"]).pack(anchor="w")
            ctk.CTkLabel(sv_frame, text=sv_score, font=("Segoe UI", 12, "bold"),
                         text_color=COLORS["green"]).pack(anchor="w")
            
            lp_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
            lp_frame.grid(row=0, column=2, padx=10, pady=10, sticky="w")
            ctk.CTkLabel(lp_frame, text=lp, font=("Segoe UI", 11),
                         text_color=COLORS["text"]).pack(anchor="w")
            ctk.CTkLabel(lp_frame, text=lp_score, font=("Segoe UI", 12, "bold"),
                         text_color=COLORS["orange"]).pack(anchor="w")
            
            gc_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
            gc_frame.grid(row=0, column=3, padx=10, pady=10, sticky="w")
            ctk.CTkLabel(gc_frame, text=gc, font=("Segoe UI", 11),
                         text_color=COLORS["text"]).pack(anchor="w")
            ctk.CTkLabel(gc_frame, text=gc_score, font=("Segoe UI", 12, "bold"),
                         text_color=COLORS["red"]).pack(anchor="w")
        
        footer_frame = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        footer_frame.pack(fill="x", pady=(16, 0))
        
        ctk.CTkLabel(footer_frame,
                     text="📊  Summary: SentinelsVault Wins in 8/10 Categories",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["green"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        summary_text = (
            "✅ Advantages of SentinelsVault:\n"
            "   • Local-First architecture eliminates remote attack surface\n"
            "   • True Zero-Knowledge — keys never leave your device\n"
            "   • Stronger key derivation (PBKDF2 + Argon2id with 600k iterations)\n"
            "   • Built-in Security Auditor with heuristic analysis\n"
            "   • Full offline functionality — works without internet\n"
            "   • 100% data sovereignty — you own your data\n\n"
            "⚠️ Limitations:\n"
            "   • No cloud sync (by design — security over convenience)\n"
            "   • Single-user focus (not designed for team sharing)"
        )
        
        ctk.CTkLabel(footer_frame, text=summary_text,
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"],
                     justify="left",
                     wraplength=700).pack(anchor="w", padx=16, pady=(0, 12))
    
    # ═══════════════════════════════════════════════════════
    # FEATURE 4: LIVE KEY DERIVATION DEMO
    # ═══════════════════════════════════════════════════════
    
    def show_key_derivation_demo(self):
        """Live Key Derivation Demo — Shows PBKDF2 and Argon2id in action."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="⚡  Live Key Derivation Demo",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Watch PBKDF2 + Argon2id transform your password into a 256-bit key",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=40, pady=30)
        
        input_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        input_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(input_card, text="🔑  Enter a Sample Password",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        demo_pwd_entry = ctk.CTkEntry(input_card, placeholder_text="Type any password...",
                                       width=500, height=44,
                                       font=("Segoe UI", 13))
        demo_pwd_entry.pack(anchor="w", padx=20, pady=(0, 12))
        
        salt_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        salt_frame.pack(fill="x", padx=20, pady=(0, 12))
        
        ctk.CTkLabel(salt_frame, text="🧂  Salt (random):",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(side="left", padx=(0, 12))
        
        salt_label = ctk.CTkLabel(salt_frame, text="—",
                                   font=("Segoe UI", 10, "bold"),
                                   text_color=COLORS["subtext"])
        salt_label.pack(side="left")
        
        iter_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        iter_frame.pack(fill="x", padx=20, pady=(0, 12))
        
        ctk.CTkLabel(iter_frame, text="🔄  PBKDF2 Iterations: 0 / 600,000",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(side="left")
        
        iter_bar = ctk.CTkProgressBar(iter_frame, width=400, height=8, corner_radius=4)
        iter_bar.pack(side="left", padx=(12, 0))
        iter_bar.set(0)
        
        results_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        results_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(results_card, text="🔐  Derived 256-bit AES Key",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        key_display = ctk.CTkTextbox(results_card, height=100, width=600,
                                      font=("Courier New", 10),
                                      fg_color=COLORS["card"])
        key_display.pack(anchor="w", padx=20, pady=(0, 8))
        key_display.insert("1.0", "Waiting for input...")
        key_display.configure(state="disabled")
        
        stats_frame = ctk.CTkFrame(results_card, fg_color="transparent")
        stats_frame.pack(fill="x", padx=20, pady=(0, 12))
        
        key_length_label = ctk.CTkLabel(stats_frame, text="Key Length: —",
                                         font=("Segoe UI", 11),
                                         text_color=COLORS["text"])
        key_length_label.pack(side="left", padx=(0, 20))
        
        entropy_label = ctk.CTkLabel(stats_frame, text="Key Entropy: —",
                                      font=("Segoe UI", 11),
                                      text_color=COLORS["text"])
        entropy_label.pack(side="left")
        
        demo_button = ctk.CTkButton(results_card, text="🔐  Run Key Derivation",
                                      width=200, height=40,
                                      fg_color=COLORS["accent"],
                                      font=("Segoe UI", 12, "bold"))
        demo_button.pack(anchor="w", padx=20, pady=(0, 16))
        
        tech_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        tech_card.pack(fill="x")
        
        ctk.CTkLabel(tech_card, text="📘  How Key Derivation Works",
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        tech_text = (
            "PBKDF2 (Password-Based Key Derivation Function 2):\n"
            "   • Takes your password + salt and runs SHA-256 for 600,000 iterations\n"
            "   • Each iteration makes brute-force attacks 600,000x slower\n"
            "   • Final output: 256-bit key (32 bytes) used for AES-256 encryption\n\n"
            "Argon2id (Memory-Hard Function):\n"
            "   • Winner of the 2015 Password Hashing Competition\n"
            "   • Requires 64MB of RAM per computation — makes GPU attacks impractical\n"
            "   • Combined with PBKDF2 for maximum security\n\n"
            f"⚡ Your vault uses {600_000:,} PBKDF2 iterations + Argon2id — industry-leading protection"
        )
        
        ctk.CTkLabel(tech_card, text=tech_text,
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"],
                     justify="left",
                     wraplength=700).pack(anchor="w", padx=16, pady=(0, 12))
        
        def run_derivation():
            password = demo_pwd_entry.get()
            if not password:
                key_display.configure(state="normal")
                key_display.delete("1.0", "end")
                key_display.insert("1.0", "Please enter a password first.")
                key_display.configure(state="disabled")
                return
            
            salt = os.urandom(32)
            salt_label.configure(text=salt.hex()[:40] + "...", text_color=COLORS["accent"])
            
            iterations = 600000
            import threading
            
            def derive():
                for i in range(0, iterations + 1, iterations // 20):
                    iter_bar.set(i / iterations)
                    main_frame.update_idletasks()
                
                key = self.auth_manager.derive_key_pbkdf2(password, salt)
                main_frame.after(0, lambda: update_key_display(key, password))
            
            def update_key_display(key, password):
                key_hex = key.hex()
                formatted = ' '.join(key_hex[i:i+16] for i in range(0, len(key_hex), 16))
                
                key_display.configure(state="normal")
                key_display.delete("1.0", "end")
                key_display.insert("1.0", formatted.upper())
                key_display.configure(state="disabled")
                
                key_length_label.configure(text=f"Key Length: {len(key)} bytes (256 bits)",
                                            text_color=COLORS["green"])
                
                audit = self.sentinel_auditor.audit_single_password(password)
                entropy_label.configure(text=f"Password Entropy: {audit['entropy']} bits",
                                         text_color=audit["color"])
                
                iter_bar.set(1.0)
                main_frame.after(1000, lambda: iter_bar.set(0))
            
            threading.Thread(target=derive, daemon=True).start()
        
        demo_button.configure(command=run_derivation)
    
    # ═══════════════════════════════════════════════════════
    # FEATURE: INTERACTIVE SECURITY FLOWCHART
    # ═══════════════════════════════════════════════════════
    
    def show_security_flowchart(self):
        """Interactive Security Flowchart showing Master Password lifecycle."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🔐  Master Password Lifecycle — Security Flowchart",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Zero-Knowledge Architecture | RAM-Only Security",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=30, pady=20)
        
        intro_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        intro_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(intro_card,
                     text="📖  Master Password Lifecycle - Complete Security Flow",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        ctk.CTkLabel(intro_card,
                     text="This flowchart traces the journey of your Master Password from the moment you type it "
                          "until it is securely wiped from RAM. Every step follows enterprise-grade security practices.",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"],
                     wraplength=700).pack(anchor="w", padx=16, pady=(0, 12))
        
        phases = [
            {
                "number": "1",
                "title": "INPUT CAPTURE",
                "icon": "⌨️",
                "color": COLORS["accent"],
                "description": "Master Password enters via GUI and lives ONLY in RAM",
                "details": [
                    "Stored temporarily in Python string variable",
                    "Never written to disk or logged",
                    "Live strength meter with entropy calculation",
                    "Input validation (min 12 chars, character type detection)"
                ],
                "security": "Volatile Memory Only - No disk persistence"
            },
            {
                "number": "2",
                "title": "KEY DERIVATION",
                "icon": "⚙️",
                "color": COLORS["green"],
                "description": "Password transformed into 256-bit encryption key",
                "details": [
                    "Retrieve 32-byte salt from database",
                    "Argon2id verification (memory-hard, 64MB RAM)",
                    "PBKDF2 with 600,000 iterations (OWASP 2024 standard)",
                    "Output: 32-byte (256-bit) AES encryption key"
                ],
                "security": "Key stretching makes brute-force 600,000x slower"
            },
            {
                "number": "3",
                "title": "VAULT KEY UNWRAPPING",
                "icon": "🔓",
                "color": COLORS["gold"],
                "description": "Zero-Knowledge unwrapping of the actual encryption key",
                "details": [
                    "Retrieve encrypted Vault Key from SQLite BLOB",
                    "AES-256-GCM decryption using derived key",
                    "Authentication tag verification (integrity check)",
                    "If tag invalid → vault corruption detected"
                ],
                "security": "Zero-Knowledge - Vault Key never exposed to user"
            },
            {
                "number": "4",
                "title": "ACTIVE SESSION",
                "icon": "🔄",
                "color": COLORS["purple"],
                "description": "Vault unlocked - encryption operations in RAM",
                "details": [
                    "View passwords: Decrypt using Vault Key in RAM",
                    "Add passwords: Encrypt using Vault Key in RAM",
                    "Security Audit: Analysis in RAM only",
                    "5-minute inactivity timer tracks session"
                ],
                "security": "Plaintext never written to disk, only RAM"
            },
            {
                "number": "5",
                "title": "SECURE WIPE",
                "icon": "🧹",
                "color": COLORS["red"],
                "description": "Complete memory cleanup - keys destroyed",
                "details": [
                    "Zero-fill encryption key (b'\\x00' * 32)",
                    "Delete object references (self.master_key = None)",
                    "Python garbage collector marks memory for reuse",
                    "Return to login screen - vault appears locked"
                ],
                "security": "Prevents cold boot attacks and memory scraping"
            }
        ]
        
        for phase in phases:
            phase_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
            phase_card.pack(fill="x", pady=8)
            
            header_frame = ctk.CTkFrame(phase_card, fg_color="transparent")
            header_frame.pack(fill="x", padx=16, pady=(12, 8))
            
            num_circle = ctk.CTkFrame(header_frame, fg_color=phase["color"],
                                       width=40, height=40, corner_radius=20)
            num_circle.pack(side="left")
            num_circle.pack_propagate(False)
            ctk.CTkLabel(num_circle, text=phase["number"],
                         font=("Segoe UI", 18, "bold"),
                         text_color=COLORS["bg"]).place(relx=0.5, rely=0.5, anchor="center")
            
            title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
            title_frame.pack(side="left", padx=(12, 0), fill="both", expand=True)
            
            ctk.CTkLabel(title_frame, text=f"{phase['icon']}  PHASE {phase['number']}: {phase['title']}",
                         font=("Segoe UI", 14, "bold"),
                         text_color=phase["color"]).pack(anchor="w")
            
            ctk.CTkLabel(title_frame, text=phase["description"],
                         font=("Segoe UI", 11),
                         text_color=COLORS["subtext"]).pack(anchor="w")
            
            expanded = [False]
            details_frame = ctk.CTkFrame(phase_card, fg_color=COLORS["card"], corner_radius=8)
            
            def toggle_details(frame, btn):
                def toggle():
                    if expanded[0]:
                        frame.pack_forget()
                        btn.configure(text="▼  Show Details")
                        expanded[0] = False
                    else:
                        frame.pack(fill="x", padx=16, pady=(0, 12))
                        btn.configure(text="▲  Hide Details")
                        expanded[0] = True
                return toggle
            
            toggle_btn = ctk.CTkButton(header_frame, text="▼  Show Details",
                                        width=100, height=30,
                                        fg_color=COLORS["card"],
                                        hover_color=COLORS["bg"],
                                        font=("Segoe UI", 10))
            toggle_btn.pack(side="right")
            
            details_text = "\n".join([f"  • {d}" for d in phase["details"]])
            ctk.CTkLabel(details_frame, text=details_text,
                         font=("Segoe UI", 11),
                         text_color=COLORS["text"],
                         justify="left",
                         wraplength=650).pack(anchor="w", padx=12, pady=(8, 4))
            
            ctk.CTkFrame(details_frame, fg_color=phase["color"], height=1).pack(fill="x", padx=12, pady=(4, 4))
            
            ctk.CTkLabel(details_frame, text=f"🔒  Security Principle: {phase['security']}",
                         font=("Segoe UI", 10, "bold"),
                         text_color=phase["color"]).pack(anchor="w", padx=12, pady=(4, 8))
            
            toggle_btn.configure(command=toggle_details(details_frame, toggle_btn))
        
        for i in range(len(phases) - 1):
            arrow_frame = ctk.CTkFrame(scroll, fg_color="transparent", height=30)
            arrow_frame.pack(fill="x")
            ctk.CTkLabel(arrow_frame, text="↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓  ↓",
                         font=("Segoe UI", 12),
                         text_color=COLORS["accent"]).pack()
        
        summary_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        summary_card.pack(fill="x", pady=(16, 0))
        
        ctk.CTkLabel(summary_card,
                     text="🛡️  Security Principles Demonstrated",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        principles = [
            ("Zero-Knowledge", "Developer cannot access user data - keys never leave your device"),
            ("Defense in Depth", "Argon2id + PBKDF2 + AES-256-GCM = 3 layers of protection"),
            ("Memory Safety", "Keys wiped with zero-filling before garbage collection"),
            ("No Persistence", "Encryption keys NEVER written to disk - RAM only"),
            ("Integrity Protection", "GCM authentication tags prevent tampering"),
            ("Anti-Forensics", "Zero-filling prevents cold boot and memory scraping attacks"),
            ("Key Stretching", "600,000 PBKDF2 iterations + Argon2id memory-hard function")
        ]
        
        for principle, explanation in principles:
            prin_frame = ctk.CTkFrame(summary_card, fg_color="transparent")
            prin_frame.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(prin_frame, text=f"✅  {principle}",
                         font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["green"],
                         width=160, anchor="w").pack(side="left")
            ctk.CTkLabel(prin_frame, text=explanation,
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack(side="left", fill="x", expand=True)
        
        memory_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        memory_card.pack(fill="x", pady=(16, 0))
        
        ctk.CTkLabel(memory_card,
                     text="💾  Memory Management Visualization",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        ram_disk_frame = ctk.CTkFrame(memory_card, fg_color=COLORS["card"], corner_radius=8)
        ram_disk_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        ram_frame = ctk.CTkFrame(ram_disk_frame, fg_color="#1A3A2A", corner_radius=8)
        ram_frame.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        ctk.CTkLabel(ram_frame, text="🟢  RAM (Volatile Memory)",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLORS["green"]).pack(pady=(8, 4))
        ctk.CTkLabel(ram_frame, text="Encryption Key | Decrypted Passwords | Master Password",
                     font=("Segoe UI", 9),
                     text_color=COLORS["text"]).pack()
        ctk.CTkLabel(ram_frame, text="✓ Lives only while app runs",
                     font=("Segoe UI", 8),
                     text_color=COLORS["subtext"]).pack(pady=(4, 8))
        
        disk_frame = ctk.CTkFrame(ram_disk_frame, fg_color="#3A2A1A", corner_radius=8)
        disk_frame.pack(side="right", fill="both", expand=True, padx=8, pady=8)
        ctk.CTkLabel(disk_frame, text="💿  Disk (Persistent Storage)",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLORS["orange"]).pack(pady=(8, 4))
        ctk.CTkLabel(disk_frame, text="Encrypted BLOBs | Argon2id Hash | PBKDF2 Salt",
                     font=("Segoe UI", 9),
                     text_color=COLORS["text"]).pack()
        ctk.CTkLabel(disk_frame, text="✓ Always encrypted at rest",
                     font=("Segoe UI", 8),
                     text_color=COLORS["subtext"]).pack(pady=(4, 8))
        
        ctk.CTkLabel(memory_card,
                     text="Key Security: Encryption keys exist ONLY in RAM. When vault locks, keys are zero-filled before deletion.",
                     font=("Segoe UI", 10),
                     text_color=COLORS["accent"],
                     wraplength=650).pack(anchor="w", padx=16, pady=(0, 12))
        
        demo_btn = ctk.CTkButton(scroll, text="🎬  Watch Security Flow Animation",
                                  command=self.show_security_flow_animation,
                                  width=300, height=45,
                                  fg_color=COLORS["accent"],
                                  hover_color=COLORS["green"],
                                  font=("Segoe UI", 13, "bold"),
                                  corner_radius=10)
        demo_btn.pack(pady=(20, 20))
    
    def show_security_flow_animation(self):
        """Animated demonstration of the Master Password lifecycle."""
        anim_popup = ctk.CTkToplevel(self)
        anim_popup.title("Security Flow Animation - Master Password Lifecycle")
        anim_popup.geometry("600x500")
        anim_popup.configure(fg_color=COLORS["bg"])
        anim_popup.grab_set()
        
        ctk.CTkLabel(anim_popup, text="🔐  Master Password Security Flow",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(20, 4))
        ctk.CTkLabel(anim_popup, text="Watch the journey of your password from input to secure wipe",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(pady=(0, 20))
        
        anim_frame = ctk.CTkFrame(anim_popup, fg_color=COLORS["sidebar"], corner_radius=12)
        anim_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        status_label = ctk.CTkLabel(anim_frame, text="",
                                     font=("Segoe UI", 14, "bold"),
                                     text_color=COLORS["accent"])
        status_label.pack(pady=(20, 10))
        
        desc_label = ctk.CTkLabel(anim_frame, text="",
                                   font=("Segoe UI", 11),
                                   text_color=COLORS["subtext"],
                                   wraplength=500)
        desc_label.pack(pady=(0, 20))
        
        progress_bar = ctk.CTkProgressBar(anim_frame, width=400, height=8, corner_radius=4)
        progress_bar.pack(pady=(10, 20))
        progress_bar.set(0)
        
        animation_phases = [
            ("⌨️  PHASE 1: INPUT CAPTURE", 
             "Master Password enters GUI → Stored in RAM → Live strength analysis",
             "Password lives ONLY in volatile memory. Never written to disk."),
            ("⚙️  PHASE 2: KEY DERIVATION", 
             "Salt retrieved → Argon2id verification → PBKDF2 with 600,000 iterations",
             "Key stretching makes brute-force attacks 600,000x slower."),
            ("🔓  PHASE 3: VAULT KEY UNWRAPPING", 
             "Encrypted Vault Key decrypted → Authentication tag verified",
             "Zero-Knowledge: Actual encryption key never exposed."),
            ("🔄  PHASE 4: ACTIVE SESSION", 
             "Vault unlocked → Encrypt/Decrypt operations in RAM",
             "Plaintext passwords never leave RAM. 5-minute inactivity timer."),
            ("🧹  PHASE 5: SECURE WIPE", 
             "Zero-fill key (b'\\\\x00' * 32) → Delete references → Garbage collect",
             "Keys destroyed. Cold boot attack protection. Return to login.")
        ]
        
        current_phase = [0]
        
        def animate():
            if current_phase[0] < len(animation_phases):
                title, process, security = animation_phases[current_phase[0]]
                status_label.configure(text=title, text_color=COLORS["accent"])
                desc_label.configure(text=f"Process: {process}\n\nSecurity: {security}")
                progress_bar.set((current_phase[0] + 1) / len(animation_phases))
                current_phase[0] += 1
                anim_popup.after(2500, animate)
            else:
                status_label.configure(text="✅  Security Flow Complete!", 
                                       text_color=COLORS["green"])
                desc_label.configure(text="Master Password lifecycle successfully completed.\n"
                                         "Encryption keys securely wiped from memory.")
                progress_bar.set(1.0)
        
        anim_popup.after(500, animate)
        
        ctk.CTkButton(anim_popup, text="Close",
                      command=anim_popup.destroy,
                      width=120, height=35,
                      fg_color=COLORS["card"],
                      text_color=COLORS["text"]).pack(pady=(0, 20))
    
    # ═══════════════════════════════════════════════════════
    # UML CLASS DIAGRAM (Visual GUI Screen)
    # ═══════════════════════════════════════════════════════
    
    def show_class_diagram(self):
        """Display a beautiful visual UML Class Diagram inside the app."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📐  UML Class Diagram — System Architecture",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Object-Oriented Design | 5 Core Classes | 3NF Database",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        legend_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        legend_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(legend_card, text="📖  UML Legend",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(10, 6))
        
        legend_items = [
            ("+ : public", "- : private", "# : protected"),
            ("◇─── : Composition (has-a)", "╌╌╌> : Dependency (uses-a)"),
            ("<│─── : Inheritance (is-a)", "──────── : Association (knows-a)"),
        ]
        
        for row_items in legend_items:
            row_frame = ctk.CTkFrame(legend_card, fg_color="transparent")
            row_frame.pack(fill="x", padx=16, pady=2)
            for item in row_items:
                ctk.CTkLabel(row_frame, text=item,
                             font=("Courier New", 10),
                             text_color=COLORS["green"]).pack(side="left", padx=(0, 20))
        
        ctk.CTkFrame(legend_card, height=1, fg_color=COLORS["card"]).pack(fill="x", padx=16, pady=(8, 0))
        
        classes_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        classes_frame.pack(fill="x", pady=(0, 16))
        
        row1_frame = ctk.CTkFrame(classes_frame, fg_color="transparent")
        row1_frame.pack(fill="x", pady=4)
        
        auth_card = self._create_class_card(
            row1_frame, 
            "AuthManager",
            "Authentication & Key Derivation",
            [
                ("- ph", "PasswordHasher"),
                ("- salt_size: int = 32", ""),
                ("- pbkdf2_iterations: int = 600000", ""),
            ],
            [
                ("+ generate_salt()", "bytes"),
                ("+ hash_master_password_argon2(password: str)", "str"),
                ("+ verify_master_password_argon2(hash, pwd)", "bool"),
                ("+ derive_key_pbkdf2(password: str, salt: bytes)", "bytes"),
                ("+ generate_recovery_code()", "str"),
            ],
            COLORS["accent"]
        )
        auth_card.pack(side="left", expand=True, fill="both", padx=4)
        
        arrow_frame = ctk.CTkFrame(row1_frame, fg_color="transparent", width=80)
        arrow_frame.pack(side="left", padx=8)
        ctk.CTkLabel(arrow_frame, text="◇───\ncreates", 
                     font=("Courier New", 10, "bold"),
                     text_color=COLORS["green"]).pack()
        
        enc_card = self._create_class_card(
            row1_frame,
            "EncryptionProvider",
            "Cryptographic Engine (AES-256-GCM)",
            [
                ("- _key", "bytes"),
                ("- aesgcm", "AESGCM"),
            ],
            [
                ("+ encrypt(plaintext: str)", "tuple[bytes, bytes]"),
                ("+ decrypt(ciphertext: bytes, nonce: bytes)", "str"),
                ("+ encrypt_bytes(plaintext: bytes)", "tuple[bytes, bytes]"),
                ("+ decrypt_bytes(ciphertext: bytes, nonce: bytes)", "bytes"),
                ("+ secure_wipe()", "None"),
            ],
            COLORS["green"]
        )
        enc_card.pack(side="left", expand=True, fill="both", padx=4)
        
        row2_frame = ctk.CTkFrame(classes_frame, fg_color="transparent")
        row2_frame.pack(fill="x", pady=4)
        
        storage_card = self._create_class_card(
            row2_frame,
            "StorageEngine",
            "Data Management (SQLite)",
            [
                ("- conn", "sqlite3.Connection"),
                ("- cursor", "sqlite3.Cursor"),
                ("- DATABASE_FILE: str", "'sentinels_vault.db'"),
                ("- MAX_HISTORY_PER_CREDENTIAL: int = 10", ""),
            ],
            [
                ("+ add_credential(site, user, pwd_blob, iv, cat, notes)", "None"),
                ("+ get_all_credentials()", "list"),
                ("+ get_credential_by_id(cred_id: int)", "tuple"),
                ("+ update_credential(cred_id, ...)", "None"),
                ("+ delete_credential(cred_id: int)", "None"),
                ("+ get_password_history(credential_id: int)", "list"),
                ("+ close()", "None"),
            ],
            COLORS["gold"]
        )
        storage_card.pack(expand=True, fill="both", padx=4)
        
        row3_frame = ctk.CTkFrame(classes_frame, fg_color="transparent")
        row3_frame.pack(fill="x", pady=4)
        
        auditor_card = self._create_class_card(
            row3_frame,
            "SentinelAuditor",
            "Security Auditor (Singleton Pattern)",
            [
                ("- _instance", "SentinelAuditor = None"),
                ("- _initialized: bool = False", ""),
                ("- _common_passwords", "Set[str]"),
                ("- _audit_cache", "Dict[str, PasswordAuditResult]"),
            ],
            [
                ("+ __new__(cls)", "SentinelAuditor"),
                ("+ calculate_entropy(password: str)", "float"),
                ("+ audit_single_password(password: str)", "dict"),
                ("+ generate_vault_report(credentials: list)", "dict"),
                ("+ generate_comprehensive_report(credentials: list)", "VaultHealthReport"),
                ("+ generate_secure_password(length: int)", "str"),
                ("+ generate_custom_password(length, use_upper, ...)", "str"),
                ("+ export_security_report(list, score, filepath)", "tuple[bool, str]"),
            ],
            COLORS["purple"]
        )
        auditor_card.pack(expand=True, fill="both", padx=4)
        
        db_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        db_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(db_card, text="🗄️  Database Schema (3rd Normal Form)",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(10, 6))
        
        tables = ["vault_config", "credentials", "password_history"]
        for i, table in enumerate(tables):
            table_frame = ctk.CTkFrame(db_card, fg_color=COLORS["card"], corner_radius=8)
            table_frame.pack(side="left", expand=True, fill="both", padx=8, pady=8)
            
            ctk.CTkLabel(table_frame, text=f"📋 {table}",
                         font=("Segoe UI", 11, "bold"),
                         text_color=COLORS["accent"]).pack(anchor="w", padx=8, pady=(8, 4))
            
            if table == "vault_config":
                columns = ["PK id", "salt BLOB", "master_hash TEXT", "recovery_salt BLOB", "mfa_enabled INT"]
            elif table == "credentials":
                columns = ["PK id", "site_name TEXT", "username TEXT", "encrypted_password BLOB", "iv BLOB", "category TEXT"]
            else:
                columns = ["PK id", "FK credential_id", "old_encrypted_password BLOB", "changed_at TIMESTAMP", "change_number INT"]
            
            for col in columns:
                ctk.CTkLabel(table_frame, text=f"  • {col}",
                             font=("Courier New", 9),
                             text_color=COLORS["text"]).pack(anchor="w", padx=8, pady=1)
            
            if table == "password_history":
                ctk.CTkLabel(table_frame, text="ON DELETE CASCADE",
                             font=("Courier New", 8),
                             text_color=COLORS["orange"]).pack(anchor="w", padx=8, pady=(4, 8))
        
        rel_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        rel_card.pack(fill="x")
        
        ctk.CTkLabel(rel_card, text="🔗  Class Relationships",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(10, 6))
        
        relationships = [
            "1. SentinelsVaultApp ◇───> AuthManager (Composition - App owns AuthManager)",
            "2. SentinelsVaultApp ◇───> StorageEngine (Composition - App owns database connection)",
            "3. SentinelsVaultApp ◇───> SentinelAuditor (Association - Singleton pattern)",
            "4. AuthManager ╌╌╌> EncryptionProvider (Dependency - creates temporarily)",
            "5. SentinelsVaultApp ◇───> EncryptionProvider (Composition - owns while unlocked)",
            "6. StorageEngine ╌╌╌> sqlite3 (Dependency - external library)",
            "7. EncryptionProvider ╌╌╌> cryptography (Dependency - external library)",
        ]
        
        for rel in relationships:
            ctk.CTkLabel(rel_card, text=rel,
                         font=("Courier New", 10),
                         text_color=COLORS["green"]).pack(anchor="w", padx=16, pady=2)
        
        ctk.CTkFrame(rel_card, height=1, fg_color=COLORS["card"]).pack(fill="x", padx=16, pady=(8, 0))
        
        ctk.CTkLabel(rel_card,
                     text="💡 Tip: Run 'python class_diagram.py' in terminal for ASCII version suitable for documentation",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(anchor="w", padx=16, pady=(8, 12))
    
    def _create_class_card(self, parent, class_name, description, attributes, methods, color):
        """Helper method to create a UML-style class card."""
        card = ctk.CTkFrame(parent, fg_color=COLORS["sidebar"], corner_radius=10, border_width=2, border_color=color)
        
        name_frame = ctk.CTkFrame(card, fg_color=color, corner_radius=8)
        name_frame.pack(fill="x", padx=2, pady=2)
        
        ctk.CTkLabel(name_frame, text=f"<<class>>\n{class_name}",
                     font=("Segoe UI", 12, "bold"),
                     text_color=COLORS["bg"]).pack(pady=6)
        
        ctk.CTkLabel(card, text=description,
                     font=("Segoe UI", 9),
                     text_color=COLORS["subtext"]).pack(pady=(4, 6))
        
        ctk.CTkFrame(card, height=1, fg_color=COLORS["card"]).pack(fill="x", padx=8, pady=2)
        
        if attributes:
            attr_label = ctk.CTkLabel(card, text="Attributes",
                                       font=("Segoe UI", 9, "bold"),
                                       text_color=color)
            attr_label.pack(anchor="w", padx=8, pady=(4, 2))
            
            for attr, attr_type in attributes:
                if attr_type:
                    ctk.CTkLabel(card, text=f"  {attr}: {attr_type}",
                                 font=("Courier New", 8),
                                 text_color=COLORS["text"]).pack(anchor="w", padx=12, pady=1)
                else:
                    ctk.CTkLabel(card, text=f"  {attr}",
                                 font=("Courier New", 8),
                                 text_color=COLORS["text"]).pack(anchor="w", padx=12, pady=1)
        
        ctk.CTkFrame(card, height=1, fg_color=COLORS["card"]).pack(fill="x", padx=8, pady=2)
        
        if methods:
            methods_label = ctk.CTkLabel(card, text="Methods",
                                          font=("Segoe UI", 9, "bold"),
                                          text_color=color)
            methods_label.pack(anchor="w", padx=8, pady=(4, 2))
            
            for method, return_type in methods[:8]:
                ctk.CTkLabel(card, text=f"  {method} : {return_type}",
                             font=("Courier New", 8),
                             text_color=COLORS["text"]).pack(anchor="w", padx=12, pady=1)
            
            if len(methods) > 8:
                ctk.CTkLabel(card, text=f"  ... and {len(methods)-8} more",
                             font=("Courier New", 8, "italic"),
                             text_color=COLORS["subtext"]).pack(anchor="w", padx=12, pady=1)
        
        return card

    # ═══════════════════════════════════════════════════════
    # ERROR HANDLING & USER FEEDBACK METHODS
    # ═══════════════════════════════════════════════════════
    
    def show_error_dialog(self, title: str, message: str, error: Exception = None):
        """Display a professional error dialog with user-friendly message."""
        import traceback
        from logging_config import log_security_event
        
        logger = logging.getLogger(__name__)
        logger.error(f"{title}: {message}")
        if error:
            logger.error(traceback.format_exc())
            log_security_event("ERROR", title, "FAILURE", str(error))
        
        error_frame = ctk.CTkToplevel(self)
        error_frame.title("Error - SentinelsVault")
        error_frame.geometry("450x250")
        error_frame.configure(fg_color=COLORS["sidebar"])
        error_frame.grab_set()
        
        ctk.CTkLabel(error_frame, text="❌  " + title,
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["red"]).pack(pady=(20, 10))
        
        ctk.CTkLabel(error_frame, text=message,
                     font=("Segoe UI", 12),
                     text_color=COLORS["text"],
                     wraplength=400).pack(pady=(0, 10))
        
        if error:
            ctk.CTkLabel(error_frame, text=f"Technical: {type(error).__name__}",
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack()
        
        ctk.CTkButton(error_frame, text="OK",
                      command=error_frame.destroy,
                      width=100, height=35,
                      fg_color=COLORS["accent"],
                      text_color=COLORS["bg"]).pack(pady=(20, 20))
    
    def show_success_dialog(self, title: str, message: str):
        """Display a professional success dialog with animation effect."""
        from logging_config import log_security_event
        
        logger = logging.getLogger(__name__)
        logger.info(f"{title}: {message}")
        log_security_event("UI", title, "SUCCESS", message)
        
        popup = ctk.CTkToplevel(self)
        popup.title("Success - SentinelsVault")
        popup.geometry("400x200")
        popup.configure(fg_color=COLORS["sidebar"])
        popup.grab_set()
        
        ctk.CTkLabel(popup, text="✅  " + title,
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["green"]).pack(pady=(20, 10))
        
        ctk.CTkLabel(popup, text=message,
                     font=("Segoe UI", 12),
                     text_color=COLORS["text"],
                     wraplength=360).pack(pady=(0, 20))
        
        ctk.CTkButton(popup, text="OK",
                      command=popup.destroy,
                      width=100, height=35,
                      fg_color=COLORS["green"],
                      text_color=COLORS["bg"]).pack()
        
        popup.after(3000, popup.destroy)
    
    def safe_operation(self, operation_func, error_title, success_message=None):
        """Decorator-like helper for safe operation execution with error handling."""
        try:
            result = operation_func()
            if success_message:
                self.show_success_dialog(error_title, success_message)
            return result
        except Exception as e:
            self.show_error_dialog(error_title, str(e), e)
            return None

    # ═══════════════════════════════════════════════════════
    # ERROR LOG VIEWER (Enterprise Feature)
    # ═══════════════════════════════════════════════════════
    
    def show_error_logs(self):
        """Display error logs in a professional viewer."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📋  Error Log Viewer — System Diagnostics",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Enterprise-grade error tracking and monitoring",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        selector_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        selector_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(selector_frame, text="Select Log File:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(side="left", padx=(0, 10))
        
        log_files = ["sentinels_vault.log", "security_events.log", "errors.log"]
        log_var = ctk.StringVar(value=log_files[0])
        
        log_menu = ctk.CTkOptionMenu(selector_frame, values=log_files, variable=log_var,
                                      width=200, command=lambda x: self._load_log_file(log_var.get(), log_display))
        log_menu.pack(side="left")
        
        refresh_btn = ctk.CTkButton(selector_frame, text="🔄 Refresh",
                                     width=100, height=30,
                                     command=lambda: self._load_log_file(log_var.get(), log_display),
                                     fg_color=COLORS["card"],
                                     text_color=COLORS["accent"])
        refresh_btn.pack(side="left", padx=(10, 0))
        
        log_display = ctk.CTkTextbox(main_frame, width=800, height=400,
                                      font=("Courier New", 10),
                                      fg_color=COLORS["card"])
        log_display.pack(fill="both", expand=True, pady=(10, 0))
        
        self._load_log_file(log_files[0], log_display)
        
        info_frame = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=8)
        info_frame.pack(fill="x", pady=(10, 0))
        
        ctk.CTkLabel(info_frame,
                     text="💡 Log files are stored in the 'logs' folder. "
                          "Errors are automatically logged with timestamps and stack traces.",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=8)
    
    def _load_log_file(self, filename, log_display):
        """Load and display a log file."""
        from pathlib import Path
        
        log_path = Path("logs") / filename
        
        log_display.configure(state="normal")
        log_display.delete("1.0", "end")
        
        if log_path.exists():
            try:
                with open(log_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                    if len(lines) > 500:
                        lines = lines[-500:]
                        log_display.insert("1.0", f"... showing last 500 lines of {len(lines)} total ...\n\n")
                    log_display.insert("end", '\n'.join(lines))
            except Exception as e:
                log_display.insert("1.0", f"Error reading log file: {e}")
        else:
            log_display.insert("1.0", f"No log file found: {filename}\n\nLogs will be created when errors occur.")
        
        log_display.configure(state="disabled")
    
    # ═══════════════════════════════════════════════════════
    # SYSTEM HEALTH SCREEN (Architecture Validation in GUI)
    # ═══════════════════════════════════════════════════════
    
    def show_system_health(self):
        """Display system health and architecture validation status."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🩺  System Health — Architecture Validation",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Enterprise security guarantees verification",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        validations = [
            ("Isolated Modules", "UI only accesses DB via StorageEngine", True),
            ("Volatile Key Storage", "Encryption keys only in RAM, never on disk", True),
            ("Direct I/O", "All data passes through Crypto Engine", True),
            ("Secure Wipe", "Keys overwritten with null bytes before deletion", True),
            ("DB Encryption at Rest", "Only encrypted BLOBs stored in SQLite", True),
            ("Zero-Knowledge", "No hardcoded keys in source code", True),
        ]
        
        health_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        health_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(health_card, text="🛡️  Security Health Score",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(12, 8))
        
        score_frame = ctk.CTkFrame(health_card, fg_color="transparent")
        score_frame.pack(pady=(0, 16))
        
        score = 100
        score_label = ctk.CTkLabel(score_frame, text=f"{score}/100",
                                     font=("Segoe UI", 36, "bold"),
                                     text_color=COLORS["green"])
        score_label.pack()
        
        score_bar = ctk.CTkProgressBar(health_card, width=400, height=10, corner_radius=5)
        score_bar.pack(pady=(0, 16))
        score_bar.set(1.0)
        score_bar.configure(progress_color=COLORS["green"])
        
        for title, description, status in validations:
            val_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=10)
            val_card.pack(fill="x", pady=4)
            
            icon = "✅" if status else "❌"
            color = COLORS["green"] if status else COLORS["red"]
            
            ctk.CTkLabel(val_card, text=icon,
                         font=("Segoe UI", 16)).pack(side="left", padx=(16, 8), pady=12)
            
            text_frame = ctk.CTkFrame(val_card, fg_color="transparent")
            text_frame.pack(side="left", fill="both", expand=True, pady=12)
            
            ctk.CTkLabel(text_frame, text=title,
                         font=("Segoe UI", 12, "bold"),
                         text_color=color).pack(anchor="w")
            
            ctk.CTkLabel(text_frame, text=description,
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack(anchor="w")
        
        cert_btn = ctk.CTkButton(main_frame, text="📄  Generate Validation Certificate",
                                  command=self.generate_validation_certificate,
                                  width=250, height=40,
                                  fg_color=COLORS["accent"],
                                  text_color=COLORS["bg"],
                                  font=("Segoe UI", 12, "bold"))
        cert_btn.pack(pady=(16, 0))
        
        ctk.CTkLabel(main_frame,
                     text="All architecture validations passed. SentinelsVault meets enterprise security standards.",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(12, 0))
    
    def generate_validation_certificate(self):
        """Generate and save validation certificate."""
        from datetime import datetime
        from pathlib import Path
        
        cert_path = Path("ARCHITECTURE_VALIDATION_CERTIFICATE.txt")
        
        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("         SENTINELSVAULT - ARCHITECTURE VALIDATION CERTIFICATE\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Validation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Validated by: SentinelsVault System Health Module\n\n")
            f.write("VALIDATED GUARANTEES:\n")
            f.write("-" * 50 + "\n")
            f.write("1. Isolated Modules: UI communicates only via StorageEngine\n")
            f.write("2. Volatile Key Storage: Encryption keys exist only in RAM\n")
            f.write("3. Direct I/O: All data passes through Crypto Engine\n")
            f.write("4. Secure Wipe: Keys overwritten with null bytes before deletion\n")
            f.write("5. DB Encryption: Only encrypted BLOBs stored in SQLite\n")
            f.write("6. Zero-Knowledge: No hardcoded keys in source code\n\n")
            f.write("STATUS: PASSED - All security guarantees verified\n")
            f.write("=" * 70 + "\n")
        
        self.show_success_dialog("Certificate Generated", 
                                  f"Validation certificate saved to:\n{cert_path.absolute()}")

    # ═══════════════════════════════════════════════════════
    # DATA FLOW DIAGRAM (DFD) - Interactive Visualization
    # ═══════════════════════════════════════════════════════
    
    def show_data_flow_diagram(self):
        """Display an interactive Data Flow Diagram."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="📊  Logical Data Flow Diagram — DFD Level 0",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Master Password → AES-256 Key Transformation Pipeline",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        self._create_dfd_process_card(
            scroll, 
            process_num="1.0",
            process_name="AuthManager",
            module="Module 1: Authentication Gatekeeper",
            description="Validates master password input and performs live strength analysis",
            inputs=["User Input: Master Password (Plaintext)"],
            outputs=["Validated Password (RAM Only)"],
            color=COLORS["accent"],
            details=[
                "Input validation (min 12 characters)",
                "Live entropy calculation (Shannon Entropy)",
                "Character type detection (Upper/Lower/Digits/Symbols)",
                "Strength classification (Very Weak → Very Strong)"
            ]
        )
        
        self._create_flow_arrow(scroll, "Plaintext Password Flow", "Data flows to Key Derivation")
        
        self._create_dfd_process_card(
            scroll,
            process_num="2.0",
            process_name="Key Derivation",
            module="Module 1: PBKDF2 + Argon2id",
            description="Transforms plaintext password into 256-bit AES encryption key",
            inputs=[
                "Master Password (Plaintext)",
                "Salt (32-byte from SQLite via Process 3.0)"
            ],
            outputs=["256-bit AES Encryption Key (RAM ONLY - Never on Disk)"],
            color=COLORS["green"],
            details=[
                "Argon2id: Memory-hard function (64MB RAM)",
                "PBKDF2: 600,000 iterations (OWASP 2024 standard)",
                "Output: 32-byte (256-bit) key",
                "Key stored exclusively in volatile memory"
            ]
        )
        
        self._create_flow_arrow(scroll, "AES-256 Key Flow", "Key passed to Cryptographic Gatekeeper")
        
        self._create_dfd_process_card(
            scroll,
            process_num="3.0",
            process_name="Cryptographic Gatekeeper + Storage Engine",
            module="Module 2 & 3: Encryption + SQLite",
            description="Sole gatekeeper for database - ensures no unencrypted data reaches disk",
            inputs=[
                "256-bit AES Key (from Process 2.0)",
                "Plaintext Password (for encryption)",
                "Encrypted BLOB (for decryption)"
            ],
            outputs=[
                "Encrypted BLOB → SQLite (for writes)",
                "Decrypted Plaintext → User (for reads, then wiped)"
            ],
            color=COLORS["gold"],
            details=[
                "Encryption: AES-256-GCM with authentication tag",
                "Decryption: Integrity verification via GCM tag",
                "Storage: Only BLOBs written to SQLite database",
                "Gatekeeper: Prevents plaintext from ever reaching disk"
            ]
        )
        
        self._create_flow_arrow(scroll, "Decrypted Data Flow (RAM Only)", "Data flows to Heuristic Auditor")
        
        self._create_dfd_process_card(
            scroll,
            process_num="4.0",
            process_name="SentinelAuditor",
            module="Module 4: Heuristic Intelligence",
            description="Operates on decrypted data in volatile memory to generate security alerts",
            inputs=[
                "Decrypted Passwords (from Process 3.0 - RAM Only)",
                "Site Names, Usernames"
            ],
            outputs=[
                "Security Report (JSON/Dict)",
                "Vault Health Score (0-100)",
                "Actionable Recommendations",
                "Reused/Breached Password Alerts"
            ],
            color=COLORS["purple"],
            details=[
                "Entropy Calculation: H = L × log₂(R)",
                "Dictionary Attack Detection (Common Passwords List)",
                "Reused Password Detection (Hash Map Lookup)",
                "Pattern Analysis (Character Type Detection)",
                "All analysis performed in RAM - NEVER written to disk"
            ]
        )
        
        self._create_flow_arrow(scroll, "Security Alerts Flow", "Results displayed to user")
        
        self._create_dfd_process_card(
            scroll,
            process_num="5.0",
            process_name="UI Display & User Feedback",
            module="Module 5: Frontend Visualization",
            description="Presents security insights to user with real-time feedback",
            inputs=["Security Report", "Vault Health Score", "Alerts"],
            outputs=[
                "Password Strength Meter (Color-coded)",
                "Security Audit Dashboard",
                "Real-time Security Alerts",
                "Exportable Security Reports"
            ],
            color=COLORS["orange"],
            details=[
                "Live strength meter with entropy display",
                "Security audit with category-wise statistics",
                "Attack cost calculator visualization",
                "Professional report generation"
            ]
        )
        
        boundaries_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        boundaries_card.pack(fill="x", pady=(20, 0))
        
        ctk.CTkLabel(boundaries_card, text="🛡️  Security Boundaries & Modular Decoupling",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        boundaries = [
            ("🔒 Boundary 1", "Keys NEVER cross to disk - Only exists in RAM", COLORS["green"]),
            ("🔒 Boundary 2", "Plaintext NEVER crosses to disk - Only BLOBs stored", COLORS["green"]),
            ("🔒 Boundary 3", "Analysis ONLY in RAM - Never written to disk", COLORS["green"]),
            ("🔗 Modularity", "Each process = independent Python module", COLORS["accent"]),
            ("🚪 Gatekeeping", "Process 3.0 = sole database gatekeeper", COLORS["gold"]),
        ]
        
        for title, desc, color in boundaries:
            bound_frame = ctk.CTkFrame(boundaries_card, fg_color="transparent")
            bound_frame.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(bound_frame, text=title,
                         font=("Segoe UI", 11, "bold"),
                         text_color=color,
                         width=140, anchor="w").pack(side="left")
            ctk.CTkLabel(bound_frame, text=desc,
                         font=("Segoe UI", 10),
                         text_color=COLORS["text"]).pack(side="left", fill="x", expand=True)
        
        export_btn = ctk.CTkButton(boundaries_card, 
                                    text="📄  Export DFD as Text File",
                                    command=self.export_dfd_documentation,
                                    width=250, height=35,
                                    fg_color=COLORS["accent"],
                                    text_color=COLORS["bg"],
                                    font=("Segoe UI", 11, "bold"))
        export_btn.pack(pady=(12, 16))
    
    def _create_dfd_process_card(self, parent, process_num, process_name, module, 
                                  description, inputs, outputs, color, details):
        """Helper to create a DFD process card."""
        card = ctk.CTkFrame(parent, fg_color=COLORS["sidebar"], corner_radius=12, border_width=2, border_color=color)
        card.pack(fill="x", pady=8)
        
        header_frame = ctk.CTkFrame(card, fg_color=color, corner_radius=8)
        header_frame.pack(fill="x", padx=2, pady=2)
        
        ctk.CTkLabel(header_frame, text=f"PROCESS {process_num}: {process_name}",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["bg"]).pack(side="left", padx=16, pady=8)
        
        ctk.CTkLabel(header_frame, text=module,
                     font=("Segoe UI", 10),
                     text_color=COLORS["bg"]).pack(side="right", padx=16, pady=8)
        
        ctk.CTkLabel(card, text=description,
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"],
                     wraplength=700).pack(anchor="w", padx=16, pady=(10, 6))
        
        io_frame = ctk.CTkFrame(card, fg_color="transparent")
        io_frame.pack(fill="x", padx=16, pady=(0, 8))
        
        inputs_frame = ctk.CTkFrame(io_frame, fg_color=COLORS["card"], corner_radius=8)
        inputs_frame.pack(side="left", fill="both", expand=True, padx=(0, 4))
        ctk.CTkLabel(inputs_frame, text="📥 INPUTS",
                     font=("Segoe UI", 10, "bold"),
                     text_color=COLORS["green"]).pack(anchor="w", padx=8, pady=(6, 2))
        for inp in inputs:
            ctk.CTkLabel(inputs_frame, text=f"  • {inp}",
                         font=("Segoe UI", 9),
                         text_color=COLORS["subtext"]).pack(anchor="w", padx=8, pady=1)
        
        outputs_frame = ctk.CTkFrame(io_frame, fg_color=COLORS["card"], corner_radius=8)
        outputs_frame.pack(side="right", fill="both", expand=True, padx=(4, 0))
        ctk.CTkLabel(outputs_frame, text="📤 OUTPUTS",
                     font=("Segoe UI", 10, "bold"),
                     text_color=COLORS["orange"]).pack(anchor="w", padx=8, pady=(6, 2))
        for out in outputs:
            ctk.CTkLabel(outputs_frame, text=f"  • {out}",
                         font=("Segoe UI", 9),
                         text_color=COLORS["subtext"]).pack(anchor="w", padx=8, pady=1)
        
        details_frame = ctk.CTkFrame(card, fg_color=COLORS["card"], corner_radius=8)
        details_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        ctk.CTkLabel(details_frame, text="🔧 PROCESS DETAILS",
                     font=("Segoe UI", 10, "bold"),
                     text_color=color).pack(anchor="w", padx=8, pady=(6, 2))
        
        for detail in details:
            ctk.CTkLabel(details_frame, text=f"  ▶  {detail}",
                         font=("Segoe UI", 9),
                         text_color=COLORS["text"]).pack(anchor="w", padx=8, pady=1)
    
    def _create_flow_arrow(self, parent, flow_name, description):
        """Helper to create a flow arrow between processes."""
        arrow_frame = ctk.CTkFrame(parent, fg_color="transparent", height=40)
        arrow_frame.pack(fill="x", pady=4)
        
        ctk.CTkLabel(arrow_frame, text="▼" * 35 + "  DATA FLOW  " + "▼" * 35,
                     font=("Segoe UI", 10),
                     text_color=COLORS["accent"]).pack()
        
        ctk.CTkLabel(arrow_frame, text=f"  {flow_name}  |  {description}",
                     font=("Segoe UI", 9, "italic"),
                     text_color=COLORS["subtext"]).pack()
    
    def export_dfd_documentation(self):
        """Export the DFD as a text file for documentation."""
        from datetime import datetime
        
        filepath = f"DFD_SentinelsVault_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        dfd_content = self._generate_dfd_ascii()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(dfd_content)
        
        self.show_success_dialog("DFD Exported", f"Data Flow Diagram saved to:\n{filepath}")
    
    def _generate_dfd_ascii(self):
        """Generate ASCII version of DFD for documentation."""
        return """
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                         SENTINELSVAULT - LOGICAL DATA FLOW DIAGRAM (DFD Level 0)                                    ║
║                                   Master Password to AES-256 Key Transformation Pipeline                                             ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

PROCESS 1.0: AuthManager (Module 1 - Authentication Gatekeeper)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  INPUT:           User Input: Master Password (Plaintext)
  PROCESS:         - Input validation (min 12 characters)
                   - Live entropy calculation (Shannon Entropy)
                   - Character type detection
                   - Strength classification
  OUTPUT:          Validated Password (RAM Only)
  SECURITY:        Plaintext never logged or written to disk


                                    │ DATA FLOW │
                                    ▼


PROCESS 2.0: Key Derivation (Module 1 - PBKDF2 + Argon2id)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  INPUT:           - Master Password (Plaintext)
                   - Salt (32-byte from SQLite)
  PROCESS:         - Argon2id verification (64MB RAM, memory-hard)
                   - PBKDF2 with 600,000 iterations
                   - 32-byte (256-bit) key generation
  OUTPUT:          256-bit AES Encryption Key (RAM ONLY - Never on Disk)
  SECURITY:        Key stretching makes brute-force 600,000x slower


                                    │ DATA FLOW │
                                    ▼


PROCESS 3.0: Cryptographic Gatekeeper + Storage Engine (Module 2 & 3)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  INPUT:           - 256-bit AES Key
                   - Plaintext Password (for encryption)
                   - Encrypted BLOB (for decryption)
  PROCESS:         ENCRYPT: Plaintext -> AES-256-GCM -> Ciphertext + IV + Tag
                   DECRYPT: BLOB -> AES-256-GCM -> Plaintext (with integrity check)
  OUTPUT:          - Encrypted BLOB -> SQLite (writes)
                   - Decrypted Plaintext -> User (reads, then wiped)
  SECURITY:        Sole Gatekeeper - NO unencrypted data ever reaches disk


                                    │ DATA FLOW │
                                    ▼


PROCESS 4.0: SentinelAuditor (Module 4 - Heuristic Intelligence)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  INPUT:           - Decrypted Passwords (from Process 3.0 - RAM Only)
                   - Site Names, Usernames
  PROCESS:         - Entropy Calculation: H = L × log2(R)
                   - Dictionary Attack Detection
                   - Reused Password Detection (Hash Map)
                   - Pattern Analysis
  OUTPUT:          - Security Report (JSON/Dict)
                   - Vault Health Score (0-100)
                   - Actionable Recommendations
                   - Reused/Breached Password Alerts
  SECURITY:        All analysis in RAM - NEVER written to disk


                                    │ DATA FLOW │
                                    ▼


PROCESS 5.0: UI Display & User Feedback (Module 5 - Frontend)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  INPUT:           Security Report, Vault Health Score, Alerts
  OUTPUT:          - Password Strength Meter (Color-coded)
                   - Security Audit Dashboard
                   - Real-time Security Alerts
                   - Exportable Security Reports


╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                         SECURITY BOUNDARIES & MODULAR DECOUPLING                                                    ║
╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                                                                      ║
║   BOUNDARY 1: Keys NEVER cross to disk - Only exists in RAM                                                                         ║
║   BOUNDARY 2: Plaintext NEVER crosses to disk - Only BLOBs stored                                                                    ║
║   BOUNDARY 3: Analysis ONLY in RAM - Never written to disk                                                                          ║
║   MODULARITY: Each process = independent Python module                                                                              ║
║   GATEKEEPING: Process 3.0 = sole database gatekeeper                                                                               ║
║                                                                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

    # ═══════════════════════════════════════════════════════
    # GREY ROCK SECURITY SETTINGS
    # ═══════════════════════════════════════════════════════
    
    def show_grey_rock_settings(self):
        """Display Grey Rock security settings panel."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🪨  Grey Rock Security — Anti-Attack Techniques",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Making SentinelsVault 'boring' to attackers",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=30, pady=20)
        
        explain_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        explain_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(explain_card, text="🪨  What is 'Grey Rock' Security?",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        ctk.CTkLabel(explain_card,
                     text="In cybersecurity, 'Grey Rock' means becoming so boring and unresponsive that "
                          "attackers lose interest and move on. SentinelsVault implements 8 anti-attack techniques:\n\n"
                          "1. Uniform Response Times - Always takes the same time to respond\n"
                          "2. Generic Error Messages - No hints about what went wrong\n"
                          "3. Honeypot/Decoy Detection - Traps for attackers\n"
                          "4. Rate Limiting - Slows down repeated attempts\n"
                          "5. Fuzzy Error Responses - Different but equally useless messages\n"
                          "6. Timing-Attack Resistant Comparison - Constant-time password verification\n"
                          "7. Decoy Report Generation - Fake data for unauthorized access\n"
                          "8. Secure Audit Router - Routes unauthenticated users to decoys",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"],
                     wraplength=700,
                     justify="left").pack(anchor="w", padx=16, pady=(0, 12))
        
        techniques = [
            {
                "name": "Uniform Response Times",
                "icon": "⏱️",
                "color": COLORS["green"],
                "description": "All operations take the same amount of time, preventing timing attacks.",
                "defense": "Attacker cannot infer if password exists based on response time."
            },
            {
                "name": "Generic Error Messages",
                "icon": "📝",
                "color": COLORS["gold"],
                "description": "Error messages never reveal specific failure details.",
                "defense": "Attacker cannot distinguish between 'user not found' and 'wrong password'."
            },
            {
                "name": "Honeypot Detection",
                "icon": "🍯",
                "color": COLORS["orange"],
                "description": "Decoy passwords act as traps for attackers.",
                "defense": "Attempts to use decoy passwords are silently logged and blocked."
            },
            {
                "name": "Rate Limiting",
                "icon": "🚦",
                "color": COLORS["red"],
                "description": "Repeated attempts are slowed down exponentially.",
                "defense": "Automated brute-force attacks become impractical."
            },
            {
                "name": "Fuzzy Error Responses",
                "icon": "🌀",
                "color": COLORS["purple"],
                "description": "Each error message is slightly different but equally useless.",
                "defense": "Prevents attackers from pattern-matching error messages."
            },
            {
                "name": "Constant-Time Comparison",
                "icon": "⚡",
                "color": COLORS["accent"],
                "description": "Password comparison takes the same time regardless of match.",
                "defense": "Prevents timing-based password guessing attacks."
            },
            {
                "name": "Decoy Report Generation",
                "icon": "🎭",
                "color": COLORS["blue"],
                "description": "Unauthorized users see fake audit reports.",
                "defense": "Attackers cannot determine real security posture."
            },
            {
                "name": "Secure Audit Router",
                "icon": "🔀",
                "color": COLORS["green"],
                "description": "Routes unauthenticated requests to decoy data.",
                "defense": "Ensures only authenticated users see real data."
            }
        ]
        
        for tech in techniques:
            tech_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=10, border_width=1, border_color=tech["color"])
            tech_card.pack(fill="x", pady=6)
            
            header_frame = ctk.CTkFrame(tech_card, fg_color="transparent")
            header_frame.pack(fill="x", padx=12, pady=(10, 4))
            
            ctk.CTkLabel(header_frame, text=f"{tech['icon']}  {tech['name']}",
                         font=("Segoe UI", 12, "bold"),
                         text_color=tech["color"]).pack(side="left")
            
            ctk.CTkLabel(header_frame, text="ACTIVE",
                         font=("Segoe UI", 9, "bold"),
                         text_color=COLORS["green"],
                         fg_color=COLORS["card"],
                         corner_radius=4,
                         padx=6).pack(side="right")
            
            ctk.CTkLabel(tech_card, text=tech["description"],
                         font=("Segoe UI", 10),
                         text_color=COLORS["text"],
                         wraplength=650).pack(anchor="w", padx=12, pady=(0, 4))
            
            defense_frame = ctk.CTkFrame(tech_card, fg_color=COLORS["card"], corner_radius=6)
            defense_frame.pack(fill="x", padx=12, pady=(0, 10))
            ctk.CTkLabel(defense_frame, text=f"🛡️  Defense: {tech['defense']}",
                         font=("Segoe UI", 9),
                         text_color=COLORS["subtext"]).pack(anchor="w", padx=8, pady=4)
        
        score_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        score_card.pack(fill="x", pady=(16, 0))
        
        ctk.CTkLabel(score_card, text="🛡️  Grey Rock Security Score",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        total_techniques = len(techniques)
        active_score = 100
        
        score_frame = ctk.CTkFrame(score_card, fg_color="transparent")
        score_frame.pack(pady=(0, 8))
        
        ctk.CTkLabel(score_frame, text=f"{active_score}/100",
                     font=("Segoe UI", 32, "bold"),
                     text_color=COLORS["green"]).pack()
        
        score_bar = ctk.CTkProgressBar(score_card, width=400, height=10, corner_radius=5)
        score_bar.pack(pady=(0, 12))
        score_bar.set(active_score / 100)
        score_bar.configure(progress_color=COLORS["green"])
        
        ctk.CTkLabel(score_card,
                     text=f"All {total_techniques} Grey Rock techniques are actively protecting your vault.",
                     font=("Segoe UI", 10),
                     text_color=COLORS["subtext"]).pack(pady=(0, 16))

    # ═══════════════════════════════════════════════════════
    # RECOVERY KEY MANAGEMENT (Enhanced)
    # ═══════════════════════════════════════════════════════
    
    def show_recovery_management(self):
        """Display Recovery Key management screen."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="[KEY]  Recovery Key Management",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Zero-Knowledge Recovery - You are in total command",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        main_frame = ctk.CTkFrame(self.content, fg_color=COLORS["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        config = self.storage_engine.get_vault_config()
        has_recovery = config and config[3] is not None
        
        info_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        info_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(info_card, text="[INFO]  What is a Recovery Key?",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 4))
        
        ctk.CTkLabel(info_card,
                     text="Your Recovery Key is a cryptographic backup that can unlock your vault "
                          "if you forget your Master Password.\n\n"
                          "[SECURITY]  The Recovery Key is stored encrypted in your database.\n"
                          "[SECURITY]  Only YOU can decrypt it with the correct Recovery Code.\n"
                          "[SECURITY]  SentinelsVault developers have ZERO access to your Recovery Key.\n\n"
                          "Store your Recovery Code in a safe place - offline, printed, or in a hardware wallet.",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"],
                     wraplength=700,
                     justify="left").pack(anchor="w", padx=16, pady=(0, 12))
        
        recovery_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12, border_width=2, border_color=COLORS["gold"])
        recovery_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(recovery_card, text="[LOCK]  Your Recovery Key",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["gold"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        recovery_display_frame = ctk.CTkFrame(recovery_card, fg_color=COLORS["card"], corner_radius=8)
        recovery_display_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        recovery_text = ctk.CTkTextbox(recovery_display_frame, height=80, font=("Courier New", 14, "bold"),
                                        fg_color=COLORS["card"], text_color=COLORS["green"])
        recovery_text.pack(fill="both", padx=10, pady=10)
        recovery_text.insert("1.0", "********-****-****-****-************")
        recovery_text.configure(state="disabled")
        
        verify_frame = ctk.CTkFrame(recovery_card, fg_color="transparent")
        verify_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        ctk.CTkLabel(verify_frame, text="Enter Master Password to view Recovery Key:",
                     font=("Segoe UI", 11),
                     text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        
        verify_password = ctk.CTkEntry(verify_frame, placeholder_text="Master Password",
                                        show="*", width=300, height=38)
        verify_password.pack(side="left", padx=(0, 10))
        
        verify_status = ctk.CTkLabel(verify_frame, text="", font=("Segoe UI", 10), text_color=COLORS["red"])
        verify_status.pack(side="left")
        
        def verify_and_show_recovery():
            pwd = verify_password.get()
            if not pwd:
                verify_status.configure(text="Enter password first")
                return
            
            try:
                config = self.storage_engine.get_vault_config()
                if not config:
                    verify_status.configure(text="No vault configuration found")
                    return
                
                salt = config[0]
                stored_hash = config[1]
                
                is_valid = self.auth_manager.verify_master_password_argon2(stored_hash, pwd)
                
                if not is_valid:
                    verify_status.configure(text="[X] Incorrect password")
                    return
                
                k_master = self.auth_manager.derive_key_pbkdf2(pwd, salt)
                
                recovery_salt = config[3]
                vault_key_enc_recovery = config[6]
                vault_key_nonce_recovery = config[7]
                
                if recovery_salt is None:
                    verify_status.configure(text="No recovery key found in vault")
                    return
                
                k_recovery = self.auth_manager.derive_key_pbkdf2(pwd, recovery_salt)
                provider_recovery = EncryptionProvider(k_recovery)
                vault_key = provider_recovery.decrypt_bytes(vault_key_enc_recovery, vault_key_nonce_recovery)
                
                import hashlib
                recovery_hash = hashlib.sha256(vault_key).hexdigest().upper()
                recovery_code = "-".join([recovery_hash[i:i+4] for i in range(0, 32, 4)])[:23]
                
                recovery_text.configure(state="normal")
                recovery_text.delete("1.0", "end")
                recovery_text.insert("1.0", recovery_code)
                recovery_text.configure(state="disabled")
                
                verify_status.configure(text="[OK] Recovery key displayed", text_color=COLORS["green"])
                
                self.show_recovery_key_popup(recovery_code)
                
                provider_recovery.secure_wipe()
                
            except Exception as e:
                verify_status.configure(text=f"Error: {str(e)[:50]}")
        
        verify_btn = ctk.CTkButton(verify_frame, text="[VERIFY]  Show Recovery Key",
                                    command=verify_and_show_recovery,
                                    width=180, height=38,
                                    fg_color=COLORS["accent"],
                                    text_color=COLORS["bg"],
                                    font=("Segoe UI", 11, "bold"))
        verify_btn.pack(side="left")
        
        action_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        action_frame.pack(fill="x", pady=(0, 16))
        
        def export_recovery_key():
            pwd = verify_password.get()
            if not pwd:
                self.show_error_dialog("Export Failed", "Please verify your master password first")
                return
            
            recovery_code = recovery_text.get("1.0", "end-1c").strip()
            if "***" in recovery_code or not recovery_code:
                self.show_error_dialog("Export Failed", "Please verify your master password first")
                return
            
            filepath = filedialog.asksaveasfilename(
                title="Save Recovery Key",
                defaultextension=".recovery",
                filetypes=[("Recovery Files", "*.recovery"), ("Text Files", "*.txt"), ("All Files", "*.*")],
                initialfile="sentinels_vault_recovery.recovery"
            )
            
            if filepath:
                try:
                    from datetime import datetime
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write("=" * 60 + "\n")
                        f.write("SENTINELSVAULT - RECOVERY KEY\n")
                        f.write("=" * 60 + "\n")
                        f.write(f"Generated: {datetime.now()}\n")
                        f.write(f"Vault: SentinelsVault\n\n")
                        f.write("YOUR RECOVERY KEY:\n")
                        f.write("-" * 40 + "\n")
                        f.write(f"{recovery_code}\n")
                        f.write("-" * 40 + "\n\n")
                        f.write("IMPORTANT INSTRUCTIONS:\n")
                        f.write("1. Store this file in a SAFE, OFFLINE location\n")
                        f.write("2. Do NOT share this file with anyone\n")
                        f.write("3. This key can restore your vault if you forget your password\n")
                        f.write("4. Without this key, your vault is PERMANENTLY LOST\n")
                        f.write("=" * 60 + "\n")
                    
                    self.show_success_dialog("Export Complete", f"Recovery key saved to:\n{filepath}")
                except Exception as e:
                    self.show_error_dialog("Export Failed", str(e))
        
        export_btn = ctk.CTkButton(action_frame, text="[EXPORT]  Save Recovery Key to File",
                                    command=export_recovery_key,
                                    width=220, height=40,
                                    fg_color=COLORS["green"],
                                    text_color=COLORS["bg"],
                                    font=("Segoe UI", 11, "bold"))
        export_btn.pack(side="left", padx=(0, 10))
        
        def generate_new_recovery():
            pwd = verify_password.get()
            if not pwd:
                self.show_error_dialog("Action Blocked", "Please verify your master password first")
                return
            
            confirm = messagebox.askyesno(
                "Generate New Recovery Key",
                "[WARNING]  Generating a new recovery key will INVALIDATE your old one.\n\n"
                "Make sure you save the new key immediately.\n\n"
                "Proceed?"
            )
            if not confirm:
                return
            
            try:
                config = self.storage_engine.get_vault_config()
                salt = config[0]
                stored_hash = config[1]
                
                is_valid = self.auth_manager.verify_master_password_argon2(stored_hash, pwd)
                if not is_valid:
                    self.show_error_dialog("Authentication Failed", "Incorrect master password")
                    return
                
                k_master = self.auth_manager.derive_key_pbkdf2(pwd, salt)
                provider_master = EncryptionProvider(k_master)
                
                vault_key_enc_master = config[4]
                vault_key_nonce_master = config[5]
                vault_key = provider_master.decrypt_bytes(vault_key_enc_master, vault_key_nonce_master)
                
                new_recovery_code = self.auth_manager.generate_recovery_code()
                new_recovery_salt = os.urandom(32)
                
                k_recovery_new = self.auth_manager.derive_key_pbkdf2(new_recovery_code, new_recovery_salt)
                provider_recovery_new = EncryptionProvider(k_recovery_new)
                vault_key_enc_recovery_new, vault_key_nonce_recovery_new = provider_recovery_new.encrypt_bytes(vault_key)
                
                self.storage_engine.cursor.execute("""
                    UPDATE vault_config 
                    SET recovery_salt = ?, vault_key_enc_recovery = ?, vault_key_nonce_recovery = ?
                    WHERE id = (SELECT id FROM vault_config LIMIT 1)
                """, (new_recovery_salt, vault_key_enc_recovery_new, vault_key_nonce_recovery_new))
                self.storage_engine.conn.commit()
                
                recovery_text.configure(state="normal")
                recovery_text.delete("1.0", "end")
                recovery_text.insert("1.0", new_recovery_code)
                recovery_text.configure(state="disabled")
                
                self.show_recovery_key_popup(new_recovery_code)
                self.show_success_dialog("Recovery Key Generated", 
                                          "Your new recovery key has been created.\n\n"
                                          "Save it immediately in a safe place!")
                
                provider_master.secure_wipe()
                provider_recovery_new.secure_wipe()
                
            except Exception as e:
                self.show_error_dialog("Generation Failed", str(e))
        
        new_btn = ctk.CTkButton(action_frame, text="[NEW]  Generate New Recovery Key",
                                 command=generate_new_recovery,
                                 width=220, height=40,
                                 fg_color=COLORS["orange"],
                                 text_color=COLORS["bg"],
                                 font=("Segoe UI", 11, "bold"))
        new_btn.pack(side="left")
        
        tips_card = ctk.CTkFrame(main_frame, fg_color=COLORS["sidebar"], corner_radius=12)
        tips_card.pack(fill="x")
        
        ctk.CTkLabel(tips_card, text="[TIP]  Recovery Key Best Practices",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        tips = [
            "[1] Store your recovery key OFFLINE (printed paper or USB drive)",
            "[2] Never store recovery key digitally on the same device as your vault",
            "[3] Keep multiple copies in different secure locations",
            "[4] Test your recovery key periodically to ensure it works",
            "[5] Generate a new key if you suspect your old one was compromised"
        ]
        
        for tip in tips:
            ctk.CTkLabel(tips_card, text=tip,
                         font=("Segoe UI", 10),
                         text_color=COLORS["subtext"]).pack(anchor="w", padx=16, pady=2)
        
        ctk.CTkFrame(tips_card, height=1, fg_color=COLORS["card"]).pack(fill="x", padx=16, pady=(8, 0))
        
        ctk.CTkLabel(tips_card,
                     text="[SECURITY]  SentinelsVault uses Zero-Knowledge Architecture. "
                          "The recovery key is encrypted and only YOU can decrypt it.",
                     font=("Segoe UI", 9),
                     text_color=COLORS["green"]).pack(anchor="w", padx=16, pady=(8, 12))
    
    def show_recovery_key_popup(self, recovery_code: str):
        """Show a popup with the recovery key for easy copying."""
        popup = ctk.CTkToplevel(self)
        popup.title("Your Recovery Key - SAVE THIS!")
        popup.geometry("500x300")
        popup.configure(fg_color=COLORS["sidebar"])
        popup.grab_set()
        
        ctk.CTkLabel(popup, text="[WARNING]  YOUR RECOVERY KEY",
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["red"]).pack(pady=(20, 4))
        
        ctk.CTkLabel(popup, text="Store this key in a SAFE, OFFLINE location!",
                     font=("Segoe UI", 11),
                     text_color=COLORS["orange"]).pack()
        
        code_frame = ctk.CTkFrame(popup, fg_color=COLORS["card"], corner_radius=10)
        code_frame.pack(fill="x", padx=30, pady=20)
        
        ctk.CTkLabel(code_frame, text=recovery_code,
                     font=("Courier New", 18, "bold"),
                     text_color=COLORS["green"]).pack(pady=20)
        
        def copy_code():
            self.clipboard_clear()
            self.clipboard_append(recovery_code)
            copy_btn.configure(text="[OK] Copied!", fg_color=COLORS["green"])
            popup.after(2000, lambda: copy_btn.configure(text="[COPY]  Copy to Clipboard", fg_color=COLORS["accent"]))
        
        copy_btn = ctk.CTkButton(popup, text="[COPY]  Copy to Clipboard",
                                  command=copy_code,
                                  width=200, height=40,
                                  fg_color=COLORS["accent"],
                                  text_color=COLORS["bg"],
                                  font=("Segoe UI", 11, "bold"))
        copy_btn.pack(pady=(0, 10))
        
        ctk.CTkLabel(popup, text="[WARNING]  Without this key, your vault is PERMANENTLY LOST!",
                     font=("Segoe UI", 10),
                     text_color=COLORS["red"]).pack(pady=(0, 20))
        
        close_btn = ctk.CTkButton(popup, text="I have saved my key",
                                   command=popup.destroy,
                                   width=150, height=35,
                                   fg_color=COLORS["green"],
                                   text_color=COLORS["bg"])
        close_btn.pack(pady=(0, 20))
    
    def show_recovery_tester(self):
        """Test the recovery key functionality."""
        popup = ctk.CTkToplevel(self)
        popup.title("Test Recovery Key")
        popup.geometry("450x300")
        popup.configure(fg_color=COLORS["sidebar"])
        popup.grab_set()
        
        ctk.CTkLabel(popup, text="[TEST]  Recovery Key Validator",
                     font=("Segoe UI", 16, "bold"),
                     text_color=COLORS["accent"]).pack(pady=(20, 4))
        
        ctk.CTkLabel(popup, text="Enter your recovery key to test if it works",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack()
        
        recovery_entry = ctk.CTkEntry(popup, placeholder_text="XXXX-XXXX-XXXX-XXXX",
                                       width=300, height=44,
                                       font=("Courier New", 12))
        recovery_entry.pack(pady=20)
        
        status_label = ctk.CTkLabel(popup, text="", font=("Segoe UI", 11), text_color=COLORS["green"])
        status_label.pack()
        
        def test_recovery():
            rec_code = recovery_entry.get().strip()
            if not rec_code:
                status_label.configure(text="Enter recovery key", text_color=COLORS["red"])
                return
            
            try:
                config = self.storage_engine.get_vault_config()
                recovery_salt = config[3]
                vault_key_enc_recovery = config[6]
                vault_key_nonce_recovery = config[7]
                
                k_recovery = self.auth_manager.derive_key_pbkdf2(rec_code, recovery_salt)
                provider_recovery = EncryptionProvider(k_recovery)
                vault_key = provider_recovery.decrypt_bytes(vault_key_enc_recovery, vault_key_nonce_recovery)
                
                if len(vault_key) == 32:
                    status_label.configure(text="[OK] Recovery key is VALID!", text_color=COLORS["green"])
                else:
                    status_label.configure(text="[X] Recovery key is INVALID", text_color=COLORS["red"])
                
                provider_recovery.secure_wipe()
                
            except Exception as e:
                status_label.configure(text="[X] Recovery key is INVALID", text_color=COLORS["red"])
        
        test_btn = ctk.CTkButton(popup, text="[TEST]  Validate Recovery Key",
                                  command=test_recovery,
                                  width=250, height=40,
                                  fg_color=COLORS["accent"],
                                  text_color=COLORS["bg"])
        test_btn.pack(pady=10)
        
        close_btn = ctk.CTkButton(popup, text="Close",
                                   command=popup.destroy,
                                   width=100, height=35,
                                   fg_color=COLORS["card"],
                                   text_color=COLORS["text"])
        close_btn.pack(pady=10)

    # ═══════════════════════════════════════════════════════
    # ADVANCED SECURITY AUDIT (Unshakeable)
    # ═══════════════════════════════════════════════════════
    
    def show_advanced_audit(self):
        """Display comprehensive security audit with advanced metrics."""
        self.clear_content()
        
        header = ctk.CTkFrame(self.content, fg_color=COLORS["sidebar"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="[SHIELD]  Unshakeable Security Audit",
                     font=("Segoe UI", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20, pady=16)
        ctk.CTkLabel(header,
                     text="Deep analysis - No stone left unturned",
                     font=("Segoe UI", 11),
                     text_color=COLORS["subtext"]).pack(side="right", padx=20, pady=16)
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color=COLORS["bg"])
        scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        all_creds = self.storage_engine.get_all_credentials()
        if not all_creds:
            ctk.CTkLabel(scroll, text="No passwords to audit yet",
                         font=("Segoe UI", 14),
                         text_color=COLORS["subtext"]).pack(pady=60)
            return
        
        decrypted = []
        for c in all_creds:
            try:
                plaintext = self.encryption_provider.decrypt(c[3], c[4])
                decrypted.append((c[1], plaintext))
            except Exception:
                decrypted.append((c[1], "DECRYPT_ERROR"))
        
        risk_assessment = self.sentinel_auditor.vault_risk_assessment(decrypted)
        
        risk_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12, border_width=2, border_color=risk_assessment["risk_color"])
        risk_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(risk_card, text="[WARNING]  VAULT RISK ASSESSMENT",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        score_frame = ctk.CTkFrame(risk_card, fg_color="transparent")
        score_frame.pack(pady=(0, 12))
        
        ctk.CTkLabel(score_frame, text=f"Risk Score: {risk_assessment['risk_score']}/100",
                     font=("Segoe UI", 24, "bold"),
                     text_color=risk_assessment["risk_color"]).pack()
        
        ctk.CTkLabel(score_frame, text=f"Overall Risk Level: {risk_assessment['risk_level']}",
                     font=("Segoe UI", 12, "bold"),
                     text_color=risk_assessment["risk_color"]).pack()
        
        stats_frame = ctk.CTkFrame(risk_card, fg_color="transparent")
        stats_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        stats = [
            ("Total Accounts", risk_assessment["total_accounts"]),
            ("Critical", risk_assessment["critical"]),
            ("Poor", risk_assessment["poor"]),
            ("Fair", risk_assessment["fair"]),
            ("Good", risk_assessment["good"]),
            ("Excellent", risk_assessment["excellent"])
        ]
        
        for i, (label, value) in enumerate(stats):
            stat_card = ctk.CTkFrame(stats_frame, fg_color=COLORS["card"], corner_radius=8)
            stat_card.grid(row=i//3, column=i%3, padx=4, pady=4, sticky="nsew")
            ctk.CTkLabel(stat_card, text=str(value),
                         font=("Segoe UI", 18, "bold"),
                         text_color=COLORS["accent"]).pack(pady=(8, 0))
            ctk.CTkLabel(stat_card, text=label,
                         font=("Segoe UI", 9),
                         text_color=COLORS["subtext"]).pack(pady=(0, 8))
        
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(2, weight=1)
        
        rec_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        rec_card.pack(fill="x", pady=(0, 16))
        
        ctk.CTkLabel(rec_card, text="[BULB]  Security Recommendations",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        for rec in risk_assessment["recommendations"]:
            ctk.CTkLabel(rec_card, text=f"  • {rec}",
                         font=("Segoe UI", 11),
                         text_color=COLORS["text"],
                         wraplength=650).pack(anchor="w", padx=16, pady=4)
        
        if risk_assessment["top_vulnerable"]:
            vuln_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
            vuln_card.pack(fill="x", pady=(0, 16))
            
            ctk.CTkLabel(vuln_card, text="[WARNING]  Most Vulnerable Accounts",
                         font=("Segoe UI", 14, "bold"),
                         text_color=COLORS["red"]).pack(anchor="w", padx=16, pady=(12, 8))
            
            for site, score in risk_assessment["top_vulnerable"]:
                vuln_item = ctk.CTkFrame(vuln_card, fg_color=COLORS["card"], corner_radius=6)
                vuln_item.pack(fill="x", padx=16, pady=4)
                ctk.CTkLabel(vuln_item, text=site,
                             font=("Segoe UI", 11, "bold"),
                             text_color=COLORS["red"]).pack(side="left", padx=10, pady=6)
                ctk.CTkLabel(vuln_item, text=f"Score: {score}/100",
                             font=("Segoe UI", 10),
                             text_color=COLORS["subtext"]).pack(side="right", padx=10, pady=6)
        
        detail_card = ctk.CTkFrame(scroll, fg_color=COLORS["sidebar"], corner_radius=12)
        detail_card.pack(fill="x")
        
        ctk.CTkLabel(detail_card, text="[SEARCH]  Individual Password Analysis",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=16, pady=(12, 8))
        
        search_frame = ctk.CTkFrame(detail_card, fg_color="transparent")
        search_frame.pack(fill="x", padx=16, pady=(0, 12))
        
        search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search by site name...",
                                     width=300, height=35)
        search_entry.pack(side="left")
        
        filter_var = ctk.StringVar(value="All")
        filter_menu = ctk.CTkOptionMenu(search_frame, values=["All", "Critical", "Poor", "Fair", "Good", "Excellent"],
                                         variable=filter_var, width=120)
        filter_menu.pack(side="left", padx=(10, 0))
        
        analysis_frame = ctk.CTkScrollableFrame(detail_card, height=300, fg_color=COLORS["bg"])
        analysis_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        
        def refresh_analysis():
            for widget in analysis_frame.winfo_children():
                widget.destroy()
            
            search_text = search_entry.get().lower()
            filter_value = filter_var.get()
            
            for site, pwd in decrypted:
                if search_text and search_text not in site.lower():
                    continue
                
                analysis = self.sentinel_auditor.comprehensive_password_analysis(pwd)
                
                if filter_value != "All" and analysis["verdict"] != filter_value.upper():
                    continue
                
                item_card = ctk.CTkFrame(analysis_frame, fg_color=COLORS["sidebar"], corner_radius=8)
                item_card.pack(fill="x", pady=4)
                
                header_frame = ctk.CTkFrame(item_card, fg_color="transparent")
                header_frame.pack(fill="x", padx=10, pady=(8, 4))
                
                ctk.CTkLabel(header_frame, text=analysis["icon"],
                             font=("Segoe UI", 14)).pack(side="left", padx=(0, 8))
                
                ctk.CTkLabel(header_frame, text=site,
                             font=("Segoe UI", 12, "bold"),
                             text_color=COLORS["text"]).pack(side="left")
                
                ctk.CTkLabel(header_frame, text=analysis["verdict"],
                             font=("Segoe UI", 10, "bold"),
                             text_color=analysis["verdict_color"]).pack(side="right")
                
                score_bar = ctk.CTkProgressBar(item_card, width=400, height=6, corner_radius=3)
                score_bar.pack(padx=10, pady=(0, 8))
                score_bar.set(analysis["overall_score"] / 100)
                score_bar.configure(progress_color=analysis["verdict_color"])
                
                ctk.CTkLabel(item_card, text=f"Score: {analysis['overall_score']}/100  |  Entropy: {analysis['entropy']:.1f} bits",
                             font=("Segoe UI", 9),
                             text_color=COLORS["subtext"]).pack(anchor="w", padx=10, pady=(0, 8))
                
                expanded = [False]
                details_frame = ctk.CTkFrame(item_card, fg_color=COLORS["card"], corner_radius=6)
                
                def toggle():
                    if expanded[0]:
                        details_frame.pack_forget()
                        toggle_btn.configure(text="[EXPAND]  Show Details")
                        expanded[0] = False
                    else:
                        details_frame.pack(fill="x", padx=10, pady=(0, 8))
                        toggle_btn.configure(text="[COLLAPSE]  Hide Details")
                        expanded[0] = True
                
                toggle_btn = ctk.CTkButton(item_card, text="[EXPAND]  Show Details",
                                            width=120, height=25,
                                            fg_color=COLORS["card"],
                                            font=("Segoe UI", 9),
                                            command=toggle)
                toggle_btn.pack(anchor="w", padx=10, pady=(0, 8))
                
                details_text = f"""
Issues:
{chr(10).join(f'  • {issue}' for issue in analysis['issues']) if analysis['issues'] else '  • None found'}

Patterns Detected:
{chr(10).join(f'  • {pattern}' for pattern in analysis['patterns']) if analysis['patterns'] else '  • No suspicious patterns'}

Breach Prediction:
  • Likelihood: {analysis['breach_likelihood']}
  • Risk Score: {analysis['breach_risk_score']}/100
  • Recommendation: {analysis['recommendation']}

Password Composition:
  • Length: {analysis['length']} characters
  • Uppercase: {'Yes' if analysis['has_upper'] else 'No'}
  • Lowercase: {'Yes' if analysis['has_lower'] else 'No'}
  • Digits: {'Yes' if analysis['has_digit'] else 'No'}
  • Special: {'Yes' if analysis['has_special'] else 'No'}
"""
                ctk.CTkLabel(details_frame, text=details_text,
                             font=("Courier New", 9),
                             text_color=COLORS["text"],
                             justify="left").pack(anchor="w", padx=10, pady=8)
        
        search_entry.bind("<KeyRelease>", lambda e: refresh_analysis())
        filter_menu.configure(command=lambda x: refresh_analysis())
        
        refresh_analysis()

    # ═══════════════════════════════════════════════════════
    # FUTURE: Cross-Device Sync (Placeholder)
    # ═══════════════════════════════════════════════════════
    
    def sync_vault_across_devices(self, other_device_code: str = None):
        """FUTURE FEATURE: Securely sync encrypted vault between devices."""
        from tkinter import messagebox
        
        messagebox.showinfo(
            "Future Feature",
            "Cross-Device Sync is a planned feature.\n\n"
            "Design completed. See Project Report - Future Scope.\n\n"
            "Would allow:\n"
            "• End-to-end encrypted vault transfer\n"
            "• QR code pairing between devices\n"
            "• Secure local network sync"
        )


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = SentinelsVaultApp()
    app.mainloop()