================================================================
  SENTINELSVAULT — Enterprise-Grade Cryptographic Password Manager
  Version: 1.0
  Architecture: Zero-Knowledge | Local-First | AES-256-GCM
================================================================

DEVELOPED BY
─────────────────────────────────────────────
  Name:     [Your Full Name]
  Roll No:  [Your Roll Number]
  Course:   [Your Course Name]
  College:  [Your College Name]
  Year:     2025-2026

----------------------------------------------------------------

PROJECT DESCRIPTION
─────────────────────────────────────────────
SentinelsVault is a local-first, offline-resilient cryptographic
password manager built using Python. It uses AES-256-GCM encryption,
PBKDF2 + Argon2id key derivation, and a Zero-Knowledge architecture
to ensure that sensitive credentials never leave the user's device.

----------------------------------------------------------------

SYSTEM REQUIREMENTS
─────────────────────────────────────────────
  Operating System : Windows 10/11 (64-bit)
  Python Version   : Python 3.10 or higher
  Disk Space       : Minimum 100MB free
  RAM              : Minimum 4GB recommended

----------------------------------------------------------------

PROJECT FOLDER STRUCTURE
─────────────────────────────────────────────
  SENTINELS_VAULT_PROJECT/
  │
  ├── main.py                  → LAUNCH THIS FILE TO RUN THE APP
  ├── auth_manager.py          → Module 1: Authentication & Key Derivation
  ├── encryption_provider.py   → Module 2: AES-256-GCM Cryptographic Engine
  ├── storage_engine.py        → Module 3: SQLite Database Management
  ├── sentinel_auditor.py      → Module 4: Security Auditor (The Sentinel)
  ├── app_ui.py                → Module 5: Graphical User Interface
  ├── sdlc_waterfall.py        → SDLC Validation & Testing Report
  ├── requirements.txt         → List of required Python libraries
  ├── README.txt               → This file
  ├── vault.log                → Auto-generated system activity log
  └── sentinels_vault.db       → Auto-generated encrypted vault database

----------------------------------------------------------------

STEP 1 — INSTALL PYTHON
─────────────────────────────────────────────
  1. Go to https://python.org/downloads
  2. Download Python 3.11 or higher
  3. During installation, CHECK the box "Add Python to PATH"
  4. Click Install Now

  Verify installation by opening Command Prompt and typing:
      python --version
  You should see: Python 3.x.x

----------------------------------------------------------------

STEP 2 — INSTALL REQUIRED LIBRARIES
─────────────────────────────────────────────
  Open Command Prompt, navigate to the project folder, then run:

      pip install customtkinter cryptography argon2-cffi pyotp

  All libraries will install automatically.

  Libraries Used:
  ┌─────────────────┬──────────────────────────────────────────┐
  │ Library         │ Purpose                                  │
  ├─────────────────┼──────────────────────────────────────────┤
  │ customtkinter   │ Modern dark-theme GUI framework          │
  │ cryptography    │ AES-256-GCM encryption engine            │
  │ argon2-cffi     │ Argon2id password hashing                │
  │ pyotp           │ OTP/MFA generation                       │
  │ sqlite3         │ Built-in — no installation needed        │
  └─────────────────┴──────────────────────────────────────────┘

----------------------------------------------------------------

STEP 3 — RUN THE APPLICATION
─────────────────────────────────────────────
  Open Command Prompt in the project folder and type:

      python main.py

  THE FIRST TIME YOU RUN:
  → You will see the Setup Screen.
  → Create a Master Password (minimum 12 characters).
  → This password CANNOT be recovered. Write it down safely.
  → Click "Initialize Vault with Argon2id".

  EVERY SUBSEQUENT RUN:
  → You will see the Login Screen.
  → Enter your Master Password to unlock the vault.
  → Click "Unlock Vault".

----------------------------------------------------------------

STEP 4 — USING THE APPLICATION
─────────────────────────────────────────────
  ADDING A PASSWORD:
  1. Click "Add Secret" in the sidebar
  2. Enter Website Name (e.g. Gmail, GitHub, Netflix)
  3. Enter Username or Email
  4. Enter password OR click "Generate Strong Password"
  5. Select a Category
  6. Click "Encrypt & Save to Vault"
  → Password is encrypted with AES-256-GCM and stored as BLOB

  VIEWING A PASSWORD:
  1. Click "My Vault" in the sidebar
  2. Find the entry you want
  3. Click "View"
  → Password is decrypted in RAM and displayed
  → Clipboard clears automatically after 30 seconds

  SECURITY AUDIT:
  1. Click "Security Audit" in the sidebar
  → The Sentinel scans all passwords
  → Shows Vault Security Score (0-100)
  → Identifies weak, reused, and common passwords

  LOCKING THE VAULT:
  1. Click "Lock Vault" at the bottom of the sidebar
  → The AES-256 key is wiped from RAM immediately
  → Returns to the Login Screen
  → Zero-Knowledge: key no longer exists anywhere

----------------------------------------------------------------

STEP 5 — RUN SDLC VALIDATION REPORT (Optional)
─────────────────────────────────────────────
  To run the automated testing and SDLC phase report, type:

      python sdlc_waterfall.py

  This will validate all 5 modules across 36 tests and print
  a formatted Iterative Waterfall Model report in the terminal.
  Results are also saved to: sdlc_report.log

----------------------------------------------------------------

SECURITY ARCHITECTURE SUMMARY
─────────────────────────────────────────────
  Encryption    : AES-256 in GCM mode (Confidentiality + Integrity)
  Key Derivation: PBKDF2-SHA256 with 600,000 iterations (OWASP 2024)
  Password Hash : Argon2id (memory-hard, 64MB RAM per computation)
  Salt          : 256-bit cryptographic random salt per vault
  IV/Nonce      : 96-bit unique random nonce per encryption
  Storage       : SQLite3 BLOB — encrypted bytes only, no plaintext
  Memory Safety : AES key wiped from RAM on vault lock (Zero-Fill)
  Attack Surface: Zero — fully offline, no network connections

----------------------------------------------------------------

IMPORTANT SECURITY NOTES
─────────────────────────────────────────────
  [!] Your Master Password CANNOT be recovered if forgotten.
      This is by design — Zero-Knowledge Architecture.
      Write it down and store it in a safe physical location.

  [!] The file "sentinels_vault.db" is your encrypted vault.
      Back it up regularly by copying it to a safe location.

  [!] Never share your Master Password with anyone.

  [!] The vault.log file records system activity.
      It contains NO passwords or sensitive data.

----------------------------------------------------------------

TROUBLESHOOTING
─────────────────────────────────────────────
  Problem : "ModuleNotFoundError"
  Solution: Run — python -m pip install customtkinter cryptography
                              argon2-cffi pyotp

  Problem : App window does not open
  Solution: Make sure you are running "python main.py" from
            inside the SENTINELS_VAULT_PROJECT folder

  Problem : "python is not recognized"
  Solution: Reinstall Python and check "Add Python to PATH"

  Problem : Forgot Master Password
  Solution: Delete "sentinels_vault.db" to reset the vault.
            WARNING — all stored passwords will be lost.

----------------------------------------------------------------

FILES GENERATED AUTOMATICALLY (Do Not Delete)
─────────────────────────────────────────────
  sentinels_vault.db  → Your encrypted password database
  vault.log           → System activity log
  sdlc_report.log     → SDLC test validation log

================================================================
  SentinelsVault v1.0 — Built with Python | SQLite | AES-256
  Zero-Knowledge | Local-First | Offline-Resilient
================================================================