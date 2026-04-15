# security_explainer.py
# SECURITY ARCHITECTURE EXPLAINER — Data Module
# Contains all structured data for the "How It Works" screen.
# This file holds ONLY data — no UI logic, no imports needed.
# The UI (app_ui.py) reads this data and renders it visually.
# Keeping data separate from UI is called "Separation of Concerns" —
# a core Software Engineering principle demonstrated here.

# ─────────────────────────────────────────────────────────────────
# SECTION 1: THE ATTACK SCENARIO
# What happens if an attacker steals your sentinels_vault.db file?
# ─────────────────────────────────────────────────────────────────
ATTACK_SCENARIO = {
    "title":       "What Happens If Someone Steals Your Database?",
    "subtitle":    "Why stealing sentinels_vault.db is completely useless to an attacker",
    "scenario":    (
        "Imagine an attacker gains full physical access to your computer "
        "and copies the file 'sentinels_vault.db'. They now have your entire "
        "vault on their machine. Can they read your passwords?"
    ),
    "answer":      "No. Here is exactly why.",
    "steps": [
        {
            "step":        "1",
            "title":       "The attacker opens the database",
            "what_they_see": (
                "Every password field contains raw binary garbage — "
                "encrypted bytes that look like: "
                "b'\\x8f\\x2a\\x91\\x4c\\xe3\\xb7...' "
                "No site name reveals any password. "
                "The database is a black box."
            ),
            "why":         (
                "AES-256-GCM encryption converts every password into "
                "256-bit ciphertext before it ever touches the disk. "
                "Without the decryption key, the bytes are mathematically "
                "indistinguishable from random noise."
            ),
            "color":       "#FF4444",
        },
        {
            "step":        "2",
            "title":       "The attacker tries to brute-force the Master Password",
            "what_they_see": (
                "They write a script to guess passwords. "
                "Each guess requires running Argon2id — "
                "which needs 64MB RAM and ~0.5 seconds per attempt "
                "on a modern machine."
            ),
            "why":         (
                "At 2 guesses per second on high-end hardware, "
                "cracking an 18-character password with mixed characters "
                "would take longer than the current age of the universe. "
                "Argon2id's memory-hard design makes GPU farms ineffective."
            ),
            "color":       "#FF8C00",
        },
        {
            "step":        "3",
            "title":       "The attacker tries to find the encryption key on disk",
            "what_they_see": (
                "They search every file, swap partition, and temp folder "
                "on the stolen machine. The key is nowhere on the disk."
            ),
            "why":         (
                "SentinelsVault's Zero-Knowledge design keeps the AES-256 "
                "key exclusively in RAM during the session. "
                "When the vault locks or the app closes, the key is "
                "overwritten with null bytes and deleted. "
                "It was never written to any file."
            ),
            "color":       "#FFD700",
        },
        {
            "step":        "4",
            "title":       "The attacker tries to tamper with the database",
            "what_they_see": (
                "They modify a single byte in the ciphertext, "
                "hoping to trick the system into revealing data."
            ),
            "why":         (
                "AES-256-GCM mode includes a 16-byte authentication tag "
                "(MAC) per entry. If even one bit is altered, the integrity "
                "check fails instantly and decryption is aborted. "
                "This defeats all 'bit-flipping' attacks."
            ),
            "color":       "#00C851",
        },
        {
            "step":        "5",
            "title":       "The verdict",
            "what_they_see": (
                "The attacker has the database, the hardware, and "
                "unlimited time. They still cannot read a single password."
            ),
            "why":         (
                "This is the mathematical guarantee of Zero-Knowledge "
                "architecture. Security does not depend on keeping the "
                "database file secret — it depends on the cryptographic "
                "strength of AES-256-GCM and Argon2id."
            ),
            "color":       "#00E676",
        },
    ]
}

# ─────────────────────────────────────────────────────────────────
# SECTION 2: PBKDF2 EXPLAINED
# Password-Based Key Derivation Function 2
# ─────────────────────────────────────────────────────────────────
PBKDF2_EXPLAINER = {
    "title":    "PBKDF2 — Turning Your Password into an AES-256 Key",
    "subtitle": "Password-Based Key Derivation Function 2 (PBKDF2-HMAC-SHA256)",
    "color":    "#00D4FF",
    "what_is_it": (
        "PBKDF2 is a 'key stretching' algorithm. Your Master Password "
        "('MySecret@99') is a human-readable string — but AES-256 needs "
        "a 32-byte (256-bit) random-looking key. "
        "PBKDF2 transforms one into the other."
    ),
    "how_it_works": [
        {
            "step":  "Input",
            "value": "Master Password + 256-bit Random Salt",
            "note":  "The salt is unique per vault — stored in the database"
        },
        {
            "step":  "Algorithm",
            "value": "HMAC-SHA256 applied 600,000 times in a loop",
            "note":  "Each iteration feeds its output as input to the next"
        },
        {
            "step":  "Output",
            "value": "32 bytes = 256 bits of derived key material",
            "note":  "Looks like: b'\\x3a\\xf2\\x91\\x4c...' — pure random bytes"
        },
        {
            "step":  "Stored?",
            "value": "NO — only kept in RAM during the session",
            "note":  "Wiped with null bytes when the vault locks"
        },
    ],
    "why_600000": (
        "OWASP 2024 recommends a minimum of 600,000 iterations. "
        "On a modern laptop, this takes about 0.3 seconds to compute. "
        "That feels instant to a legitimate user logging in once. "
        "But for an attacker trying to guess passwords, "
        "it means only ~3 guesses per second — making brute-force "
        "billions of times harder than a simple SHA256 hash."
    ),
    "why_salt": (
        "The salt ensures that even if two users have the identical "
        "Master Password, their derived keys — and therefore their "
        "ciphertexts — look completely different. "
        "This defeats 'Rainbow Table' attacks where attackers precompute "
        "a table of password-to-hash mappings."
    ),
    "real_numbers": [
        ("Iterations per login",     "600,000"),
        ("Time per login attempt",   "~0.3 seconds (user feels nothing)"),
        ("Attacker guesses/second",  "~3 on a modern GPU"),
        ("18-char password space",   "10^35 possible combinations"),
        ("Time to crack (estimate)", "Longer than the age of the universe"),
    ]
}

# ─────────────────────────────────────────────────────────────────
# SECTION 3: ARGON2ID EXPLAINED
# The memory-hard password hashing function
# ─────────────────────────────────────────────────────────────────
ARGON2_EXPLAINER = {
    "title":    "Argon2id — Memory-Hard Password Verification",
    "subtitle": "Winner of the 2015 Password Hashing Competition (PHC)",
    "color":    "#C084FC",
    "what_is_it": (
        "Argon2id is used to VERIFY the Master Password on login. "
        "During setup, the Master Password is hashed with Argon2id "
        "and the result is stored in the database. "
        "On every login, the entered password is hashed again and "
        "compared — no plaintext password is ever stored."
    ),
    "what_makes_it_special": [
        {
            "feature": "Memory-Hard",
            "detail":  (
                "Argon2id requires 64MB of RAM per hash computation. "
                "Standard GPUs have thousands of cores but share RAM. "
                "Running 1,000 parallel cracking attempts would need "
                "64GB of RAM — completely impractical for attackers."
            ),
            "color": "#C084FC"
        },
        {
            "feature": "Time-Hard",
            "detail":  (
                "The time_cost=2 parameter means 2 full passes of "
                "the memory array. Combined with memory hardness, "
                "each attempt takes significant time even on top hardware."
            ),
            "color": "#00D4FF"
        },
        {
            "feature": "Side-Channel Resistant",
            "detail":  (
                "The 'id' variant combines data-dependent and "
                "data-independent memory access patterns, making it "
                "resistant to both GPU brute-force and timing attacks "
                "that could exploit CPU cache behavior."
            ),
            "color": "#00C851"
        },
        {
            "feature": "OWASP Recommended",
            "detail":  (
                "OWASP (Open Web Application Security Project) lists "
                "Argon2id as the first choice for password hashing in "
                "their 2024 Password Storage Cheat Sheet, above bcrypt, "
                "scrypt, and PBKDF2 for new applications."
            ),
            "color": "#FFD700"
        },
    ],
    "parameters": [
        ("time_cost",    "2",     "Iterations through memory"),
        ("memory_cost",  "65536", "64 MB RAM required per hash"),
        ("parallelism",  "2",     "CPU threads used"),
        ("hash_len",     "32",    "Output length in bytes"),
    ],
    "vs_bcrypt": (
        "bcrypt (the older standard) uses only 4KB of memory — "
        "modern GPUs can run millions of bcrypt attempts per second. "
        "Argon2id's 64MB requirement reduces this to hundreds, "
        "making it 10,000x harder to crack with GPU clusters."
    )
}

# ─────────────────────────────────────────────────────────────────
# SECTION 4: DUAL-LAYER SYSTEM — HOW THEY WORK TOGETHER
# ─────────────────────────────────────────────────────────────────
DUAL_LAYER = {
    "title":    "The Dual-Layer Security System",
    "subtitle": "Why SentinelsVault uses BOTH Argon2id AND PBKDF2",
    "color":    "#00C851",
    "explanation": (
        "Most password managers use one algorithm for everything. "
        "SentinelsVault uses two in parallel for different jobs, "
        "exploiting the specific strength of each."
    ),
    "layers": [
        {
            "name":    "Layer 1: Argon2id",
            "job":     "Password VERIFICATION",
            "how":     (
                "On setup: Argon2id hashes your Master Password and "
                "stores the result in vault_config. "
                "On login: Argon2id hashes the entered password and "
                "compares it to the stored hash. "
                "If they match, access is granted."
            ),
            "why_this_one": (
                "Argon2id's memory-hardness is perfect for verification "
                "because you only need to do it once per login. "
                "The 64MB RAM requirement makes offline cracking "
                "essentially impossible."
            ),
            "color": "#C084FC"
        },
        {
            "name":    "Layer 2: PBKDF2-SHA256",
            "job":     "Key DERIVATION (AES-256 key generation)",
            "how":     (
                "Simultaneously with Argon2id verification, PBKDF2 "
                "transforms the Master Password + salt into a "
                "32-byte AES-256 key. "
                "This key is passed to the EncryptionProvider "
                "and stored only in RAM."
            ),
            "why_this_one": (
                "PBKDF2 is the enterprise standard for key derivation. "
                "It produces deterministic output — the same password "
                "and salt always produce the same key — "
                "which is required for AES decryption to work correctly."
            ),
            "color": "#00D4FF"
        },
    ],
    "synergy": (
        "Together, they provide Defense-in-Depth: "
        "Argon2id stops an attacker from verifying whether "
        "a guessed password is correct (verification layer), "
        "while PBKDF2 stops them from deriving the AES key "
        "even if they somehow bypass verification (key layer). "
        "An attacker must break BOTH simultaneously."
    )
}

# ─────────────────────────────────────────────────────────────────
# SECTION 5: AES-256-GCM EXPLAINED
# ─────────────────────────────────────────────────────────────────
AES_EXPLAINER = {
    "title":    "AES-256-GCM — The Encryption Engine",
    "subtitle": "Advanced Encryption Standard, 256-bit key, Galois/Counter Mode",
    "color":    "#FFD700",
    "what_is_it": (
        "AES-256-GCM is the encryption algorithm used to scramble "
        "your passwords before storing them in SQLite. "
        "'256' refers to the key length in bits. "
        "'GCM' is the mode of operation."
    ),
    "two_guarantees": [
        {
            "guarantee": "Confidentiality",
            "icon":      "🔒",
            "detail":    (
                "AES-256 in counter mode (CTR) turns your plaintext "
                "into indistinguishable random bytes. "
                "With 2^256 possible keys, even if every computer "
                "on Earth tried one billion keys per second, "
                "it would take 10^56 years to exhaust all keys."
            ),
            "color": "#00D4FF"
        },
        {
            "guarantee": "Integrity (The GCM Tag)",
            "icon":      "🛡️",
            "detail":    (
                "GCM mode generates a 16-byte authentication tag "
                "(MAC — Message Authentication Code) alongside the "
                "ciphertext. On decryption, the tag is verified first. "
                "If even one bit was changed (by an attacker or "
                "disk corruption), the tag check fails and "
                "decryption is immediately aborted."
            ),
            "color": "#00C851"
        },
    ],
    "iv_importance": (
        "Each encryption generates a fresh 12-byte random IV "
        "(Initialization Vector / Nonce). "
        "This means encrypting the same password twice "
        "produces completely different ciphertext each time. "
        "Without a unique IV, patterns in the ciphertext could "
        "leak information about repeated passwords."
    ),
    "nist_standard": (
        "AES was standardized by NIST (National Institute of Standards "
        "and Technology) in 2001. It is used by the US military, "
        "intelligence agencies, banks, and every major tech company. "
        "No practical attack against AES-256 has ever been demonstrated."
    ),
}

# ─────────────────────────────────────────────────────────────────
# SECTION 6: THE COMPLETE SECURITY CHAIN
# A step-by-step flowchart of the entire encryption path
# ─────────────────────────────────────────────────────────────────
SECURITY_CHAIN = {
    "title":    "The Complete Security Chain",
    "subtitle": "From Master Password to encrypted BLOB — every step explained",
    "color":    "#00D4FF",
    "steps": [
        {
            "number":  "01",
            "title":   "User Enters Master Password",
            "detail":  "Plaintext string in RAM only. Never written to disk.",
            "output":  "'MyVaultPassword@2024'",
            "color":   "#8B949E",
        },
        {
            "number":  "02",
            "title":   "Argon2id Hashing (Verification Layer)",
            "detail":  "Password hashed with 64MB memory, stored as '$argon2id$...' in vault_config.",
            "output":  "Stored Argon2id hash in SQLite",
            "color":   "#C084FC",
        },
        {
            "number":  "03",
            "title":   "PBKDF2 Key Derivation (Key Layer)",
            "detail":  "Password + 256-bit salt → 600,000 SHA256 iterations → 32-byte key.",
            "output":  "AES-256 Key (RAM only)",
            "color":   "#00D4FF",
        },
        {
            "number":  "04",
            "title":   "EncryptionProvider Initialized",
            "detail":  "AES-256-GCM cipher object created in memory with the derived key.",
            "output":  "Active AESGCM object (RAM only)",
            "color":   "#FFD700",
        },
        {
            "number":  "05",
            "title":   "User Saves a Password",
            "detail":  "Plaintext password ('Netflix123') passed to encrypt() method.",
            "output":  "'Netflix123' (plaintext, RAM only)",
            "color":   "#8B949E",
        },
        {
            "number":  "06",
            "title":   "Random IV Generated",
            "detail":  "12 cryptographically random bytes generated via os.urandom(12).",
            "output":  "Unique 96-bit nonce (never reused)",
            "color":   "#FF8C00",
        },
        {
            "number":  "07",
            "title":   "AES-256-GCM Encryption",
            "detail":  "Plaintext + Key + IV → Ciphertext + 16-byte GCM authentication tag.",
            "output":  "Ciphertext BLOB + Auth Tag",
            "color":   "#00C851",
        },
        {
            "number":  "08",
            "title":   "Stored in SQLite as BLOB",
            "detail":  "Ciphertext bytes written to disk. IV stored alongside. No plaintext anywhere.",
            "output":  "sentinels_vault.db (encrypted at rest)",
            "color":   "#00D4FF",
        },
        {
            "number":  "09",
            "title":   "Vault Locked — Key Wiped",
            "detail":  "Key overwritten with 32 null bytes (0x00). RAM location freed. Key is gone.",
            "output":  "Zero footprint on disk or RAM",
            "color":   "#FF4444",
        },
    ]
}

# ─────────────────────────────────────────────────────────────────
# SECTION 7: COMPARISON TABLE
# SentinelsVault vs competitors across 10 security dimensions
# ─────────────────────────────────────────────────────────────────
COMPARISON_TABLE = {
    "title":    "SentinelsVault vs Existing Password Managers",
    "subtitle": "A technical comparison across 10 security dimensions",
    "color":    "#00C851",
    "columns":  ["Feature", "Google Chrome", "LastPass", "SentinelsVault"],
    "rows": [
        ["Encryption Algorithm",   "AES-128",      "AES-256",        "AES-256-GCM"],
        ["Key Derivation",         "PBKDF2 (low)",  "PBKDF2 (100k)",  "PBKDF2 (600k) + Argon2id"],
        ["Data Storage",           "Google Servers","Cloud Servers",   "Local SQLite Only"],
        ["Zero-Knowledge",         "No",            "Partial",         "Yes — complete"],
        ["Offline Operation",      "No",            "No",              "Yes — fully offline"],
        ["Remote Attack Surface",  "High",          "High",            "Zero"],
        ["Security Auditing",      "None",          "Paid feature",    "Built-in (free)"],
        ["Password History",       "No",            "Paid feature",    "Built-in (free)"],
        ["Memory Key Wipe",        "No",            "No",              "Yes — null byte wipe"],
        ["Open Source Logic",      "No",            "No",              "Yes — fully transparent"],
    ],
    "column_colors": ["#8B949E", "#FF8C00", "#FF4444", "#00C851"]
}


def get_all_sections() -> dict:
    """
    Returns all explainer sections as a single dictionary.
    Called by app_ui.py to render the complete How It Works screen.
    This is the single public interface of this module.
    """
    return {
        "attack_scenario": ATTACK_SCENARIO,
        "pbkdf2":          PBKDF2_EXPLAINER,
        "argon2":          ARGON2_EXPLAINER,
        "dual_layer":      DUAL_LAYER,
        "aes":             AES_EXPLAINER,
        "security_chain":  SECURITY_CHAIN,
        "comparison":      COMPARISON_TABLE,
    }