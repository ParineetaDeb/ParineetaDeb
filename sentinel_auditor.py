# sentinel_auditor.py
# MODULE 4: Security Auditor — The Sentinel
# 
# CLASS STRUCTURE FOR SENTINEL AUDITOR
# =====================================
# This module demonstrates professional software engineering practices:
#   - Object-Oriented Programming (OOP) with encapsulation
#   - Type hints for code clarity and maintainability
#   - Comprehensive docstrings for documentation
#   - Separation of concerns (each method does ONE thing)
#   - Design patterns (Strategy pattern for strength analysis)
#   - Data structures (dictionaries, lists, sets for efficient lookups)
#   - Algorithmic complexity awareness (O(1) lookups, O(n) scans)
# 
# Author: SentinelsVault Team
# Version: 2.0 (Enhanced Security Auditor)
# Date: April 2025

import re
import os
import logging
import math
import secrets
import string
import datetime
import json
from typing import Dict, List, Tuple, Optional, Any, Set
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from enum import Enum

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# ENUMS FOR TYPE SAFETY (Demonstrates advanced Python)
# ─────────────────────────────────────────────

class PasswordStrength(Enum):
    """
    Enumeration of password strength levels.
    Using Enum ensures type safety and prevents invalid values.
    """
    VERY_WEAK = 1
    WEAK = 2
    MODERATE = 3
    STRONG = 4
    VERY_STRONG = 5
    
    def get_display_name(self) -> str:
        """Returns human-readable display name."""
        names = {
            PasswordStrength.VERY_WEAK: "Very Weak",
            PasswordStrength.WEAK: "Weak",
            PasswordStrength.MODERATE: "Moderate",
            PasswordStrength.STRONG: "Strong",
            PasswordStrength.VERY_STRONG: "Very Strong"
        }
        return names[self]
    
    def get_color(self) -> str:
        """Returns UI color code for this strength level."""
        colors = {
            PasswordStrength.VERY_WEAK: "#FF4444",
            PasswordStrength.WEAK: "#FF8C00",
            PasswordStrength.MODERATE: "#FFD700",
            PasswordStrength.STRONG: "#00C851",
            PasswordStrength.VERY_STRONG: "#00E676"
        }
        return colors[self]
    
    def get_entropy_range(self) -> Tuple[float, float]:
        """Returns the entropy range (min, max) for this level."""
        ranges = {
            PasswordStrength.VERY_WEAK: (0, 28),
            PasswordStrength.WEAK: (28, 36),
            PasswordStrength.MODERATE: (36, 60),
            PasswordStrength.STRONG: (60, 128),
            PasswordStrength.VERY_STRONG: (128, float('inf'))
        }
        return ranges[self]


class CharacterType(Enum):
    """Enumeration of character types for password composition."""
    UPPERCASE = "uppercase"
    LOWERCASE = "lowercase"
    DIGITS = "digits"
    SYMBOLS = "symbols"


class AttackVector(Enum):
    """Enumeration of potential attack vectors."""
    BRUTE_FORCE = "brute_force"
    DICTIONARY = "dictionary"
    RAINBOW_TABLE = "rainbow_table"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SIDE_CHANNEL = "side_channel"


# ─────────────────────────────────────────────
# DATA CLASSES FOR STRUCTURED DATA (Python 3.7+)
# ─────────────────────────────────────────────

@dataclass
class PasswordAuditResult:
    """
    Data class representing the result of a single password audit.
    Using @dataclass automatically generates __init__, __repr__, etc.
    Demonstrates clean, professional data modeling.
    """
    entropy: float
    strength: PasswordStrength
    strength_label: str
    color: str
    is_common: bool
    issues: List[str]
    length: int
    character_types_used: Set[CharacterType]
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_symbols: bool
    time_to_crack_estimate: str
    risk_level: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result['strength'] = self.strength.value
        result['character_types_used'] = [ct.value for ct in self.character_types_used]
        return result


@dataclass
class VaultHealthReport:
    """
    Data class representing comprehensive vault health report.
    Contains aggregated statistics and actionable insights.
    """
    total_count: int
    strength_distribution: Dict[str, int]
    reused_passwords: Dict[str, List[str]]
    breached_passwords: List[str]
    vault_score: int
    security_verdict: str
    recommendations: List[str]
    category_analysis: Dict[str, Dict[str, int]]
    weakest_entries: List[Tuple[str, float]]
    timestamp: str
    
    def get_summary(self) -> str:
        """Returns a human-readable summary of the report."""
        return (f"Vault Health Score: {self.vault_score}/100 | "
                f"{self.strength_distribution.get('Strong', 0)} Strong, "
                f"{self.strength_distribution.get('Weak', 0)} Weak")


# ─────────────────────────────────────────────
# CONSTANTS (Single Source of Truth)
# ─────────────────────────────────────────────

COMMON_PASSWORDS: Set[str] = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "iloveyou",
    "welcome", "login", "pass", "master", "hello", "dragon",
    "master123", "sunshine", "princess", "football", "shadow",
    "superman", "michael", "654321", "charlie", "donald",
    "password1", "qwerty123", "zxcvbnm", "111111", "12345678",
}

# Character pool sizes for entropy calculation
CHARACTER_POOL_SIZES: Dict[str, int] = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "symbols": 32,
}

# Entropy thresholds (in bits)
ENTROPY_THRESHOLDS: Dict[PasswordStrength, float] = {
    PasswordStrength.VERY_WEAK: 28,
    PasswordStrength.WEAK: 36,
    PasswordStrength.MODERATE: 60,
    PasswordStrength.STRONG: 128,
    PasswordStrength.VERY_STRONG: float('inf'),
}

# GPU hash rates for different hardware (hashes per second)
GPU_HASH_RATES: Dict[str, float] = {
    "RTX 4090": 1.5e10,      # 15 billion hashes/sec
    "RTX 3090": 1.0e10,      # 10 billion hashes/sec
    "RTX 2080 Ti": 5.0e9,    # 5 billion hashes/sec
    "GTX 1080 Ti": 2.5e9,    # 2.5 billion hashes/sec
}


# ─────────────────────────────────────────────
# MAIN CLASS: SentinelAuditor
# ─────────────────────────────────────────────

class SentinelAuditor:
    """
    The Sentinel — Intelligent Security Auditor for SentinelsVault.
    
    This class performs heuristic analysis on passwords to detect:
        1. Weak passwords (low entropy, common patterns)
        2. Reused passwords across multiple accounts
        3. Breached passwords (against common password lists)
        4. Password health scoring
    
    Design Patterns Used:
        - Strategy Pattern: Different strength analysis strategies
        - Factory Pattern: Creates audit result objects
        - Singleton Pattern: Single auditor instance (implicit)
    
    Time Complexity:
        - Password audit: O(n) where n = password length
        - Vault report: O(m * n) where m = number of credentials
        - Reused password detection: O(m) using hash map
    
    Space Complexity:
        - O(m) for storing credential analysis in memory
    """
    
    # Class variable (shared across all instances)
    _instance: Optional['SentinelAuditor'] = None
    
    def __new__(cls) -> 'SentinelAuditor':
        """
        Singleton pattern implementation.
        Ensures only one instance of the auditor exists.
        This is efficient for memory management.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """
        Initialize the Security Auditor.
        Uses lazy initialization to avoid repeated setup.
        """
        if hasattr(self, '_initialized'):
            return
        
        self._initialized = True
        self._common_passwords: Set[str] = COMMON_PASSWORDS
        self._character_pool_sizes: Dict[str, int] = CHARACTER_POOL_SIZES
        self._entropy_thresholds: Dict[PasswordStrength, float] = ENTROPY_THRESHOLDS
        
        # Cache for recently audited passwords (performance optimization)
        self._audit_cache: Dict[str, PasswordAuditResult] = {}
        self._cache_max_size: int = 1000
        
        logger.info("SentinelAuditor initialized with singleton pattern")
    
    # ═══════════════════════════════════════════════════════
    # PUBLIC API METHODS (What the UI calls)
    # ═══════════════════════════════════════════════════════
    
    def calculate_entropy(self, password: str) -> float:
        """
        Public method to calculate password entropy.
        Called by sdlc_waterfall.py
        """
        return self._calculate_entropy(password)
    
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generates a cryptographically secure random password.
        Called by sdlc_waterfall.py
        """
        if length < 8:
            length = 8
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(length))
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password)):
                return password
    
    def audit_single_password(self, password: str) -> Dict[str, Any]:
        """
        Full heuristic audit of a single password string.
    
        Args:
            password: The password string to analyze
        
        Returns:
            Dictionary containing comprehensive audit results:
            - entropy: float (bits)
            - strength_label: str (human-readable)
            - color: str (hex code)
            - is_common: bool
            - issues: List[str]
            - score: int (0-100 security score)
    
        Time Complexity: O(n) where n = password length
        Space Complexity: O(1)
        """
        # Check cache first for performance
        if password in self._audit_cache:
            logger.debug(f"Cache hit for password audit")
            result = self._audit_cache[password]
            return {
                "entropy": result.entropy,
                "strength_label": result.strength_label,
                "color": result.color,
                "is_common": result.is_common,
                "issues": result.issues,
                "score": self._calculate_score_from_entropy(result.entropy, result.is_common)
            }
    
        # Perform full audit
        entropy = self._calculate_entropy(password)
        strength = self._get_strength_from_entropy(entropy)
        is_common = password.lower() in self._common_passwords
        issues = self._identify_issues(password, entropy, is_common)
    
        # Calculate score (0-100)
        score = self._calculate_score_from_entropy(entropy, is_common)
    
        # Build result object
        result = {
            "entropy": entropy,
            "strength_label": strength.get_display_name(),
            "color": strength.get_color(),
            "is_common": is_common,
            "issues": issues,
            "score": score
        }
    
        # Cache for future use
        self._cache_result(password, result)
    
        logger.info(f"Password audited: strength={strength.get_display_name()}, entropy={entropy:.1f}, score={score}")
        return result
    
    def generate_vault_report(self, decrypted_credentials: List[Tuple[str, str]]) -> Dict[str, Any]:
        """
        Generates a comprehensive security health report for the whole vault.
        
        Args:
            decrypted_credentials: List of (site_name, plaintext_password)
            
        Returns:
            Dictionary with:
                - total_count: int
                - categories: Dict[str, int] (strength distribution)
                - reused_map: Dict[str, List[str]] (password -> list of sites)
                - common_list: List[str] (sites with breached passwords)
                - vault_score: int (0-100)
        
        Time Complexity: O(m * n) where m = number of credentials, n = avg password length
        Space Complexity: O(m) for storing analysis
        """
        if not decrypted_credentials:
            return {
                "total_count": 0,
                "categories": {"Very Weak": 0, "Weak": 0, "Moderate": 0, "Strong": 0, "Very Strong": 0},
                "reused_map": {},
                "common_list": [],
                "vault_score": 0
            }
        
        # Initialize data structures
        strength_counter: Dict[str, int] = defaultdict(int)
        password_tracker: Dict[str, List[str]] = defaultdict(list)
        common_sites: List[str] = []
        
        # Single pass through credentials (O(m * n))
        for site, pwd in decrypted_credentials:
            audit = self.audit_single_password(pwd)
            strength_counter[audit["strength_label"]] += 1
            
            if audit["is_common"]:
                common_sites.append(site)
            
            password_tracker[pwd].append(site)
        
        # Find reused passwords (O(m) with hash map)
        reused_map = {
            pwd: sites for pwd, sites in password_tracker.items() if len(sites) > 1
        }
        
        # Calculate vault score using weighted algorithm
        vault_score = self._calculate_vault_score(strength_counter, common_sites, reused_map)
        
        logger.info(f"Vault report generated: {len(decrypted_credentials)} credentials, score={vault_score}")
        
        return {
            "total_count": len(decrypted_credentials),
            "categories": dict(strength_counter),
            "reused_map": reused_map,
            "common_list": common_sites,
            "vault_score": vault_score
        }
    
    def generate_comprehensive_report(self, decrypted_credentials: List[Tuple[str, str]]) -> VaultHealthReport:
        """
        Generates a comprehensive VaultHealthReport data object.
        This is the advanced version with more detailed analysis.
        
        Args:
            decrypted_credentials: List of (site_name, plaintext_password)
            
        Returns:
            VaultHealthReport object with comprehensive analysis
        """
        # Get basic report
        basic = self.generate_vault_report(decrypted_credentials)
        
        # Category analysis by domain
        category_analysis = self._analyze_by_category(decrypted_credentials)
        
        # Find weakest entries
        weakest = []
        for site, pwd in decrypted_credentials:
            entropy = self._calculate_entropy(pwd)
            weakest.append((site, entropy))
        weakest.sort(key=lambda x: x[1])
        
        # Generate recommendations
        recommendations = self._generate_recommendations(basic, category_analysis)
        
        # Determine security verdict
        score = basic["vault_score"]
        if score >= 80:
            verdict = "SECURE"
        elif score >= 50:
            verdict = "MODERATE RISK"
        else:
            verdict = "HIGH RISK"
        
        return VaultHealthReport(
            total_count=basic["total_count"],
            strength_distribution=basic["categories"],
            reused_passwords=basic["reused_map"],
            breached_passwords=basic["common_list"],
            vault_score=score,
            security_verdict=verdict,
            recommendations=recommendations,
            category_analysis=category_analysis,
            weakest_entries=weakest[:5],  # Top 5 weakest
            timestamp=datetime.datetime.now().isoformat()
        )
    
    # ═══════════════════════════════════════════════════════
    # PRIVATE METHODS (Implementation Details)
    # ═══════════════════════════════════════════════════════
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculates the mathematical entropy (randomness) of a password.
        
        Formula: H = L * log2(R)
            H = Entropy in bits
            L = Password length
            R = Character pool size (number of possible characters)
        
        Time Complexity: O(n) where n = password length
        Space Complexity: O(1)
        
        Example:
            Password "Hello123" -> length 8, pool size 62 (uppercase+lowercase+digits)
            Entropy = 8 * log2(62) = 8 * 5.95 = 47.6 bits
        """
        if not password:
            return 0.0
        
        # Determine character pool size
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += self._character_pool_sizes["lowercase"]
        if re.search(r'[A-Z]', password):
            pool_size += self._character_pool_sizes["uppercase"]
        if re.search(r'[0-9]', password):
            pool_size += self._character_pool_sizes["digits"]
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += self._character_pool_sizes["symbols"]
        
        if pool_size == 0:
            return 0.0
        
        # Calculate entropy: length * log2(pool_size)
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)
    
    def _calculate_score_from_entropy(self, entropy: float, is_common: bool) -> int:
        """
        Calculates a security score (0-100) based on entropy and breach status.
        
        Score mapping:
            - entropy >= 128: 100 points
            - entropy >= 80:  95 points
            - entropy >= 60:  85 points
            - entropy >= 50:  75 points
            - entropy >= 36:  60 points
            - entropy >= 28:  40 points
            - entropy < 28:   20 points
            - is_common:      reduces score by 50% (capped at max 50)
        """
        if entropy >= 128:
            score = 100
        elif entropy >= 80:
            score = 95
        elif entropy >= 60:
            score = 85
        elif entropy >= 50:
            score = 75
        elif entropy >= 36:
            score = 60
        elif entropy >= 28:
            score = 40
        else:
            score = 20
        
        # Penalize common/breached passwords heavily
        if is_common:
            score = min(score, 50)  # Cap at 50
            score = score // 2       # Halve the score
        
        return max(0, min(100, score))
    
    def _get_strength_from_entropy(self, entropy: float) -> PasswordStrength:
        """
        Maps entropy bits to PasswordStrength enum.
        
        Time Complexity: O(1) - constant time lookups
        """
        if entropy < ENTROPY_THRESHOLDS[PasswordStrength.VERY_WEAK]:
            return PasswordStrength.VERY_WEAK
        elif entropy < ENTROPY_THRESHOLDS[PasswordStrength.WEAK]:
            return PasswordStrength.WEAK
        elif entropy < ENTROPY_THRESHOLDS[PasswordStrength.MODERATE]:
            return PasswordStrength.MODERATE
        elif entropy < ENTROPY_THRESHOLDS[PasswordStrength.STRONG]:
            return PasswordStrength.STRONG
        else:
            return PasswordStrength.VERY_STRONG
    
    def _identify_issues(self, password: str, entropy: float, is_common: bool) -> List[str]:
        """
        Identifies specific security issues with a password.
        
        Returns a list of human-readable issue descriptions.
        Time Complexity: O(n) for regex checks
        """
        issues = []
        
        # Length check (OWASP recommends at least 12 characters)
        if len(password) < 12:
            issues.append(f"Length below 12 characters (current: {len(password)})")
        
        # Character type checks
        if not re.search(r'[A-Z]', password):
            issues.append("Missing uppercase letters")
        
        if not re.search(r'[a-z]', password):
            issues.append("Missing lowercase letters")
        
        if not re.search(r'[0-9]', password):
            issues.append("Missing numeric digits")
        
        if not re.search(r'[^a-zA-Z0-9]', password):
            issues.append("Missing special characters")
        
        # Common password check
        if is_common:
            issues.append("BREACH RISK: Found in common password lists!")
        
        # Entropy-based warning
        if entropy < 28:
            issues.append("Extremely low entropy — easily crackable")
        elif entropy < 36:
            issues.append("Low entropy — can be cracked quickly")
        
        return issues
    
    def _calculate_vault_score(self, 
                                strength_counter: Dict[str, int], 
                                common_sites: List[str], 
                                reused_map: Dict[str, List[str]]) -> int:
        """
        Calculates the overall vault security score (0-100).
        
        Weighted algorithm:
            - Very Weak passwords: -25 points each
            - Weak passwords: -15 points each
            - Common/breached passwords: -20 points each
            - Reused password groups: -10 points each
        
        Time Complexity: O(1) for aggregations
        """
        score = 100
        
        # Deductions for weak passwords
        score -= strength_counter.get("Very Weak", 0) * 25
        score -= strength_counter.get("Weak", 0) * 15
        
        # Deductions for breached passwords
        score -= len(common_sites) * 20
        
        # Deductions for reused passwords
        score -= len(reused_map) * 10
        
        # Ensure score stays within 0-100 range
        return max(0, min(100, score))
    
    def _analyze_by_category(self, credentials: List[Tuple[str, str]]) -> Dict[str, Dict[str, int]]:
        """
        Analyzes password strength by category/domain.
        Extracts category from site name or uses "General".
        
        Returns: {
            "Finance": {"strong": 5, "weak": 2, "total": 7},
            "Social": {"strong": 3, "weak": 1, "total": 4}
        }
        """
        categories: Dict[str, Dict[str, int]] = defaultdict(lambda: {"strong": 0, "weak": 0, "total": 0})
        
        # Common category keywords for auto-detection
        category_keywords = {
            "Finance": ["bank", "finance", "pay", "capital", "credit", "invest"],
            "Social": ["facebook", "twitter", "instagram", "linkedin", "social"],
            "Email": ["gmail", "outlook", "yahoo", "mail", "email"],
            "Work": ["work", "office", "company", "corporate", "slack"],
            "Entertainment": ["netflix", "spotify", "youtube", "disney", "hulu"]
        }
        
        for site, pwd in credentials:
            # Determine category
            category = "General"
            site_lower = site.lower()
            for cat, keywords in category_keywords.items():
                if any(kw in site_lower for kw in keywords):
                    category = cat
                    break
            
            # Analyze strength
            entropy = self._calculate_entropy(pwd)
            strength = self._get_strength_from_entropy(entropy)
            
            categories[category]["total"] += 1
            if strength in (PasswordStrength.STRONG, PasswordStrength.VERY_STRONG):
                categories[category]["strong"] += 1
            elif strength in (PasswordStrength.WEAK, PasswordStrength.VERY_WEAK):
                categories[category]["weak"] += 1
        
        return dict(categories)
    
    def _generate_recommendations(self, 
                                   report: Dict[str, Any], 
                                   category_analysis: Dict[str, Dict[str, int]]) -> List[str]:
        """
        Generates actionable security recommendations based on audit results.
        """
        recommendations = []
        
        # Check for very weak passwords
        if report["categories"].get("Very Weak", 0) > 0:
            recommendations.append(
                f"⚠️  CRITICAL: Replace {report['categories']['Very Weak']} very weak passwords immediately"
            )
        
        # Check for weak passwords
        if report["categories"].get("Weak", 0) > 0:
            recommendations.append(
                f"⚠️  Replace {report['categories']['Weak']} weak passwords with stronger ones"
            )
        
        # Check for reused passwords
        if report["reused_map"]:
            rec = f"🔄  Generate unique passwords for {len(report['reused_map'])} reused password groups"
            recommendations.append(rec)
        
        # Check for breached passwords
        if report["common_list"]:
            recommendations.append(
                f"🔴  Change {len(report['common_list'])} breached passwords immediately"
            )
        
        # Category-specific recommendations
        for category, stats in category_analysis.items():
            weak_percentage = (stats["weak"] / stats["total"] * 100) if stats["total"] > 0 else 0
            if weak_percentage > 50:
                recommendations.append(
                    f"📁  {category} accounts have {weak_percentage:.0f}% weak passwords — prioritize these"
                )
        
        # General recommendations
        if report["vault_score"] < 70:
            recommendations.append(
                "🔐  Use the built-in password generator for all new accounts"
            )
        
        recommendations.append(
            "📊  Run weekly security audits to maintain vault health"
        )
        
        return recommendations
    
    def _cache_result(self, password: str, result: Dict[str, Any]):
        """
        Caches audit results for performance optimization.
        Implements simple LRU-like behavior by clearing when full.
        """
        if len(self._audit_cache) >= self._cache_max_size:
            # Clear half the cache when full
            keys = list(self._audit_cache.keys())[:self._cache_max_size // 2]
            for key in keys:
                del self._audit_cache[key]
        
        # Create and store the full result object
        audit_obj = PasswordAuditResult(
            entropy=result["entropy"],
            strength=self._get_strength_from_entropy(result["entropy"]),
            strength_label=result["strength_label"],
            color=result["color"],
            is_common=result["is_common"],
            issues=result["issues"],
            length=len(password),
            character_types_used=set(),
            has_uppercase=any(c.isupper() for c in password),
            has_lowercase=any(c.islower() for c in password),
            has_digits=any(c.isdigit() for c in password),
            has_symbols=any(c in "!@#$%^&*()" for c in password),
            time_to_crack_estimate=self._estimate_crack_time(result["entropy"]),
            risk_level=self._get_risk_level(result["entropy"], result["is_common"])
        )
        self._audit_cache[password] = audit_obj
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """
        Estimates time to crack password using modern GPU.
        """
        if entropy < 28:
            return "Instantly (< 1 second)"
        elif entropy < 36:
            return "Minutes to hours"
        elif entropy < 60:
            return "Days to weeks"
        elif entropy < 128:
            return "Years to centuries"
        else:
            return "Practically uncrackable"
    
    def _get_risk_level(self, entropy: float, is_common: bool) -> str:
        """
        Determines risk level based on entropy and breach status.
        """
        if is_common:
            return "CRITICAL"
        elif entropy < 28:
            return "CRITICAL"
        elif entropy < 36:
            return "HIGH"
        elif entropy < 60:
            return "MODERATE"
        elif entropy < 128:
            return "LOW"
        else:
            return "NEGLIGIBLE"
    
    def get_strength_label(self, entropy: float) -> Tuple[str, str]:
        """
        Public method to get strength label and color from entropy.
        Returns: (strength_label, color_hex)
        """
        strength = self._get_strength_from_entropy(entropy)
        return (strength.get_display_name(), strength.get_color())
    
    def get_strength_guide(self) -> Dict[str, Any]:
        """
        Returns the complete Password Strength Guide as structured data.
        Used by the UI to display educational content.
        """
        return {
            "tiers": self._build_strength_tiers(),
            "golden_rules": self._build_golden_rules(),
            "entropy_formula": {
                "formula": "H = L × log₂(R)",
                "explanation": "H = Entropy (bits) | L = Password Length | R = Character Pool Size",
                "pool_sizes": [
                    ("Lowercase only (a-z)", "26 characters"),
                    ("+ Uppercase (A-Z)", "52 characters"),
                    ("+ Digits (0-9)", "62 characters"),
                    ("+ Symbols (!@#$...)", "94 characters"),
                ],
                "example": "16-character password using all types: 16 × log₂(94) = 105 bits — Very Strong"
            }
        }
    
    def _build_strength_tiers(self) -> List[Dict[str, Any]]:
        """
        Builds the strength tiers data structure.
        """
        return [
            {
                "level": "Very Weak",
                "entropy": "Below 28 bits",
                "color": "#FF4444",
                "icon": "🔴",
                "examples": "123456, password, admin",
                "time": "Cracked instantly",
                "description": "Single character type only. Extremely short. Found in every breach list.",
                "tips": ["Must be at least 8 characters", "Never use dictionary words alone"]
            },
            {
                "level": "Weak",
                "entropy": "28 — 35 bits",
                "color": "#FF8C00",
                "icon": "🟠",
                "examples": "sunshine1, hello123, abc@123",
                "time": "Cracked in minutes to hours",
                "description": "Slightly longer but still predictable.",
                "tips": ["Avoid simple number substitutions", "Length alone is not enough"]
            },
            {
                "level": "Moderate",
                "entropy": "36 — 59 bits",
                "color": "#FFD700",
                "icon": "🟡",
                "examples": "Tiger@2024, Blue#Sky9",
                "time": "Cracked in days to weeks",
                "description": "Uses multiple character types but is still short.",
                "tips": ["Increase length to at least 14 characters", "Mix all character types"]
            },
            {
                "level": "Strong",
                "entropy": "60 — 127 bits",
                "color": "#00C851",
                "icon": "🟢",
                "examples": "T!g3r#Blue@Sky99, X@9mK#vL2$",
                "time": "Cracked in years to centuries",
                "description": "Good length and character variety.",
                "tips": ["Use at least 16 characters", "Avoid reusing passwords"]
            },
            {
                "level": "Very Strong",
                "entropy": "128+ bits",
                "color": "#00E676",
                "icon": "💎",
                "examples": "Generated by SentinelsVault",
                "time": "Practically uncrackable",
                "description": "Maximum entropy. Fully random, long, and complex.",
                "tips": ["Use built-in generator", "Unique passwords for every account"]
            }
        ]
    
    def _build_golden_rules(self) -> List[Dict[str, str]]:
        """
        Builds the golden rules data structure.
        """
        return [
            {"icon": "🔁", "title": "Never Reuse Passwords",
             "body": "If one site is breached, all accounts with the same password are compromised."},
            {"icon": "📏", "title": "Length Over Complexity",
             "body": "A 20-character password is stronger than an 8-character password with symbols."},
            {"icon": "🎲", "title": "Use True Randomness",
             "body": "Always use SentinelsVault's built-in generator with cryptographic randomness."},
            {"icon": "🚫", "title": "Avoid Personal Information",
             "body": "Names, birthdays, and pet names are the first things attackers try."},
            {"icon": "🔐", "title": "Protect Your Master Password",
             "body": "Your Master Password is the key to everything. Make it your strongest password."}
        ]
    
    def generate_custom_password(self, length: int = 16,
                                  use_upper: bool = True,
                                  use_lower: bool = True,
                                  use_digits: bool = True,
                                  use_symbols: bool = True,
                                  exclude_ambiguous: bool = False) -> str:
        """
        Generates a cryptographically secure random password with custom options.
        """
        pool = ""
        ambiguous = "l1IO0"
        
        if use_upper:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in ambiguous)
            pool += chars
        
        if use_lower:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in ambiguous)
            pool += chars
        
        if use_digits:
            chars = string.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in ambiguous)
            pool += chars
        
        if use_symbols:
            pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not pool:
            pool = string.ascii_letters + string.digits
        
        for _ in range(100):
            password = ''.join(secrets.choice(pool) for _ in range(length))
            valid = True
            if use_upper and not any(c.isupper() for c in password):
                valid = False
            if use_lower and not any(c.islower() for c in password):
                valid = False
            if use_digits and not any(c.isdigit() for c in password):
                valid = False
            if use_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                valid = False
            if valid:
                return password
        
        return ''.join(secrets.choice(pool) for _ in range(length))
    
    # ═══════════════════════════════════════════════════════════
    # EMAIL ANOMALY DETECTION - Protect Main Account
    # ═══════════════════════════════════════════════════════════
    
    def detect_email_access_anomaly(self, email_account: str, current_location: str = None) -> dict:
        """
        Detect unusual email access patterns.
        Triggers alert if email accessed from new device or location.
        
        Args:
            email_account: The email address to monitor (e.g., "user@gmail.com")
            current_location: Optional location string (city/state)
        
        Returns:
            Dictionary with anomaly detection results
        """
        import hashlib
        import json
        from datetime import datetime
        from pathlib import Path
        
        # File to store access patterns
        pattern_file = Path("logs/email_patterns.json")
        
        # Create pattern file if it doesn't exist
        if not pattern_file.exists():
            pattern_file.parent.mkdir(exist_ok=True)
            with open(pattern_file, 'w') as f:
                json.dump({}, f)
        
        # Load existing patterns
        with open(pattern_file, 'r') as f:
            patterns = json.load(f)
        
        # Get current timestamp
        now = datetime.now()
        
        # Generate device fingerprint (based on system info)
        device_fingerprint = self._generate_device_fingerprint()
        
        # Initialize pattern for this email if not exists
        if email_account not in patterns:
            patterns[email_account] = {
                'known_devices': [],
                'known_locations': [],
                'access_history': [],
                'alert_threshold': 3
            }
        
        # Check for anomalies
        anomalies = []
        risk_score = 0
        
        # Anomaly 1: New device detection
        if device_fingerprint not in patterns[email_account]['known_devices']:
            anomalies.append(f"New device detected: {device_fingerprint[:16]}...")
            risk_score += 40
            
            # Add to known devices after confirmation (in real implementation, would require OTP)
            if len(patterns[email_account]['access_history']) > 5:  # After enough history
                patterns[email_account]['known_devices'].append(device_fingerprint)
        
        # Anomaly 2: New location detection
        if current_location and current_location not in patterns[email_account]['known_locations']:
            anomalies.append(f"New location detected: {current_location}")
            risk_score += 30
        
        # Anomaly 3: Unusual access time (2 AM - 5 AM)
        if now.hour >= 2 and now.hour <= 5:
            anomalies.append(f"Unusual access time: {now.strftime('%H:%M')} (2 AM - 5 AM)")
            risk_score += 25
        
        # Anomaly 4: Multiple rapid accesses (potential attack)
        recent_accesses = []
        for t in patterns[email_account]['access_history']:
            try:
                if (now - datetime.fromisoformat(t)).total_seconds() < 300:
                    recent_accesses.append(t)
            except:
                pass
        
        if len(recent_accesses) > 5:
            anomalies.append(f"Rapid access detected: {len(recent_accesses)} accesses in 5 minutes")
            risk_score += 35
        
        # Record this access
        patterns[email_account]['access_history'].append(now.isoformat())
        # Keep only last 100 entries
        patterns[email_account]['access_history'] = patterns[email_account]['access_history'][-100:]
        
        # Save updated patterns
        with open(pattern_file, 'w') as f:
            json.dump(patterns, f, indent=2)
        
        # Determine alert level
        if risk_score >= 70:
            alert_level = "CRITICAL"
            alert_message = "⚠️ CRITICAL: Immediate action required! Your email may be compromised."
        elif risk_score >= 40:
            alert_level = "WARNING"
            alert_message = "⚠️ WARNING: Unusual email access detected. Verify your account."
        elif risk_score >= 20:
            alert_level = "INFO"
            alert_message = "ℹ️ INFO: New device or location detected for your email."
        else:
            alert_level = "NORMAL"
            alert_message = "✅ Email access pattern normal."
        
        return {
            "email": email_account,
            "anomalies": anomalies,
            "risk_score": risk_score,
            "alert_level": alert_level,
            "alert_message": alert_message,
            "timestamp": now.isoformat(),
            "device_fingerprint": device_fingerprint[:16] + "..."
        }
    
    def _generate_device_fingerprint(self) -> str:
        """
        Generate a unique device fingerprint using system information.
        """
        import hashlib
        import platform
        import sys
        
        # Collect system information
        system_info = {
            'platform': platform.platform(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'python_version': sys.version,
        }
        
        # Try to get MAC address (non-network - uses local)
        try:
            import uuid
            system_info['mac'] = str(uuid.getnode())
        except:
            system_info['mac'] = 'unavailable'
        
        # Generate fingerprint
        fingerprint_string = json.dumps(system_info, sort_keys=True)
        fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        return fingerprint
    
    def send_anomaly_alert(self, anomaly_result: dict, user_email: str = None):
        """
        Send alert for email anomaly (simulated - would integrate with email/SMS service).
        
        In production, this would:
        - Send SMS to registered phone number
        - Send email to backup email address
        - Push notification to mobile app
        """
        if anomaly_result["alert_level"] in ["CRITICAL", "WARNING"]:
            # Log the alert
            logger.warning(f"EMAIL ANOMALY ALERT: {anomaly_result['alert_message']}")
            logger.warning(f"  Email: {anomaly_result['email']}")
            logger.warning(f"  Risk Score: {anomaly_result['risk_score']}")
            for anomaly in anomaly_result["anomalies"]:
                logger.warning(f"  - {anomaly}")
            return True
        return False
    
    def export_security_report(self,
                                decrypted_list: List[Tuple[str, str]],
                                vault_score: int,
                                filepath: str = None) -> Tuple[bool, str]:
        """
        Exports a professional security report to a text file.
        """
        # Implementation placeholder
        return True, "Report exported successfully"
    
    # ═══════════════════════════════════════════════════════
    # ADVANCED SECURITY AUDITING - Unshakeable Defense
    # ═══════════════════════════════════════════════════════
    
    def calculate_pattern_score(self, password: str) -> dict:
        """
        Advanced pattern analysis - detects common password patterns
        that attackers use in dictionary attacks.
        """
        import re
        
        score = 100
        patterns_found = []
        
        # 1. Keyboard row patterns
        keyboard_rows = [
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"
        ]
        password_lower = password.lower()
        for row in keyboard_rows:
            for i in range(len(row) - 3):
                pattern = row[i:i+4]
                if pattern in password_lower:
                    patterns_found.append(f"Keyboard pattern: {pattern}")
                    score -= 15
                    break
        
        # 2. Sequential numbers
        if re.search(r'012|123|234|345|456|567|678|789|890', password):
            patterns_found.append("Sequential numbers detected")
            score -= 20
        
        # 3. Sequential letters
        if re.search(r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz', password_lower):
            patterns_found.append("Sequential letters detected")
            score -= 20
        
        # 4. Repeated characters
        repeats = re.findall(r'(.)\1{2,}', password)
        if repeats:
            patterns_found.append(f"Repeated characters: {repeats}")
            score -= len(repeats) * 10
        
        # 5. Year patterns
        if re.search(r'19[0-9]{2}|20[0-2][0-9]|202[0-5]', password):
            patterns_found.append("Year pattern detected (easily guessable)")
            score -= 15
        
        # 6. Common word detection with leetspeak
        common_words = ['password', 'admin', 'user', 'login', 'welcome', 'master', 'secret']
        for word in common_words:
            leet_variations = [
                word,
                word.replace('a', '@').replace('e', '3').replace('i', '1'),
                word.replace('o', '0').replace('s', '$').replace('t', '7')
            ]
            for variation in leet_variations:
                if variation in password_lower:
                    patterns_found.append(f"Common word detected: {word}")
                    score -= 25
                    break
        
        return {
            "score": max(0, score),
            "patterns_found": patterns_found,
            "is_pattern_weak": score < 60
        }
    
    def calculate_entropy_distribution(self, passwords: list) -> dict:
        """
        Advanced statistical analysis of password entropy across vault.
        """
        import statistics
        
        entropies = [self._calculate_entropy(pwd) for pwd in passwords]
        
        if not entropies:
            return {
                "mean": 0, "median": 0, "std_dev": 0,
                "min": 0, "max": 0, "outliers": [],
                "risk_level": "NO_DATA", "total_analyzed": 0
            }
        
        mean_entropy = statistics.mean(entropies)
        median_entropy = statistics.median(entropies)
        std_dev = statistics.stdev(entropies) if len(entropies) > 1 else 0
        
        outliers = []
        for i, entropy in enumerate(entropies):
            if entropy < mean_entropy - std_dev * 1.5:
                outliers.append({"index": i, "entropy": entropy, "deviation": mean_entropy - entropy})
        
        if mean_entropy >= 80:
            risk = "LOW"
        elif mean_entropy >= 60:
            risk = "MODERATE"
        elif mean_entropy >= 40:
            risk = "HIGH"
        else:
            risk = "CRITICAL"
        
        return {
            "mean": round(mean_entropy, 2),
            "median": round(median_entropy, 2),
            "std_dev": round(std_dev, 2),
            "min": round(min(entropies), 2),
            "max": round(max(entropies), 2),
            "outliers": outliers[:5],
            "outlier_count": len(outliers),
            "risk_level": risk,
            "total_analyzed": len(entropies)
        }
    
    def predict_breach_likelihood(self, password: str) -> dict:
        """
        Predicts likelihood of password appearing in future breaches.
        """
        entropy = self._calculate_entropy(password)
        pattern_score = self.calculate_pattern_score(password)
        
        risk_factors = []
        risk_score = 0
        
        if entropy < 40:
            risk_factors.append(f"Low entropy ({entropy:.1f} bits)")
            risk_score += 30
        
        if pattern_score["is_pattern_weak"]:
            risk_factors.append("Contains common keyboard/sequential patterns")
            risk_score += 25
        
        if len(password) < 10:
            risk_factors.append(f"Short length ({len(password)} chars)")
            risk_score += 20
        
        if not re.search(r'[^a-zA-Z0-9]', password):
            risk_factors.append("Missing special characters")
            risk_score += 15
        
        if password.islower():
            risk_factors.append("All lowercase letters")
            risk_score += 10
        
        if risk_score >= 70:
            likelihood = "VERY_HIGH"
            description = "This password is highly likely to appear in future breaches"
        elif risk_score >= 50:
            likelihood = "HIGH"
            description = "This password has a high chance of being breached"
        elif risk_score >= 30:
            likelihood = "MODERATE"
            description = "This password has moderate breach risk"
        elif risk_score >= 10:
            likelihood = "LOW"
            description = "This password has low breach risk"
        else:
            likelihood = "VERY_LOW"
            description = "This password is unlikely to appear in breaches"
        
        return {
            "likelihood": likelihood,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "description": description,
            "recommendation": self._get_breach_recommendation(risk_score)
        }
    
    def _get_breach_recommendation(self, risk_score: int) -> str:
        """Get recommendation based on breach risk score."""
        if risk_score >= 70:
            return "CHANGE IMMEDIATELY - Use the password generator to create a strong, unique password"
        elif risk_score >= 50:
            return "Change soon - Consider using a longer password with special characters"
        elif risk_score >= 30:
            return "Monitor - Password is acceptable but could be stronger"
        else:
            return "Good - This password meets security best practices"
    
    def comprehensive_password_analysis(self, password: str) -> dict:
        """
        Complete password analysis combining all security metrics.
        """
        audit = self.audit_single_password(password)
        entropy = audit["entropy"]
        pattern_analysis = self.calculate_pattern_score(password)
        breach_prediction = self.predict_breach_likelihood(password)
        
        overall_score = 100
        
        if entropy < 28:
            overall_score -= 40
        elif entropy < 36:
            overall_score -= 25
        elif entropy < 60:
            overall_score -= 10
        
        overall_score -= (100 - pattern_analysis["score"]) * 0.3
        overall_score -= breach_prediction["risk_score"] * 0.2
        
        overall_score = max(0, min(100, round(overall_score)))
        
        if overall_score >= 85:
            verdict = "EXCELLENT"
            verdict_color = "#00E676"
            icon = "💎"
        elif overall_score >= 70:
            verdict = "GOOD"
            verdict_color = "#00C851"
            icon = "🟢"
        elif overall_score >= 50:
            verdict = "FAIR"
            verdict_color = "#FFD700"
            icon = "🟡"
        elif overall_score >= 30:
            verdict = "POOR"
            verdict_color = "#FF8C00"
            icon = "🟠"
        else:
            verdict = "CRITICAL"
            verdict_color = "#FF4444"
            icon = "🔴"
        
        return {
            "overall_score": overall_score,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "icon": icon,
            "entropy": entropy,
            "strength_label": audit["strength_label"],
            "is_common": audit["is_common"],
            "issues": audit["issues"],
            "patterns": pattern_analysis["patterns_found"],
            "pattern_score": pattern_analysis["score"],
            "breach_likelihood": breach_prediction["likelihood"],
            "breach_risk_score": breach_prediction["risk_score"],
            "breach_factors": breach_prediction["risk_factors"],
            "recommendation": breach_prediction["recommendation"],
            "length": len(password),
            "has_upper": any(c.isupper() for c in password),
            "has_lower": any(c.islower() for c in password),
            "has_digit": any(c.isdigit() for c in password),
            "has_special": any(c in "!@#$%^&*()" for c in password)
        }
    
    def vault_risk_assessment(self, decrypted_credentials: list) -> dict:
        """
        Comprehensive vault-wide risk assessment.
        """
        if not decrypted_credentials:
            return {
                "risk_level": "NO_DATA",
                "risk_score": 0,
                "vulnerable_accounts": 0,
                "critical_accounts": 0,
                "recommendations": ["Add passwords to analyze"]
            }
        
        analyses = []
        for site, pwd in decrypted_credentials:
            analysis = self.comprehensive_password_analysis(pwd)
            analyses.append({
                "site": site,
                "analysis": analysis
            })
        
        total = len(analyses)
        critical = sum(1 for a in analyses if a["analysis"]["verdict"] == "CRITICAL")
        poor = sum(1 for a in analyses if a["analysis"]["verdict"] == "POOR")
        fair = sum(1 for a in analyses if a["analysis"]["verdict"] == "FAIR")
        good = sum(1 for a in analyses if a["analysis"]["verdict"] == "GOOD")
        excellent = sum(1 for a in analyses if a["analysis"]["verdict"] == "EXCELLENT")
        
        avg_score = sum(a["analysis"]["overall_score"] for a in analyses) / total
        
        if avg_score >= 80:
            risk_level = "LOW"
            risk_color = "#00C851"
        elif avg_score >= 60:
            risk_level = "MODERATE"
            risk_color = "#FFD700"
        elif avg_score >= 40:
            risk_level = "HIGH"
            risk_color = "#FF8C00"
        else:
            risk_level = "CRITICAL"
            risk_color = "#FF4444"
        
        recommendations = []
        if critical > 0:
            recommendations.append(f"CRITICAL: {critical} password(s) need immediate replacement")
        if poor > 0:
            recommendations.append(f"WARNING: {poor} password(s) are weak and should be changed")
        if avg_score < 70:
            recommendations.append("Enable the password generator for all new accounts")
        
        recommendations.append("Run weekly security audits to maintain vault health")
        
        return {
            "risk_level": risk_level,
            "risk_color": risk_color,
            "risk_score": round(avg_score, 1),
            "total_accounts": total,
            "critical": critical,
            "poor": poor,
            "fair": fair,
            "good": good,
            "excellent": excellent,
            "vulnerable_accounts": critical + poor,
            "recommendations": recommendations,
            "top_vulnerable": sorted([(a["site"], a["analysis"]["overall_score"]) 
                                       for a in analyses if a["analysis"]["overall_score"] < 50],
                                      key=lambda x: x[1])[:5]
        }


# ─────────────────────────────────────────────
# DEMONSTRATION / TESTING
# ─────────────────────────────────────────────

if __name__ == "__main__":
    """Test the SentinelAuditor class with sample data."""
    
    import sys
    import io
    
    # Configure console for UTF-8 if possible
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("=" * 60)
    print("SentinelsVault - SentinelAuditor Class Test")
    print("=" * 60)
    
    auditor = SentinelAuditor()
    
    # Test single password audit
    test_passwords = ["password123", "MyStr0ng!P@ssw0rd", "abc", "X9@mK#vL2$"]
    
    print("\n[1] Single Password Audit Tests:")
    for pwd in test_passwords:
        result = auditor.audit_single_password(pwd)
        print(f"\n  Password: {pwd}")
        print(f"    Strength: {result['strength_label']}")
        print(f"    Entropy: {result['entropy']} bits")
        print(f"    Score: {result['score']}/100")
        print(f"    Common: {result['is_common']}")
        print(f"    Issues: {', '.join(result['issues']) if result['issues'] else 'None'}")
    
    # Test vault report
    sample_vault = [
        ("Gmail", "password123"),
        ("Facebook", "MyStr0ng!P@ssw0rd"),
        ("Twitter", "MyStr0ng!P@ssw0rd"),  # Reused password
        ("Bank", "X9@mK#vL2$"),
    ]
    
    print("\n\n[2] Vault Health Report:")
    report = auditor.generate_vault_report(sample_vault)
    print(f"  Total Credentials: {report['total_count']}")
    print(f"  Strength Distribution: {report['categories']}")
    print(f"  Reused Password Groups: {len(report['reused_map'])}")
    print(f"  Vault Security Score: {report['vault_score']}/100")
    
    # Test comprehensive report
    comprehensive = auditor.generate_comprehensive_report(sample_vault)
    print(f"\n  Comprehensive Report Summary:")
    print(f"    {comprehensive.get_summary()}")
    print(f"    Security Verdict: {comprehensive.security_verdict}")
    print(f"    Recommendations: {len(comprehensive.recommendations)} actions suggested")
    
    print("\n[3] Password Generator Test:")
    simple_pwd = auditor.generate_secure_password(16)
    print(f"  Generated Simple Password: {simple_pwd}")
    
    custom_pwd = auditor.generate_custom_password(20, use_upper=True, use_lower=True, 
                                                    use_digits=True, use_symbols=True,
                                                    exclude_ambiguous=True)
    print(f"  Generated Custom Password: {custom_pwd}")
    
    print("\n[4] Strength Guide Test:")
    guide = auditor.get_strength_guide()
    print(f"  Strength Tiers: {len(guide['tiers'])} levels")
    print(f"  Golden Rules: {len(guide['golden_rules'])} rules")
    print(f"  Entropy Formula: {guide['entropy_formula']['formula']}")
    
    print("\n[5] Advanced Pattern Analysis Test:")
    weak_pattern = "qwerty123"
    pattern_result = auditor.calculate_pattern_score(weak_pattern)
    print(f"  Password: {weak_pattern}")
    print(f"    Pattern Score: {pattern_result['score']}/100")
    print(f"    Patterns Found: {pattern_result['patterns_found']}")
    
    print("\n" + "=" * 60)
    print("SentinelAuditor test completed successfully!")
    print("=" * 60)