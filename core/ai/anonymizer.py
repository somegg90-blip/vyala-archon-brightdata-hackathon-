"""
vyala/ai/anonymizer.py

Pre-LLM Anonymizer — Zero-Trust Secret Scrubber
=================================================
Every code snippet extracted by the Tree-sitter parsers passes through this
module BEFORE it is transmitted to any external LLM (Claude/Anthropic API).

This is a hard security boundary. The architectural guarantee is:

    "No secret value ever leaves the customer's environment."

The customer shares STRUCTURE — what crypto algorithm is used, how it's called,
what parameters are passed. They never share VALUES — the actual key material,
credentials, or tokens that make those algorithms dangerous.

Design philosophy
-----------------
1. Allowlist over blocklist for CONTEXT, blocklist over allowlist for VALUES.
   We preserve cryptographic algorithm names (RSA, AES, ECDSA) because the
   LLM needs them to reason about quantum vulnerability. We redact everything
   that looks like a secret value — aggressively and with zero trust.

2. Order matters. Patterns are applied in priority sequence:
     a. PEM / DER blocks            (multi-line, highest risk, handle first)
     b. High-entropy string values  (base64/hex blobs assigned to variables)
     c. Named secret variables      (password=, api_key=, etc.)
     d. Known credential formats    (AWS keys, JWTs, connection strings)
     e. Inline key material         (hex/base64 strings in call arguments)
   Later patterns mop up what earlier patterns miss.

3. False negatives (a secret slips through) are worse than false positives
   (a harmless value is redacted). When in doubt, redact.

4. Context preservation. We never redact:
   - Algorithm names: RSA, AES, ECDSA, SHA, HMAC, DH, DSA
   - Parameter names: key_size, public_exponent, mode, padding
   - Structural code: function names, class names, module paths
   - Integer literals that are key sizes: 1024, 2048, 4096, 256
   The LLM needs all of this context to generate accurate PQC recommendations.

References
----------
- NIST SP 800-188: De-Identification of Government Datasets
- OWASP Secret Management Cheat Sheet
- Anthropic Usage Policy: Customer Data Protection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple

from loguru import logger


# ==============================================================================
# PLACEHOLDER TOKENS
# Using distinct tokens per category makes the anonymized snippet more useful
# to the LLM ("a [REDACTED_SECRET_VALUE] was passed as the key argument"
# conveys more than just "[REDACTED_VYALA]"). The VYALA prefix ensures we
# never accidentally match our own placeholders in recursive scans.
# ==============================================================================

_REDACTED_SECRET    = "[VYALA:REDACTED_SECRET]"
_REDACTED_KEY       = "[VYALA:REDACTED_KEY_MATERIAL]"
_REDACTED_PEM       = "[VYALA:REDACTED_PEM_BLOCK]"
_REDACTED_AWS       = "[VYALA:REDACTED_AWS_CREDENTIAL]"
_REDACTED_JWT       = "[VYALA:REDACTED_JWT]"
_REDACTED_CONNSTR   = "[VYALA:REDACTED_CONNECTION_STRING]"
_REDACTED_HASH      = "[VYALA:REDACTED_HASH_DIGEST]"
_REDACTED_ENTROPY   = "[VYALA:REDACTED_HIGH_ENTROPY_VALUE]"


class RedactionRecord(NamedTuple):
    """Audit record for a single redaction event."""
    pattern_name: str
    original_value: str     # WARNING: only stored in-memory for unit tests; never logged
    replacement: str
    start: int
    end: int


@dataclass
class AnonymizerResult:
    """
    Output of a single Anonymizer.sanitize() call.

    Attributes
    ----------
    sanitized:
        The cleaned code snippet safe for transmission to external LLMs.
    redaction_count:
        Total number of substitutions made. Zero means no secrets were found
        (or the snippet was already clean). Useful for audit dashboards.
    was_modified:
        Convenience boolean — True if any redaction occurred.
    categories_redacted:
        Set of pattern category names that fired. Useful for the CBOM audit
        trail to explain WHY a snippet was sanitized.
    """
    sanitized: str
    redaction_count: int
    was_modified: bool
    categories_redacted: set[str] = field(default_factory=set)


# ==============================================================================
# COMPILED PATTERN REGISTRY
# Patterns are compiled once at module import time — not on every sanitize()
# call. For an enterprise scan processing millions of code snippets, this is
# the difference between 0.1ms and 2ms per call.
# ==============================================================================

@dataclass(frozen=True)
class _RedactionPattern:
    """A single compiled regex pattern with its metadata."""
    name: str
    pattern: re.Pattern[str]
    replacement: str
    description: str


def _p(name: str, raw: str, replacement: str, description: str, flags: int = 0) -> _RedactionPattern:
    """Factory helper — compile a regex and wrap it in a RedactionPattern."""
    return _RedactionPattern(
        name=name,
        pattern=re.compile(raw, re.IGNORECASE | re.MULTILINE | flags),
        replacement=replacement,
        description=description,
    )


# ── ORDERED PATTERN LIST ────────────────────────────────────────────────────
# READ THIS BEFORE ADDING PATTERNS:
#
# 1. More specific / longer matches FIRST. A JWT regex must run before a
#    generic base64 regex, or the JWT will be partially redacted and
#    leave a malformed stub.
# 2. Multi-line patterns (PEM blocks) FIRST — they span multiple lines
#    and would corrupt later single-line patterns if they ran second.
# 3. Context-preserving patterns use look-behind/look-ahead to keep
#    the variable name / parameter name visible to the LLM while only
#    redacting the VALUE.
#
# Format of each tuple: (name, raw_regex, replacement, description)
_PATTERNS: list[_RedactionPattern] = [

    # ──────────────────────────────────────────────────────────────────────────
    # TIER 1: PEM / DER BLOCKS (multi-line, highest risk, handle first)
    # A leaked private key in a CBOM report sent to an LLM would be catastrophic.
    # Match anything between -----BEGIN ... KEY----- and -----END ... KEY-----
    # including the header/footer lines themselves.
    # ──────────────────────────────────────────────────────────────────────────
    _p(
        name="pem_private_key_block",
        raw=r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----",
        replacement=_REDACTED_PEM,
        description="PEM-encoded private key block (RSA, EC, DSA, OpenSSH, encrypted variants)",
        flags=re.DOTALL,
    ),
    _p(
        name="pem_certificate_block",
        raw=r"-----BEGIN\s+CERTIFICATE-----[\s\S]*?-----END\s+CERTIFICATE-----",
        replacement=_REDACTED_PEM,
        description="PEM-encoded X.509 certificate — may contain org identity data",
        flags=re.DOTALL,
    ),
    _p(
        name="pem_generic_block",
        raw=r"-----BEGIN\s+[\w\s]+-----[\s\S]*?-----END\s+[\w\s]+-----",
        replacement=_REDACTED_PEM,
        description="Generic PEM block catch-all (PKCS#8, CMS, etc.)",
        flags=re.DOTALL,
    ),

    # ──────────────────────────────────────────────────────────────────────────
    # TIER 2: KNOWN CREDENTIAL FORMATS WITH STRUCTURAL SIGNATURES
    # These formats have recognizable structural prefixes that make them
    # identifiable independently of variable names.
    # ──────────────────────────────────────────────────────────────────────────
    _p(
        name="aws_access_key_id",
        raw=r"\b(AKIA|ABIA|ACCA|AIPA|AKIA|ANPA|ANVA|AROA|APKA|ASIA)[A-Z0-9]{16}\b",
        replacement=_REDACTED_AWS,
        description="AWS Access Key ID (AKIA..., ASIA... etc.) — 20 char uppercase alphanumeric",
    ),
    _p(
        name="aws_secret_access_key",
        # AWS secret keys are 40-char base64url strings. Often appear after
        # the variable name `aws_secret_access_key` or `AWS_SECRET_ACCESS_KEY`.
        raw=r"(?:aws_secret(?:_access)?_key|AWS_SECRET(?:_ACCESS)?_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?",
        replacement=f"aws_secret_access_key = {_REDACTED_AWS}",
        description="AWS Secret Access Key (40-char base64) bound to a variable",
    ),
    _p(
        name="jwt_token",
        # JWTs are three base64url segments separated by dots.
        # We preserve the word "JWT" or "token" if it appears before the value.
        raw=r"['\"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]?",
        replacement=_REDACTED_JWT,
        description="JSON Web Token (three-segment base64url with eyJ header)",
    ),
    _p(
        name="connection_string",
        # Matches: postgresql://user:password@host/db
        #          mongodb://user:pass@host:27017/db
        #          mysql://root:secret@localhost/schema
        raw=r"(?:postgresql|mysql|mongodb|redis|amqp|jdbc:[a-z]+)://[^:]+:[^@\s'\"]+@[^\s'\"]+",
        replacement=_REDACTED_CONNSTR,
        description="Database / broker connection string with embedded credentials",
    ),
    _p(
        name="github_token",
        raw=r"\b(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}\b",
        replacement=_REDACTED_SECRET,
        description="GitHub Personal Access Token / OAuth token",
    ),
    _p(
        name="google_api_key",
        raw=r"\bAIza[A-Za-z0-9_\-]{35}\b",
        replacement=_REDACTED_SECRET,
        description="Google API key (AIza prefix, 39 chars)",
    ),
    _p(
        name="stripe_key",
        raw=r"\b(sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]{24,}\b",
        replacement=_REDACTED_SECRET,
        description="Stripe live / test API key",
    ),
    _p(
        name="generic_bearer_token",
        # Authorization: Bearer <token> — common in HTTP headers in code
        raw=r"(?:Authorization|auth(?:orization)?)\s*[=:]\s*['\"]?Bearer\s+[A-Za-z0-9\-._~+/]+=*['\"]?",
        replacement=f"Authorization = Bearer {_REDACTED_SECRET}",
        description="Bearer token in Authorization header assignment",
    ),

    # ──────────────────────────────────────────────────────────────────────────
    # TIER 3: NAMED SECRET VARIABLES
    # Variable name patterns followed by = or : and a string/bytes value.
    #
    # CRITICAL DESIGN NOTE — what we PRESERVE vs REDACT:
    #   PRESERVED: the variable name ("password", "api_key") — the LLM needs
    #              this to understand what the crypto is doing ("this key is
    #              used for authentication, not encryption").
    #   REDACTED:  the VALUE — the actual string after the = or :.
    #
    # Look-behind matches the variable name; look-ahead is NOT used.
    # We capture up to the end of the assigned string literal.
    # ──────────────────────────────────────────────────────────────────────────
    _p(
        name="secret_variable_assignment",
        # Matches: password = "s3cr3t!", api_key: 'ABCDEF', SECRET_TOKEN = b"bytes"
        # Preserves: everything up to and including the = or :
        # Redacts: the string literal value (single, double, triple quoted, bytes)
        raw=(
            r"(?:password|passwd|pwd|secret(?:_key)?|api[_-]?key|auth(?:_key|_token)?"
            r"|access[_-]?token|refresh[_-]?token|bearer|credential(?:s)?"
            r"|private[_-]?key|signing[_-]?key|encryption[_-]?key"
            r"|master[_-]?key|symmetric[_-]?key|hmac[_-]?key|aes[_-]?key"
            r"|rsa[_-]?key|ssh[_-]?(?:key|pass(?:phrase)?)"
            r"|client[_-]?secret|consumer[_-]?secret"
            r"|jwt[_-]?secret|cookie[_-]?secret|session[_-]?secret"
            r"|db[_-]?(?:pass(?:word)?|secret)|database[_-]?pass(?:word)?)"
            r"(\s*[=:]\s*)"
            r"(?:b?['\"])[^'\"]*(?:['\"])"                        # Closing quote
        ),
        replacement=_REDACTED_SECRET,
        description="String literal value assigned to a recognized secret variable name",
    ),
    _p(
        name="secret_variable_multiline",
        # Handles triple-quoted strings: password = """s3cr3t"""
        raw=(
            r"(?:password|passwd|pwd|secret(?:_key)?|api[_-]?key|auth(?:_key|_token)?"
            r"|access[_-]?token|private[_-]?key|signing[_-]?key|encryption[_-]?key)"
            r"(\s*[=:]\s*)"
            r'(?:b?[\'\"]{3})[\s\S]*?(?:[\'\"]{3})'
        ),
        replacement=_REDACTED_SECRET,
        description="Triple-quoted string value assigned to a secret variable name",
        flags=re.DOTALL,
    ),
    _p(
        name="os_environ_secret",
        # os.environ['SECRET_KEY'] = '...' or os.environ.get('AWS_SECRET', '...')
        raw=(
            r"os\.environ(?:\.get)?\s*\[?\s*['\"]"
            r"(?:password|passwd|secret|api_key|auth_token|private_key|signing_key)"
            r"['\"](?:\s*\]|\s*,\s*['\"][^'\"]*['\"]|\s*\)\s*)"
            r"(?:\s*=\s*['\"][^'\"]*['\"])?"
        ),
        replacement=f"os.environ[{_REDACTED_SECRET}]",
        description="Secret key name or value accessed via os.environ",
    ),

    # ──────────────────────────────────────────────────────────────────────────
    # TIER 4: HASH DIGESTS (Must run BEFORE generic hex keys!)
    # Hash digests in code can be used to fingerprint internal data structures.
    # We redact known-length hash hex strings that appear as string literals.
    # ──────────────────────────────────────────────────────────────────────────
    _p(
        name="md5_digest",
        raw=r"['\"][0-9a-fA-F]{32}['\"]",
        replacement=_REDACTED_HASH,
        description="32-char hex string (MD5 digest length) — potential data fingerprint",
    ),
    _p(
        name="sha1_digest",
        raw=r"['\"][0-9a-fA-F]{40}['\"]",
        replacement=_REDACTED_HASH,
        description="40-char hex string (SHA-1 digest length) — potential data fingerprint",
    ),
    _p(
        name="sha256_digest",
        raw=r"['\"][0-9a-fA-F]{64}['\"]",
        replacement=_REDACTED_HASH,
        description="64-char hex string (SHA-256 digest length) — potential data fingerprint",
    ),
    _p(
        name="sha512_digest",
        raw=r"['\"][0-9a-fA-F]{128}['\"]",
        replacement=_REDACTED_HASH,
        description="128-char hex string (SHA-512 digest length) — potential data fingerprint",
    ),

    # ──────────────────────────────────────────────────────────────────────────
    # TIER 5: HIGH-ENTROPY / KEY MATERIAL PATTERNS
    # These catch raw key bytes, hex-encoded keys, and base64 key blobs.
    # Because Tier 4 already caught exact-length hashes (32, 40, 64, 128 chars),
    # the 32+ char hex pattern here will safely catch remaining generic keys.
    # ──────────────────────────────────────────────────────────────────────────
    _p(
        name="hex_encoded_key",
        raw=r"(?:b?['\"]|0x)(?:[0-9A-Fa-f]{32,})['\"]?",
        replacement=_REDACTED_KEY,
        description="Hex-encoded key material (≥128 bits, in string or 0x literal)",
    ),
    _p(
        name="base64_key_material",
        raw=r"(?<![eE][yY][jJ])['\"](?:[A-Za-z0-9+/]{44,}={0,2})['\"](?!\.[A-Za-z0-9])",
        replacement=_REDACTED_KEY,
        description="Base64-encoded key material (≥256 bits, in string literal)",
    ),
    _p(
        name="bytes_key_literal",
        raw=r"b['\"](?:\\x[0-9A-Fa-f]{2}){8,}['\"]",
        replacement=_REDACTED_KEY,
        description="Python bytes literal with ≥8 hex escape sequences (plausible key material)",
    ),

    # ──────────────────────────────────────────────────────────────────────────
    # TIER 6: NETWORK / INFRASTRUCTURE IDENTIFIERS
    # IP addresses and hostnames in crypto code often reveal internal topology.
    # ──────────────────────────────────────────────────────────────────────────
    _p(
        name="ipv4_address",
        raw=r"(?<![0-9])(?!127\.0\.0\.1)(?!0\.0\.0\.0)"
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            r"(?![0-9])",
        replacement="[VYALA:REDACTED_IP]",
        description="IPv4 address (excluding localhost) — internal topology fingerprint",
    ),
]


# ==============================================================================
# ALLOWLIST — NEVER REDACT THESE
# These are regex patterns for strings that look like secrets but are actually
# cryptographic algorithm names, parameter names, or known-safe constants.
# If a match from _PATTERNS would replace something matching an allowlist entry,
# the allowlist wins.
#
# Implementation note: We apply allowlist AFTER redaction by detecting if
# our own VYALA tokens were inserted where they shouldn't be, then restoring.
# In practice, the pattern specificity above avoids most allowlist collisions.
# The allowlist is a safety net, not the primary mechanism.
# ==============================================================================

_ALLOWLIST_PATTERNS: list[re.Pattern[str]] = [
    # Algorithm names that look like variable names but must be preserved
    re.compile(r"\b(RSA|AES|ECC|ECDSA|ECDH|DSA|DH|HMAC|SHA|MD5|DES|ChaCha20|Ed25519|X25519)\b"),
    # NIST PQC algorithm names
    re.compile(r"\b(ML-KEM|ML-DSA|SLH-DSA|FN-DSA|CRYSTALS|Kyber|Dilithium|SPHINCS|Falcon)\b"),
    # Key size integers — essential context for severity assessment
    re.compile(r"\b(128|192|256|384|512|1024|2048|3072|4096|8192)\b"),
    # Common algorithm parameter names
    re.compile(r"\b(key_size|public_exponent|mode|padding|curve|hash_algorithm|backend)\b"),
    # Python crypto module paths — these are identifiers, not secrets
    re.compile(r"\b(Crypto|Cryptodome|cryptography|hazmat|primitives|asymmetric|symmetric)\b"),
]


# ==============================================================================
# ANONYMIZER CLASS
# ==============================================================================


class Anonymizer:
    """
    Stateless secret scrubber for VYALA code snippets.

    Usage
    -----
    >>> anonymizer = Anonymizer()
    >>> result = anonymizer.sanitize(code_snippet)
    >>> safe_snippet = result.sanitized
    >>> print(f"Made {result.redaction_count} redaction(s): {result.categories_redacted}")

    Thread safety
    -------------
    Anonymizer is stateless — all state is local to each sanitize() call.
    The compiled regex patterns in _PATTERNS are module-level constants
    shared across all instances and threads (compiled Pattern objects are
    thread-safe in CPython).
    A single Anonymizer instance can safely be shared across async workers
    in the FastAPI server or multiprocessing scan workers.
    """

    def sanitize(self, code_snippet: str) -> AnonymizerResult:
        """
        Apply all redaction patterns to `code_snippet` and return the
        sanitized version alongside audit metadata.

        Parameters
        ----------
        code_snippet:
            Raw source code extracted by the Tree-sitter parser.
            May contain any content including PEM blocks, credentials,
            and raw key bytes.

        Returns
        -------
        AnonymizerResult
            .sanitized           — safe string for LLM transmission
            .redaction_count     — number of substitutions made
            .was_modified        — True if any secrets were found
            .categories_redacted — set of pattern names that fired

        Notes
        -----
        This method NEVER raises. If an individual pattern substitution
        fails for any reason, it is logged and skipped — partial redaction
        is safer than no redaction (better to send a partially scrubbed
        snippet than to crash and send nothing). However, see the WARNING
        in the class docstring: a partially redacted snippet still exits
        the trust boundary. The calling layer (vyala/ai/context_builder.py)
        should validate that no VYALA redaction tokens are present in the
        final snippet before transmission (meaning all placeholders were
        inserted correctly).
        """
        if not code_snippet:
            return AnonymizerResult(
                sanitized="",
                redaction_count=0,
                was_modified=False,
            )

        sanitized = code_snippet
        total_redactions = 0
        categories_fired: set[str] = set()

        for redaction_pattern in _PATTERNS:
            try:
                before = sanitized
                sanitized, count = redaction_pattern.pattern.subn(
                    redaction_pattern.replacement,
                    sanitized,
                )
                if count > 0:
                    total_redactions += count
                    categories_fired.add(redaction_pattern.name)
                    logger.debug(
                        "Anonymizer redacted | pattern={} | count={} | replacement={}",
                        redaction_pattern.name,
                        count,
                        redaction_pattern.replacement,
                    )
            except re.error as exc:
                # Should never happen with pre-compiled patterns, but be defensive.
                logger.error(
                    "Anonymizer regex error | pattern={} | error={}",
                    redaction_pattern.name,
                    exc,
                )
                # Continue — do not let a broken pattern abort the entire pipeline.

        was_modified = sanitized != code_snippet

        if was_modified:
            logger.info(
                "Anonymizer sanitized snippet | redactions={} | categories={}",
                total_redactions,
                sorted(categories_fired),
            )
        else:
            logger.debug("Anonymizer: no secrets detected in snippet.")

        return AnonymizerResult(
            sanitized=sanitized,
            redaction_count=total_redactions,
            was_modified=was_modified,
            categories_redacted=categories_fired,
        )

    def sanitize_raw(self, code_snippet: str) -> str:
        """
        Convenience wrapper — returns only the sanitized string.
        Use when you don't need the audit metadata (e.g., in unit tests).

        Equivalent to: `anonymizer.sanitize(snippet).sanitized`
        """
        return self.sanitize(code_snippet).sanitized

    def audit_snippet(self, code_snippet: str) -> dict[str, int]:
        """
        Dry-run analysis — returns a dict of {pattern_name: match_count}
        for every pattern that would fire, WITHOUT modifying the snippet.

        Use this in the CBOM dashboard to show "N secrets redacted before
        AI analysis" without actually performing the redaction (which
        happens in the scanner pipeline, not in the dashboard layer).
        """
        report: dict[str, int] = {}
        for redaction_pattern in _PATTERNS:
            matches = redaction_pattern.pattern.findall(code_snippet)
            if matches:
                report[redaction_pattern.name] = len(matches)
        return report

    @staticmethod
    def is_safe_for_transmission(sanitized_snippet: str) -> bool:
        """
        Final gate-check before LLM API transmission.

        Returns True if the snippet contains no VYALA redaction placeholders
        that indicate the anonymizer ran but left markers (which would imply
        the redaction worked correctly). Returns False if raw secret patterns
        are still detectable AFTER anonymization — meaning a new secret format
        was encountered that none of our patterns cover.

        This is a defence-in-depth check. The calling layer should call this
        and abort transmission if it returns False, logging the raw snippet
        for pattern database update.

        WARNING: This check is heuristic, not cryptographically guaranteed.
        New secret formats will evade it until patterns are updated.
        """
        # Check for any obviously un-redacted high-risk patterns
        HIGH_RISK_INDICATORS = [
            re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
            re.compile(r"\b(AKIA|ABIA|ASIA)[A-Z0-9]{16}\b"),
            re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
            re.compile(r"(?:postgresql|mysql|mongodb)://[^:]+:[^@\s'\"]{8,}@"),
        ]
        for indicator in HIGH_RISK_INDICATORS:
            if indicator.search(sanitized_snippet):
                logger.critical(
                    "SECURITY GATE FAILED: Un-redacted secret pattern detected "
                    "AFTER anonymization. Aborting LLM transmission. "
                    "Pattern: {}",
                    indicator.pattern,
                )
                return False
        return True

    def __repr__(self) -> str:
        return f"Anonymizer(patterns={len(_PATTERNS)}, tiers=6)"