"""
vyala/models/cbom.py

Crypto Bill of Materials (CBOM) — Pydantic v2 Data Models
==========================================================
These models are the canonical data contract for VYALA. Every component
(Tree-sitter parser, Claude AI layer, FastAPI endpoints, Next.js frontend)
speaks this schema and nothing else.

Design principles:
  • Immutable by default (model_config: frozen=True on leaf models)
  • Every field documents WHY it exists, not just what it is
  • Optional fields are explicitly None — no silent defaults hiding bad data
  • Enums over bare strings — the compiler (mypy) catches typos, not prod
  • NIST PQC nomenclature is first-class (CRYSTALS-Kyber, Dilithium, SPHINCS+)

References:
  - NIST SP 800-208  (Stateful Hash-Based Signatures)
  - NIST FIPS 203    (ML-KEM / CRYSTALS-Kyber)
  - NIST FIPS 204    (ML-DSA / CRYSTALS-Dilithium)
  - NIST FIPS 205    (SLH-DSA / SPHINCS+)
  - IETF RFC 9180    (HPKE — Hybrid Public Key Encryption)
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator


# ==============================================================================
# ENUMERATIONS
# All categorical values are enums. This prevents "RSA" vs "rsa" bugs from
# silently propagating through the pipeline into broken dashboard filters.
# ==============================================================================


class MigrationComplexity(str, Enum):
    """
    Estimated engineering effort to replace a vulnerable crypto primitive.

    Populated by the Claude AI layer after it analyses the usage_context.
    The str mixin means JSON serialisation produces "LOW" not "MigrationComplexity.LOW".
    """
    LOW    = "LOW"     # Drop-in library swap; no protocol changes (e.g. hash fn upgrade)
    MEDIUM = "MEDIUM"  # Key exchange refactor; moderate integration surface
    HIGH   = "HIGH"    # Protocol redesign; certificate chain migration; HSM involvement


class QuantumVulnerabilityClass(str, Enum):
    """
    NIST/academic classification of the cryptographic vulnerability type.

    Shor's algorithm breaks asymmetric crypto (RSA, ECC, DH).
    Grover's algorithm halves the effective security of symmetric crypto.
    """
    SHOR_VULNERABLE   = "SHOR_VULNERABLE"    # RSA, ECC, DH, DSA — broken by quantum
    GROVER_WEAKENED   = "GROVER_WEAKENED"    # AES-128, SHA-256 — weakened, not broken
    QUANTUM_SAFE      = "QUANTUM_SAFE"       # AES-256, SHA-384+ — currently safe
    UNKNOWN           = "UNKNOWN"            # AI could not classify; needs human review


class SeverityLevel(str, Enum):
    """
    Operational risk severity — combines quantum vulnerability class with
    the asset's exposure and how soon Q-Day is projected for that key size.

    Maps to dashboard badge colours in vyala-web.
    """
    CRITICAL = "CRITICAL"  # Harvest-now-decrypt-later risk; long-lived secrets (certs, keys)
    HIGH     = "HIGH"      # Vulnerable algo, medium-term secret lifetime
    MEDIUM   = "MEDIUM"    # Grover-weakened; survivable with key-size doubling
    LOW      = "LOW"       # Informational; quantum-safe but flagged for inventory
    INFO     = "INFO"      # Non-crypto reference; context only


class SupportedLanguage(str, Enum):
    """
    Languages VYALA's Tree-sitter grammars can parse.
    Extend this enum when a new grammar is added to requirements.txt.
    """
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA       = "java"
    GO         = "go"
    RUST       = "rust"
    C          = "c"
    CPP        = "cpp"
    CSHARP     = "csharp"
    UNKNOWN    = "unknown"


class CBOMStatus(str, Enum):
    """Lifecycle state of the overall scan report."""
    PENDING    = "PENDING"     # Scan queued, not started
    SCANNING   = "SCANNING"   # Tree-sitter pass in progress
    ANALYSING  = "ANALYSING"  # Claude AI enrichment pass in progress
    COMPLETE   = "COMPLETE"   # All findings enriched; report finalised
    FAILED     = "FAILED"     # Scan aborted; see error_message


# ==============================================================================
# LEAF MODELS
# ==============================================================================


class CodeLocation(BaseModel):
    """
    Precise source location of a crypto finding.
    Separated from CryptoFinding so the frontend can render
    IDE-style line links (VSCode, IntelliJ deep links).
    """
    model_config = {"frozen": True}

    file_path:   str = Field(
        ...,
        description="Absolute or repo-root-relative path to the source file.",
        examples=["src/auth/jwt_signer.py", "lib/crypto/rsa_utils.java"],
    )
    line_number: int = Field(
        ...,
        ge=1,
        description="1-indexed line number where the crypto primitive is invoked.",
    )
    column_start: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-indexed column of the token start. Populated by Tree-sitter.",
    )
    column_end: Optional[int] = Field(
        default=None,
        ge=0,
        description="0-indexed column of the token end. Populated by Tree-sitter.",
    )


class PQCRecommendation(BaseModel):
    """
    NIST-grounded Post-Quantum replacement recommendation.
    Populated exclusively by the Claude AI layer (vyala/ai/).
    Null until the AI enrichment pass completes.

    All algorithm names use NIST FIPS/SP designations as canonical IDs,
    with common names as aliases.
    """
    model_config = {"frozen": True}

    primary_algorithm: str = Field(
        ...,
        description=(
            "NIST-standardised PQC replacement. "
            "E.g. 'ML-KEM-768 (CRYSTALS-Kyber)', 'ML-DSA-65 (Dilithium)', "
            "'SLH-DSA-SHA2-128s (SPHINCS+)', 'FN-DSA (FALCON-512)'."
        ),
    )
    hybrid_transition_recommended: bool = Field(
        default=True,
        description=(
            "Whether to run classical + PQC in parallel during migration. "
            "NIST and NSA both recommend hybrid mode to hedge against PQC implementation bugs."
        ),
    )
    migration_notes: Optional[str] = Field(
        default=None,
        description="AI-generated step-by-step migration guidance specific to this usage context.",
    )
    nist_reference: Optional[str] = Field(
        default=None,
        description="Canonical NIST document. E.g. 'FIPS 203', 'SP 800-208'.",
        examples=["FIPS 203", "FIPS 204", "FIPS 205"],
    )


# ==============================================================================
# CORE FINDING MODEL
# ==============================================================================


class CryptoFinding(BaseModel):
    """
    A single detected instance of a cryptographic primitive in source code.

    Lifecycle:
      1. Tree-sitter parser creates the finding with raw AST data.
         (finding_id, location, language, algorithm_detected, code_snippet,
          is_quantum_vulnerable, severity are set at parse time.)
      2. Claude AI enriches the finding in-place.
         (usage_context, pqc_recommendation, migration_complexity,
          vulnerability_class are set during AI pass.)
      3. Human reviewer may override fields via the IDE plugin (Phase 2).
    """
    model_config = {"frozen": True}

    # ── Identity ────────────────────────────────────────────────────────────────
    finding_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for this finding. UUIDv4.",
    )

    # ── Source Location (Phase 1 — Tree-sitter) ─────────────────────────────────
    file_path: str = Field(
        ...,
        description="Repo-root-relative path. Mirrors CodeLocation.file_path for fast access.",
        examples=["src/payments/encryption.py"],
    )
    line_number: int = Field(
        ...,
        ge=1,
        description="1-indexed line number of the crypto call site.",
    )
    location: CodeLocation = Field(
        ...,
        description="Full source location with column offsets (from Tree-sitter node).",
    )
    language: SupportedLanguage = Field(
        ...,
        description="Source language as detected by file extension + Tree-sitter grammar.",
    )

    # ── Crypto Primitive Detection (Phase 1 — Tree-sitter) ──────────────────────
    algorithm_detected: str = Field(
        ...,
        description=(
            "Canonical algorithm identifier as detected. Use key size where known. "
            "E.g. 'RSA-2048', 'ECDSA-P256', 'AES-128-CBC', 'SHA-1', 'DH-1024'."
        ),
        examples=["RSA-2048", "ECDSA-P256", "AES-128-CBC", "MD5"],
    )
    code_snippet: str = Field(
        ...,
        description=(
            "The verbatim source line(s) containing the crypto call. "
            "WARNING: This field holds raw source code. The AI anonymizer pass "
            "(vyala/ai/anonymizer.py) MUST scrub secrets, keys, and PII before "
            "this model is serialised to disk or transmitted to the LLM."
        ),
        examples=["private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"],
    )

    # ── Quantum Risk Assessment (Phase 1 — rule-based, Phase 2 — AI refined) ───
    is_quantum_vulnerable: bool = Field(
        default=True,
        description=(
            "True if the algorithm is broken by Shor's or meaningfully weakened "
            "by Grover's algorithm. Defaults to True — safe > sorry. "
            "Set False only for confirmed quantum-safe primitives (AES-256, SHA-3-512…)."
        ),
    )
    vulnerability_class: QuantumVulnerabilityClass = Field(
        default=QuantumVulnerabilityClass.UNKNOWN,
        description="Academic classification of the quantum attack vector.",
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.HIGH,
        description=(
            "Operational risk level. Rule-engine sets initial value; "
            "AI refines based on secret lifetime and exposure context."
        ),
    )

    # ── AI Enrichment Fields (Phase 1+, populated by Claude) ────────────────────
    usage_context: Optional[str] = Field(
        default=None,
        description=(
            "Claude's natural-language description of what this crypto is actually doing. "
            "E.g. 'Signing JWT access tokens for external API consumers'. "
            "Null until the AI enrichment pass completes."
        ),
    )
    pqc_recommendation: Optional[PQCRecommendation] = Field(
        default=None,
        description=(
            "Structured NIST PQC replacement recommendation. "
            "Null until the AI enrichment pass completes."
        ),
    )
    # Kept as a flat field alongside pqc_recommendation for fast dashboard filtering.
    pqc_replacement: Optional[str] = Field(
        default=None,
        description=(
            "Short-form PQC algorithm name for display. "
            "Mirrors pqc_recommendation.primary_algorithm. "
            "E.g. 'ML-KEM-768 (CRYSTALS-Kyber)'."
        ),
    )
    migration_complexity: Optional[MigrationComplexity] = Field(
        default=None,
        description=(
            "AI-estimated engineering effort to migrate this finding. "
            "Null until the AI enrichment pass completes."
        ),
    )

    # ── Audit Trail ─────────────────────────────────────────────────────────────
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when Tree-sitter created this finding.",
    )
    ai_enriched_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when Claude completed enrichment. Null if pending.",
    )
    human_reviewed: bool = Field(
        default=False,
        description="True if a human reviewer has validated or overridden this finding (Phase 2).",
    )
    false_positive: bool = Field(
        default=False,
        description="Marked True by human reviewer if the finding is a false positive.",
    )

    # ── Validators ──────────────────────────────────────────────────────────────

    @field_validator("code_snippet")
    @classmethod
    def snippet_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("code_snippet cannot be blank — the AST node must yield source text.")
        return v

    @field_validator("line_number")
    @classmethod
    def line_must_be_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"line_number must be ≥ 1, got {v}.")
        return v

    @model_validator(mode="after")
    def sync_pqc_replacement_shortform(self) -> "CryptoFinding":
        """
        Keep pqc_replacement (flat string) consistent with the structured
        PQCRecommendation object. Runs after all fields are set.
        """
        # model is frozen — we use object.__setattr__ to bypass immutability
        # only during construction (model_validator runs before freeze).
        if self.pqc_recommendation and not self.pqc_replacement:
            object.__setattr__(
                self, "pqc_replacement", self.pqc_recommendation.primary_algorithm
            )
        return self

    # ── Computed Properties ─────────────────────────────────────────────────────

    @computed_field  # type: ignore[misc]
    @property
    def fingerprint(self) -> str:
        """
        Deterministic SHA-256 fingerprint of (file_path, line_number, algorithm_detected).
        Used to deduplicate findings across incremental scans without comparing full objects.
        """
        raw = f"{self.file_path}:{self.line_number}:{self.algorithm_detected}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @computed_field  # type: ignore[misc]
    @property
    def is_ai_enriched(self) -> bool:
        """True when Claude has completed the enrichment pass on this finding."""
        return self.usage_context is not None and self.pqc_recommendation is not None


# ==============================================================================
# REPORT METADATA
# ==============================================================================


class ScanMetadata(BaseModel):
    """
    Contextual metadata about the scan session.
    Stored alongside findings to enable historical CBOM diffing:
    'Did we introduce new RSA usage between commit A and commit B?'
    """
    model_config = {"frozen": True}

    project_name: str = Field(
        ...,
        min_length=1,
        description="Human-readable project or repository name.",
        examples=["payments-service", "auth-gateway", "legacy-core-banking"],
    )
    project_version: Optional[str] = Field(
        default=None,
        description="Semver, git tag, or commit SHA of the scanned codebase.",
        examples=["v2.3.1", "abc1234"],
    )
    scan_root: Optional[str] = Field(
        default=None,
        description="Absolute path or repo URL that was scanned.",
    )
    scanned_by: Optional[str] = Field(
        default=None,
        description="VYALA version string. E.g. 'vyala/0.1.0'.",
    )
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the scan was initiated.",
    )
    scan_duration_seconds: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Wall-clock time for the complete scan (parse + AI enrichment).",
    )
    languages_scanned: list[SupportedLanguage] = Field(
        default_factory=list,
        description="All languages for which a Tree-sitter grammar was invoked.",
    )
    files_scanned: int = Field(
        default=0,
        ge=0,
        description="Total number of source files examined.",
    )
    files_skipped: int = Field(
        default=0,
        ge=0,
        description="Files excluded by .gitignore rules, size limits, or binary detection.",
    )


# ==============================================================================
# TOP-LEVEL CBOM REPORT
# ==============================================================================


class CBOMReport(BaseModel):
    """
    The Crypto Bill of Materials — the primary artefact VYALA produces.

    A CBOMReport is the complete, versioned inventory of cryptographic
    primitives found in a codebase. It is:
      • Serialised to JSON for the FastAPI → Next.js pipeline
      • Stored in the database as a scan session record
      • Diffed against previous reports to track crypto debt over time
      • The input to Phase 2 (IDE plugin) and Phase 3 (autonomous migration)

    Treat this model as the single source of truth. Nothing enters the
    dashboard that did not pass through this schema.
    """
    # Do NOT freeze CBOMReport — it is mutated during the scan lifecycle
    # (status transitions, findings appended, duration recorded).

    # ── Identity ────────────────────────────────────────────────────────────────
    report_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique report ID. UUIDv4. Stable across status transitions.",
    )

    # ── Metadata (flat fields for ergonomic top-level access) ───────────────────
    project_name: str = Field(
        ...,
        min_length=1,
        description="Human-readable project name. Sourced from ScanMetadata.",
    )
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the scan was initiated.",
    )
    metadata: ScanMetadata = Field(
        ...,
        description="Full scan session metadata including version, duration, and file counts.",
    )

    # ── Status ──────────────────────────────────────────────────────────────────
    status: CBOMStatus = Field(
        default=CBOMStatus.PENDING,
        description="Lifecycle state of this report. Transitions: PENDING → SCANNING → ANALYSING → COMPLETE.",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Human-readable error description if status == FAILED.",
    )

    # ── Findings ─────────────────────────────────────────────────────────────────
    findings: list[CryptoFinding] = Field(
        default_factory=list,
        description=(
            "Ordered list of all crypto findings in the scanned codebase. "
            "Sorted by severity (CRITICAL → INFO) then file_path for deterministic output."
        ),
    )

    # ── Computed Summary (derived — fast dashboard stats without iterating findings) ──

    @computed_field  # type: ignore[misc]
    @property
    def total_findings(self) -> int:
        """Total number of crypto findings, including false positives."""
        return len(self.findings)

    @computed_field  # type: ignore[misc]
    @property
    def quantum_vulnerable_count(self) -> int:
        """Number of findings flagged as quantum-vulnerable and not false positives."""
        return sum(
            1 for f in self.findings
            if f.is_quantum_vulnerable and not f.false_positive
        )

    @computed_field  # type: ignore[misc]
    @property
    def critical_findings_count(self) -> int:
        """CRITICAL severity findings — the ones that keep CISOs awake."""
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @computed_field  # type: ignore[misc]
    @property
    def ai_enriched_count(self) -> int:
        """Findings that have completed the Claude AI enrichment pass."""
        return sum(1 for f in self.findings if f.is_ai_enriched)

    @computed_field  # type: ignore[misc]
    @property
    def enrichment_progress_pct(self) -> float:
        """
        0.0–100.0 progress of the AI enrichment pass.
        Streamed to the frontend via SSE so the dashboard shows a live progress bar.
        """
        if not self.findings:
            return 0.0
        return round((self.ai_enriched_count / len(self.findings)) * 100, 2)

    @computed_field  # type: ignore[misc]
    @property
    def algorithms_detected(self) -> list[str]:
        """Deduplicated, sorted list of all algorithm names found. For the summary widget."""
        return sorted({f.algorithm_detected for f in self.findings})

    @computed_field  # type: ignore[misc]
    @property
    def severity_breakdown(self) -> dict[str, int]:
        """
        Count of findings per severity level.
        Shape: {"CRITICAL": 3, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
        Directly consumed by the dashboard donut chart.
        """
        breakdown: dict[str, int] = {level.value: 0 for level in SeverityLevel}
        for finding in self.findings:
            breakdown[finding.severity.value] += 1
        return breakdown

    # ── Helpers ──────────────────────────────────────────────────────────────────

    def get_findings_by_severity(self, severity: SeverityLevel) -> list[CryptoFinding]:
        """Filter findings by severity. Used by the FastAPI query layer."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_file(self, file_path: str) -> list[CryptoFinding]:
        """Return all findings in a specific file. Used by the IDE plugin deep-link."""
        return [f for f in self.findings if f.file_path == file_path]

    def get_unenriched_findings(self) -> list[CryptoFinding]:
        """
        Return findings not yet processed by Claude.
        The AI enrichment worker (vyala/ai/) calls this to build its work queue.
        """
        return [f for f in self.findings if not f.is_ai_enriched]