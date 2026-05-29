"""
vyala_brightdata/core/parsers/dependency_parser.py

Dependency File Parser — Regex-based crypto scanner for manifest files
=======================================================================
Tree-sitter parsers only handle source code (.py, .js, etc.).
This parser handles DEPENDENCY FILES — requirements.txt, package.json,
pom.xml, go.mod, Cargo.toml — and detects classical crypto libraries
that signal quantum vulnerability.

Design:
  • No Tree-sitter needed — these files have no AST; regex is correct here.
  • Emits CryptoFinding instances with the same schema as source parsers.
  • Treats each matched dependency line as a "finding" at its line number.
"""

from __future__ import annotations

import os
import re
import json
from pathlib import Path
from typing import Iterator

from loguru import logger

from ..models.cbom import (
    CryptoFinding,
    CodeLocation,
    SeverityLevel,
    SupportedLanguage,
    QuantumVulnerabilityClass,
)

# ==============================================================================
# CRYPTO LIBRARY SIGNATURES
# Maps a regex pattern (matched against a dependency name) to metadata.
# ==============================================================================

_CRYPTO_SIGNATURES: list[dict] = [
    # ── RSA / Asymmetric (Shor-vulnerable) ────────────────────────────────────
    {
        "pattern": re.compile(r"\brsa\b", re.IGNORECASE),
        "algorithm": "RSA",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"pycryptodome|pycrypto|cryptodome", re.IGNORECASE),
        "algorithm": "RSA/AES (PyCryptodome)",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"cryptography", re.IGNORECASE),
        "algorithm": "RSA/EC (cryptography lib)",
        "severity": SeverityLevel.HIGH,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"\becdsa\b", re.IGNORECASE),
        "algorithm": "ECDSA",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"\bpyopenssl\b", re.IGNORECASE),
        "algorithm": "RSA/EC (PyOpenSSL)",
        "severity": SeverityLevel.HIGH,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    # ── JavaScript / Node crypto libs ─────────────────────────────────────────
    {
        "pattern": re.compile(r"\bnode-rsa\b", re.IGNORECASE),
        "algorithm": "RSA (node-rsa)",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"\bjsencrypt\b", re.IGNORECASE),
        "algorithm": "RSA (jsencrypt)",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"\bnodejs-rsa\b|\bforge\b", re.IGNORECASE),
        "algorithm": "RSA (node-forge)",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    {
        "pattern": re.compile(r"\becies\b|\belliptic\b", re.IGNORECASE),
        "algorithm": "ECDSA/ECDH (elliptic)",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    # ── Java / Maven crypto ────────────────────────────────────────────────────
    {
        "pattern": re.compile(r"bouncycastle|bcprov", re.IGNORECASE),
        "algorithm": "RSA/EC (Bouncy Castle)",
        "severity": SeverityLevel.HIGH,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    # ── Symmetric (Grover-weakened) ────────────────────────────────────────────
    {
        "pattern": re.compile(r"\baes\b|\bdes\b|\b3des\b|\bblowfish\b", re.IGNORECASE),
        "algorithm": "AES/DES (symmetric)",
        "severity": SeverityLevel.MEDIUM,
        "vuln_class": QuantumVulnerabilityClass.GROVER_WEAKENED,
    },
    # ── MD5/SHA1 (hash) ────────────────────────────────────────────────────────
    {
        "pattern": re.compile(r"\bmd5\b|\bsha1\b|\bsha-1\b", re.IGNORECASE),
        "algorithm": "MD5/SHA-1 (weak hash)",
        "severity": SeverityLevel.MEDIUM,
        "vuln_class": QuantumVulnerabilityClass.GROVER_WEAKENED,
    },
    # ── Go crypto ─────────────────────────────────────────────────────────────
    {
        "pattern": re.compile(r"golang\.org/x/crypto", re.IGNORECASE),
        "algorithm": "RSA/EC (golang.org/x/crypto)",
        "severity": SeverityLevel.HIGH,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
    # ── Rust crypto ───────────────────────────────────────────────────────────
    {
        "pattern": re.compile(r"\brsa\s*=|openssl\s*=", re.IGNORECASE),
        "algorithm": "RSA (Rust crate)",
        "severity": SeverityLevel.CRITICAL,
        "vuln_class": QuantumVulnerabilityClass.SHOR_VULNERABLE,
    },
]

# File extensions this parser handles (never source code — that's Tree-sitter's job)
DEPENDENCY_EXTENSIONS = frozenset({
    ".txt",      # requirements.txt, constraints.txt
    ".toml",     # pyproject.toml, Cargo.toml
    ".json",     # package.json, composer.json
    ".xml",      # pom.xml, build.xml
    ".gradle",   # build.gradle
    ".mod",      # go.mod
    ".lock",     # poetry.lock, yarn.lock, Pipfile.lock
    ".cfg",      # setup.cfg
})

# File NAMES that are always dependency files regardless of extension
DEPENDENCY_FILENAMES = frozenset({
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "constraints.txt",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
})

_SKIP_DIRS = frozenset({
    "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".git", "dist", "build", "target",
})


class DependencyParser:
    """
    Scans dependency/manifest files for crypto library references.

    Unlike source parsers, this does NOT use Tree-sitter.
    It walks line-by-line with regex — the right tool for flat manifest files.

    Usage
    -----
    >>> parser = DependencyParser(target_directory="/tmp/scraped_repo")
    >>> findings = parser.scan()
    """

    def __init__(self, target_directory: str) -> None:
        resolved = Path(target_directory).resolve()
        if not resolved.exists():
            raise NotADirectoryError(f"Target directory does not exist: '{resolved}'")
        self.target_directory = str(resolved)
        logger.debug(
            "DependencyParser initialised | target={}", self.target_directory
        )

    def scan(self) -> list[CryptoFinding]:
        """
        Walk target_directory, find all dependency files, regex-scan each one.
        Returns a list of CryptoFinding instances (may be empty).
        """
        findings: list[CryptoFinding] = []
        dep_files = list(self._find_dependency_files())

        if not dep_files:
            logger.info("DependencyParser: no dependency files found in {}", self.target_directory)
            return findings

        logger.info(
            "DependencyParser: found {} dependency file(s) to scan", len(dep_files)
        )

        for file_path in dep_files:
            try:
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)
                if file_findings:
                    logger.info(
                        "DependencyParser: {} finding(s) in {}",
                        len(file_findings),
                        os.path.basename(file_path),
                    )
            except Exception as exc:
                logger.warning(
                    "DependencyParser: failed to scan {} | error={}", file_path, exc
                )

        logger.info(
            "DependencyParser complete | files={} | findings={}",
            len(dep_files),
            len(findings),
        )
        return findings

    def _find_dependency_files(self) -> Iterator[str]:
        """Yield absolute paths to all dependency files under target_directory."""
        for root, dirs, files in os.walk(self.target_directory, topdown=True):
            # Prune skip dirs in-place (prevents descent into node_modules etc.)
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_DIRS and not d.startswith(".")
            ]
            for filename in sorted(files):
                full_path = os.path.join(root, filename)
                ext = Path(filename).suffix.lower()
                if filename in DEPENDENCY_FILENAMES or ext in DEPENDENCY_EXTENSIONS:
                    yield full_path

    def _scan_file(self, file_path: str) -> list[CryptoFinding]:
        """Scan a single dependency file for crypto library references."""
        findings: list[CryptoFinding] = []

        try:
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.warning("Cannot read {} | {}", file_path, exc)
            return findings

        filename = os.path.basename(file_path)

        # For JSON files (package.json etc.) we try structured parsing first
        if file_path.endswith(".json"):
            findings.extend(self._scan_json_file(file_path, lines))
            return findings

        # For all other files: line-by-line regex scan
        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip comments and blank lines
            if not line or line.startswith(("#", "//", "<!--", "*", ";")):
                continue

            for sig in _CRYPTO_SIGNATURES:
                if sig["pattern"].search(line):
                    finding = CryptoFinding(
                        file_path=file_path,
                        line_number=line_no,
                        location=CodeLocation(
                            file_path=file_path,
                            line_number=line_no,
                        ),
                        language=SupportedLanguage.UNKNOWN,
                        algorithm_detected=sig["algorithm"],
                        code_snippet=line[:200],  # cap at 200 chars
                        is_quantum_vulnerable=sig["vuln_class"] in (
                            QuantumVulnerabilityClass.SHOR_VULNERABLE,
                            QuantumVulnerabilityClass.GROVER_WEAKENED,
                        ),
                        vulnerability_class=sig["vuln_class"],
                        severity=sig["severity"],
                    )
                    findings.append(finding)
                    break  # one finding per line — avoid duplicate alerts

        return findings

    def _scan_json_file(self, file_path: str, lines: list[str]) -> list[CryptoFinding]:
        """
        For JSON manifests (package.json), parse the JSON and scan dependency names.
        Falls back to line-by-line scan if JSON is malformed.
        """
        findings: list[CryptoFinding] = []
        raw = "".join(lines)

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.debug("JSON parse failed for {}, falling back to line scan", file_path)
            # Fall back to treating it as plain text
            for line_no, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                for sig in _CRYPTO_SIGNATURES:
                    if sig["pattern"].search(line):
                        findings.append(CryptoFinding(
                            file_path=file_path,
                            line_number=line_no,
                            location=CodeLocation(file_path=file_path, line_number=line_no),
                            language=SupportedLanguage.UNKNOWN,
                            algorithm_detected=sig["algorithm"],
                            code_snippet=line[:200],
                            is_quantum_vulnerable=True,
                            vulnerability_class=sig["vuln_class"],
                            severity=sig["severity"],
                        ))
                        break
            return findings

        # Gather all dependency names from common JSON structures
        dep_sections = []
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if key in data and isinstance(data[key], dict):
                dep_sections.extend(data[key].keys())

        # Map dep name back to approximate line number
        line_index: dict[str, int] = {}
        for line_no, raw_line in enumerate(lines, start=1):
            for dep in dep_sections:
                if dep in raw_line and dep not in line_index:
                    line_index[dep] = line_no

        for dep_name in dep_sections:
            for sig in _CRYPTO_SIGNATURES:
                if sig["pattern"].search(dep_name):
                    lno = line_index.get(dep_name, 1)
                    findings.append(CryptoFinding(
                        file_path=file_path,
                        line_number=lno,
                        location=CodeLocation(file_path=file_path, line_number=lno),
                        language=SupportedLanguage.UNKNOWN,
                        algorithm_detected=sig["algorithm"],
                        code_snippet=dep_name,
                        is_quantum_vulnerable=True,
                        vulnerability_class=sig["vuln_class"],
                        severity=sig["severity"],
                    ))
                    break

        return findings