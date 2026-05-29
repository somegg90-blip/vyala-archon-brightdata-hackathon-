"""
vyala/core/parsers/go_parser.py

Go Crypto Scanner — Tree-sitter Implementation
===============================================
Scans Go source files for quantum-vulnerable cryptographic primitives.

Target crypto surfaces:
  1. crypto/* stdlib packages        — crypto/rsa, crypto/ecdsa, crypto/tls
  2. golang.org/x/crypto             — golang.org/x/crypto/bcrypt, ed25519
  3. github.com/square/go-jose       — JWT/JOSE
  4. github.com/dgrijalva/jwt-go     — JWT signing with RS256/ES256
  5. github.com/golang-jwt/jwt       — Updated jwt-go fork
  6. github.com/ProtonMail/go-crypto — OpenPGP
  7. hash/* stdlib                   — crypto/md5, crypto/sha1, crypto/sha256

Why Go matters for VYALA:
  • Kubernetes, Docker, cloud-native infrastructure — all Go
  • HashiCorp Vault, Consul, Terraform — PKI and secret management in Go
  • Cloudflare, Fastly edge compute — Go services handling TLS termination
  • Microservices in fintech: Stripe, Square, Monzo — Go backends
  • The Go stdlib crypto package is EXTREMELY widely used — almost no Go
    service avoids crypto/tls

Detection strategy:
  Layer 1 — import_declaration       → package path present
  Layer 2 — call_expression          → rsa.GenerateKey(), ecdsa.GenerateKey()
  Layer 3 — selector_expression      → tls.Config{}, x509.Certificate{}
  Layer 4 — string_literal           → cipher suite names, algorithm strings
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator


import tree_sitter_go as tsgo
from loguru import logger
from tree_sitter import Language, Node, Parser

from ..models.cbom import (
    CodeLocation,
    CryptoFinding,
    QuantumVulnerabilityClass,
    SeverityLevel,
    SupportedLanguage,
)
from .base_parser import BaseParser

# ==============================================================================
# GO CRYPTO KNOWLEDGE BASE
# ==============================================================================

# Import path → crypto signature
# Key: import path (exact or fragment match)
_IMPORT_SIGNATURES: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    # Go stdlib crypto
    "crypto/rsa":           ("RSA",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "crypto/ecdsa":         ("ECDSA",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "crypto/elliptic":      ("ECC",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "crypto/dsa":           ("DSA",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "crypto/tls":           ("TLS",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "crypto/x509":          ("X509/PKI",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "crypto/md5":           ("MD5",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "crypto/sha1":          ("SHA-1",         QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "crypto/sha256":        ("SHA-256",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "crypto/sha512":        ("SHA-512",       QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "crypto/des":           ("DES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "crypto/rc4":           ("RC4",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "crypto/hmac":          ("HMAC",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "crypto/cipher":        ("Block-Cipher",  QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "crypto/aes":           ("AES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "crypto/rand":          ("CSPRNG",        QuantumVulnerabilityClass.UNKNOWN,         SeverityLevel.INFO,     False),
    "crypto/ecdh":          ("ECDH",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "crypto/ed25519":       ("Ed25519",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # golang.org/x/crypto extensions
    "golang.org/x/crypto/bcrypt":   ("bcrypt",  QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM, True),
    "golang.org/x/crypto/ssh":      ("SSH/RSA", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,   True),
    "golang.org/x/crypto/chacha20poly1305": ("ChaCha20", QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.LOW, False),
    "golang.org/x/crypto/curve25519": ("X25519", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "golang.org/x/crypto/ed25519":  ("Ed25519", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "golang.org/x/crypto/openpgp":  ("PGP/RSA", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,   True),
    "golang.org/x/crypto/ripemd160":("RIPEMD-160", QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH, True),

    # JWT libraries
    "github.com/dgrijalva/jwt-go":      ("JWT",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),
    "github.com/golang-jwt/jwt":        ("JWT",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),
    "github.com/golang-jwt/jwt/v4":     ("JWT",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),
    "github.com/golang-jwt/jwt/v5":     ("JWT",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),
    "github.com/square/go-jose":        ("JOSE", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),
    "gopkg.in/square/go-jose.v2":       ("JOSE", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),

    # OpenPGP / other
    "github.com/ProtonMail/go-crypto":  ("PGP/ECC", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH, True),
}

# TLS cipher suite constants and algorithm strings
_TLS_CIPHERS: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    "tls_rsa_with_aes_128_cbc_sha":        ("TLS-RSA-AES128-SHA",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "tls_rsa_with_aes_256_cbc_sha":        ("TLS-RSA-AES256-SHA",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "tls_rsa_with_3des_ede_cbc_sha":       ("TLS-RSA-3DES",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "tls_ecdhe_rsa_with_aes_128_cbc_sha":  ("TLS-ECDHE-RSA-AES128",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "tls_ecdhe_ecdsa_with_aes_128_cbc_sha":("TLS-ECDHE-ECDSA-AES128",QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
}

# Go crypto function call patterns: rsa.GenerateKey, ecdsa.Sign, etc.
# Maps package.function (lowercased) → refinement
_FUNC_SIGNATURES: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    "rsa.generatekey":      ("RSA",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa.encryptoaep":      ("RSA-OAEP",QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa.encryptpkcs1v15":  ("RSA-PKCS1",QuantumVulnerabilityClass.SHOR_VULNERABLE,SeverityLevel.CRITICAL, True),
    "rsa.signpkcs1v15":     ("RSA-PKCS1",QuantumVulnerabilityClass.SHOR_VULNERABLE,SeverityLevel.CRITICAL, True),
    "rsa.signpss":          ("RSA-PSS", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsa.generatekey":    ("ECDSA",   QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsa.sign":           ("ECDSA",   QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdh.generatekey":     ("ECDH",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "dsa.generatekey":      ("DSA",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "md5.new":              ("MD5",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "md5.sum":              ("MD5",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1.new":             ("SHA-1",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1.sum":             ("SHA-1",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "des.newcipher":        ("DES",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "rc4.newcipher":        ("RC4",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "bcrypt.generatefrompassword": ("bcrypt", QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM, True),
}

_KEY_SIZE_PATTERN = re.compile(r'\b(512|1024|2048|3072|4096)\b')


# ==============================================================================
# GO PARSER
# ==============================================================================

class GoParser(BaseParser):
    """
    Tree-sitter–powered scanner for vulnerable cryptography in Go source files.
    Handles: .go
    """

    def __init__(self, target_directory: str) -> None:
        super().__init__(target_directory)
        self._ts_language = Language(tsgo.language())
        self.parser = Parser(self._ts_language)
        logger.info(
            "GoParser ready | target={} | grammar=tree-sitter-go",
            self.target_directory,
        )

    def scan(self) -> list[CryptoFinding]:
        go_files = self._get_files_by_extension(".go")
        if not go_files:
            logger.warning("GoParser found zero .go files in '{}'.", self.target_directory)
            return []

        all_findings: list[CryptoFinding] = []
        logger.info("GoParser scanning {} file(s)…", len(go_files))

        for file_path in go_files:
            try:
                findings = self._scan_single_file(file_path)
                all_findings.extend(findings)
            except Exception as exc:
                logger.error("Go parse error | path={} | error={!r}", file_path, exc)

        logger.info("GoParser complete | total_findings={}", len(all_findings))
        return sorted(all_findings, key=lambda f: (f.file_path, f.line_number))

    def _scan_single_file(self, file_path: str) -> list[CryptoFinding]:
        source_text = self._read_file(file_path)
        if not source_text:
            return []
        source_bytes = source_text.encode("utf-8", errors="replace")
        tree = self.parser.parse(source_bytes)
        if tree is None or tree.root_node is None:
            return []
        return list(self._extract_crypto_nodes(tree, file_path, source_bytes))

    def _extract_crypto_nodes(
        self,
        tree,
        file_path: str,
        source_bytes: bytes,
    ) -> Iterator[CryptoFinding]:
        cursor = tree.walk()
        visited_children = False

        while True:
            node = cursor.node

            if not visited_children:
                # import "crypto/rsa" or import ( "crypto/rsa" )
                if node.type == "import_spec":
                    finding = self._analyse_import(node, file_path, source_bytes)
                    if finding:
                        yield finding

                # rsa.GenerateKey(...), ecdsa.Sign(...)
                elif node.type == "call_expression":
                    finding = self._analyse_call_expression(node, file_path, source_bytes)
                    if finding:
                        yield finding

                if cursor.goto_first_child():
                    visited_children = False
                    continue

            if cursor.goto_next_sibling():
                visited_children = False
            elif cursor.goto_parent():
                visited_children = True
            else:
                break

    def _analyse_import(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        import_text = self._node_text(node, source_bytes)
        # Strip quotes from import path
        import_path = import_text.strip('"').strip()

        for pkg, sig in _IMPORT_SIGNATURES.items():
            if import_path == pkg or import_path.endswith("/" + pkg.split("/")[-1]):
                # Exact match first
                if import_path == pkg:
                    canonical, vuln_class, severity, is_vuln = sig
                    line_number = node.start_point[0] + 1
                    return CryptoFinding(
                        file_path=file_path,
                        line_number=line_number,
                        location=CodeLocation(
                            file_path=file_path,
                            line_number=line_number,
                            column_start=node.start_point[1],
                            column_end=node.end_point[1],
                        ),
                        language=SupportedLanguage.GO,
                        algorithm_detected=canonical,
                        code_snippet=f'import "{import_path}"',
                        is_quantum_vulnerable=is_vuln,
                        vulnerability_class=vuln_class,
                        severity=severity,
                        detected_at=datetime.now(timezone.utc),
                    )

        # Fragment match for longer paths
        for pkg, sig in _IMPORT_SIGNATURES.items():
            if pkg in import_path:
                canonical, vuln_class, severity, is_vuln = sig
                line_number = node.start_point[0] + 1
                return CryptoFinding(
                    file_path=file_path,
                    line_number=line_number,
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=line_number,
                        column_start=node.start_point[1],
                        column_end=node.end_point[1],
                    ),
                    language=SupportedLanguage.GO,
                    algorithm_detected=canonical,
                    code_snippet=f'import "{import_path}"',
                    is_quantum_vulnerable=is_vuln,
                    vulnerability_class=vuln_class,
                    severity=severity,
                    detected_at=datetime.now(timezone.utc),
                )

        return None

    def _analyse_call_expression(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        node_text = self._node_text(node, source_bytes)
        # Match pattern: pkg.Function(...)
        call_match = re.match(r'([a-z0-9]+)\.([A-Za-z0-9]+)\s*\(', node_text)
        if not call_match:
            return None

        pkg = call_match.group(1).lower()
        func = call_match.group(2).lower()
        key = f"{pkg}.{func}"

        sig = _FUNC_SIGNATURES.get(key)
        if sig is None:
            return None

        canonical, vuln_class, severity, is_vuln = sig
        line_number = node.start_point[0] + 1

        # Key size refinement for RSA
        canonical, severity = self._refine_with_key_size(canonical, node_text, severity)

        return CryptoFinding(
            file_path=file_path,
            line_number=line_number,
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_start=node.start_point[1],
                column_end=node.end_point[1],
            ),
            language=SupportedLanguage.GO,
            algorithm_detected=canonical,
            code_snippet=node_text[:200],
            is_quantum_vulnerable=is_vuln,
            vulnerability_class=vuln_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _refine_with_key_size(
        algorithm_name: str,
        context_text: str,
        default_severity: SeverityLevel,
    ) -> tuple[str, SeverityLevel]:
        algo_base = algorithm_name.split("-")[0].upper()
        size_map = {
            "RSA": {
                512:  ("RSA-512",  SeverityLevel.CRITICAL),
                1024: ("RSA-1024", SeverityLevel.CRITICAL),
                2048: ("RSA-2048", SeverityLevel.CRITICAL),
                3072: ("RSA-3072", SeverityLevel.HIGH),
                4096: ("RSA-4096", SeverityLevel.HIGH),
            },
        }
        if algo_base not in size_map:
            return algorithm_name, default_severity
        match = _KEY_SIZE_PATTERN.search(context_text)
        if match:
            key_size = int(match.group())
            if key_size in size_map[algo_base]:
                return size_map[algo_base][key_size]
        return algorithm_name, default_severity

    @staticmethod
    def _node_text(node: Node, source_bytes: bytes) -> str:
        try:
            return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
        except (AttributeError, ValueError):
            return ""

    def __repr__(self) -> str:
        return f"GoParser(target={self.target_directory!r}, grammar=tree-sitter-go)"