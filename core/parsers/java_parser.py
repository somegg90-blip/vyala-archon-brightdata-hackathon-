"""
vyala/core/parsers/java_parser.py

Java Crypto Scanner — Tree-sitter Implementation
==================================================
Scans Java source files for quantum-vulnerable cryptographic primitives.

Target APIs (the Java crypto universe):
  1. JCA/JCE (javax.crypto, java.security)   — the stdlib, used EVERYWHERE
  2. Bouncy Castle (org.bouncycastle)         — #1 enterprise crypto lib
  3. Spring Security (org.springframework.security.crypto)
  4. Apache Commons Crypto
  5. Conscrypt / Google Tink
  6. Direct algorithm string literals        — KeyPairGenerator.getInstance("RSA")

Detection strategy:
  Layer 1 — import_declaration               → coarse signal (library present)
  Layer 2 — method_invocation / getInstance  → fine signal (algo name in string arg)
  Layer 3 — string_literal in crypto context → key sizes, algo names, mode strings

Why Java is critical:
  • Banking cores: COBOL wrappers over Java crypto (still)
  • Healthcare: HL7/FHIR APIs use Java with JCA
  • Enterprise middleware: Spring Boot microservices, Kafka producers
  • Android apps: all use JCA under the hood

NIST references: SP 800-131A Rev 2, CNSA 2.0, FIPS 140-3
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator


import tree_sitter_java as tsjava
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
# JAVA CRYPTO KNOWLEDGE BASE
# ==============================================================================

# JCA/JCE algorithm string constants that appear in getInstance() calls.
# Java crypto is almost entirely driven by string literals — this is the
# primary detection surface and far richer than import analysis alone.
#
# Key: lowercased algorithm string as it appears in Java source
# Value: (canonical_name, vulnerability_class, severity, is_quantum_vulnerable)
_ALGORITHM_STRING_MAP: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {

    # ── RSA variants ──────────────────────────────────────────────────────────
    "rsa":                      ("RSA",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa/ecb/pkcs1padding":     ("RSA-PKCS1",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa/ecb/oaepwithsha-256andmgf1padding": ("RSA-OAEP-SHA256", QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsa/ecb/oaepwithsha-1andmgf1padding":   ("RSA-OAEP-SHA1",   QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "rsassa-pkcs1-v1_5":        ("RSA-PKCS1",     QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # ── DSA ───────────────────────────────────────────────────────────────────
    "dsa":                      ("DSA",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha1withdsa":              ("DSA-SHA1",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha256withdsa":            ("DSA-SHA256",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # ── ECC / ECDSA / ECDH ───────────────────────────────────────────────────
    "ec":                       ("ECC",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdsa":                    ("ECDSA",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "ecdh":                     ("ECDH",          QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha256withecdsa":          ("ECDSA-SHA256",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha384withecdsa":          ("ECDSA-SHA384",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha512withecdsa":          ("ECDSA-SHA512",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha1withecdsa":            ("ECDSA-SHA1",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # ── Diffie-Hellman ────────────────────────────────────────────────────────
    "dh":                       ("DH",            QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "diffiehellman":            ("DH",            QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # ── RSA signatures ────────────────────────────────────────────────────────
    "sha1withrsa":              ("RSA-SHA1",      QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha256withrsa":            ("RSA-SHA256",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha384withrsa":            ("RSA-SHA384",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "sha512withrsa":            ("RSA-SHA512",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "md5withrsa":               ("RSA-MD5",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),

    # ── AES (symmetric — Grover weakened at 128-bit) ──────────────────────────
    "aes":                      ("AES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes/cbc/pkcs5padding":     ("AES-128-CBC",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "aes/ecb/pkcs5padding":     ("AES-ECB",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),  # ECB = extra bad
    "aes/gcm/nopadding":        ("AES-GCM",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.LOW,      True),
    "aes/ctr/nopadding":        ("AES-CTR",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),

    # ── Legacy symmetric ──────────────────────────────────────────────────────
    "des":                      ("DES",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "desede":                   ("3DES",          QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "desede/cbc/pkcs5padding":  ("3DES-CBC",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "rc4":                      ("RC4",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "arcfour":                  ("RC4",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "blowfish":                 ("Blowfish",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),

    # ── Hash functions ────────────────────────────────────────────────────────
    "md5":                      ("MD5",           QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha-1":                    ("SHA-1",         QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha1":                     ("SHA-1",         QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "sha-256":                  ("SHA-256",       QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "sha-384":                  ("SHA-384",       QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "sha-512":                  ("SHA-512",       QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "sha-3":                    ("SHA-3",         QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),

    # ── MAC ───────────────────────────────────────────────────────────────────
    "hmacmd5":                  ("HMAC-MD5",      QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.CRITICAL, True),
    "hmacsha1":                 ("HMAC-SHA1",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.HIGH,     True),
    "hmacsha256":               ("HMAC-SHA256",   QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM,   True),
    "hmacsha384":               ("HMAC-SHA384",   QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),
    "hmacsha512":               ("HMAC-SHA512",   QuantumVulnerabilityClass.QUANTUM_SAFE,    SeverityLevel.LOW,      False),

    # ── TLS/SSL ───────────────────────────────────────────────────────────────
    "ssl":                      ("TLS/SSL",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "tls":                      ("TLS",           QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "tlsv1":                    ("TLS-1.0",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "tlsv1.1":                  ("TLS-1.1",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "tlsv1.2":                  ("TLS-1.2",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "sslv3":                    ("SSL-3.0",       QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
}

# Import-level signatures.
# Key: import path fragment (checked with 'in' so partial matches work).
_IMPORT_SIGNATURES: dict[str, tuple[str, QuantumVulnerabilityClass, SeverityLevel, bool]] = {
    "javax.crypto":                          ("JCA/JCE",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "java.security":                         ("Java-Security",   QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "org.bouncycastle":                      ("BouncyCastle",    QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "org.springframework.security.crypto":   ("Spring-Crypto",  QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "com.google.crypto.tink":               ("Google-Tink",     QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.LOW,      False),
    "javax.net.ssl":                         ("TLS/SSL",         QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.HIGH,     True),
    "java.security.interfaces.RSAKey":       ("RSA",             QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "java.security.interfaces.ECKey":        ("ECC",             QuantumVulnerabilityClass.SHOR_VULNERABLE, SeverityLevel.CRITICAL, True),
    "org.apache.commons.crypto":             ("Apache-Commons-Crypto", QuantumVulnerabilityClass.GROVER_WEAKENED, SeverityLevel.MEDIUM, True),
}

# getInstance / getAlgorithm method names that signal crypto context
_CRYPTO_METHOD_NAMES = frozenset({
    "getinstance", "generatekeypair", "generatekey",
    "getkeygenerator", "getalgorithm", "init",
    "getkeyfactory", "createcipher", "createdigest",
})

# Key size pattern
_KEY_SIZE_PATTERN = re.compile(r'\b(512|1024|2048|3072|4096)\b')


# ==============================================================================
# JAVA PARSER
# ==============================================================================

class JavaParser(BaseParser):
    """
    Tree-sitter–powered scanner for vulnerable cryptography in Java source files.

    Detection pipeline per file:
      1. import_declaration nodes      → Library-level signal
      2. string_literal nodes          → Algorithm string args to getInstance()
      3. method_invocation context     → Confirms crypto call context
    """

    def __init__(self, target_directory: str) -> None:
        super().__init__(target_directory)
        self._ts_language = Language(tsjava.language())
        self.parser = Parser(self._ts_language)
        logger.info(
            "JavaParser ready | target={} | grammar=tree-sitter-java",
            self.target_directory,
        )

    def scan(self) -> list[CryptoFinding]:
        java_files = self._get_files_by_extension(".java")
        if not java_files:
            logger.warning("JavaParser found zero .java files in '{}'.", self.target_directory)
            return []

        all_findings: list[CryptoFinding] = []
        logger.info("JavaParser scanning {} file(s)…", len(java_files))

        for file_path in java_files:
            try:
                findings = self._scan_single_file(file_path)
                all_findings.extend(findings)
            except Exception as exc:
                logger.error("Java parse error | path={} | error={!r}", file_path, exc)

        logger.info("JavaParser complete | total_findings={}", len(all_findings))
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
                # Import declarations — library-level detection
                if node.type == "import_declaration":
                    finding = self._analyse_import_node(node, file_path, source_bytes)
                    if finding:
                        yield finding

                # String literals — algorithm name detection
                # Catches: KeyPairGenerator.getInstance("RSA"), Cipher.getInstance("AES/CBC/PKCS5Padding")
                elif node.type == "string_literal":
                    finding = self._analyse_string_literal(node, file_path, source_bytes)
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

    def _analyse_import_node(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        import_text = self._node_text(node, source_bytes)
        line_number = node.start_point[0] + 1

        for pkg_fragment, sig in _IMPORT_SIGNATURES.items():
            if pkg_fragment in import_text:
                canonical, vuln_class, severity, is_vuln = sig
                # Refine: if the import mentions a specific algorithm
                refined = self._refine_from_import_text(import_text)
                if refined:
                    canonical = refined

                return CryptoFinding(
                    file_path=file_path,
                    line_number=line_number,
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=line_number,
                        column_start=node.start_point[1],
                        column_end=node.end_point[1],
                    ),
                    language=SupportedLanguage.JAVA,
                    algorithm_detected=canonical,
                    code_snippet=import_text,
                    is_quantum_vulnerable=is_vuln,
                    vulnerability_class=vuln_class,
                    severity=severity,
                    detected_at=datetime.now(timezone.utc),
                )
        return None

    def _analyse_string_literal(
        self,
        node: Node,
        file_path: str,
        source_bytes: bytes,
    ) -> CryptoFinding | None:
        """
        Detect algorithm names inside string literals.
        Checks the parent node for crypto method context.
        """
        raw = self._node_text(node, source_bytes)
        # Strip quotes
        algo_str = raw.strip('"\'').lower()

        sig = _ALGORITHM_STRING_MAP.get(algo_str)
        if sig is None:
            return None

        # Validate: parent or grandparent should be a method_invocation
        # to avoid flagging random strings that happen to say "RSA"
        if not self._is_in_crypto_context(node):
            return None

        canonical, vuln_class, severity, is_vuln = sig
        line_number = node.start_point[0] + 1

        # Key size refinement
        parent_text = self._get_parent_line_text(node, source_bytes)
        canonical, severity = self._refine_with_key_size(canonical, parent_text, severity)

        return CryptoFinding(
            file_path=file_path,
            line_number=line_number,
            location=CodeLocation(
                file_path=file_path,
                line_number=line_number,
                column_start=node.start_point[1],
                column_end=node.end_point[1],
            ),
            language=SupportedLanguage.JAVA,
            algorithm_detected=canonical,
            code_snippet=parent_text or raw,
            is_quantum_vulnerable=is_vuln,
            vulnerability_class=vuln_class,
            severity=severity,
            detected_at=datetime.now(timezone.utc),
        )

    def _is_in_crypto_context(self, node: Node) -> bool:
        """
        Walk up to 4 levels of ancestors looking for a method_invocation
        whose method name is a known crypto factory method.
        """
        current = node.parent
        for _ in range(4):
            if current is None:
                break
            if current.type in ("method_invocation", "object_creation_expression"):
                # Check if the method name matches known crypto methods
                for child in current.children:
                    if child.type in ("identifier", "field_access"):
                        method_name = ""
                        if child.type == "identifier":
                            method_name = child.text.decode("utf-8", errors="replace").lower() if child.text else ""
                        elif child.type == "field_access":
                            # e.g. KeyPairGenerator.getInstance
                            for sub in child.children:
                                if sub.type == "identifier":
                                    method_name = sub.text.decode("utf-8", errors="replace").lower() if sub.text else ""
                        if method_name in _CRYPTO_METHOD_NAMES:
                            return True
            current = current.parent
        # If no method context found, still allow if parent is an assignment
        # or variable_declarator (e.g. String algo = "RSA")
        return False

    def _get_parent_line_text(self, node: Node, source_bytes: bytes) -> str:
        """Get the text of the containing statement for context."""
        current = node.parent
        for _ in range(3):
            if current is None:
                break
            if current.type in ("expression_statement", "local_variable_declaration",
                                  "method_invocation", "variable_declarator"):
                return self._node_text(current, source_bytes)
            current = current.parent
        return self._node_text(node, source_bytes)

    @staticmethod
    def _refine_from_import_text(import_text: str) -> str | None:
        """Extract algorithm hint from import path."""
        lower = import_text.lower()
        hints = {
            "rsa": "RSA", "ecdsa": "ECDSA", "ecdh": "ECDH",
            "ec": "ECC", "dsa": "DSA", "dh": "DH",
            "aes": "AES", "des": "DES", "hmac": "HMAC",
            "md5": "MD5", "sha": "SHA",
        }
        for key, name in hints.items():
            if key in lower:
                return name
        return None

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
        return f"JavaParser(target={self.target_directory!r}, grammar=tree-sitter-java)"