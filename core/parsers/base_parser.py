"""
vyala/core/parsers/base_parser.py

Abstract Base Parser — The Scanning Contract
=============================================
Every language parser in VYALA (Python, JavaScript, Java, Go, Rust, C/C++)
inherits from this class. The contract is simple and non-negotiable:

    give me a directory → I give you a list of CryptoFindings.

Design principles:
  • The ABC enforces the interface at *import time*, not at runtime crash.
    If a subclass forgets to implement `scan()`, Python raises TypeError
    the moment the class is instantiated — not 3 hours into a production scan.
  • All I/O helpers live here so subclasses share one hardened implementation.
    A bug fixed in `_read_file` is fixed for every language parser simultaneously.
  • Skipped directories are defined once in a class-level constant.
    Adding a new vendor directory to the blocklist is a one-line change.
  • Logging is structured (loguru) so every skipped file and every I/O error
    is traceable in the scan audit log without adding noise to the terminal.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Final, Iterator

from loguru import logger

# ── FIXED IMPORT: Relative path to models ──
from ..models.cbom import CryptoFinding


# ==============================================================================
# MODULE-LEVEL CONSTANTS
# ==============================================================================

# Directories that are NEVER scanned — they contain third-party or generated
# code that is not part of the target project's crypto surface area.
# Kept as a frozenset for O(1) membership tests inside os.walk.
_DEFAULT_SKIP_DIRS: Final[frozenset[str]] = frozenset({
    # Dependency trees (npm, pip, etc.)
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "env",
    ".env",
    "site-packages",
    "__pypackages__",

    # Build artefacts
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    "target",          # Rust / Maven
    "out",             # Gradle
    ".gradle",
    "bin",
    "obj",             # .NET

    # Version control & IDE internals
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",

    # CI / container artefacts
    ".github",
    ".circleci",
    "coverage",
    "htmlcov",
})


# ==============================================================================
# ABSTRACT BASE CLASS
# ==============================================================================


class BaseParser(ABC):
    """
    Abstract base class for all VYALA language parsers.

    Subclass responsibilities
    -------------------------
    Implement exactly one method:

        def scan(self) -> list[CryptoFinding]:
            ...

    Inherited helpers
    -----------------
    _read_file(file_path)                → str
    _get_files_by_extension(extension)   → Iterator[str]
    _iter_files_by_extensions(extensions)→ Iterator[str]

    Usage example (concrete subclass sketch)
    ----------------------------------------
    >>> class PythonParser(BaseParser):
    ...     def scan(self) -> list[CryptoFinding]:
    ...         findings = []
    ...         for path in self._get_files_by_extension(".py"):
    ...             source = self._read_file(path)
    ...             findings.extend(self._parse_source(path, source))
    ...         return findings
    """

    # Subclasses may override this to add language-specific skip dirs
    # without losing the global defaults.
    SKIP_DIRS: frozenset[str] = _DEFAULT_SKIP_DIRS

    def __init__(self, target_directory: str) -> None:
        """
        Parameters
        ----------
        target_directory:
            Absolute or relative path to the root of the codebase to scan.
            Validated at construction time — fail fast before any I/O begins.

        Raises
        ------
        NotADirectoryError
            If `target_directory` does not exist or is not a directory.
            We raise immediately rather than silently returning zero findings,
            which would be indistinguishable from a genuinely clean codebase.
        """
        resolved = Path(target_directory).resolve()

        if not resolved.exists():
            raise NotADirectoryError(
                f"[VYALA] Target directory does not exist: '{resolved}'\n"
                f"Hint: Check the --path argument passed to `vyala scan`."
            )
        if not resolved.is_dir():
            raise NotADirectoryError(
                f"[VYALA] Target path is a file, not a directory: '{resolved}'\n"
                f"Hint: Pass the project ROOT, not an individual file."
            )

        self.target_directory: str = str(resolved)
        logger.debug(
            "Parser initialised | class={} | target={}",
            self.__class__.__name__,
            self.target_directory,
        )

    # ==========================================================================
    # ABSTRACT INTERFACE — subclasses MUST implement this
    # ==========================================================================

    @abstractmethod
    def scan(self) -> list[CryptoFinding]:
        """
        Scan `self.target_directory` for cryptographic primitives.

        Returns
        -------
        list[CryptoFinding]
            Every crypto usage found in the target directory, as validated
            Pydantic models ready for insertion into a CBOMReport.
            Returns an empty list if no findings are detected — never None.

        Implementation contract
        -----------------------
        • MUST NOT raise exceptions for individual file parse failures.
          Catch per-file errors internally, log them, and continue scanning.
          A single malformed file must never abort a full enterprise scan.
        • MUST call `_read_file()` for all file I/O so error handling is
          centralised and consistent across all language parsers.
        • MUST use `_get_files_by_extension()` to enumerate source files
          so skip-dir filtering is applied uniformly.
        • SHOULD log progress at DEBUG level for individual files and
          at INFO level for scan completion summaries.
        """
        ...  # pragma: no cover

    # ==========================================================================
    # PROTECTED HELPERS — shared I/O utilities for all subclasses
    # ==========================================================================

    def _read_file(self, file_path: str) -> str:
        """
        Safely read a source file and return its full text content.

        Tries UTF-8 first (the overwhelming majority of modern source files),
        then falls back to latin-1 which is a strict superset of ASCII and
        never raises a decoding error — it will misrepresent some bytes in
        truly binary files, but those will not contain meaningful crypto
        patterns and will produce zero findings anyway.

        Parameters
        ----------
        file_path:
            Absolute path to the file to read.

        Returns
        -------
        str
            Full text content of the file, or an empty string on any I/O
            or permission error. An empty string is a safe no-op: the
            Tree-sitter parser will produce zero nodes and the caller
            will simply find nothing — which is correct behaviour when
            a file cannot be read.

        Notes
        -----
        We deliberately swallow errors here rather than re-raising.
        Enterprise codebases routinely contain:
          • Binary files with source-like extensions (.py.enc, .js.min)
          • Files owned by root with 0600 permissions in Docker volumes
          • Symlinks pointing to deleted targets
        Any of these must not abort a full scan. Every error is logged
        at WARNING level so the audit trail is complete.
        """
        try:
            with open(file_path, encoding="utf-8") as fh:
                return fh.read()

        except UnicodeDecodeError:
            # File is not valid UTF-8 — retry with a lossless 8-bit encoding.
            try:
                with open(file_path, encoding="latin-1") as fh:
                    logger.debug(
                        "UTF-8 decode failed, retried with latin-1 | file={}", file_path
                    )
                    return fh.read()
            except OSError as exc:
                logger.warning(
                    "Could not read file after latin-1 fallback | file={} | error={}",
                    file_path,
                    exc,
                )
                return ""

        except PermissionError as exc:
            logger.warning(
                "Permission denied reading file | file={} | error={}", file_path, exc
            )
            return ""

        except OSError as exc:
            # Catches FileNotFoundError, IsADirectoryError, broken symlinks, etc.
            logger.warning(
                "I/O error reading file | file={} | error={}", file_path, exc
            )
            return ""

    def _get_files_by_extension(self, extension: str) -> list[str]:
        """
        Walk `self.target_directory` and return all files matching `extension`.

        Skip directories are pruned *in-place* from `os.walk`'s `dirs` list
        (``dirs[:] = [...]``). This is the canonical os.walk pruning technique
        — it prevents descent into skipped directories entirely rather than
        filtering results after the fact, which is both faster and correct for
        deeply nested ``node_modules`` trees.

        Parameters
        ----------
        extension:
            File extension to match, with leading dot. E.g. ``".py"``, ``".java"``.
            Case-insensitive matching is applied so ``.PY`` and ``.py`` both match.

        Returns
        -------
        list[str]
            Sorted list of absolute file paths matching the extension.
            Sorted for deterministic ordering across OS / filesystem types —
            critical for reproducible CBOM reports.

        Examples
        --------
        >>> parser._get_files_by_extension(".py")
        ['/repo/src/auth.py', '/repo/src/crypto_utils.py']
        """
        normalised_ext = extension.lower().lstrip(".")  # "py", not ".PY"
        matched: list[str] = []
        skipped_dirs: list[str] = []

        for root, dirs, files in os.walk(self.target_directory, topdown=True):
            # ── Prune skip-dirs in-place ───────────────────────────────────────
            # os.walk yields mutable `dirs`; modifying it controls recursion.
            original_dir_count = len(dirs)
            dirs[:] = [
                d for d in dirs
                if d not in self.SKIP_DIRS and not d.startswith(".")
            ]
            pruned = original_dir_count - len(dirs)
            if pruned:
                skipped_dirs.append(f"{root} ({pruned} dir(s) pruned)")

            # ── Collect matching files ─────────────────────────────────────────
            for filename in files:
                if filename.lower().endswith(f".{normalised_ext}"):
                    matched.append(os.path.join(root, filename))

        if skipped_dirs:
            logger.debug(
                "Pruned skip-dirs during walk | parser={} | ext={} | locations=[{}]",
                self.__class__.__name__,
                extension,
                ", ".join(skipped_dirs),
            )

        result = sorted(matched)
        logger.info(
            "File discovery complete | parser={} | ext=.{} | found={} file(s)",
            self.__class__.__name__,
            normalised_ext,
            len(result),
        )
        return result

    def _iter_files_by_extensions(self, extensions: list[str]) -> Iterator[str]:
        """
        Yield files matching *any* of the given extensions in a single pass.

        Use this when a single parser handles multiple file types
        (e.g. a TypeScript parser that handles both ``.ts`` and ``.tsx``),
        avoiding multiple full directory walks.

        Parameters
        ----------
        extensions:
            List of extensions with leading dots. E.g. ``[".ts", ".tsx"]``.

        Yields
        ------
        str
            Absolute file path for each matching file, in sorted order.
        """
        normalised = frozenset(ext.lower().lstrip(".") for ext in extensions)

        for root, dirs, files in os.walk(self.target_directory, topdown=True):
            dirs[:] = [
                d for d in dirs
                if d not in self.SKIP_DIRS and not d.startswith(".")
            ]
            for filename in sorted(files):
                suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if suffix in normalised:
                    yield os.path.join(root, filename)

    # ==========================================================================
    # DUNDER HELPERS
    # ==========================================================================

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"target_directory={self.target_directory!r})"
        )