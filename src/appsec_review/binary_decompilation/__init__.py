"""Pre-run Ghidra decompilation of third-party binaries into hash-addressed publications."""

from .publication import (
    AUTHORITY, SCHEMA, PublicationError, load_table, managed_code_reason, publish_export,
    verify_publication,
)
from .runner import (
    DecompilationError, decompilation_identity, decompile_binary, expected_publication, export_argv,
    publication_path, resolve_current, store_root, verified_binary, verify_binary,
)

__all__ = [
    "AUTHORITY", "SCHEMA", "DecompilationError", "PublicationError", "decompilation_identity",
    "decompile_binary", "expected_publication", "export_argv", "load_table", "managed_code_reason",
    "publication_path", "publish_export", "resolve_current", "store_root", "verified_binary", "verify_binary", "verify_publication",
]
