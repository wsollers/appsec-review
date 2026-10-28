"""Shared syntax-navigation wire constants (no parser or job imports)."""

SCHEMA = "appsec-review/syntax-projection/1"
MAX_NAME_BYTES = 512
MODES = {"definitions": "definition", "calls": "call_expression",
         "imports": "import", "references": "reference"}
