"""Shared syntax-navigation wire constants (no parser or job imports)."""

SCHEMA = "appsec-review/syntax-projection/1"
CFG_SCHEMA = "appsec-review/tree-sitter-cfg/1"
MAX_NAME_BYTES = 512
MODES = {"definitions": "definition", "calls": "call_expression",
         "imports": "import", "references": "reference"}
GUARD_POLARITIES = (
    "null_check",
    "bounds_check",
    "auth_or_role_check",
    "error_return_guard",
    "sanitization_guard",
    "general_condition",
)
QUERY_CFG_FUNCTION = "query_cfg_function"
QUERY_GUARD_DOMINATORS = "query_guard_dominators"
