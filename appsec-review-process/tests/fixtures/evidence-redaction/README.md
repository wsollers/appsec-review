# evidence-redaction fixtures

Templates, not evidence. Every `@@NAME@@` placeholder is replaced at test time by an obviously
synthetic value that `tests/test_evidence_redaction.py` builds by concatenation from a fixed seed,
so this repository never contains a scannable secret literal. `@@NAME:json@@` inserts the value
JSON-escaped; `@@NAME:uescape@@` inserts it with its leading characters spelled as `\uXXXX`.
Each directory is one case; the test materializes it into a temporary attempt-private directory.
Oversized, binary, deeply nested, CRLF, link and secret-named-file cases are generated in the test
because they cannot or should not be committed.
