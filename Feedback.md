## [P1] Hash the same prompt bytes that the handoff embeds

`_load_config()` reads the prompt with `Path.read_text()` but hashes a second raw `read_bytes()` result (`appsec-review-process/owasp_validator_handoff.py:255-256`). Python's text reader normalizes CRLF to LF, so on a standard Windows checkout the generated handoff embeds LF text while declaring the SHA-256 of CRLF bytes. The current checkout produces different declared and embedded-text hashes, and the T07 focused suite consequently errors in 16 of 20 tests with `T06 handoff composition/source/prompt hash mismatch` before result validation runs.

Read the prompt bytes once and derive both the embedded text and hash from those same bytes, or canonicalize both consistently. Add a regression that builds a handoff from CRLF prompt bytes and proves `sha256(prompt_contract.text.encode()) == prompt_contract.sha256`, while retaining deterministic behavior on LF checkouts.
