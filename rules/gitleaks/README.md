# Local gitleaks rules

`generic-secrets.toml` extends gitleaks' built-in rules (`useDefault`) with one generic rule: a
secret-named identifier, an optional array declarator, and a long high-entropy string literal. The built-in
rules need a vendor token format or a plain `name = "value"`, so `const char key[] = "..."` slips past them.
A match is a lead for review, never a finding.

`rules.lock.json` records the file's SHA-256; `job_evidence_collection` mounts the directory read-only at
`/rules-gitleaks` only when the hash matches. Changing the rule requires updating the lock, which
invalidates only gitleaks evidence and what is built from it. See
`docs/operations/cpp-memory-safety-detection.md`.
