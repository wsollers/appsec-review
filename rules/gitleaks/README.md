# Local gitleaks rules

`generic-secrets.toml` extends gitleaks' built-in rules (`useDefault`) and widens one of them. The built-in
`generic-api-key` rule needs a key-like name followed directly by an assignment, so
`const char key[] = "..."` slips past it. The file redefines `generic-api-key` with only a `regex`: the
built-in pattern with an optional array declarator added. Gitleaks merges a same-id rule field by field, so
the built-in entropy, keyword prefilter, allowlists and stop words are inherited. A match is a lead for
review, never a finding.

A test checks that the pattern still reports everything the installed built-in rule reports, so a gitleaks
upgrade that changes the upstream pattern fails it; re-copy the upstream pattern then, keeping the one
addition.

`rules.lock.json` records the file's SHA-256; `job_evidence_collection` mounts the directory read-only at
`/rules-gitleaks` only when the hash matches. Changing the rule requires updating the lock, which
invalidates only gitleaks evidence and what is built from it. See
`docs/operations/cpp-memory-safety-detection.md`.
