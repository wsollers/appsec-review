# Local Semgrep rules

`security.yml` is a repository-authored, MIT-licensed deterministic baseline for the Semgrep CE
adapter. It is intentionally small: tool output is evidence for later review, not an accepted
finding. `rules.lock.json` records the exact SHA-256 and provenance. Updating a rule requires
updating that lock; its identity invalidates only Semgrep and downstream evidence publication.
