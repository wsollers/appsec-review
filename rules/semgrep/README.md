# Local Semgrep rules

`security.yml` is a repository-authored, MIT-licensed deterministic baseline for the Semgrep CE
adapter. It is intentionally small: tool output is evidence for later review, not an accepted
finding.

`review-signals.yml` holds targeted structural patterns for review prioritization (trust-all
certificate handlers, disabled TLS or CSRF checks, concatenated SQL or shell text, unhardened XML
factories). Rule ids are `appsec-review.review-signal.<category>.<name>`;
`job_review_prioritization` maps `<category>` onto its signal taxonomy. A match is a review lead,
never a finding. See [`../../docs/architecture/review-prioritization.md`](../../docs/architecture/review-prioritization.md).

`rules.lock.json` records the exact SHA-256 of both files and their provenance. Updating a rule
requires updating that lock; its identity invalidates only Semgrep and downstream evidence and
prioritization publication. Validate a change with the pinned engine before locking it, for
example `semgrep scan --metrics off --config rules/semgrep/review-signals.yml <copy-of-target>`
(Semgrep skips `tests/` paths by default, so scan a copy of the fixture outside `tests/`).
