# Swift execution policy

Swift is an inventoried language, not enabled review coverage. The typed global setting
`tools.enable_swift` defaults to `false` in `appsec-review.toml` and is copied into each run's
hash-bound `data/configuration/resolved.json`. It is not an environment or prompt setting.

When the setting is `false`, `.swift` files remain in the target catalog so the system can report
their existence. They are removed before analysis planning and are not admitted to Tree-sitter,
build, CodeQL, source-history, evidence-collection, security-tagging, or review-prioritization
scopes. Evidence tools receive a policy-staged target containing only their non-Swift accepted
inputs (`tool-spotbugs`, `tool-blint` and `tool-grype`, which read produced artifacts rather than
source, are exempt from staging in `job_evidence_collection`). Accepted language-build and history
handoffs and non-catalog retrieval shards are checked
again at consumption time; a Swift path or typed Swift language value fails closed. The sole
downstream exception is the coverage-matrix row that preserves the catalog count and forces every
analysis lane to `unavailable` with the durable `KNOWN_GAP`. Absence of Swift findings is therefore
never a clean result.

Setting `tools.enable_swift = true` removes this policy gate for lanes that already support their
inputs. It does not claim complete Swift support. In particular, the current Tree-sitter image has
no pinned Swift grammar, and CodeQL Swift has no accepted macOS source/build executor. Those remain
named gaps until their platform, acquisition, execution, normalization, and acceptance contracts
are implemented. Tree-sitter image acquisition, grammar locks, and container inventory are owned
by the separate grammar-parity work and are intentionally unchanged here.

Changing the setting changes the canonical resolved-configuration hash, so accepted work from a
run with the opposite policy cannot be reused as if the policy were unchanged.
