# Cross-language CodeQL architecture

The CodeQL vertical slice has four deterministic stages:

1. `plan.inventory` validates the pinned runtime live and partitions accepted target/build scopes.
2. `database.scopes` creates or verifies one immutable database checkpoint per scope.
3. `query.scopes` queries a copy of each database with its pinned default suite and, when
   configured, each independently pinned custom suite.
4. `normalize.scopes` maps bounded SARIF into immutable observation/evidence shards, after which
   `acceptance.publish_handoff` composes the accepted retrieval manifest.

The stage names are fixed in central TOML. Scope execution is independent and concurrency-bounded;
one producer failure becomes only that scope's gap. All identity inputs are explicit: target and
file hashes, accepted handoffs, build receipt and protected argv, environment image, dependency
identity, extractor tree, CLI, asset lock, limits, query profile, pack/lock/suite, database tree,
and normalizer version. Query profiles have independent checkpoints and SARIF artifacts; changing
or failing a custom suite does not invalidate the database or erase the default-suite result.

The shared implementation lives in `src/appsec_review/codeql/` and
`src/appsec_review/jobs/job_codeql_analysis/`. Language-specific jobs do not own a second CodeQL
runtime, SARIF normalizer, or retrieval schema.
