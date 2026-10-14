# Dependency intelligence

See [`engineering-security-signals.md`](engineering-security-signals.md) for this producer's place
in the combined engineering-signal data flow and downstream review boundary.

`job_dependency_intelligence` is the generic dependency identity and OpenSSF Scorecard producer.
It consumes only accepted target-catalog, language-build, artifact-index, and evidence-collection
handoffs. Target content, protected compiler commands, SBOM observations, model output, and remote
responses are data.

## Contract

The job publishes `appsec-review/dependency-intelligence-handoff/1` and one immutable `inventory`
retrieval shard named `dependency-intelligence`. The shard contains:

- `dependency_package` entities with declared, SBOM/package, artifact, and native observations;
- `review_signal` entities for normalized Scorecard context;
- exact response artifact hashes and `DERIVED_FROM` relations from Scorecard context to a dependency;
- dependency-scoped coverage rows and gaps.

Scorecard is review context and a red-team seed. It is never a vulnerability finding, never changes
finding severity, and cannot establish that reviewed bytes are identical to repository source.

## Identity resolution

Inputs are normalized and deduplicated by purl when present, otherwise by normalized package name
and version/constraint. Package metadata repository URLs take precedence. Only canonical HTTPS
repository identities on the configured public-host allowlist are accepted as exact.

Native observations are extracted deterministically from hash-verified protected compiler/linker
rows and accepted artifacts. The parser recognizes `-lfoo`, `-l:libfoo.so`, forwarded `-Wl` link
arguments, archive/shared-library paths, Windows import names, frameworks, ELF loader names and
SONAMEs. When hash-bound workspace manifests contain pkg-config or CMake package metadata, bounded
fields such as name, version, URL, and repository are retained. Each observation carries its
command id/hash or artifact hash.

Only an unresolved native candidate may reach model inference. The request contains one bounded
candidate, evidence-reference allowlist, supported repository hosts, a registered persona, role,
task, and runtime skill. The result schema is
`appsec-review/native-dependency-resolution-proposal/1`. Candidate identity, repository fields,
host, evidence references, and confidence are validated. Model confidence is capped at 0.95 and
the resulting identity remains `exact_repository_identity: false` until accepted metadata
corroborates it.

## Network and gaps

The Scorecard client uses a configured HTTPS base URL and host allowlist, rejects redirects, and
enforces request, response-byte, timeout, and retry bounds. Exact HTTP response bytes, including
bounded non-success and malformed responses, are retained run-owned and hash referenced. It never
follows a repository-provided endpoint.

Every dependency without usable Scorecard context remains present and receives a scoped gap. The
closed operational kinds are `unresolved_repository`, `unsupported_host`, `scorecard_not_found`,
`scorecard_rate_limit`, `scorecard_request_failure`, `scorecard_malformed_response`,
`model_unavailable`, `model_failure`, and `bounds`. A gap is missing coverage, not evidence that the
dependency is safe.

## Public API

`appsec_review.jobs.job_dependency_intelligence` exports `build_job`,
`load_accepted_dependency_intelligence`, `parse_native_candidates`, `normalize_dependencies`,
`repository_identity`, `apply_model_resolution`, and the bounded `ScorecardClient`. Inference and
HTTP transport are injectable for deterministic tests and alternate orchestration environments.
