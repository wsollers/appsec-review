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

- `dependency_package` entities with declared, SBOM/package, artifact, and native observations,
  plus their deterministic maximal-exposure classification;
- `review_signal` entities for normalized Scorecard context;
- exact response artifact hashes and `DERIVED_FROM` relations from Scorecard context to a dependency;
- dependency-scoped coverage rows and gaps.

After repository inference, a distinct deterministic unit canonicalizes repository identities and
groups every referring `dependency_id`. Scorecard retrieval consumes only that repository inventory,
so each unique repository causes at most one cache lookup and one remote retrieval per run (up to
`retries + 1` HTTP attempts; shipped `retries = 1`). The result
is then associated back to every dependency in the group; repository deduplication never discards
the package, SBOM, native provenance, exposure, CVE, or advisory identities.

Scorecard is review context and a red-team seed. It is never a vulnerability finding, never changes
finding severity, and cannot establish that reviewed bytes are identical to repository source.

Every normalized dependency is also consumed by review-data indexing's bounded
`dependency_advisories` lookup. PURLs map to configured OSV ecosystem/package identities; records
without a supported purl receive a bounded name-only lookup across the pinned ecosystems. These
matches retain the dependency identity, resolution basis, maximal exposure, and lookup ambiguity.
They are CVE/SBOM review leads only: the OSV package-name index does not evaluate affected version
ranges, so inventory-only matches always publish `applicability_verified: false` until corroborated
by a scanner or future version-range evaluator.

## Maximal exposure

Each normalized dependency receives one value from the ordered vocabulary
`DEV < DEBUG < QA < PREPROD < PROD`. The normalizer considers only bounded structured fields on
accepted observations: manifest/package scopes, build configuration/profile/environment fields,
and native loader kinds. It does not classify dependency names, versions, repository text, or
arbitrary target prose.

Development-only manifest scope maps to `DEV`, debug configuration to `DEBUG`, test and quality
assurance scope to `QA`, staging/preproduction scope to `PREPROD`, and explicit runtime,
production, release, loader-needed, or SONAME evidence to `PROD`. Every recognized observation is
retained in `exposure_evidence`, including contradictions. `maximal_exposure` is the greatest
observed class, and `exposure_inference_basis` is `maximum-observed-evidence`.

When no recognized scope evidence exists, the record is assigned `PROD` with
`exposure_inference_basis = conservative-default` and an empty evidence list. This deliberately
avoids understating review priority. It is not proof that the dependency is deployed in production.
The fields remain unchanged in both the dependency retrieval entity and accepted handoff.

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
enforces request, response-byte, timeout, and retry bounds. Before HTTP, the retrieval unit checks a
repository-owned content-addressed cache. Each cache entry has an atomic repository pointer, UTC
fetch time, exact response SHA-256 and byte length. A hit is accepted only when the pointer and blob
verify and its age is no greater than the centrally configured TTL. Stale entries are refreshed;
missing entries are fetched; corrupt entries produce `scorecard_cache_invalid` and are refreshed.
Successful refresh bytes are written under their content hash and the pointer is atomically updated.
Cache writes are bounded by a per-repository filesystem lock.

Whether cached or fetched, exact successful response bytes are copied into the run and hash
referenced. Bounded non-success and malformed HTTP responses are also retained run-owned. The cache
is optimization and reference history, not run evidence by itself, and the client never follows a
repository-provided endpoint.

Every dependency without usable Scorecard context remains present and receives a scoped gap. The
closed operational kinds are `unresolved_repository`, `unsupported_host`, `scorecard_not_found`,
`scorecard_rate_limit`, `scorecard_request_failure`, `scorecard_malformed_response`,
`scorecard_cache_invalid`, `scorecard_cache_write_failure`, `repository_bound`, `model_unavailable`,
`model_failure`, and `bounds`. A gap is missing coverage, not evidence that the dependency is safe.

## Public API

`appsec_review.jobs.job_dependency_intelligence` exports `build_job`,
`load_accepted_dependency_intelligence`, `parse_native_candidates`, `normalize_dependencies`,
`deduplicate_repositories`, `infer_maximal_exposure`, `repository_identity`,
`apply_model_resolution`, `ScorecardCache`, and the bounded `ScorecardClient`. Inference and HTTP
transport are injectable for deterministic tests and alternate orchestration environments.
