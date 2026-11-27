---
title: "Operating dependency intelligence"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_dependency_intelligence"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Operating dependency intelligence

Run `job_dependency_intelligence` after target cataloging, accepted language builds, artifact
indexing, and evidence collection. Its central configuration must declare this topology in order:

1. `inputs.load_accepted`
2. `resolution.detect_dependencies`, `resolution.curate_components`,
   `resolution.investigate_components`, `resolution.infer_repositories`
3. `repositories.deduplicate`
4. `scorecards.fetch`
5. `publication.publish_sbom`, `publication.native_advisory_lookup`, `publication.publish_context`
6. `acceptance.publish_handoff`

The SPDX 2.3 native enrichment and its telemetry have a separate
[operator guide](native-sbom.md). Its status describes inventory coverage, independently of
repository inference and Scorecard availability.
The [canonical job page](job_dependency_intelligence.md) supplies the generated input/dataset
declarations and exact stage acceptance checks; curation and metadata investigation precede
repository resolution and do not turn inferred upstreams into confirmed package releases.

Native curation sends only `candidate_id`, `native_name`, `package_root`, `root_id`, `domain`
and `context_paths` to the model. Full authenticated evidence, file records and observations stay
application-side; a model proposal cannot replace them. The native proposer does not retry timeout
failures. Other provider/schema failures retain their configured retry policy.

Configure positive deterministic bounds for dependency and unique-repository counts, native candidate count, command
tokens, metadata file count/bytes, inference candidate bytes, and the inference failure limit
(`inference_failure_limit`: once that many native candidate sets have ended in a model failure within
one unit, the remaining unresolved candidates are recorded as `model_failure_bound` gaps instead of
further calls). Configure a repository-host
allowlist; model provider/name/reasoning/token/timeout/retry settings; and Scorecard HTTPS base URL,
host allowlist, request count, response bytes, timeout, retry, repository-relative cache root,
cache-lock timeout, and maximum cache age. The default maximum age is seven days, matching the
upstream weekly scan cadence; operators may tune it centrally. Do not place these values in prompts.

The accepted artifact is under the final task's run-owned directory. Verify it through
`load_accepted_dependency_intelligence`; that reader checks the framework handoff, artifact hashes,
manifest content hash, shard hash, and immutable SQLite metadata before returning content. Raw
successful Scorecard JSON is stored below the Scorecard task and referenced by SHA-256. Bounded
HTTP error and malformed response bytes are also retained there when the client received them, so
operators can distinguish service behavior from a missing request without trusting response text.
The accepted document includes the deduplicated repository groups and `scorecard_metrics` with
unique repository, cache-hit, and HTTP-request counts. A warm-cache rerun should normally report
zero HTTP requests until entries exceed the configured maximum age.

Operational triage should group gaps by `dependency_id`:

- unresolved or unsupported repository: improve accepted package metadata or inspect the retained
  native command/artifact evidence;
- no Scorecard/404: confirm the public repository identity and Scorecard availability;
- rate limit/request failure: repair service capacity or connectivity and rerun;
- malformed response: retain the exact response hash and investigate API compatibility;
- cache invalid/write failure: inspect `data/feeds/openssf-scorecard`; the run may still contain a
  fresh remote response, but the cache failure remains an explicit operational gap;
- repository bound: review the deduplicated repository count before increasing the central bound;
- model unavailable/failure: the deterministic candidate remains usable, but repository coverage
  is incomplete. A `model_failure` gap carries `failure_class` (`empty_reply`, `no_json_object`,
  `schema_mismatch`, `several_objects`, `truncated_output`, `refusal`, or the transport category
  for timeouts, provider and budget failures) and the matching inference recording keeps the
  bounded reply text, stop reason and usage, so the cause is read from the run, never guessed.
  An identical candidate set (candidate, evidence allowlist, host allowlist) is asked once per
  unit and its outcome, including a failure, is reused for every dependency that carries it;
- model failure bound: the unit reached `inference_failure_limit`; the remaining candidates were
  not asked. Read the preceding `model_failure` gaps' classes before raising the limit;
- bounds: increase the specific central limit only after reviewing target scale and retained data.

Exposure triage should start with `maximal_exposure`, then inspect `exposure_evidence` before using
it to prioritize review. `PROD` with `exposure_inference_basis = conservative-default` means the
accepted observations had no recognized scope; it does not claim verified production deployment.
Conflicting evidence is expected and retained, with the maximum class chosen in the fixed order
`DEV < DEBUG < QA < PREPROD < PROD`. Improve upstream manifest, SBOM, build-configuration, or loader
observations when a conservative default is too broad; do not manually weaken the accepted output.

After acceptance, review-data indexing offers every `dependency_package` entity to the bounded
`dependency_advisories` route. A supported purl selects one OSV ecosystem and package name;
otherwise a name-only lookup is bounded across the pinned ecosystems. Model-inferred native
identities take the same route. Inventory-only matches remain
`applicability_verified = false` and carry an `applicability_unverified` gap until accepted scanner
or version-range evidence corroborates applicability. Version-range evidence comes only from
`osv_version_matching = "index"` (the shipped setting for both dependency intelligence and
review-data indexing; see
[OSV version matching](third-party-data-sync.md#osv-version-matching-against-the-index)), which
verifies a match when the purl's version is in an affected range and names a gap when it cannot
decide. A package-name match, inferred repository,
maximal-exposure value, Scorecard response, or absence of any of them is not a vulnerability
finding.

### Pinned OSV and source reachability

`publication.publish_context` also produces `sca-reachability.json`. Its OSV source is the
immutable external feed selection admitted into the attempt claim, not the current feed pointer.
The reader verifies the selected manifest and SQLite hash, records the external read, and uses the
existing bounded OSV matcher. Exact mode evaluates explicit-version matches from that same index;
an absent index is a named gap, not permission to walk raw advisory directories. Corrupted pins,
changed bytes and malformed databases fail without being relabeled as successful fallback.

Reachability reads only target-domain files named by the accepted catalog partition and verifies
their SHA-256 before extracting imports, calls and native FFI boundaries. An empty partition never
triggers a target scan. Missing or truncated coverage is named in `gaps`; positive call sites retain
the source hash. Static absence is `unknown`, never proof of `unreachable_in_target` or an OpenVEX
`not_affected` determination. The document carries snapshot provenance and partial-coverage status,
and its gaps propagate to the dependency-intelligence handoff.

Scanner observations join accepted dependencies by ecosystem, full package coordinates (including
namespace), exact installed version, and any PURL qualifiers/subpath, never display name alone.
Normalization retains ecosystem, explicit direct/transitive scope, version claims and their grades,
and domain/root/package-root identity in both dependency records and observation provenance.
Versions remain case-sensitive; Maven group IDs, npm scopes and Go module paths survive PURL
decoding. A nested corroborated version contributes its scalar value, never a stringified record.
Inferred, conflicted or unknown versions and manifest constraints cannot become installed versions
through a PURL fallback. Distinct ecosystems and roots do not merge merely because names match.
Explicit non-string grades, including null, are unknown rather than absent: malformed `status`,
`kind` or outer `version_kind` cannot authorize a PURL fallback. Original claims remain in observation
provenance and OSV matching reports `osv_dependency_identity_incomplete`. Truly absent legacy grades
still allow exact scalar or PURL versions; normalization does not invent a null grade for them.
Conflicting versions, missing coordinates or missing/unmatched instance IDs retain an unbound advisory
with empty `dependency_ids`, `unknown` reachability and a `sca_dependency_binding_unresolved`
gap. An advisory for one version or ecosystem does not attach to fixed releases or same-named
foreign packages. OSV symbols come only from the affected entry selected by the version matcher.
Published SCA signal identities bind the advisory, package name/version, ecosystem, exact PURL
(including qualifiers/subpath), and sorted dependency IDs. Same-named foreign coordinates cannot
collide in the immutable inventory shard, and changing the bound root instances changes signal
identity without treating a different observation order as a different package.

The bounded `query_sca_reachability` API keeps the argument name `reachability_class`, but filters
the producer's `reachability` field exactly. Prioritization reads `package_name` and uses only that
advisory's `ffi_mechanisms` and matching `ffi_boundary` call sites for the native-FFI modifier.
Promoted lead identity includes ecosystem, version, PURL and dependency IDs; its existing `subject`
field retains the package coordinate. These remain static review leads, not certified execution
paths, and do not change the normalized priority scale or promotion threshold. Accepted handoff,
SCA artifact and query-shard reads retain their consumption receipts.

`symbol_reachable` means **bounded static symbol-use evidence**, not proof of whole-program
runtime reachability. Currently positive symbol evidence is limited to Python AST calls through
unambiguous top-level imports/aliases, matched to an explicit affected module/symbol mapping.
Imports, declarations, same-named local calls, strings and comments cannot establish that state.
Shadowed/reassigned bindings, accepted local-module collisions, ambiguous/incomplete installed versions,
parse failures and unsupported binding forms retain uncertainty with named gaps. No import-to-
distribution mapping is guessed from a distribution's display name. Multiple scopes are handled
conservatively: a shadow/reassignment can suppress otherwise valid calls elsewhere in the file.

Other language imports and native FFI loader/declaration patterns remain contextual evidence only
(`package_imported` when matched), not vulnerable-symbol calls. Native context is heuristic and
does not identify the loaded binary or prove a call through it; an unrelated function elsewhere
in a loader's file does not inherit that library's identity. Non-Python and native symbol binding,
dynamic dispatch/reflection, inter-file alias flow and whole-program execution are not established
by this artifact. Inspect its gaps rather than treating these limitations as clean coverage.

The job's typed settings bound `max_source_files`, `max_bytes_per_file`,
`max_call_sites_per_advisory`, `max_advisories`, and `max_osv_candidates_per_package`. Reaching a
bound reports omitted coverage. Source extraction is bounded by the accepted file/byte limits,
without an internal 32-entry call bucket. Matching locations are deduplicated by path, line and
symbol before the configured per-advisory cap is applied; distinct calls to the same symbol on
the same line share one location because this schema has no column. A truncation gap
`reachability_call_sites_truncated:<advisory>:<package-coordinate>:omitted=<count>` reports the exact omitted unique
locations within scanned coverage, not an estimate of unscanned code. These checks do not run
scanners, refresh feeds or create a new pipeline stage.

### Native advisory lookup (NVD CPE ranges)

OSV has no ecosystem for a vendored C library, Grype and osv-scanner match package-manager
coordinates only, and cve-bin-tool matches only the version strings its checkers know inside the
binaries it is handed. A component whose release this job corroborated from its own headers
(`pkg:generic/<name>@<version>`, see [native SBOM](../architecture/native-sbom.md)) therefore
reaches no scanner. `publication.native_advisory_lookup`
(`jobs/job_dependency_intelligence/native_advisories.py`) closes that gap without a model or the
network: it opens the verified cve-bin-tool snapshot read-only (`verify_consumer`: pointer, manifest
and file hashes, build record, SQLite integrity; the snapshot is the NVD CPE range database) and
decides every `cve_range` row whose product is the component's normalized name, across **all**
vendors, against the corroborated version: an exact-version row matches only an equal version,
a `*` row is decided by its four range bounds with a dotted-numeric comparison (one to four parts,
zero-padded). The comparison is conservative: a bound that is not dotted numeric (`2023-11-16`,
`r118`, `0.9.5a`) and a release whose distro-style suffix (`1.0.6-r3`) sits exactly on a bound are
`unknown`, reported as the gap `version_uncomparable: <component>: <CVE> ...`, never a match and
never a clean result. The empty `purl2cpe` table is consulted and recorded (`purl2cpe: []`).

Every match is a **lead with a stated confidence, not a confirmed vulnerability**: NVD considers
the release affected, which says nothing about whether the affected code is compiled, reachable or
patched here. `confidence: canonical` means the row's vendor is the product's own NVD spelling
(`zlib/zlib`, `lz4_project/lz4`, `bzip/bzip2`: the product itself, `<product>_project`, or the
product without its trailing release digits); every other vendor (`cloudflare/zlib`,
`ruby-lang/zlib`, `davegamble/cjson`) is `confidence: alternate_vendor`, reported with lower
confidence rather than hidden, because the same product name is used by forks, bindings and
unrelated projects. The vendor and product are always on the record so a reviewer can re-rate
a lead (`davegamble` is cJSON's upstream author yet an alternate vendor under this rule).

The matches are indexed as an `observations` shard (`native-advisory`, dataset
`native_advisory_observations`) in this job's manifest: one `finding` record per match
(`tool_id: native-advisory-lookup`, `scanner_identity: native-advisory-lookup/1`,
`match_basis: cpe-range`, `category: vulnerability_matching`, the CVE as `rule_id`, the snapshot's
NVD severity, CVSS score, version and vector, `known_exploited` from `cve_exploited`, the matched
row's bounds, the dependency ids, and the provenance `snapshot_id`, `manifest_sha256`,
`nvd_snapshot_id` and `cve.db` SHA-256) plus one `scan_summary` per component (products queried,
rows evaluated and rejected, `unknown_advisories`, outcome). A finding projects the same
`observation.matches` pair as a Grype or cve-bin-tool match, so `advisory_pairs` turns it into a
`dependency_advisories` fact joined to the pinned OSV, NVD, KEV and EPSS snapshots and the review
sees it as a `dependency_advisory` lead; each finding is `DERIVED_FROM` the `dependency_package`
entity it names. The whole decision record (`native-advisory-lookup.json`, dataset
`native_advisory_lookup`) is retained beside the unit.

Named gaps, never silence: `tools.enable_native_advisory_lookup = false` records a
`CONFIGURED_DISABLED` gap and `TOOL_CONFIGURED_DISABLED` event; a missing or unverifiable snapshot
is `verified immutable cve-bin-tool database unavailable: <reason>` for every component; a native
component without a corroborated version is an `advisory_version_unresolved` gap naming it (it is
not looked up: a CPE range needs a version); an uncomparable bound is `version_uncomparable`; and
the typed bounds `jobs.job_dependency_intelligence.settings.native_advisory_lookup`
(`component_limit`, `rows_per_component`, `match_limit`) each report `truncated:` when exceeded.
Rows with a scanner-covered purl type (`pkg:npm/...`, `pkg:pypi/...`, ...) are left to the package
scanners. On the C/C++ smoke target the lookup lists, for zlib 1.2.11, bzip2 1.0.6, lz4 1.9.1 and
cjson 1.7.17, the planted CVE-2018-25032, CVE-2019-12900 and CVE-2019-17543 beside the other
ranges NVD assigns those releases (replayed read-only against snapshot
`sha256-9b5fac4b35e740ac8d12c0a6`); cjson 1.7.17 matches CVE-2024-31755 (exact), CVE-2023-53154 and,
as alternate-vendor leads, four `davegamble/cjson` ranges.

Focused verification:

```text
scripts/run-tests.sh --expect-tests 31 --parallel --test-workers 2 --shuffle-seed 5126 -- tests/unit/job_dependency_intelligence/test_coordinate_consumers.py
```

Mocked tests verify parser, inference, HTTP, gap, and publication contracts. They do not prove live
Scorecard reachability or provider availability; those remain explicit environment acceptance work.


## Tuning and whole-job recovery: `job_dependency_intelligence`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.command_token_limit` | `4096` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.dependency_limit` | `100000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.inference_candidate_bytes` | `32768` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.inference_failure_limit` | `8` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_advisories` | `5000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_bytes_per_file` | `524288` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_call_sites_per_advisory` | `32` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_osv_candidates_per_package` | `500` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_source_files` | `2000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.metadata_bytes_per_file` | `1048576` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.metadata_file_limit` | `10000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.model.max_input_tokens` | `32000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.model.max_output_tokens` | `16000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.model.retries` | `1` | coverage | integer >=0; exact parser/cross-field bounds† |
| `settings.model.timeout_seconds` | `120` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_advisory_lookup.component_limit` | `4096` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_advisory_lookup.match_limit` | `20000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_advisory_lookup.rows_per_component` | `512` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_candidate_limit` | `10000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_evidence_limit` | `50000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_evidence_per_candidate` | `32` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_field_bytes` | `4096` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.batch_candidates` | `10` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.bytes_per_file` | `262144` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.component_limit` | `10000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.field_bytes` | `4096` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.files_per_root` | `128` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.group_limit` | `2048` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.max_calls` | `256` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.max_payload_bytes` | `98304` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_inference.source_bytes_limit` | `8388608` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_path_chars` | `512` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_root_limit` | `2048` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.native_source_bytes_limit` | `67108864` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.repository_limit` | `100000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.sbom_conversion_timeout_seconds` | `120` | execution | positive integer; exact parser/cross-field bounds† |
| `settings.sbom_element_limit` | `100000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.sbom_input_bytes` | `16777216` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.sbom_output_bytes` | `33554432` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.scorecard.cache_lock_timeout_seconds` | `5` | execution | positive integer; exact parser/cross-field bounds† |
| `settings.scorecard.max_requests` | `10000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.scorecard.max_response_bytes` | `1048576` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.scorecard.retries` | `2` | execution | integer >=0; exact parser/cross-field bounds† |
| `settings.scorecard.timeout_seconds` | `30` | execution | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/jobs/job_dependency_intelligence/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.reachability_enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.model.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.model.provider` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.model.model` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.model.reasoning` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.native_inference.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.scorecard.cache_max_age_seconds` | Selects model, source, algorithm, required evidence or authority; not a reviewed execution/coverage capacity. |
| `steps.inputs.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.resolution.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.repositories.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.scorecards.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.publication.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
