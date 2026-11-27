---
title: "Operating the security-tagging stage"
kind: "operations"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_owasp_control_assessment", "job_security_tagging"]
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# Operating the security-tagging stage

`security_tagging` assigns basis-qualified tags from the
[security tag taxonomy](../architecture/security-tag-taxonomy.md) to code subjects. It reads only
the attempt's admitted retrieval manifest and shards, plus hash-checked source spans for invoked
graph facts; it does not discover files by scanning the target tree. Input authority follows
[accepted-upstream admission](../architecture/job-input-contracts.md#admission-and-read-receipts),
not a mutable pointer alone. In the
`wave1_review` Dagster graph it runs after CodeQL, review prioritization and code-graph indexing
when registered (`orchestration/topology.py`). The default-enabled `job_owasp_control_assessment` then
consumes accepted tag assignments and a bounded component tag cloud as routing context, never
control proof. Tagging does not depend on OWASP. Review data indexing follows all enabled
producers, then package assembly, document issue analysis and inference review; final report
publication is terminal. Direct `start`/`resume`/`plan-resume` select the same enabled
prioritization → code graph → tagging → OWASP → indexing chain; `--force-from` cannot bypass a
disabled-job gate. OWASP is enabled by default in all shipped profiles. The direct CLI and
Dagster derive review-job membership from the same typed contracts, including enabled CI and
post-build producers; third-party metadata sync remains standalone.
Run it standalone only after an accepted manifest exists; without one the input validator fails the
job.

The vocabulary, capability rules, and crosswalk are pinned by path and SHA-256 under
`jobs.job_security_tagging.settings.taxonomy` in `appsec-review.toml`. Editing any of the three
files without updating its pinned hash fails the job before any unit runs. A namespace marked
`proposed` in the vocabulary cannot be emitted until its catalog is pinned.

The collation pass (T-5008, [design](../architecture/collation-pass.md)) adds a `collation` step
after capability collection that assigns closed facet tags (`role`, `exposure`, `trust`,
`mechanism`, `asset`, `state`) to every first-party file and component, and a `target:*` class
per component, from the collected tags, pinned lexical and path rules over hash-verified
first-party bytes, build receipts and target documents. Its rules live in the pinned
capability-rules file, its settings under `jobs.job_security_tagging.settings.collation`, and its
records in the `tags` index shard `facets`. The deterministic step (`collation.collate_facets`) and the
optional recorded model pass (`collation.model_pass`, off by default; one bounded call per first-party
component through the application's recorded transport, writing `model-pass.json` and
`unit-purposes.json`) are implemented.
The step publishes `facet-facts.json` (the assignment set) and `collation.json`
(`appsec-review/collation-pass/1`: per first-party file its facets and assignment ids, per component
its facets and `target:*` classes, the files skipped per disposition, the sources that were available
and the named gaps) beside the other collector artifacts. Settings:

| Key (`settings.collation`) | Default | Effect |
|---|---|---|
| `max_source_bytes_per_file` | 262144 | a larger first-party file is not read; gap `collation:source_unread:<path>` |
| `max_files_per_component` | 4096 | further first-party files of a component are skipped; gap `collation:file_bound` |
| `source_dispositions` | resolved from `jobs.job_inference_security_review.settings.source_dispositions` | which files are first-party; a literal table must equal the review's |
| `model_pass.enabled` | `false` | the recorded model pass (stage 4); needs an enabled `model_pass.model` profile |

A facet is routing data: a `target:cli` component sends OWASP to a not-applicable ledger and a
`trust:user-tainted` unit to input-handling hunts, but no facet is evidence of a weakness or its
absence. A gap named `collation:*` says which source the pass could not use; it never implies a tag.

Two bounds sit beside the taxonomy pins in `jobs.job_security_tagging.settings`:

| Key | Default | Allowed | Effect when exceeded |
|---|---|---|---|
| `max_entities_per_shard` | 50000 | 1 to 1,000,000 | entities read per accepted shard; reaching it records a named gap |
| `max_assignments` | 500000 | 1 to 2,000,000 | assignments per collector; exceeding it fails that collector |

Check these outputs after a run:

- the job attempt's `artifacts/security-tagging/` directory: `taxonomy-identity.json`,
  `scope.json`, one assignment set per collector, `derived.json`, the validated `assignments.json`,
  `tag-cloud.json`, and `handoff.json`;
- `data/indices/tags/<family>/` for the immutable tag shards; and
- `data/indices/accepted.json`, which now points at `data/indices/manifests/tags-<attempt>.json`.
  That manifest carries every upstream shard plus the tag shards, so retrieval and MCP clients
  keep seeing earlier evidence.

Query assignments with the existing retrieval tools, for example `search` with
`indexes=["tags"]` and `kinds=["tag_assignment"]`, or `trace` from an assignment to its subject and
to the observed tags a derived tag came from.

Reading the results:

- A `derived` tag means the control, weakness, or technique is applicable or relevant to review. It
  never means present or satisfied. Only `reported` or `confirmed` weakness tags cite findings, and
  the job publishes no security findings itself.
- Every `gap:*` tag and every entry in the handoff `gaps` list is missing coverage. An empty region
  of the tag cloud is never evidence that the target is clean.
- The job completes with gaps by design. Invoked capabilities now come from bounded, direct-eligible,
  source-resolved graph entry/sink facts; package inventory still supplies only `declared` capability.
  Its standing gaps are limited mapped graph-class coverage, the upstream CWE->CAPEC->ATT&CK crosswalk (deferred until
  the MITRE feed is pinned into the run), and the unimplemented `taint_path`, `iac_resource`,
  `k8s_object`, and `container_stage` crosswalk scopes. The feed-backed rollups add the `rollup_gap`
  notes declared on their namespaces in `data/reference/taxonomy/vocabulary.json`. Each is named in
  the handoff.

The [current job page](job_security_tagging.md) names the exact collector decisions, rejected
graph-fact causes, immutable publication and acceptance checks.

A re-run in the same application run produces the same assignment set for the same accepted
manifest and pinned taxonomy, and replaces earlier tag shards in the accepted manifest instead of
duplicating them.


## Tuning and whole-job recovery: `job_security_tagging`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.collation.max_files_per_component` | `4096` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.collation.max_source_bytes_per_file` | `262144` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.collation.model_pass.max_components` | `64` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.collation.model_pass.max_excerpt_lines` | `400` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_assignments` | `500000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_entities_per_shard` | `50000` | coverage | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/config/collation.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.collation.model_pass.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `steps.taxonomy.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.scope.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.collection.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.collation.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.crosswalk.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.integrity.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.publication.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
