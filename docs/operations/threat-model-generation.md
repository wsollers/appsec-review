# Generated DFD and threat model

`job_threat_model_generation` (T-107) builds a data-flow diagram and a candidate threat list from
evidence other jobs already accepted. The design is
[dfd-and-threat-model-generation](../architecture/dfd-and-threat-model-generation.md); this page
describes the first slice that is implemented.

The output is **generated**. It is not the target owner's document, it is never counted as a
supplied `dfd` or `threat_model`, and no review claim may cite it: its authority is
`routing_context`, which may guide where a reviewer looks and never satisfies an obligation.

## Disabled by default

`[jobs.job_threat_model_generation.settings] enabled = false` in `appsec-review.toml`. The job is
registered and configured so its contract, datasets and tests are in place, and it stays out of
`wave1_review` until the owner enables it. Enabling it is a configuration decision that has not been
made; nothing in this page authorizes it. A frozen run keeps its configuration, so enabling the job
later does not add it to an existing run.

When enabled, the job runs after `job_owasp_control_assessment`, `job_dependency_intelligence` and
`job_security_tagging` (scheduling edges only) and before `job_review_data_indexing`, which schedules
after it so the dataset inventory sees its files. No job consumes its handoff.

## What it reads

Accepted evidence only (`TargetAccess.ACCEPTED_EVIDENCE`): no checkout, no target tree, no model, no
network. Every read is a bounded query of an index shard bound in a handoff the attempt admitted.

| Producer | Output kinds | Required |
| --- | --- | --- |
| `job_target_catalog` | `build_units`, `components`, `source_files` | envelope required |
| `job_artifact_indexing` | `artifact_catalog`, `artifact_relationships` | optional |
| `job_language_build` | `build_actions` | optional |
| `job_cpp_compiled_analysis` | `cpp_build_graph` | optional |
| `job_code_graph_index` | `code_graph_facts` | optional |
| `job_tree_sitter_ast` | `tree_sitter_ast` | optional |
| `job_review_prioritization` | `priority_items` | optional |

An absent, disabled, empty or partial optional input never fails the job: it becomes a ledger row
and a gap. Reference data comes from `data/reference/threat-model/` (interaction catalog, threat
templates, crosswalk); its three SHA-256 digests are recorded in every document's `origin`.

## What it writes

Everything is under `data/jobs/job_threat_model_generation/attempts/<attempt>/artifacts/threat-model/`
and is hash-bound by the handoff. Nothing is written to any index, and never to `documents`.

| File | Dataset | Content |
| --- | --- | --- |
| `dfd.json` | `generated_dfd` | Elements, flows, trust boundaries, unknowns |
| `threat-model.json` | `generated_threat_model` | Actors, entry points, candidate threats, unknowns |
| `evidence.json` | `generated_model_evidence` | Every evidence reference the two documents cite, once |
| `views/dfd.mmd`, `views/dfd-proc-*.mmd`, `views/threat-model.md` | `generated_model_views` | Mermaid diagrams and the Markdown view, rendered from the JSON |
| `result.json` | `threat_model_documents` | Input ledger, counts, joined gaps, artifact references |
| `work/*.json` | `threat_model_documents` | Canonical working records the units hand to each other |

All five datasets are `artifact_only`, sensitivity `internal`, authority `routing_context`. The
handoff's `publication.publish_handoff` output names `result.json`; `result.json` names every other
published file with its hash. JSON Schemas are in `docs/schemas/threat-model/`.

A candidate threat is a question the evidence raises, not a finding. Every threat has mitigation
state `not_examined` in this slice; the job never states that a control is absent.

## Steps

`load.accepted_inputs`, `facts.structure`, `facts.interactions`, `assembly.dfd`,
`threats.enumerate`, `validation.resolve_citations`, `publication.render`,
`publication.publish_handoff`. All are deterministic. Before publication the four documents are
validated against their schemas and cross-references, and the views are re-rendered and compared
byte for byte with what `publication.render` wrote; a violation fails the attempt and publishes
nothing.

## Configuration

`[jobs.job_threat_model_generation.settings]` is a closed key set. An unknown, missing or mistyped
key, or a value out of range, is refused when the configuration is loaded.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Whether the job is in the review graph |
| `max_processes` | 200 | Processes kept; more is a `truncated` gap |
| `max_entry_points` | 4000 | Entry points kept |
| `max_flows` | 8000 | Flows kept |
| `max_threats` | 4000 | Candidate threats kept |
| `max_query_rows` | 2000 | Rows per index query; a query that reaches it is a `truncated` gap naming the query |
| `max_evidence_refs_per_element` | 8 | Citations kept per record |
| `max_render_nodes` | 120 | Nodes per diagram; over it the model renders an overview plus one diagram per process |

Each bound is an integer from 1 to 100000. `[...settings.reservation]` (`cpu`, `memory_mb`,
`io_slots`, `admission_timeout_seconds`) is the admission-ledger reservation the two `facts.*` units
hold while they read index shards. There is no `model` table in this slice.

## Every run completes with gaps

In this slice the job's status is `COMPLETED_WITH_GAPS` on every run. The deployment inventory
producer (`job_deployment_inventory`, T-108) is not registered, so `load.accepted_inputs` always
reports one `input_unavailable` gap for it and the ledger always has one `not_registered` row.
`SUCCEEDED` is not reachable until that producer exists and every optional input is accepted
complete.

## Reuse and resume

An accepted attempt is reused when its upstream handoff digests, the resolved configuration, the
dataset contract and the release identities are unchanged and it has no retryable gap. A new
accepted handoff of any declared producer (a repaired upstream) changes a pinned digest, so the job
runs again and nothing upstream of it does.

An absent optional producer, a declared output that was not published and a partial upstream are
retryable gaps. While one remains, the runtime does not reuse the accepted attempt: a resume runs
the job again as a new attempt. A disabled producer and the unregistered deployment producer are not
retryable and do not prevent reuse.

## Reading the result

- **Input ledger** (`result.json` `input_ledger`, and the first table of `threat-model.md`): one row
  per declared input with `state` (`read`, `absent`, `disabled`, `not_registered`, `partial`,
  `empty`), the admitted handoff digest, the producer's coverage and gap count, and how many records
  were read. It says what was supplied and read; `evidence.json` says what was cited.
  `job_target_catalog/source_files` is declared and admitted but no lane of this slice queries it, so
  its row shows zero records.
- **Unknowns** (`dfd.json` and `threat-model.json` `unknowns`): statements about the model, each
  with `would_resolve` naming the input that would turn it into an element. This is the work list.
- **Gaps** (`result.json` `gaps`): `producer-gap/1` records about inputs and bounds. Each gap is
  declared once, by the unit that found it, in that unit's result; `result.json` carries the join and
  the publishing unit declares none. A gap with scope `structure.redacted` means the index had
  withheld names or paths (`<redacted>`, `<truncated>`); the affected processes are named
  `redacted-name` and identified by record.

The job fails only when the reference data is invalid, an admitted input or a working file changed,
or the documents violate their contract. The failure class in the task receipt is
`ThreatModelGenerationFailed`, or the runtime's integrity error for a changed input. The publishing
unit writes one event, `THREAT_MODEL_PUBLISHED`, with the counts, the gap count and the identity of
`result.json`.

## Running it by hand

This is a **manual live operation**. It requires the owner's explicit authorization, an existing
application run with an accepted `job_target_catalog`, and the job enabled in that run's
configuration (a disabled job is refused):

```text
appsec-review --config appsec-review.toml run job_threat_model_generation --run-id RUN_ID --upstream-from-run
```

The job reads accepted evidence only, so no `--target` is given. `--upstream-from-run` binds the
accepted handoffs the graph would pass; it is not a path to input files.

## Not implemented

- Model elaboration (`elaboration.model_review`), its guidance, receipts and the `model` settings.
- The declarations lane (`facts.declarations`): declared operations, dependencies, component roles,
  tags, tool observations, OWASP control results.
- The deployment inventory (T-108): listeners, services and service relationships. Every exposure
  statement is an unknown until it exists.
- Mitigation evidence: every candidate threat is `not_examined`.
- Assets: `assets` is empty, and each data store has an `asset_sensitivity_unknown`.
- Consumers: no job reads the output, nothing is indexed, and the final report does not show it.

## Verification boundary

Unit tests cover the job through the real runner with fixture upstream handoffs
(`tests/test_threat_model_generation_job.py`). The integration and acceptance scenarios
(`tests/integration/test_threat_model_generation.py`,
`tests/acceptance/test_threat_model_generation.py`) are written and have not been run; they and any
live run are manual validation owned by the user.
