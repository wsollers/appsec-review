# Design artifact discovery

## Purpose

A security review gets a lot more useful when the reviewer knows what the project says about
itself. That means its design documents, threat models, API specifications, RPC interface
definitions, data schemas, API test collections, and unit or system tests. These artifacts show
intended trust boundaries, declared attack surface, and which behavior is already exercised by
tests. They are hard to find by hand in a large tree.

`job_design_artifact_discovery` is an information-gathering job. It runs after the target catalog
is accepted and before analysis planning. It finds and classifies these artifacts, then publishes
them as one bounded, hash-verified retrieval shard, so later jobs and review workers can query them
instead of scanning the target.

The job only gathers information. It reports no security findings (`security_findings` is always
empty). When a category is absent, that is a fact about the cataloged paths. It is never evidence
that the target is secure.

## Placement in the review graph

```text
review_intake -> target_catalog -> design_artifact_discovery -> [ci_configuration_analysis]
  -> target_analysis_plan -> ...
```

- The direct CLI `start` / `plan-resume` / `resume` graph inserts the job between
  `job_target_catalog` and `job_target_analysis_plan`. You can pass it to `--force-from`.
- The Dagster `wave1_review` graph runs it after `job_target_catalog` and before
  `job_ci_configuration_analysis`. That job then feeds `job_target_analysis_plan`.

The gather-phase jobs run one after another, not in parallel, on purpose. Every index-publishing
job writes a manifest that builds on the accepted manifest and then advances the single
`data/indices/accepted.json` pointer. If two jobs did this in parallel, the last one to finish
would drop the other's shard. The order also matters to `job_target_analysis_plan`. That job walks
back past any manifest that holds CI `observations` to that manifest's first upstream. With design
discovery placed before CI, the `analysis/design_artifacts` shard is in the manifest the plan
builds on, so it carries forward into downstream manifests.

## Inputs and trust

- The only inputs are the accepted `job_target_catalog` handoff and the cataloged file list, both
  verified through `load_target_catalog`. The job never walks the target tree itself.
- Catalog gaps with reason `binary_excluded`, `file_too_large`, or `inventory_bound_reached` are
  classified by path only. This catches design PDFs, DOCX files, and Visio diagrams that the
  catalog does not store. Each one becomes a named gap: "identified by name only; content not
  cataloged".
- Content probes read a file only after checking that its bytes still match the catalog SHA-256.
  A mismatch fails the job, because it means the target changed after the catalog was accepted.
- Target content is data. Probes match fixed byte patterns and keep only structured facts:
  category, subtype, matching rule, and numeric signals. Free text such as titles or descriptions
  never enters the payload, so injected instructions in a target file cannot reach the index.

## Topology

| Step | Task | Behavior |
| --- | --- | --- |
| `design_discovery` | `classify_paths` | Applies the path rules to every cataloged path and to path-only catalog gaps. Marks which candidates need a content probe. Bounded by `max_artifacts`. |
| `design_discovery` | `probe_content` | Verifies hashes, then matches signatures in a prefix of at most `max_probe_bytes`. Merges path and content evidence per category. Bounded by `max_probe_files` and `max_file_bytes`. |
| `design_publication` | `build_index` | Builds the immutable `analysis/design_artifacts` SQLite shard and its coverage rows. |
| `design_publication` | `publish_handoff` | Writes a manifest from the accepted upstream set plus this shard (replacing any earlier copy), verifies it, and publishes the summary handoff. |

The central configuration in `appsec-review.toml` is checked against this topology. If the
configured steps or tasks differ, the input validator fails.

## Taxonomy

The ruleset is `design-artifact-rules/1`, in
`src/appsec_review/jobs/job_design_artifact_discovery/discovery.py`.

| Category | Subtypes | Main signals |
| --- | --- | --- |
| `design_document` | `adr`, `rfc`, `architecture`, `design`, `diagram`, `security_policy` | Document or diagram suffixes under design, ADR, or RFC folders, or with design words in the name; `.drawio`, `.puml`, `.mmd`, `workspace.dsl`; `SECURITY.*` |
| `threat_model` | `document`, `diagram`, `structured`, `microsoft_tmt`, `threagile`, `threat_dragon`, `pytm` | Threat-model, STRIDE, or attack-tree words in the path; `.tm7`; `threagile.yaml`; content: a Threat Dragon model, a pytm import, or a `<ThreatModel>` root |
| `api_specification` | `openapi`, `swagger`, `asyncapi`, `raml`, `api_blueprint`, `wsdl`, `graphql_schema` | Spec file names and suffixes; content: an `openapi: 3.x`, `swagger: 2.x`, or `asyncapi:` root key, or a `#%RAML` header |
| `interface_definition` | `protobuf`, `thrift`, `avro_idl`, `flatbuffers`, `capnproto`, `smithy`, `omg_idl`, `android_aidl` | IDL suffixes |
| `data_schema` | `json_schema`, `xml_schema`, `avro_schema` | `*.schema.json`, `schemas/` folders, `.xsd`, `.avsc`; content: a `$schema` pointing at json-schema.org |
| `api_test` | `postman_collection`, `insomnia_export`, `http_request_file`, `bruno_request`, `pact_contract`, `dredd_configuration` | Collection, request, and contract file names; content: Postman, Insomnia, or Pact signatures |
| `test` | `unit_test`, `integration_test`, `system_test`, `performance_test`, `harness_configuration` | Per-language test naming rules, test folders, `src/test/`, Gherkin `.feature`, load-test files, test-runner configuration |

Test level comes from folder names (`integration`, `e2e`, `cypress`, `perf`, ...) and name
markers. A plain source file under a folder named `system` or `integration` is not counted as a
test unless a test-only folder or test naming rule also applies. JVM and .NET class-name rules are
case-sensitive, so names like `Audit.java` and `Latest.cs` are not counted as tests.

Content signals are numeric only:

- `.proto` files: `service_count` and `rpc_count`, a first measure of RPC attack surface.
- GraphQL files: `root_operation_type_count`.
- Detected OpenAPI, Swagger, and AsyncAPI documents: `path_entry_count`, counted within the probed
  prefix.

A file can match more than one category. For example, a Pact file is both an `api_test` and a JSON
document. Each category keeps its full list of evidence (`method` is `path` or `content`, plus the
`rule` name). When content evidence exists, its subtype wins over the path-derived subtype.

## Outputs

- **Catalog artifact** (`appsec-review/design-artifact-catalog/1`): one entry per artifact with
  its path, SHA-256, size, cataloged flag, categories with evidence, signals, and probe status
  (`probed`, `probed_prefix`, `not_probed`, `too_large`, `bound_reached`, `unavailable`).
- **Retrieval shard** `analysis/design_artifacts`: one `source_file` entity per artifact. The
  payload includes `category`, `subtype`, `category_set`, and `subtype_set`. Cataloged artifacts
  carry a whole-file `SourceLocation`, so `read_excerpt` resolves them against the hash-verified
  bytes. Uncataloged artifacts have no location. Coverage rows are written per category, plus
  `design:absent_categories`.
- **Handoff summary** (`appsec-review/design-artifact-discovery-handoff/1`): counts by category
  and by subtype, `absent_categories`, gaps, the manifest identity, and an empty
  `security_findings` list. Any gap makes the terminal status `PARTIAL`, and the review completes
  with gaps.

## Reviewer query tool

`query_design_artifacts` is a retrieval core method and an MCP tool. It reads only the accepted
`analysis/design_artifacts` shard, using these filters:

| Filter | Meaning |
| --- | --- |
| `category` | Matches any of an artifact's categories, not only the primary one. Restricted to the taxonomy enum. |
| `subtype` | Exact subtype within `category`. Rejected unless `category` is also given. |
| `path_prefix` | A literal folder prefix: `tests/integration` matches that path and everything under it, but `test` does not match `tests/`. The prefix is normalized and rejected if it escapes the target. It never reaches SQLite as a pattern, so wildcards and globs have no effect. |
| `cataloged` | `false` lists the artifacts identified by name only. |
| `probe_status` | One of the probe states listed under Outputs. |
| `limit`, `cursor` | Signed pagination, the same as the other query tools. |

Results are ordered by path. The path is returned as the entity `name`, because payload `path`
keys are withheld by the core, and in the hash-verified location for cataloged files. Shard gaps
come back as `coverage_gaps`. A run without an accepted design shard returns an availability gap,
not an empty result claiming nothing exists. Generic `find` and `search` over the `analysis` index
still work.

## Planner consumption

`job_target_analysis_plan` reads the accepted discovery output in a dedicated
`catalog_summary.load_design_context` task and records it as the plan's `design_context` section
(`appsec-review/target-analysis-design-context/1`).

- **Binding.** The design handoff must be accepted, and must name the same target fingerprint and
  `job_target_catalog` handoff the planner loaded. Hash or schema mismatches fail the plan.
- **Missing or stale input.** If no accepted handoff exists, `status` is `UNAVAILABLE`. This
  happens, for example, in the Dagster `project_build_review` graph, which does not run discovery.
  If the handoff is bound to a different catalog, `status` is `STALE`. Either way the plan carries
  a named coverage gap and empty lists. It does not fail.
- **Contents.**
  - `declared_interfaces` (API specifications and IDL), `threat_models`, `design_documents`,
    `data_schemas`, and `api_tests`.
  - Each entry holds its path, SHA-256, cataloged flag, categories, numeric signals, and owning
    component.
  - `declared_interfaces` is ordered by declared surface: RPCs plus HTTP path entries plus GraphQL
    root types, largest first, then by path.
  - Each list is capped at `design_context_max_items` (default 256). If a list is cut, the plan
    records a gap.
  - Also: `test_counts_by_level`, `counts_by_category`, `absent_categories`, and the design
    handoff and summary identities.
- **Per component.** Each plan component gains `design_context` category counts for the artifacts
  it owns, using the same longest-root ownership rule as scanner scope.
- **Validation.** `validate_plan` requires every cataloged entry to be an exact catalog
  path/SHA-256 identity and every owner to be an accepted component.
- **Gaps.** The discovery job's own gaps, such as name-only binary documents and probe bounds, are
  added to the plan's `coverage_gaps` with the prefix `design context:`.
- **Index.** The plan shard adds a `CONTAINS` relation from each component to its declared
  interfaces, threat models, and design documents. Reviewers can follow these with `trace`.

Design context is never sent to the build-recipe model. That model's request is limited to build
descriptors, and target documents are data, not inputs to it. Discovery runs before the planner
in both graphs, so a change in discovery invalidates the plan and everything after it on resume.

## Bounds and gaps

| Setting | Default | Range | When exceeded |
| --- | --- | --- | --- |
| `max_artifacts` | 20000 | 1–200000 | Discovery stops; named gap |
| `max_probe_files` | 2000 | 0–50000 | The rest are classified by path only; named gap with count |
| `max_probe_bytes` | 16384 | 256–1 MiB | Only the prefix is probed (`probed_prefix`) |
| `max_file_bytes` | 1 MiB | 1 B–16 MiB | Probe skipped (`too_large`); named gap |

The settings are hashed into the shard fingerprint and the resolved configuration, so changing any
bound invalidates reuse for this job and every job after it.

## Resumability

The implementation identity hashes `job.py` and `discovery.py`. If the catalog, configuration,
ruleset, and implementation are unchanged, a resume reuses the accepted handoff. An existing shard
with the same fingerprint is reused instead of rebuilt, because shards are immutable.

## Non-goals and follow-ups

- The job does not parse or validate specifications, run tests, or contact any API.
- Scanner selection is unchanged. Choosing specification-aware producers, such as Checkov's
  OpenAPI framework, needs evidence-collection adapter support first. Today that adapter is
  bounded to typed IaC, Dockerfile, GitHub Actions, and CloudFormation inputs.
- Inference review workers do not yet receive `design_context` as bounded task context.
- Full-text content, declared interface operations, and binary-document conversion are built by
  `job_document_conversion` and `job_design_content_index`; see
  [`design-content-index.md`](design-content-index.md). Interface scanners and possible vector
  recall remain in `docs/TODO.md`.
- Linking test files to the source units they cover is not attempted.
