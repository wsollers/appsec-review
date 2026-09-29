# ADR-0028: Job definitions in one `appsec-review-process/pipeline/` folder

Status: **Proposed 2026-09-29** (brief K, branch `registry-move`). The move and `registry_paths.py`
come from brief K and decision D-16. Two choices need the controller to confirm: `job-graph.json`
moved too, and the fingerprint consequence described below.

## Context

A job was defined in two places: `appsec-review-process/job-graph.json` and the records under
`appsec-review-process/registry/`. Brief J already moved personas and roles to
`appsec-review-process/personas/`, and `persona_registry.py` became the only code that knows where
those records live. The other record paths were spelled out in about 120 modules and tests.

## Decision

1. **One folder.** `appsec-review-process/pipeline/` holds `job-graph.json`, `tunables.json`,
   `job-templates/`, `output-contracts/`, `domains/`, `tooling-profiles/`,
   `permission-capabilities/`, `container-images/`, `prompt-fragments/`, `AUTHORING-TEMPLATE.md`
   and the registry `README.md`. `appsec-review-process/registry/` no longer exists. Personas and
   roles stay in `personas/`.
2. **Name.** This folder is not the repository-root `pipeline/` (the Layer 1 evidence scripts).
   Docs always write it with its `appsec-review-process/` prefix, and its README says so. No
   rename is proposed.
3. **One path module.** `appsec-review-process/registry_paths.py` holds every path: `REGISTRY`
   (the directory passed around as `registry_dir`), `JOB_GRAPH`, `TUNABLES`, `<KIND>_DIR`,
   `template(id)` and `contract(id)` for absolute paths, `rel(...)` / `template_rel` /
   `contract_rel` / `GRAPH_REL` for the process-relative names lifecycles use as implementation-hash
   keys, and `repo_rel(...)` for repository-relative names. Every loader, lifecycle, test, the
   item definition, `images/registry_records.py`, the Dagster bootstrap and the docs generators
   (`job_catalog.py` and `pipeline_job_graph.py`, both loaded by file path so they stay standard
   library only) import it. `persona_registry.folder_root` still resolves `personas/` beside the
   registry directory, so it needed no code change. Like `persona_registry.py`, `registry_paths.py` is
   not listed in any job's implementation files.
4. **Commits.** 1 = pure `git mv` (271 renames, all R100). 2 = path fixes only. 3 = regenerated
   views and docs.

## Consequence: fingerprints change (paths leak into fingerprints)

Brief K asked for identical fingerprints before and after. That is not possible, and this change
does not hide it. Each job's prod fingerprint changes for two reasons:

- **Paths are hash keys.** Every lifecycle's implementation-hash map (`_code_hashes`, `code_hashes`,
  `_code`, `job_executor.own_hashes` from `items/*/item.json`) keys a record file by its path
  (`registry/output-contracts/x.json`). After the move the key is `pipeline/output-contracts/x.json`,
  and the file hash is unchanged. Other places that hash a path:
  - `job_graph.definition_hash` keys its `files` map by `appsec-review-process/job-graph.json`, which
    changes the fingerprint for 00-intake.
  - `create_job_handoff._source_record` records `appsec-review-process/registry/...`, which changes
    the handoff fingerprints for partition discovery and Scorecard.
  - The inline `code` maps in `ossf_scorecard.current_inputs` and
    `critical_findings_sarif.current_inputs` do the same.

  Keeping the old strings as labels would keep the hashes stable, but the labels would then name
  paths that do not exist. The brief rules that out.
- **The modules that spell the paths were edited.** Commit 2 changes the path constants inside the
  implementation files the fingerprints hash, so their content hashes change too.

What the comparison proves (`ADR-0028-fingerprint-comparison.md`, 255 components):

- All 105 persona composition pins (`composition_sha256`, content-only by design) are identical, and
  so is the one path-free item hash (`job_executor.related_hashes`).
- In every changed implementation-hash map, the moved JSON records keep byte-identical hashes under
  their renamed keys. The only value changes are the `.py` modules edited in commit 2 and
  `items/02-operations-doc-ingest/item.json`. No schema, contract, template or other record content
  changed.
- Every changed map has at least one renamed key. The few docstring-only edits therefore invalidate
  nothing that the path move did not already invalidate.

Effect: prod runs accepted before this change are not reused. Each job reruns once on its next
launch. Dev mode (ADR-0025) decides from data, so it is unaffected apart from the one item's own
implementation list.

**For the controller:** if fingerprints should survive future moves, a follow-up could key
implementation maps by a stable logical name (`kind/id`) rather than a path. That is a logic
change and outside brief K.

## Left as written

History (ADRs, decision logs, agent briefs, continuation prompts, proposals, dated reports) keeps
the old paths. Two tracked prompt texts also still say `registry/`:

- `phase-1-implementation-prompt.md` is attested by prompt hash (A01), so editing it would void the
  vetting.
- `pipeline/prompt-fragments/governing-rules.md` is prompt content, so editing it changes every job
  prompt that includes it.

Both are listed as open in `TODO.md` section K.
