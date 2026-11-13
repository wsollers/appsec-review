# Documentation program: generated inventory, authored job pages, subsystem dives

Session prompt. Start a fresh session on `wsollers/appsec-review` with this file, `AGENTS.md`,
`.claude/skills/multi-session-coordination/SKILL.md` and `.claude/skills/docs-sync/SKILL.md` read
in that order. This document is the brief; it decides nothing that `AGENTS.md` decides.

## Goal

Turn `docs/` from an accumulation of plans, implementation records and operations notes into a
maintained set with two halves:

- a **generated half**, regenerated from code and configuration and checked by unit tests: the
  job, step and task inventory; the tool each task launches; the datasets each job publishes and
  the retrieval route each dataset has; the model, role, persona and runtime skills each
  model-backed task uses; the tool-to-intelligence-bucket and bucket-to-availability matrices;
  the docs index;
- an **authored half**, written once and reconciled by the docs-sync procedure: a purpose
  paragraph and pseudocode per job that has real internal logic, a Mermaid dataflow diagram per
  such job, the gaps a job can publish and its acceptance checks, one architecture dive per
  subsystem, and a testing document that states the tier contract going forward.

Every fact has one home. Generated content is never hand-edited (`AGENTS.md`, "Generated and
run-owned material"). Authored pages link to the home of a fact; they do not restate it.

## Authority and constraints

1. `AGENTS.md` rules apply unchanged. `docs/agent-reader.md` stays navigation only.
2. Follow the multi-session skill before every change. Another session is walking jobs into
   `tests/unit` under T-113; do not edit the operations page of the job that walk is on (its
   state is under `docs/walks/`, host-local). Code-graph gap work is registered as T-115 to
   T-126; link to those ids, do not restate their scope.
3. No change to `appsec-review.toml`, `containers/catalog.toml`, `pipeline/guidance/registry.json`
   or any `DATASETS` table. The generator reads them; if one is wrong, add a `docs/TODO.md` entry
   and keep going. (`appsec-review.toml` bytes are hashed into every run's frozen configuration;
   see T-117.)
4. Documentation-only commits need documentation checks and the focused unit tests this program
   adds, not the full suite. No integration, acceptance or live tests.
5. Commit coherent stages on the assigned branch; do not push unless the user asks. Record each
   stage's reconciled commit in `docs/docs-sync.json`.
6. Dated decision records are never rewritten. A superseded plan or implementation record gets a
   status line (`status: historical`, pointer to the current page) and stays.

## Stage 0: register the work

Fetch `origin/main`, read `docs/TODO.md` for the next free id (other sessions add entries daily),
and add one entry per stage below in the registry's entry format, with index rows, `Blocked by`
in stage order, files, acceptance checks and `Refs`. Run `tests/test_todo_registry.py`. Commit
`docs/TODO.md` alone before any other change.

## Stage 1: the ledger

Produce `docs/docs-ledger.json` (`schema: appsec-review/docs-ledger/1`): one row per file under
`docs/`, `containers/**/README.md`, `scripts/README.md` and `AGENTS.md`, with `path`, `kind`
(`architecture | operations | process | task | walk | review | schema | history | generated`),
`subsystem` (from the list in Stage 6), `disposition` (`keep | revise | merge-into | retire |
generated`), `merge_target` when `merge-into`, `reason` (one sentence), and `decision_record:
true` for any document that records a dated decision. Start from the delta since
`docs/docs-sync.json` `synced_commit` (`aba6bbb6`, 2026-10-28) per the docs-sync skill, then cover
the rest. `docs/walks/` rows are `keep` and host-local; do not read their content for rules.

Acceptance: `tests/docs/test_docs_ledger.py` fails on a tracked doc with no row, a row whose
file does not exist, a `merge-into` without a target, or a `retire` of a `decision_record`.

## Stage 2: generator, frontmatter, index and link tests

Write `scripts/generate-docs.py` (Python, standard library plus the repository's own loaders) and
`scripts/generate-docs.sh`. It reads:

- `appsec-review.toml` through `appsec_review.config.load_config` (jobs, steps, tasks, the
  `model`/`reasoning`/budget keys, enabled flags, pools);
- `containers/catalog.toml` (images, tool ids, state, purpose);
- every job's `DATASETS` table and typed `Job.contract` (what it consumes and publishes, the
  stage of each dataset: indexed, artifact-only, protected);
- `src/appsec_review/mcp/schema.py` `TOOLS` and the retrieval index each tool serves;
- `pipeline/guidance/registry.json` (roles, personas, stacks, runtime skills with their allowed
  jobs, the assignment table);
- `tests/job-test-map.json`;
- `docs/intelligence-buckets.json` (Stage 3) when present.

It writes, deterministically (sorted keys, LF, no timestamps):

- `docs/generated/inventory.json`: the full job → step → task tree with tool, datasets, routes,
  model usage and test files per job;
- `docs/generated/guidance.md`: one heading per role, persona, stack and runtime skill, with
  the registry text and the jobs it is assigned to, so authored pages can link by anchor;
- a fenced block per job page between `<!-- generated:begin job=<id> -->` and
  `<!-- generated:end -->` markers, containing: purpose line from the TOML description if any,
  steps and tasks with the launched tool, consumed upstream datasets with their schema ids,
  published datasets with stage and MCP route, model usage (model, reasoning, budgets, role,
  persona, task prompt, runtime skills) with links into `guidance.md`, unit test files, Dagster
  placement and pool, and a Mermaid `flowchart LR` skeleton whose node labels are the job,
  dataset and schema ids verbatim;
- `docs/README.md` and one index per `kind` from each document's YAML frontmatter.

Frontmatter on every authored document (`title`, `kind`, `subsystem`, `status: current |
historical`, `jobs: [...]` where relevant). Each generated file and block carries a first line
`generated from: <sources> by scripts/generate-docs.py; do not edit`. Each authored page carries
`last reconciled: <commit>` taken from `docs/docs-sync.json`.

Acceptance: `tests/docs/test_generated_docs.py` regenerates into a temp dir and fails on any
difference from the committed output; `tests/docs/test_docs_frontmatter.py` fails on a document
without frontmatter or with an unknown `kind`, `subsystem` or `status`; `tests/docs/test_docs_links.py`
fails on a relative link or anchor that does not resolve; `tests/docs/test_docs_identifiers.py`
fails on a backticked `job_*`, task, dataset, schema or gap identifier in authored prose that does
not exist in the inventory. Every test is under ten seconds and independent.

## Stage 3: intelligence buckets and the two matrices

Author `docs/intelligence-buckets.json` (`schema: appsec-review/intelligence-buckets/1`): at most
twelve buckets (for example `source_snapshot`, `syntax`, `symbols_and_calls`, `dataflow`,
`observations_sast`, `dependencies_and_advisories`, `build_and_deployment`, `binary`, `history`,
`documents`, `review_claims`, `metrics`), each with a one-sentence definition, and a mapping from
every catalog tool id and every dataset id to exactly one bucket. The generator joins it and
writes:

- `docs/generated/matrix-tool-bucket.md`: tool, bucket, the jobs and tasks that launch it,
  languages it covers, image state;
- `docs/generated/matrix-bucket-availability.md`: bucket, producers per language, datasets,
  stage, retrieval index, MCP tool, the review roles with the capability, and a last column
  `gap` that names the `docs/TODO.md` id for every empty cell.

Wide matrices are also written as `docs/generated/matrix-*.json`; the Markdown is a summary of at
most seven columns.

Acceptance: `tests/docs/test_intelligence_buckets.py` fails on a tool or dataset with no bucket,
a bucket with no definition, or an empty matrix cell with no `gap` id. New gaps found here get
`docs/TODO.md` entries in the same commit.

## Stage 4: authored job pages

For each job, in `tests/job-test-map.json` order, `docs/operations/<job>.md` (create or revise
per the ledger) with this shape:

1. frontmatter;
2. **Purpose**: one paragraph saying what the job is for, what question it answers for the
   review, and what it refuses to claim;
3. the generated block;
4. **Process**: numbered, language-neutral pseudocode, one block per step headed by the step
   name, every identifier in backticks spelled as the code spells it, each point at which the job
   can give up naming the `producer-gap/1` cause it publishes;
5. **Dataflow**: the Mermaid skeleton completed with the internal units and gap edges, same node
   labels;
6. **Gaps**: every gap cause with its retryable or advisory classification and what a walk should
   expect;
7. **Acceptance**: the walk charter's four checks as they apply to this job;
8. **Resume and invalidation**: what the checkpoint binds and what change forces a rebuild;
9. **Model usage** (model-backed jobs only): why that role and persona, linking into
   `docs/generated/guidance.md`; nothing copied from the registry.

Authored sections 4, 5 and 8 are required only for jobs with real internal logic (roughly the
twenty that have an operations page today). For the others, sections 2, 3, 6 and 7 suffice and the
generated tree stands for the process. Shared mechanisms (image lookup and host pins, signing,
`accepted_upstream`, gap records, the guidance bundle, the retrieval manifest) are linked to their
single page under `docs/architecture/` or `docs/operations/`, never restated; create the two or
three that are missing.

Acceptance: the Stage 2 tests pass; `docs/docs-sync.json` moves to the reconciled commit; the
T-113 walk's current job page is untouched.

## Stage 5: testing as a forward contract

Revise `docs/architecture/testing.md` to state the tier contract decided on 2026-11-12 under
T-113 as the rule going forward: unit tests are code-level with canned fixtures, under ten
seconds each and ten minutes for the suite, with no Docker, tools or models; integration may run
Docker, tools and models under the 300 s default; live under 1800 s; selection per tier comes from
`tests/job-test-map.json`; acceptance is per job with the charter's four checks; long runs go
through `scripts/run-tests.sh`. Beside every rule, name the test, guard or script that enforces it.
A rule nothing enforces gets a `docs/TODO.md` entry and is marked "stated, not enforced".
`AGENTS.md` keeps its short form and links here; do not add rules to `AGENTS.md`.

Acceptance: the links test passes; every "enforced by" names an existing file.

## Stage 6: subsystem architecture dives

One current-state document per subsystem under `docs/architecture/`, each with the same sections:
**As built today**, **Decisions** (dated, linking to the historical record, never rewriting it),
**Named gaps** (T ids), **Jobs and pages** (links), **Dataflow** (Mermaid). Subsystems:

1. images and deployment (containers, signing, host pins, the source mount);
2. target acquisition and build (topology, project build, capture, build environments);
3. code intelligence (CodeQL, graph, clangd, Tree-sitter, SVF, retrieval and MCP);
4. scanners and evidence collection;
5. review inference and guidance;
6. runtime interchange (handoffs, gaps, indexing, manifests);
7. reporting and metrics;
8. testing and operations.

Existing plan documents that became implementation records (for example
`code-graph-precomputation.md`) are marked `status: historical` and linked from the dive; the
dive is the current view.

Acceptance: frontmatter, links and identifier tests pass; `docs/architecture/README.md` is
regenerated from frontmatter.

## Stage 7: merges, retirements and the optional rendered site

Apply the ledger's `merge-into` and `retire` dispositions. A retired file is deleted only when it
is not a decision record and the ledger row says why; a merged file leaves a one-line pointer for
one release, then is removed. Optionally add an ignored static-site build (MkDocs or similar) over
the Markdown as a derived view; it is never the source and never committed.

Acceptance: the ledger has no `retire` or `merge-into` rows left; all docs tests pass;
`docs/docs-sync.json` is at the final commit.

## Conventions

- Markdown (GFM) with YAML frontmatter is the source format. Tables have at most seven columns.
  Mermaid is the diagram format for job and subsystem pages; no raster images. The one
  exception is the executive front page `docs/overview.md`, whose diagram is the hand-authored
  `docs/assets/review-pipeline.svg` (text, diffable, no external fonts or images). The index
  generator keeps `docs/overview.md` as the first link of `docs/README.md` and never
  regenerates it.
- Labeled links: `[label](relative/path.md#anchor)`; reference-style definitions are allowed
  at the foot of a page when a generator emits them.
- Prose follows the repository's style: short sentences, one fact per sentence, identifiers in
  backticks, no claims about behaviour that a file does not show.
- One commit per stage, or per job page batch within Stage 4. Each commit message names the
  stage and the T id. Run only the docs tests added here plus `tests/test_todo_registry.py`.

## Reporting

At the end of each stage report: the commit, the files changed, the focused test commands with
elapsed time and result, the `docs/TODO.md` ids added, and anything the ledger or matrices
exposed that needs the user's decision. Stop for the user before Stage 7 deletions.
