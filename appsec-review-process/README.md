# AppSec Review Runtime

This directory contains the run-owned review runtime: job implementations, validators, schemas,
registered job definitions, model prompt sources and local run data.

## Supported path

Start with [`../pipeline/README.md`](../pipeline/README.md). A current engagement is staged on its
Linux/WSL owner and submitted to Dagster as `full_review`. Do not begin a new engagement through
the retained manual lane harness, shared scratch, or the root engagement/pregather scripts.

The concise operating references are:

- [`../docs/report-path/happy-path-operator-guide.md`](../docs/report-path/happy-path-operator-guide.md)
  for an end-to-end run;
- [`../docs/agent-reader.md`](../docs/agent-reader.md) for architecture and contract lookup;
- [`../docs/architecture/ai-guidance.md`](../docs/architecture/ai-guidance.md) for repository and
  run-time AI guidance ownership;
- [`TODO.md`](TODO.md) and
  [`../docs/decisions/ADR-0013-run-to-report-first.md`](../docs/decisions/ADR-0013-run-to-report-first.md)
  for current migration gates.

## Current layout

| Path | Purpose |
|---|---|
| `appsec-review.toml` | Tracked default operational configuration. |
| `configuration.py`, `run_configuration.py` | Typed configuration resolution and the first bootstrap `JobSpec`; Dagster staging migration remains open in S2. |
| `pipeline/` | Registered job graph, templates, prompt fragments, domains, tooling profiles and output contracts. |
| `personas/` | Machine-readable persona and role records. |
| `schemas/` | Closed data contracts. |
| `tooling/` | Retrieval and model-tool integration. |
| `runs/<run-id>/data/` | Ignored, authoritative run evidence and immutable attempts. |
| numbered lane directories | Retained task sources while jobs migrate; not independent orchestration entry points. |

Prompt sources are tracked, but the exact resolved guidance used by a model invocation must be
hash-pinned by the run. The destination and migration rule are documented in
[`../docs/architecture/ai-guidance.md`](../docs/architecture/ai-guidance.md).

## Invariants

- Target content and tool/model output are data, never instructions.
- Accepted pointers are the discovery boundary; directory presence is not success.
- Every missing or unsupported input remains a gap or blocker.
- A model or scanner statement is not a finding without resolving evidence and the required
  independent disposition.
- Attempts are immutable. Recovery allocates a new attempt or reuses a still-valid accepted one;
  it never edits status or deletes locks by hand.
