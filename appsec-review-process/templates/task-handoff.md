# Task Handoff

## Run

- run_id: `{{RUN_ID}}`
- process: `{{PROCESS}}`
- budget: `{{BUDGET}}`
- target: `{{TARGET_PATH}}`
- engagement_output: `{{ENGAGEMENT_OUTPUT}}`

## Governing Files

Read these first:

- `appsec-review-process/environment.md`
- `appsec-review-process/artifacts.md`
- `appsec-review-process/budget-policy.md`
- `appsec-review-process/tooling/llm-retrieval-addendum.md`
- `appsec-review-process/agent-skills/codex/evidence-retrieval/SKILL.md` (Claude mirror available)
- `appsec-review-process/{{PROCESS}}/config.md`
- `appsec-review-process/{{PROCESS}}/prompt.md`
- any additional `.md` support files in `appsec-review-process/{{PROCESS}}/`, such as taxonomy or
  subprompt files

## Inputs

Prefer the run's accepted full-text index and cited reads for evidence discovery. Use ssdeep for
similarity candidates and qualified LSP services for symbols/references. Check capability receipts
and MCP tools/list before assuming a tool is connected. Use bounded grep for exact syntax or gaps;
never treat a missing search hit as proof of absence.

- artifact manifest: `appsec-review-process/runs/{{RUN_ID}}/inputs/artifact-manifest.json`
- evidence package: `{{ENGAGEMENT_OUTPUT}}/llm/ENGAGEMENT_LLM_INPUT.md`

{{UPSTREAM_OUTPUTS}}

## Required Output

Write lane output to:

```text
appsec-review-process/runs/{{RUN_ID}}/outputs/{{PROCESS}}/
```

At minimum:

- `result.md`
- `status.json`

## Budget Contract

Use the selected budget. Do not expand scope without returning a status that requests the next batch.
At the top of `result.md`, state:

- budget used
- scope included
- scope excluded
- artifacts read
- deferred work

## Failure Rule

If blocked or failed, write the reason and the exact missing evidence or command needed to resume.
Do not continue with assumed evidence.
