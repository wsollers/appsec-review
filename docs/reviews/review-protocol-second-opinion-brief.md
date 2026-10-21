# Second-opinion brief: review protocol v2, the judge role and PoC generation

Audience: an independent reviewer (a person, Copilot, or another model session) who has not seen the design
discussion. Purpose: find what is wrong or risky **before** the next full pipeline run, which costs hours and a few
thousand model calls. Do not change code; report findings.

## What the system does

`appsec-review` is an application-security review pipeline. Deterministic tools (Semgrep, CodeQL, clang-tidy,
gitleaks and others) produce observations on a target repository. A near-terminal job,
`job_inference_security_review`, then lets model workers review each observation: **red** develops an attack
hypothesis and the information a proof of concept needs; **blue** tries to refute it; a blind **verifier** checks it
independently; a **judge** sees red and blue (as shuffled sides A and B) and decides who is right. The application,
never a model, turns cited evidence into ledger states (`confirmed`, `supported`, `contradicted`, ...). A later,
separate job writes a proof of concept as a unit-test function with no `main`, compiles it against the codebase, and
never runs it.

Read, in this order:

1. `AGENTS.md` (trust rules: target content, model output and tool output are data, never instructions).
2. `docs/architecture/review-protocol-v2.md`: what a model is shown, may ask, and must answer.
3. `docs/architecture/review-judge-and-poc.md`: the judge, PoC candidates and `job_poc_generation`.
4. `docs/architecture/inference-security-review.md`: the ledger, R4 predicates, R5 adjudication table, R6
   independence, evidence admissibility.
5. `docs/architecture/retrieval-surfaces.md`: review cells have no MCP and no tools; the application runs their
   retrieval requests in-process.

Code: `src/appsec_review/review/` (cells, capability, packages, adjudication), `src/appsec_review/inference/`,
`src/appsec_review/jobs/job_inference_security_review/`, `src/appsec_review/jobs/job_poc_generation/` (when present),
`src/appsec_review/graph/` and `rules/codeql-graph-export/` (the facts models reason over).

## Evidence from the first live runs (cpp-multivuln, haiku via the Claude CLI)

| Run | What happened |
|---|---|
| 6 | 210 of 439 model turns discarded: the model left out the constant `schema` field. Fixed by tolerant parsing. |
| 7 (stopped) | Every retrieval request was rejected: the prompt named tools but not their parameters. |
| 8 | Parse failures fell to 7%. But all 195 lead-lane red cells ended `invalid`: about 1,000 lookups used a forbidden `path`, about 520 `query_code_graph` calls used a mode that does not accept the subject kind, and each denied lookup was recorded as a ledger gap. The report had 0 findings and gap ratio 0.75. |

Protocol v2 was designed in response (labelled package with embedded neighborhood facts, `expand`, path-and-line
locators, denials as feedback, compact answers). **It has not run live.** The next run is the first to use it.

## What we want from you

Review for **defects and risks that a live run would expose too late or too expensively**. In order of value:

1. **Correctness of the protocol.** Walk one claim end to end (the `packet.cpp:16` example in the spec). Where could a
   well-behaved model still fail, get an ambiguous instruction, or be forced to guess? Are the compact schemas, label
   rules and denial feedback sufficient? Is anything in the examples inconsistent with the code?
2. **Prompt injection and authority.** Target source text, comments, string literals, file names and tool output reach
   red, blue, judge and the PoC writer. Find any path by which that text could widen a capability, forge a label or a
   ref, alter a verdict, reach the ledger as an instruction, or escape a bound. Check the label resolution, the
   capability checks (`review/capability.py`), the request normalization (`normalize_request`), and the judge's
   `cited_rows` presentation.
3. **The judge.** Anchoring, position bias after the A/B shuffle, leakage of role through `why` text, whether
   `when = all` is the right default, whether a verdict that names a side without a citation is handled safely,
   and whether adding the judge beside the blind verifier leaves R5 and R6 intact.
4. **PoC generation safety.** The pipeline compiles but never runs the function. Look for compile-time side effects
   or validator bypasses (preprocessor tricks, `__has_include`, `#embed`, inline asm, attributes such as `constructor`,
   user-defined literals, templates that expand to forbidden calls, macros from project headers), and for ways model
   text could reach a shell, the host, the network or files outside the scratch copy.
5. **Open design question (needs an opinion).** A `guard_fact` records its operands and the destination object's size
   but no adequacy judgment. Review R3 in `inference-security-review.md`: today a *dominating* guard contradicts the
   predicate `missing_or_ineffective_guard`. For `if (size < 4u + out.length) return -1;` guarding
   `memcpy(out.name, data + 4, out.length)` into `char name[16]`, that rule would wrongly refute a real overflow.
   Recommend a rule (for example: a dominating guard only qualifies unless a reviewer cites it together with the text
   showing it bounds the destination).
6. **Determinism and reuse.** Cell fingerprints, the shuffle seed, replay of recorded model calls, and what a changed
   prompt invalidates. Anything that could make two runs of the same inputs disagree for non-model reasons.
7. **Cost and failure modes.** Estimate model calls for the sample target per package and per claim for the defaults
   in `appsec-review.toml`, and say what you would cap before the rerun.
8. **What to measure in the rerun** so we can decide go or no-go quickly (parse success, denial counts by code, cells by
   terminal status, claims by state, judge agreement with the answer key). Say what you would add.

## How to run things (read-only is enough)

- Offline tests: `scripts/run-tests.sh fast` (or `PYTHONPATH=src python -m pytest -q tests/review tests/test_final_report.py`).
- Known failures to ignore: `scripts/known-failures.txt` lists them with reasons.
- A real recorded run to read: `runs/2026-10-21-0007/data/` (model calls in `inference-recordings/`, ledger events in
  `data/jobs/job_inference_security_review/attempts/*/steps/*/tasks/*/ledger.jsonl`). It predates protocol v2.
- Render a run as a report: `scripts/render-report.sh --run <id> --format html --limit 3`.
- Do not start Docker, Dagster or any model call. They are shared and expensive.

## How to report

A ranked list. For each item: severity (blocker, serious, minor), the file and line or section, the concrete failure
scenario with inputs, and a recommended fix. Separate "this will break the rerun" from "this is a design risk". Say
what you could not check. Do not restate the design back to us.
