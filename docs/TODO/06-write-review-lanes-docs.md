# 06 -- Write the review-lanes docs (red team, blue team, verification, remediation, synthesis)

Goal: there is no doc for how the LLM review lanes work; the knowledge is spread over
`appsec-review-process/<lane>/config.md|prompt.md|subprompts.md` and `appsec-review-process/README.md`
§Prompt Architecture. Produce a succinct `docs/review-lanes/` bucket.

## Inputs
- `appsec-review-process/README.md` §Operating Model, §Prompt Architecture, §Evidence Discipline.
- Lane folders: `07-red-team-adversarial`, `08-blue-team-refutation`, `09-independent-verification`,
  `11-remediation-proposal`, `12-scoring-prioritization`, `10-synthesis-report`, and the
  characterization/threat-model lanes `01`, `03`, `04`, `05`, `06`, `13`, `15`.
- `appsec-review-process/process-manifest.json` (order), `docs/architecture/design-v3.md` §4.1
  (lane <-> L-number map), `docs/design-parity/full-review-workflow.mmd` (which lanes are real jobs).

## Steps
1. `docs/review-lanes/README.md`: the lane sequence, budgets (`probe`/`standard`/`full`), what a
   lane must state (read/covered/excluded/next), and the rule that nothing promotes a tool hit to a
   finding. One screen.
2. `docs/review-lanes/red-team.md`, `blue-team.md`, `verification.md`, `remediation.md`,
   `scoring-and-synthesis.md`: for each, purpose, required inputs, outputs, verdict taxonomy
   (`schemas/verdict-taxonomies.json`), and current build status from the parity views. Half a
   page each; link to the lane folder rather than duplicating prompt text.
3. Cross-link from `docs/README.md` and `docs/agent-reader.md` (chunk 10 owns the reader edit --
   leave a note there instead of editing it).

## Done when
A reader can answer "what does lane 08 consume and produce, and is it built?" from these docs
without opening a prompt file.

## Touches
New files under `docs/review-lanes/` only, plus `docs/README.md`.
