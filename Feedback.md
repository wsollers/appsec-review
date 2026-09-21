# Review Feedback for PR #32 (B14)

Reviewed at head `c8c3155`, diff vs `claude/b13-pinned-container-adapter` only. Every behavioural
finding was reproduced twice against unmodified code (review subagent, then coordinator) using the
PR's own `tests/persona_invocation_support.py` to run real invocations. Most of the adapter held —
see the end. **Note: the base of this stack, PR #29, has open round-2 feedback.**

## [P1] A JSON output whose KEYS are the prohibited claim-class ids gets an `OK` result

Same class as the two gaps fixed in `f4d51ee` (prohibited text reaching an `OK` result through a
surface the scan does not see). If the owner reads the doc's "backstop, not a classifier" limitation
as covering it, treat as P2 — but `docs/persona-invocation-adapter.md:244-246` says "Every published
file is a claim surface … JSON keys included".

Two causes in `appsec-review-process/persona_invocation.py`:

- Only output PATHS get `[-_./]+` read as spaces (~`:959`). In JSON keys, JSON values and `.md`/`.txt`
  bodies `_` stays a word character, so every `\b…\b` rule misses snake_case: `cvss_score`,
  `is_exploitable`, `critical_severity`.
- Each JSON key and each value is scanned as a SEPARATE string (`_strings`, ~`:893`), so
  `{"severity": "critical"}` never meets `severity\s*(?:is|=|:)`.

Reproduction: a real invocation whose invoker adds `notes/assessment.json`, listed honestly in its
manifest, with all nine baseline classes in the request's `prohibited_claim_classes`:

```json
{"final_severity":"critical","severity":"high","cvss_score":9.8,"is_exploitable":true,
 "exploitability_verdict":"yes","verified_finding":true,"remediation_status":"fixed",
 "compliance_verdict":"compliant"}
```

Observed: `result: OK None   verifier: []`. Also `OK`: a `.md` body containing `critical_severity`;
JSON `{"severity":"critical"}`. Controls that held: `critical severity`, `high-severity`,
`**critical** severity` → `PROHIBITED_CLAIM`.

Why missed: every hostile-text test uses space-separated prose inside one string value.

Fix direction: give every scanned text the normalisation paths already get (split on `_`, `-`,
camelCase); for JSON also scan each `key value` pair joined; reject any key or string EQUAL to a
prohibited class id. Regression: the payload above, the `critical_severity` body, the split pair.

## [P2] A claim surface and several byte forms escape the scan

- `claims[].claim_id` is never scanned (~`:1003` adds statement, limitations, locator only). Its
  pattern `[A-Za-z0-9_-]` permits words, and it is published in the listed `invoker-output.json`:
  `claim_id = "exploitable"` → `OK`; `"cvss-9-8-certified"` → `OK`.
- `.md` bodies that return `OK`: NUL bytes (`critical\x00severity`, `explo\x00itable`), zero-width
  space (`exploit​able`), soft hyphen, Cyrillic `е` in `exploitable`. The manifest's own
  strings ban `\x00-\x1f\x7f` by schema; output files are not held to it.

Homoglyph / zero-width arguably fall under the stated backstop limitation; `claim_id` and C0 control
bytes do not. Fix direction: scan `claim_id` with separators as spaces; reject C0 controls other than
`\n\r\t` and category-Cf characters in output text; consider NFKC before scanning.

## [P2] An unreadable directory hides an unlisted file; result is `OK` and the verifier agrees

`scan_output_tree` (`:862`) and `_snapshot` (`:840`) call `os.walk` without `onerror`; a directory
that cannot be listed is skipped silently, so the file inside never counts as unlisted.

Reproduction (as a non-root user — root masks it): invoker writes `hidden/verdict.md` with
verified/critical/exploitable text, then `chmod 000 hidden`.

```
status=OK cause=None verifier_errors=0
files really in output root: hidden/verdict.md, invoker-output.json, notes/fixture-note.json
result.outputs:              invoker-output.json, notes/fixture-note.json
after chmod 700 -> verifier: "the output root on disk is not the tree invocation.json recorded"
```

The verifier's answer depends on a mode bit, and the doc's `MALFORMED_RESULT` ("an unlisted file") /
`OUTPUT_ESCAPE` entries are contradicted. Fix: `onerror` that raises → `irregular`, or require every
directory to be listable (`u+rwx`). Regression: the case above, skipped only when running as root.

## [P2] Family independence is defeated by listing one model under two family names

`family` is a free declared string. `validate_runtime` (~`:795-801`) checks only the shape of each
`allowed_models` entry and accepts two entries with identical `provider`/`model_id`/`snapshot` and
different `family`. Observed: allow-list accepted; a `verify` invocation over a producer that ran
the identical model under the other family string → `OK None`, verifier `[]`.

The list is integrator-supplied, so this is hardening — but it is the "rule applied to declared
values" pattern (lesson 19) and the doc never says `family` has nothing behind it. Fix: require one
`(provider, model_id)` → exactly one family in `validate_runtime`, and refuse a producer with an
identical `(provider, model_id)` whatever its family says.

## [P2] "52 single-check removals, all killed" — five more removals survive the 84-test module

Each removed alone in a scratch copy; `test_persona_invocation` stayed `OK`:

1. the locator scan `+ [c["locator"] for c in citations]` (~`:1003`);
2. verifier: `finished_at < started_at`;
3. verifier: "this outcome cannot leave the invoker running";
4. output-tree case-collision check `len(lowered) != len(set(lowered))`;
5. `_read_pinned`'s "changed identity while it was opened" check.

Checks 1–4 work in the unmodified code (probed) — these are tests that cannot fail, not broken
checks. 4 is reachable on Linux with `A.md` + `a.md`; 2 and 3 need record and result edited together
and resealed. 5 needs a race and was not exercised.

## For an owner decision (not a defect)

Transitive review is accepted: P1 produces, P2 verifies it, P1 then judges P2's result — only direct
producers are checked. design-v3 §5.1 forbids one agent doing all three roles; this passes the letter.
The doc does not mention it.

## Probes that held

- Verifier tamper matrix: 636 cases over every file of a real attempt, every top-level and nested
  object key (marker, wrong type, delete, added key; with and without a consistent reseal). Nothing
  echoed; `to_worker_envelope` refused whenever the verifier refused. The only real acceptance is a
  resealed edit of the invoker's own free text — the stated unsigned-result limitation.
- Timeout: an invoker that ignores cancel and later writes a complete valid output → `FAILED TIMEOUT`,
  `invoker_stopped=False`, no outputs, verifier `[]`, envelope `NOT_ACCEPTED` listing only the logs.
- Package immutability (request, nested budget, inputs, composition, capabilities, tool actions,
  input data). Inputs: two roots / `/proc/self/root` spelling / hardlink / symlinked dir or root /
  FIFO / input inside the attempt / prompt as input / case-variant duplicate — all refused.
- Budget: negative, 1e30, float, bool, zero, over-limit refused. Claim ceiling: every widening,
  duplicate, empty, upper-case, baseline-moved variant refused. Repeated keys nested in arrays or
  via `\u` escapes → `MALFORMED_RESULT`; UTF-16 malformed; BOM text scanned.
- Model: `latest`, trailing whitespace, upper-case family refused; the allow-list lives only on
  `PersonaRuntime`. Tool ids derive from registry text. No defaulted safety input in the public API;
  `NOT_ACCEPTED` hard-coded.
- Merge `c8c3155`: both adapters intact; B13 + runtime suites 161 OK; B14 suites 84 OK; whole host
  suite 1019 run with the 8 known host errors; parity validator and `--check-contracts` pass.

## Not covered

Windows; code-server run; races (directory swapped between write and check, input changed during
open); outputs near the 16 MiB limit; device/socket files (FIFO only); a full 52-mutant rerun.
