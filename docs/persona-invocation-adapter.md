# Persona invocation adapter

## Status

Backlog batch B14. `appsec-review-process/persona_invocation.py` implements
`appsec-review/persona-invocation-adapter/1.0`, and `worker_adapters.PersonaInvocationAdapter`
exposes it through the narrow adapter protocol (`kind = "persona"`). This is the **dispatch protocol
only**. There is no model client and no network call in this batch, and **no lifecycle persona job
uses it**: nothing in the graph, the manifest, the launcher, Dagster, the registry records or any
`owasp_*.py` module was changed. The order decided on 2026-09-20 is B13, B14, B15, C01, C02, T10.

The adapter takes one request, re-derives every pin in it, asks the B11 permission gate, hands a
frozen package of verified bytes to an integrator-supplied invoker, re-derives what the invoker
wrote, and records one terminal result that a read-only verifier re-derives again from disk.

## Protocol

```text
request --> resolve_request --> permission gate --> PersonaInvoker.invoke --> scan + derive --> result
             (creates nothing)   (B11, at the        (opaque; bytes in,       (invoker output    (frozen;
                                  runtime clock)      files out)               is untrusted)      on disk)
```

`run_invocation(runtime, *, run_id, job_id, attempt_id, attempt_root, request)` is the only entry
point that executes. Every hostile request is refused with `PersonaRequestError` before a directory
is created or the invoker is called. After that point the attempt owns three adapter files in
`log_path` and the invoker's files in `output_root`:

| File | Writer | Content |
|---|---|---|
| `request.json` | adapter | the canonical request |
| `invocation.json` | adapter | `appsec-review/persona-invocation-record/1.0`: what was handed over, how the call ended, timestamps and the adapter's own scan of the output root |
| `invocation-result.json` | adapter, last | `appsec-review/persona-invocation-result/1.0` |
| `invoker-output.json` | invoker, last | `appsec-review/persona-invoker-output/1.0`, the invoker manifest |

The trusted side is `PersonaRuntime`, a frozen dataclass with no defaulted field: `invoker`,
`registry_dir`, `prompt_root`, `readable_roots`, `allowed_models`, `source_snapshot_sha256`,
`registry_ceiling`, `clock`, `cancel`, `stop_grace_seconds`.

## Request pins

Schema: `schemas/persona-invocation-request.schema.json`, id
`appsec-review/persona-invocation-request/1.0`. Closed, every property required. Each pin below is
bound to what it is derived from, and a test edits that pin alone.

| Pin | Bound to |
|---|---|
| `run_id`, `job_id`, `attempt_id` | the worker request it arrived in |
| `outer_prompt` `{path, sha256, bytes}` | exact UTF-8 bytes beneath `runtime.prompt_root`; see the note under this table |
| `persona` (six ids, six hashes) | the named job template and the five records **that template composes**; see the note under this table |
| `model` `{provider, family, model_id, snapshot}` | `runtime.allowed_models`; all four parts required, no default, no alias (note below) |
| `invoker_id` | `runtime.invoker.invoker_id` |
| `tools` | tool ids derived from the tooling profile (next section); never text |
| `budget` | seven required integers with bounds (below) |
| `readable_inputs` `[{root, path, sha256, bytes, role, producer_request_sha256}]` | exact bytes beneath a named `runtime.readable_roots` entry |
| `output_root`, `log_path` | new, disjoint, single-spelling directories beneath the attempt, created by the adapter |
| `allowed_claim_classes`, `prohibited_claim_classes` | the registry ceiling (next section) |
| `producers` | the independence rule |
| `permission`, `permission_fingerprint_sha256` | B11: the pin must equal `decision.fingerprint_material.sha256` and the fingerprint re-computed from the decision's capability set |

`persona_invocation.PROMPT_ROOT` is the module's own directory, so a prompt path is process-relative
(`02-evidence-pregather/...`, never `appsec-review-process/...`) and resolves in the code-server
layout. The six composition records are the job template, persona, role, domain, tooling profile
and output contract; each hash is the sha256 of the record's canonical JSON, so it does not depend
on newline conversion in a checkout.

A model identity is one immutable version. An alias word in `model_id` or `snapshot` (`latest`,
`default`, `current`, `stable`, `auto`, `preview`, `newest`, `any`) and a snapshot without digits
are refused, and a missing part is reported as a missing model identity before the schema runs.

Budget bounds. "Unbounded context" is any missing, non-integer, zero or over-ceiling limit, or a
prompt plus input set larger than `input_byte_limit`; all are refused before invocation.

| Limit | Bounds |
|---|---|
| `input_byte_limit` | 1 .. 64 MiB |
| `input_unit_limit` | 1 .. 2,000,000 model units |
| `output_byte_limit` | 1 .. 16 MiB |
| `output_unit_limit` | 1 .. 1,000,000 model units |
| `output_file_limit` | 1 .. 256 |
| `tool_call_limit` | 0 .. 10,000, and zero exactly when `tools` is empty |
| `timeout_seconds` | 1 .. 86,400 wall-clock seconds |

Units are what a provider calls tokens. The word is avoided in property names because the evidence
redactor replaces the value under any secret-looking key name.

Paths have one spelling: relative, `/`-separated, the alphabet `A-Z a-z 0-9 . _ - space`, no `.`,
`..`, empty or leading-slash segment (`tool_instance_shapes.output_path_errors`), no segment with
outer space or a trailing dot. A readable input must be a regular file with link count one, reached
without crossing a link, whose real path is exactly `root/path`. Identity is device and inode: the
prompt and the inputs must be pairwise different files even when two root names reach one
directory. Nothing inside the attempt root is ever readable, so an attempt cannot read its own
status, manifest or log directory. Inputs are read once, and the bytes that were hashed are the
bytes handed to the invoker.

## Registry composition, tool ids and claim ceiling

Persona records (`appsec-review/persona/0.1`) have **no claim-class field and no tool ids**, and
this batch does not edit registry records. The adapter therefore derives a conservative
default-deny from the composition a job template names:

- **Tool ids.** A tooling profile lists `allowed_actions` as sentences. Each action is addressed as
  `act-` plus the first 24 hex digits of the sha256 of its exact text. A request may select only
  ids the profile derives; editing the sentence changes the id and the profile hash.
- **Allowed claim classes** = `role.allowed_outputs`, intersected with the profile's
  `claim_limits.allowed` list when it has one, minus every prohibited class.
- **Prohibited claim classes** = the baseline below, plus `role.forbidden_outputs`, plus the
  profile's `claim_limits.forbidden` list, plus every `claim_limits` key whose value is anything
  other than `allowed` or `allowed_<qualifier>` (so `forbidden`, `follow_up_only` and
  `forbidden_without_execution` all prohibit).
- A request may **narrow**: `allowed_claim_classes` is a non-empty subset of the ceiling, and
  `prohibited_claim_classes` must contain the whole derived prohibited set and may add classes the
  ceiling would have allowed. It may never name a class outside that closed set.

Baseline, prohibited for every invocation whatever a record says: `compliance_score`,
`compliance_verdict`, `exploitability_verdict`, `final_severity`, `malicious_intent`,
`observed_runtime_state`, `remediation_status`, `verified_finding`, `verified_security_finding`.
These follow ADR-0008 claim limits and the ADR-0009 validator boundary: promotions belong to the
refutation, verification, scoring and synthesis lanes.

`validate_persona_registry(registry_dir)` checks every tracked persona record and every job-template
composition for what the adapter relies on: ids and file names agree, role outputs are unique
claim-class ids, a role does not allow and forbid one class or allow a baseline class,
`claim_limits` values are closed words or id lists rather than free text, and actions are unique
bounded single lines. It passes on the tracked registry as-is. `not_invocable_templates` lists
compositions whose ceiling is empty. Today that is exactly `02-evidence-index`: the role allows only
`evidence_index`, and the `local-evidence-retrieval` profile's `claim_limits.allowed` list does not
carry it. That job is deterministic, so the default-deny is reported rather than repaired.

## Untrusted text

Prompt text, evidence bytes and invoker output are data (`design-v3.md` section 6.1). They cannot
change scope, permissions, claim class, output path, persona, model or budget, because none of
those is ever read from them: each comes from the request and is re-derived from the registry, the
B11 gate or bytes on disk. Capability-looking text in a prompt or in evidence has no trusted
`origin`; the only capabilities an invoker receives are the ones `require_granted` returned.

Nothing read from a request value, a prompt, evidence, an attempt or invoker output is interpolated
into a path, an argument list or a message. Schema failures are reported as a count plus the
`$.a.b[0]` locations, which are built from declared property names and indices only. The invoker's
exception text and return value are discarded. Tests carry a marker string through a hostile
prompt, hostile evidence, hostile request values and a hostile invoker and search every error,
result and envelope for it.

An invoker may report content that reads as an instruction in `injection_suspected`, by location
only (`root`, `path`, `sha256`, `locator`); the suspected text itself has no field.

## Independence and self-verification

Rule id `appsec-review/persona-independence/1.0`, written into every result.

- `invocation_role` is `produce`, `verify`, `refute` or `judge`.
- A **producing** invocation names no producer and reads no input with role `producer_output` or
  `producer_result`.
- A **reviewing** invocation (`verify`, `refute`, `judge`) names 1 to 64 producers, each
  `{run_id, job_id, attempt_id, request_sha256, persona_id, model}`. Every producer must be read
  through at least one `producer_output` input, and every such input must name a declared producer.
- A reviewing invocation carries **exactly one `producer_result` input for each declared producer**
  (its `producer_request_sha256` names that producer) and none for anything else. Its bytes are that
  producer's own `invocation-result.json`. There is no optional path: a reviewing request without
  it is rejected before anything is created.
- `resolve_request` (shared by the adapter and the verifier) reads those pinned bytes as data: at
  most 4 MiB, UTF-8 JSON in which no object repeats a key, inside the result schema, in the
  canonical byte form, `result_sha256` matching, `execution_status` `OK` and no cause.
- For each producer, the reviewer is refused when it is **the same attempt**, **the same persona**,
  or **the same model family**, judged on the values **read from the producer result bytes**
  (`self-verification: the result of producers[i] ...`). The pure request check applies the same
  rule to the declared values first, so an honest declaration of a dependent producer never reaches
  the disk.
- The declared `run_id`, `job_id`, `attempt_id`, `request_sha256`, `persona_id` and `model` must then
  each **equal** the producer result, and every `producer_output` input naming that producer must
  match, by sha256 and size, an entry of that result's `outputs`.
- A producer may be of any role. A `judge` may review a `verify` result; what matters is that the
  producer ended `OK`, because only an `OK` result lists output.
- Every failure is a `PersonaRequestError` with fixed text; nothing read from a producer result is
  echoed.
- A result whose `verified_invocations` contains its own request hash, or any entry at all from a
  producing invocation, is `SELF_VERIFICATION`. An entry that is not a declared producer is
  `UNDECLARED_CITATION`.

Sources: `design-v3.md` section 5.1 (an observation may not be discovered, verified and adjudicated
by the same agent); ADR-0008 claim limits ("a different persona and, where B14 records it, a
different model family from the cell it challenges; no cell verifies its own claim"); the
design-parity plan ("prevent one worker result from self-verifying"). Panel-level diversity
(section 5.1 minimum distinct families per vote tier, section 5.2 quorum) is C04, not this adapter.

## Invoker contract

```python
class PersonaInvoker(Protocol):
    invoker_id: str
    def invoke(self, package: InvocationPackage, *, output_root: Path,
               cancel: threading.Event) -> None: ...
```

`InvocationPackage` is frozen and carries bytes, not paths: the frozen request and its hash,
`package_sha256`, the prompt bytes, the six frozen composition records, `tool_actions` (selected id
to action text), the allowed and prohibited claim classes, `inputs` (root, path, role, hash,
producer hash, bytes) and `granted_capabilities` from the gate.

An invoker writes its files beneath `output_root`, then writes `invoker-output.json` last in the
canonical byte form (`write_invoker_output` does both the listing and the form), polls `cancel`,
raises `InvokerUnavailable` when it cannot run at all, and returns nothing. Output files are UTF-8
`.json`, `.md` or `.txt`. `FixtureInvoker` is the deterministic model-free implementation used by
the tests and available to C01/C02; the hostile test invokers run it and then depart from it in
exactly one way, so every tested state is one a real invoker could produce.

## Outcomes

The wall-clock timeout and cancellation are enforced by the adapter: the invoker runs on a worker
thread, and on timeout, cancellation or an interrupt the adapter sets the invoker's `cancel` event,
waits `stop_grace_seconds`, records whether the invoker stopped, and accepts nothing from the
output root. `KeyboardInterrupt` and `SystemExit` are recorded as `CANCELED` and re-raised.

| Cause | Status | Meaning |
|---|---|---|
| (none) | `OK` | every identity, file, budget, tool, claim and citation re-derived |
| `PERMISSION_DENIED` | `BLOCKED` | the gate did not re-derive `GRANTED` at the runtime clock; the invoker was not called |
| `INVOKER_UNAVAILABLE` | `BLOCKED` | the invoker raised `InvokerUnavailable` |
| `TIMEOUT` | `FAILED` | `timeout_seconds` elapsed |
| `CANCELED` | `CANCELED` | `runtime.cancel` was set, or an interrupt arrived |
| `INVOKER_EXCEPTION` | `FAILED` | the invoker raised anything else |
| `OUTPUT_ESCAPE` | `FAILED` | something outside the output root changed, or the output root is irregular (detail below) |
| `MALFORMED_RESULT` | `FAILED` | the manifest or an output file is not what the contract requires (detail below) |
| `IDENTITY_MISMATCH` | `FAILED` | the manifest names another request, invoker, persona, persona hash or model |
| `BUDGET_EXCEEDED` | `FAILED` | more files or bytes than the budget, or reported units or tool calls over their limits |
| `UNDECLARED_TOOL` | `FAILED` | a reported tool id the request did not allow |
| `PROHIBITED_CLAIM` | `FAILED` | a claim class outside `allowed_claim_classes`, or text matching a lexical rule of a prohibited class or naming its id |
| `UNDECLARED_CITATION` | `FAILED` | a citation that is not a declared readable input at its pinned hash, or a verified invocation that is not a declared producer |
| `SELF_VERIFICATION` | `FAILED` | see the independence section |

`OUTPUT_ESCAPE` covers: the attempt changed outside the output root; the prompt or a readable
input changed during the call; the output root holds a link, a hard-linked or special file, an
empty directory or a name outside the path alphabet; the manifest lists a path that leaves the root.

`MALFORMED_RESULT` covers: a manifest that is missing, over 1 MiB, not UTF-8 JSON, not canonical or
outside its closed schema; a listed file that is missing; an unlisted file; a wrong size or hash; a
suffix outside the allow-list; a file that is not UTF-8, or not JSON when named `.json`; usage that
disagrees with bytes on disk; duplicate claim ids; published text in a form that cannot be scanned
as it is read (detail below).

The first failing rule, in the fixed order of `derive_output`, names the cause. A non-`OK` result
lists no outputs, no usage and no claim classes.

Every published file is a claim surface. The scanned texts are: every claim statement, limitation
and locator in the manifest; the full text of every output file; in a JSON output every string, and
every scalar member read together with its nearest key (`{"level": "x"}` is read as `level: x`, also
through arrays); every published output path. JSON keys, claim ids and path segments are scanned as
identifiers. A JSON output whose objects repeat a key is `MALFORMED_RESULT`: a parser keeps the last
value while a reader of the bytes sees both, so the first would be published unchecked.

One normalisation (`scan_forms`) applies to every scanned text, whatever surface it came from. The
lexical rules (`CLAIM_TEXT_RULES`) read two forms: the NFKC text as written, and that text with
combining marks dropped and `-`, `_`, `.`, `/`, camelCase boundaries and letter/digit boundaries read
as spaces, so snake_case, camelCase and dotted spellings meet the same rules as prose. In addition,
a text whose normalised form **equals** a prohibited class id (the id normalised the same way), or
an identifier that **contains** one, is `PROHIBITED_CLAIM`. Prose that merely mentions a class id
inside a longer sentence is not refused by that rule.

Text that cannot be scanned as it is read is `MALFORMED_RESULT` (`text_form_ok`), in file bodies,
parsed JSON keys and strings, and manifest text alike: a control character other than newline,
carriage return and tab (NUL, the other C0 and C1 controls, U+007F); any format character (category
Cf: zero-width space and joiners, soft hyphen U+00AD, direction overrides, and the byte-order mark,
so a file must not start with a BOM); a lone surrogate; and a word of three or more letters that
mixes LATIN letters with CYRILLIC or GREEK ones (a homoglyph spelling, which NFKC does not fold).
Whole words in another script, accented letters and two-letter unit symbols are accepted.

## Result and verification

`verify_invocation_result(attempt_root, *, run_id, job_id, attempt_id, request, registry_dir,
prompt_root, readable_roots, allowed_models, source_snapshot_sha256, registry_ceiling)` has no
optional argument and returns fixed-text errors. It trusts no record:

1. The expected request is resolved again: schema, bounds, registry composition, ceiling, tool ids,
   and the prompt and every readable input against bytes on disk.
2. The log directory must hold exactly the three adapter files, each a regular file with link
   count one. Each JSON file must be canonical and inside its closed schema.
3. **Every file that is hashed is also read and cross-checked.** `request.json` must equal the
   expected request. Every field of `invocation.json` is re-derived from the request, the result or
   the output root. The result's identity fields, `persona_id` included, are re-derived from the
   request, the registry and the inputs.
4. The permission gate is re-evaluated at `started_at`: the cause is `PERMISSION_DENIED` exactly
   when that evaluation is not `GRANTED`.
5. For a returned invocation the output root is scanned again. The scan must equal the tree
   `invocation.json` recorded, `derive_output` must give the cause the result claims, and the
   outputs, manifest hash, usage, claim classes, claim count and verified invocations must equal
   what that derivation gives. For any other outcome the cause must be the cause of that outcome
   and no scan may be recorded.

The result, `invocation.json` and the output root are three projections of one run and must agree.
Tests edit each top-level field of the result, of `invocation.json` and of the invoker manifest one
at a time, with and without correctly resealing every hash the result carries, and tamper with
every file of the attempt in turn; each is rejected and nothing is echoed. `result_sha256` is an
integrity check, not an authenticator.

`load_verified_result` returns a deeply immutable record read from disk.
`fingerprint_material(resolved)` (`appsec-review/persona-invocation-fingerprint/1.0`) gives an
integrator the composition hash, the B11 capability fingerprint and the request-without-permission
hash, so re-issuing an identical grant does not change a job's input fingerprint.

## Worker-result envelope

`to_worker_envelope(...)` takes the verifier's arguments plus `input_fingerprint` and
`resume_command`. It reads the verified result from the attempt, never from a caller's copy; sets
`worker_kind` to `persona`; takes `output_contract` from the pinned composition; lists the three
adapter files and, only for `OK`, the output files; uses a fixed summary per cause; and always
reports `NOT_ACCEPTED`. Acceptance belongs to the publication boundary.

All adapter documents and the fixture output pass through `evidence_redaction.redact_tree`
unchanged, and no property name of theirs matches the redactor's secret-ish key rule.

## Limitations

- No model is called. Units and tool calls are self-reported by the invoker; the adapter bounds
  them and re-derives only what bytes on disk can prove (input bytes, output bytes, files, hashes).
- An in-process invoker is not sandboxed. The adapter detects changes to the attempt outside the
  output root, to the prompt and to the readable inputs; it cannot see a write somewhere else on
  the host. A real invoker should run inside the B13 boundary or an equivalent OS sandbox.
- A Python thread cannot be killed. After a timeout the invoker may still be running
  (`invoker_stopped: false`); its late writes are never accepted because the result is already
  terminal and lists no outputs.
- A declared producer is bound to the bytes of a producer result that the integrator pinned, not
  to an authenticated producer. Results are unsigned: whoever can write a canonical result with a
  matching `result_sha256` can state any persona or model. This adapter does not open the producer's
  attempt or re-run its verifier, so C02 must pin only results that passed
  `verify_invocation_result`. A producer output that an integrator labels `evidence` is not
  recognised as producer output.
- Requiring a different model family for every reviewer is stricter than the panel-level minimum
  in `design-v3.md` section 5.1. It follows the ADR-0008 sentence that names B14. A deployment with
  one model family cannot run reviewing invocations.
- The lexical rules are a backstop, not a classifier. They fail closed on phrasing such as a
  quoted severity word in a summary, and they do not recognise a paraphrase, a synonym, a key and
  value separated by more than one level of nesting, or a confusable spelling inside one script
  family (the mixed-script rule covers LATIN with CYRILLIC or GREEK only).
- Whoever can rewrite every file of an attempt consistently can produce another valid attempt;
  nothing here is signed. The verifier guarantees agreement between the projections and with the
  expected request, registry and inputs.
- Verification re-reads the prompt and the readable inputs, so it fails closed once they are gone.
- `registry_ceiling: null` means "no ceiling" to B11, exactly as for B13.
- The design-parity manifest still lists persona invocation as open; updating it is an integration
  step on a shared surface.

## Integration follow-ups

Shared surfaces, to be done sequentially by whoever owns them. None were edited in B14.

1. C01 pool specification: expand a `kind: "persona"` worker into one request per instance, with a
   private attempt root per instance, the exact input list, a budget and the model identity; use
   `fingerprint_material` in the instance fingerprint; pass `PersonaRuntime.cancel` from the pool.
2. C02 wait-all: treat `invocation-result.json` as terminal only after `verify_invocation_result`
   passes; build a reviewer's `producers` and its `producer_result` inputs from those verified
   results, never from a request.
3. T10 dispatch: map a T06 handoff to a request. The handoff travels as a readable input with role
   `handoff`; its tool contract, budget and prohibited claim classes must be translated by trusted
   code into pins, never read by the adapter.
4. Registry: give persona or role records a first-class claim-class ceiling and tool ids, add
   verification-lane roles, and decide whether `02-evidence-index` should be invocable.
5. A real invoker (a model client) and its provider allow-list, run inside the B13 boundary; B15
   assigns it to the persona pool.
6. `validate_job_output.py` / `publish_job_output.py`: call the verifier before publication and
   route outputs through the redactor.
7. `appsec-review-process/TODO.md`, `docs/design-parity-completion-plan.md` and the parity
   manifest: mark B14 done once reviewed.
