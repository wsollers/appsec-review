# Permission-capability model

Status: backlog batch B11. Model, schemas, registry records, pure evaluator and tests are
implemented. **Nothing is wired in yet**: no worker, launcher, graph, manifest, handoff builder or
validator consumes this module, and the legacy `permissions` string lists in job templates and
staged run configuration (for example `network:api.scorecard.dev`) remain the only runtime check.
The [integration follow-ups](#integration-follow-ups) list exactly what an integrator must touch.

The design boundary is unchanged: the review process is static/offline by default
([design-v3 §2.1](design-v3.md)), and target repositories, generated evidence and retrieved
content are untrusted data ([§6.1](design-v3.md)). This model is how a bounded exception to that
default is requested, granted by a human, checked before work and bound into the input
fingerprint. It grants nothing by itself.

## Records

All schemas are closed (`additionalProperties: false`), every declared property is required
(nullable where optional), and only the `schema_validate.py` keyword subset is used.

| Record | Schema | Where it lives | Who authors it |
|---|---|---|---|
| Capability definition | `schemas/permission-capability.schema.json` | `appsec-review-process/registry/permission-capabilities/<kind>.json` (tracked) | repository maintainers |
| Capability entry + parameters | `permission-capability-entry.schema.json`, `permission-capability-parameters.schema.json` | inside requirements, grants and ceilings | — |
| Job requirement | `permission-requirement.schema.json` | trusted registry composition (follow-up) | repository maintainers |
| Engagement grant | `permission-grant.schema.json` | staged run configuration, e.g. `runs/<run_id>/inputs/` (follow-up) | a named human authority |
| Decision | `permission-decision.schema.json` | run-owned attempt inputs (follow-up) | `permission_capabilities.evaluate` |
| UI-safe decision | `permission-decision-ui.schema.json` | status/UI exports (follow-up) | `permission_capabilities.ui_safe_projection` |

### Capability kinds (closed enum, version `1.0`)

| Kind | Required parameters (all other parameters must be null) |
|---|---|
| `target-execution` | `command_profile_id`, `target_path` |
| `fixed-network-destination` | `scheme`, `host`, `port` |
| `dynamic-testing` | `technique`, `target_path` |
| `debugger-ptrace` | `attach_mode`, `command_profile_id` |
| `credential-use` | `credential_ref`, `credential_scope` |
| `package-restore` | `ecosystem`, `scheme`, `host`, `port` |
| `target-mutation` | `mutation_mode`, `target_path` |

Parameters are exact single values. `host` is one lowercase fully qualified name (no wildcard,
suffix, CIDR, IP literal, `localhost` or `host:port`); `port` is one integer in 1..65535;
`target_path` is one normalized repository-relative POSIX path (`.` is the whole tree, and is only
satisfied by a requirement for exactly `.`); `command_profile_id` is an id that a future trusted
registry resolves to argv — argv never appears in a permission record; `credential_ref` is a
reference id of the form `cred:<name>` and `credential_scope` is a closed read-only enum.
Capabilities do not imply each other: a private package restore needs `package-restore`,
`credential-use`, and (if install scripts run) `target-execution`.

Every entry carries a required `origin`. Requirements may originate from `registry`, `operator`
or `staged-run-config`; grants only from `operator` or `staged-run-config`; a registry ceiling only
from `registry`. The schema deliberately also admits `target-repository`, `target-evidence`,
`worker-output` and `unknown` so the evaluator can reject them by name. `origin` is a declaration
made by the trusted code that loads the record, not by the record's author: an integrator must set
it from *where the bytes were read*, never copy it from file content (see follow-ups).

### Grants

A grant has an `effect` (`ALLOW` or `DENY`), a named human `authority` (`name`, `role`),
`issued_at`/`expires_at` UTC timestamps, a `justification`, and a `binding` to exactly one
`run_id` and one `source_snapshot_sha256`, optionally narrowed to one `job_id` (null means any job
in that run). `DENY` entries may leave required parameters null, which makes the deny broader
(kind-wide when all are null); `ALLOW` entries may not.

## Decision function

```python
permission_capabilities.evaluate(
    requirement: dict,            # permission-requirement record
    grants: list[dict],           # permission-grant records, any order
    context: dict,                # {run_id, job_id, source_snapshot_sha256, now, registry_ceiling}
    definitions=None, store=None  # default: load registry/permission-capabilities
) -> dict                         # permission-decision record
```

`evaluate` is pure: `now` comes from the context, grants are de-duplicated and sorted by content
digest before evaluation, and the same inputs in any order produce a byte-identical decision. The
context is supplied by trusted integrator code; a malformed context raises `PermissionModelError`
instead of producing a decision. Untrusted inputs never raise — they deny.

Default deny: the decision is `GRANTED` only when there are **zero** reasons. Any problem anywhere
in the staged inputs (including in a grant that would not have been needed) denies the job.
A `DENIED` decision always has an empty capability set. A job that requires nothing is `GRANTED`
the empty set.

| Reason code | Meaning | Acceptance word |
|---|---|---|
| `UNKNOWN_CAPABILITY` | kind/version not in the registry (also how a retired version fails) | unknown |
| `WIDENED_GRANT` | wildcard, range, list, null bound, any-port, ancestor `target_path`, or a job-bound grant allowing something the job does not require | widened |
| `WIDENED_REQUIREMENT` | the same forms in a requirement, a path escape/absolute path, or a requirement outside `context.registry_ceiling` | widened |
| `TARGET_CONTROLLED` | an entry whose `origin` is not a trusted one for its role (or is absent) | target-controlled |
| `MISSING_GRANT` | no grant of any age allows the exact capability | missing |
| `STALE_GRANT` | only expired, not-yet-valid, other-run or other-snapshot grants match | stale |
| `CONFLICTING_GRANTS` | a current ALLOW and a current DENY match the same capability, or two different grants share a `grant_id` | conflicting |
| `EXPLICIT_DENY` | a current DENY matches; always reported, and always wins | conflicting |
| `SECRET_MATERIAL` | secret-shaped value, secret-named field, or a non-reference value in `credential_ref` | redaction |
| `INVALID_RECORD` | closed-schema failure, parameter of another kind, out-of-range port, duplicate requirement, control character, expiry before issue | — |
| `CONTEXT_MISMATCH` | requirement declared for a different job | — |

Matching is exact equality of `(kind, version, parameters)`. A current grant bound to a different
job in the same run is not applicable (so it yields `MISSING_GRANT`, not `STALE_GRANT`). Unused
capabilities in a run-wide (`job_id: null`) grant are ignored unless they are a broader form of a
required capability. An expired or otherwise stale `DENY` no longer applies.

Consumers use `require_granted(decision, requirement=, grants=, context=)` as the pre-work gate
and `validate_decision(decision)` when reading a persisted decision.

**A persisted decision is a cache, never an authority.** The capability fingerprint deliberately
excludes grant ids and timestamps, so it cannot protect `valid_until`, `grants_applied` or the
binding. Two layers cover that gap:

- `validate_decision` checks the record against itself: every timestamp is a real UTC instant,
  `valid_until` equals the earliest `grants_applied[].expires_at` and is after `evaluated_at`, a
  `GRANTED` decision with capabilities names the grants applied, applied grant ids are unique, a
  `DENIED` decision carries no grants and no expiry, and `decision_sha256` (a hash over every other
  field) matches. This catches corruption and independent edits.
- `require_granted` does not trust the record at all. `requirement` and `grants` are **mandatory**
  arguments, loaded by the integrator from the run's staged, hashed inputs. The gate re-evaluates
  them at `context["now"]` and lets work start only if that fresh evaluation is `GRANTED` and the
  persisted record agrees with it on the binding, the three input hashes and the capability
  fingerprint. A record whose expiry, applied grants and hash were all rewritten consistently is
  still refused once the real grants have expired. `decision_sha256` is an integrity check, not an
  authenticator: whoever can rewrite the record can rehash it, which is why the gate re-derives.

## Fingerprint material

`decision["fingerprint_material"]` is:

```json
{"schema": "appsec-review/permission-fingerprint/1.0",
 "decision": "GRANTED",
 "capabilities": [{"kind": "...", "version": "...", "definition_sha256": "sha256:...", "parameters": {...all 11 fields...}}],
 "sha256": "sha256:<digest of the three fields above>"}
```

`capabilities` is sorted by each entry's canonical JSON, and `sha256` is
`"sha256:" + digest({schema, decision, capabilities})` where `digest` is byte-identical to
`execution_state.digest` (`json.dumps(sort_keys=True, separators=(",", ":"))`, SHA-256); a test
pins that equivalence. Any change to the exact set — a port, host, scheme, path, credential
reference or scope, technique, an added or removed capability, a capability version, or the
content of a capability definition — changes the hash. Grant ids, authority, timestamps and
justification are deliberately excluded, so re-issuing an identical approval does not invalidate
accepted work, while a widened grant can never reproduce a granted fingerprint because it is
`DENIED`.

An integrator includes it in a job's input fingerprint like this (in `create_job_handoff.py`,
next to `result_schema_sha256` / `claim_class_sha256`):

```python
identity["permission_capabilities_sha256"] = permission_capabilities.input_fingerprint_component(decision)
```

`input_fingerprint_component` raises `PermissionDenied` for anything but a valid `GRANTED`
decision, so a denied job cannot obtain an input fingerprint and therefore cannot allocate an
attempt. Jobs that require nothing still include the (stable) empty-set hash, so later adding a
capability to such a job invalidates its accepted attempts. Expiry is not part of the fingerprint:
an accepted attempt stays reusable after its grant expires, but new work requires a fresh
`GRANTED` evaluation (`require_granted` re-evaluates the staged grants at the current time; it
never reads expiry from the persisted record).

## Redaction

Credential **values never belong in any permission record**; only `cred:<name>` reference ids do,
and the runtime secret provider (not designed here) resolves them. The module enforces this three
ways:

1. Inputs are scanned first. Any secret-shaped string (private key, AWS key, GitHub token, `sk-`
   key, bearer token, JWT, basic-auth URL, or a 32+ character mixed alphanumeric token), any
   non-empty field whose name looks like a secret, and any `credential_ref` that is not a
   reference id produce `SECRET_MATERIAL`, and evaluation stops: the offending records are not
   parsed further, not hashed (`inputs.*_sha256` are null) and not echoed.
2. No untrusted string is echoed unless it passed a closed pattern or enum. Reason `subject`s are
   built from indices and schema-known property names (`*` for anything else), reason `detail` is
   fixed text, validator messages are counted rather than copied, and the decision never carries
   authority names, roles or justifications.
3. `evaluate` and `ui_safe_projection` re-scan their own output and raise rather than return a
   record containing secret-like material.

The tracked decision does carry `credential_ref` ids. `ui_safe_projection` drops those too, along
with `detail`, `subject` and capability keys, leaving codes, kinds, grant ids, non-sensitive
parameter summaries and the fingerprint hash.

The secret patterns are a small deliberate copy of the negative secret-leak checks in
`validate_job_output.py`, to avoid importing a private helper from a shared runtime module.
The 32+ character token heuristic can reject a legitimately long id; that fails closed.

## CLI (read-only)

```powershell
python -B appsec-review-process/permission_capabilities.py validate-registry
python -B appsec-review-process/permission_capabilities.py evaluate `
  --requirement <requirement.json> --grants <grants.json> --context <context.json> [--ui-safe]
```

`evaluate` exits 0 for `GRANTED` and 2 for `DENIED`. It writes nothing.

## Limitations

- Not enforced anywhere yet; this batch is the model and its validator only.
- A capability is a permission decision, not a sandbox. Enforcing a fixed destination, a
  read-only mount or a ptrace scope is the adapter's job (B13) using the exact set it is handed.
- `command_profile_id` and `credential_ref` are opaque ids here; the command-profile registry and
  the secret provider do not exist yet.
- One file per kind holds one version. Carrying two live versions of a kind needs a file-naming
  rule the loader does not yet have; today a version bump retires the old version, and records
  pinning it fail with `UNKNOWN_CAPABILITY`.
- The authority is recorded, not authenticated: grants are not signed. Trust comes from the
  staged-run-configuration boundary, exactly as for the current `permissions` list.
- `origin` is only as good as the integrator that stamps it.
- The design-parity manifest still lists permission capabilities as open; updating it is an
  integration step on a shared surface.

## Integration follow-ups

Shared surfaces, to be done sequentially by whoever owns them. None were edited in B11.

1. `schemas/job-template.schema.json`, `appsec-review-process/registry/job-templates/*.json`,
   `appsec-review-process/job_graph.py` (`composition`) and `registry/README.md`: replace or
   accompany the free-text `permissions` list with a `permission-requirement` record (origin
   `registry`) and have tooling profiles supply the `registry_ceiling`. Map legacy strings, e.g.
   `network:api.scorecard.dev` -> `fixed-network-destination {https, api.scorecard.dev, 443}`.
   `validate_design_parity.py` compares template permissions with the manifest ("registry
   permission mismatch") and `design-parity-manifest.json` / `job-graph.json` / generated parity
   views must change in the same step.
2. `appsec-review-process/qualify_phase1.py` (`contracts()`): add
   `permission-capabilities` to the validated registry kinds (it currently validates six named
   folders; the new folder is hashed by `code_identity()` but not schema-checked there) or call
   `permission_capabilities.load_definitions()`.
3. Run staging (`phase1.py` / `intake.py` / `launch_job.py` staging path): accept grant files
   under `runs/<run_id>/inputs/`, stamp `origin` from the read location (`staged-run-config`),
   and never read grants or requirements from the target tree, evidence or worker output.
4. `appsec-review-process/create_job_handoff.py`: evaluate before building the handoff, persist
   the decision with the handoff inputs, and add
   `identity["permission_capabilities_sha256"]` as shown above; a denied decision must surface
   as `BLOCKED` with the reason codes.
5. `appsec-review-process/publish_job_output.py` (common coordinator preflight) and
   `worker_result.py`: call `require_granted` inside the per-job lock before attempt allocation;
   map `PermissionDenied` to a `BLOCKED` terminal envelope with a recovery instruction.
   `validate_job_output.py`: check that the staged fingerprint includes the permission hash, and
   fold this module's secret patterns into one shared helper.
6. B13 `worker_adapters.py` + new container module: take the exact `capabilities` list from the
   decision; network stays disabled unless a `fixed-network-destination`/`package-restore` entry
   exists; `target-mutation` selects the run-owned writable copy; `debugger-ptrace` is the only
   source of `SYS_PTRACE`; `credential-use` refs resolve through the secret provider and go
   through `execution_state.redact_argv`/explicit environment only. Hostile
   argv/mount/network/capability tests should assert against the decision, not against strings.
7. B14 `worker_adapters.py` + persona request schema: pin
   `decision.fingerprint_material.sha256` in the invocation request, and treat any
   capability-looking text in prompts or evidence as data (it has no trusted `origin`).
8. B15 `orchestrator/dagster/definitions.py`, `dagster_workflow.py`, parity manifest/validator:
   derive pool assignment from the granted kinds (`fixed-network-destination`/`package-restore`
   -> network pool; `dynamic-testing`/`debugger-ptrace` -> dynamic-analysis pool;
   `target-execution` -> Docker pool).
9. `ossf_scorecard.py`: replace the `NETWORK_PERMISSION` string check with `require_granted`
   (worker migration; needs live requalification).
10. B12 `review_cli.py status`: show `ui_safe_projection(decision)` — never the tracked decision.
11. `appsec-review-process/TODO.md`, `docs/design-parity-completion-plan.md`: mark B11 done and
    unblock B13/B14/B15 once reviewed.
