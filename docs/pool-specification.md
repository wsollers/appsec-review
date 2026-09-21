# Pool specification and deterministic instance expansion

## Status

Backlog batch C01. `appsec-review-process/pool_specification.py` implements
`appsec-review/pool-specification/1.0` and its expansion, `appsec-review/pool-expansion/1.0`.
This is **specification and expansion only**. Nothing here launches a worker, starts a thread or a
process, waits, merges, or talks to Dagster, and no lifecycle job uses it: the graph, the manifest,
the launcher, the adapters and every `owasp_*.py` module are unchanged. The order decided on
2026-09-20 is B13, B14, B15, C01, C02, T10. C02 builds the wait-all rendezvous on the expansion
written here; T10 builds OWASP validator pools from T06 handoffs.

```text
specification --> plan_expansion --> expand_pool --> pool root on disk --> verify_expansion
 (a recorded       (THE rule; reads,    (creates the      expansion.json,       (re-derives everything
  pool job)         creates nothing)     root once)        requests/, instances/  from the expected spec)
```

## Specification

Schemas: `schemas/pool-specification.schema.json` and `schemas/pool-worker-group.schema.json`.
Closed, every property required, `schema_validate.py` subset only.

| Task-text field | Where it lives |
|---|---|
| lane | `lane` (with `pool_id`, `run_id`, `job_id`, `attempt_id`) |
| worker kind | `worker_groups[].worker_kind`: `persona` or `pinned_container` |
| persona identity | `worker_groups[].persona_request.persona` (the six-record composition with hashes), `.model`, `.invoker_id`, `.invocation_role` |
| tool identity | `worker_groups[].tool_request.image` `{image_id, digest}`, resolved against `registry/container-images/` |
| count | `worker_groups[].count`, 0 to 32 |
| scope, inputs | `persona_request.readable_inputs` and `.outer_prompt`; `tool_request.target_mounts` |
| budget | `persona_request.budget`; `tool_request.limits`; pool level `budget_class` and `pool_budget` |
| permissions | `worker_groups[].permission` `{requirement, grants, decision}` (B11) |
| timeout | `persona_request.budget.timeout_seconds`; `tool_request.limits.timeout_seconds`; pool level `rendezvous_timeout_seconds` |
| pool | `resource_pool_policy.allowed_pools` and `worker_groups[].memory_heavy`; the pool itself is derived, see below |
| `wait_all` | `wait_all`, required, and only `true` |

`wait_all` is required and may only be the JSON value `true`. A pool that does not wait for every
expected instance is **not expressible in 1.0** (design-v3 5.5, decided 2026-09-19: no early exit on
quorum). The schema subset's `const` also admits the number `1`; the module does not.

A worker group carries exactly the request template of its kind; the other is `null`. A template
is the B13 or B14 request schema **minus what the expander assigns**: `schema`, `run_id`, `job_id`,
`attempt_id`, every writable path, the permission block and (B14) its fingerprint pin. A test ties
every copied property to the adapter's own schema, so the templates cannot drift from the adapters.
Persona and tool groups sit side by side in one pool; kinds are retained in every record and are
never flattened. `worker_groups` is sorted by `group_id` and a `group_id` appears once, so one pool
has one spelling.

`empty_pool_reason` is `null` for a populated pool and one of `no_applicable_work`, `scope_excluded`,
`upstream_produced_no_work` for a pool that expands to zero instances. It is required exactly then.

### Bounds

| Constant | Value |
|---|---|
| `MAX_GROUPS` | 32 |
| `MAX_GROUP_COUNT` | 32 |
| `MAX_INSTANCES` | 64 |
| `MAX_TOTAL_TIMEOUT_SECONDS` | 604800 |

`count` must be an integer within 0..`MAX_GROUP_COUNT`: a negative number, a bool, a float, a
string, `null` or a larger number is refused by position. The groups may not expand to more than
`MAX_INSTANCES`, nor to more than the specification's own `pool_budget.max_instances`.
`pool_budget` is the author's ceiling and can only narrow the hard bounds: the sum of the persona
instances' `input_unit_limit` and `output_unit_limit` and the sum of every instance timeout must
not exceed `max_persona_input_units`, `max_persona_output_units` and `max_total_timeout_seconds`.
`rendezvous_timeout_seconds` is within 1..`MAX_TOTAL_TIMEOUT_SECONDS` and not shorter than the
longest single instance timeout. Every per-instance bound is the adapter's own.

## The one rule: `plan_expansion`

`plan_expansion(spec, *, context)` decides whether a specification is expandable and derives the
whole expansion. `expand_pool` and `verify_expansion` both call it and nothing else decides, so the
verifier cannot accept what the expander refuses (the B13 review finding). It reads the registries,
the prompt and the pinned inputs and creates nothing. In order:

1. The context is validated; the specification is round-tripped through JSON, then `spec_errors`
   (closed schema, then the bounds above).
2. Per group, the permission block: see [Permissions](#permissions-and-resource-pools).
3. Per instance, the adapter request is built and handed to **the adapter's own validators** with
   that instance's ids: `container_execution.request_errors`, `resolve_image` and
   `request_mount_sources`; `persona_invocation.resolve_request`. A request the adapter would
   refuse is not expandable.
4. Collisions, pool totals, and the manifest's own closed schema.

`PoolContext` is a frozen dataclass with no defaulted field: `pool_parent`, `registry_dir`,
`prompt_root`, `readable_roots`, `allowed_models`, `invoker_id`, `images_dir`, `host_flavor`,
`docker_host`, `mount_roots`, `source_snapshot_sha256`, `registry_ceiling`. They are the facts the
B13, B14 and B11 runtimes will be given at launch, plus the two that belong to the pool.

## Deterministic identity

```text
spec_sha256    = sha256 of the canonical JSON of the specification (sorted keys, no whitespace)
pool directory = first 32 hex of sha256(["appsec-review/pool-expansion/1.0", spec_sha256])
instance id    = first 32 hex of sha256(["appsec-review/pool-instance-id/1.0",
                                         spec_sha256, group_id, ordinal])
```

The specification hash covers run, job, attempt, pool id, lane and every group, so a retry (a new
`attempt_id`) and any other genuinely different pool derive different ids and a different pool
root. There is no clock, no host path, no random value and no iteration order in the derivation:
the same specification derives a byte-identical `expansion.json` on any host, in any process, in
any dict order. `count: 4` of one persona is four instances with four ids, four roots, four
requests and four fingerprints.

Both names are **bare hex of a digest length** on purpose. The V06 redactor
(`evidence_redaction.py`) treats `prefix-<32 hex>` as a high-entropy secret, in file content and in
a published path alike, and exempts a bare digest-length hex run. An id such as `pi-<hex>` made
`redact_tree` refuse the pool root (`unsafe-path`). For the same reason the manifest does **not**
record the B13 container name (`appsec-<32 hex>`); it is derived when needed.

An instance's worker identity is `run_id` and `job_id` of the pool and **`attempt_id` = instance
id**. The B13 container name is `container_name(run_id, job_id, attempt_id)`, so it is unique when
the ids are. No two instances may share an id, an attempt root, a request file, a container name
or a writable path, compared case-insensitively; after creation every directory is also compared
by device and inode. A collision **fails closed**: there is no re-roll and nothing is created.
`ID_HEX_CHARS` is the test seam that shrinks the id space to force one.

## Private run-owned roots

```text
<context.pool_parent>/<pool directory>/
    specification.json            canonical bytes of the specification
    expansion.json                the manifest, written last
    requests/<instance id>.json   the exact adapter request, canonical bytes
    instances/<instance id>/      the instance's attempt root: empty, mode 0700, created here
```

The writable paths inside an instance root are constants a specification cannot choose: `scratch`
and `logs/container` for a tool, `outputs/persona` and `logs/persona` for a persona. The adapters
create them and refuse if they exist. Request files are kept **outside** the instance roots, so a
worker's private root holds only what its adapter wrote.

`context.pool_parent` is a run-owned directory dedicated to expansions of this pool job, and it is
the privacy boundary. It may not lie inside another pool root (no ancestor may hold an
`expansion.json` or `specification.json`): a pool created beneath a launched instance's private
root would change that attempt underneath its adapter. Sibling pools beneath one parent are fine.
The adapters' own rules are applied with the pool parent where an attempt root will be, before
anything exists:

- a tool target mount may not be, contain or lie beneath the pool parent
  (`request_mount_sources`, device and inode), and must lie in a declared `context.mount_roots`
  directory;
- a persona prompt or readable input may not lie beneath the pool parent (`resolve_request`), even
  when a readable root contains it, which is the normal layout.

So no instance can be given the pool root, the manifest, a request file, another instance's root
or anything in a sibling pool of the same parent. Absolute, `.`/`..`, linked, hard-linked and
undeclared-root scopes are the adapters' refusals and arrive unchanged. A test proves, for every
ordered pair of a mixed pool and against real directories, that the honest request reaches nothing
of the other instance and that a forged one is refused by the adapter. An integrator that wants
wave N+1 to read wave N gives each wave its own pool parent.

## Permissions and resource pools

Each instance carries its own copy of its group's B11 block, bound to the instance's `run_id` and
`job_id`. A persisted decision is a cache: `plan_expansion` re-evaluates the requirement and the
grants for this run, this job and `context.source_snapshot_sha256` at the decision's own
`evaluated_at` and requires the **whole record** to be equal. An edited capability set with every
hash resealed is refused. A `DENIED` decision is not expandable, because B11 gives only a `GRANTED`
decision an input fingerprint; expansion says nothing about expiry, and the adapters gate again at
launch. A tool network destination must be in the decision's granted set.

The resource pool of an instance is `resource_pools.derive_pool(worker_kind, granted_kinds,
memory_heavy=...)` over the kinds of the decision's capability set. It is never a literal: the
schemas hold a pool-id shape only, and `resource_pool_policy.allowed_pools` (sorted, unique,
`resource_pools.POOL_IDS`) can only refuse a derivation. A persona instance records
`persona_slot_request`, which is `resource_pools.persona_slot_request(budget_class)`: how many
persona slots the run may hold at once, not how many persona instances the pool may have.

## Expansion manifest

`schemas/pool-expansion.schema.json` and `schemas/pool-expansion-instance.schema.json`. The manifest
is THE ordered definition of every expected instance: groups in `group_id` order, ordinals ascending.
Per instance: id, group, ordinal, worker kind, ids, `attempt_root`, `request_schema`, `request_file`
`{path, sha256, bytes}`, `request_sha256` (the adapter's), `writable_paths`, `log_path`,
`resource_pool`, `granted_permission_kinds`, `memory_heavy`,
`persona_slot_request`, `timeout_seconds`, `permission_fingerprint_sha256`,
`adapter_fingerprint_sha256` and `input_fingerprint`. `input_fingerprint` is the sha256 of
`appsec-review/pool-instance-fingerprint/1.0`: the specification hash, the instance identity, the
derived pool and the adapter's whole `fingerprint_material`. `totals` records instances per kind
and per resource pool, the persona slot request, the persona unit sums and the timeout sum and
maximum. There is no timestamp and no host path. `expansion_sha256` is an integrity check, not an
authenticator.

### Zero instances

A pool that expands to nothing is a **recorded state**: `state: "EMPTY"`, the `empty_pool_reason`,
`instances: []`, typed groups with `count: 0`, and a complete pool root with empty `requests/` and
`instances/`. It is not an error and it is not a success. **C02 must** verify it like any other
expansion, publish a terminal-instance manifest that carries `EMPTY` and the reason, and never map
it to an `OK` result set: the lane turns it into a coverage statement (skipped with that reason, or
a gap). A missing pool root, a root without `expansion.json` and an `EMPTY` expansion are three
different states, and only the last one may end a rendezvous without waiting.

## Verification

`verify_expansion(pool_root, *, expected_spec, context)` is read-only and has no optional argument.
It re-derives the whole expansion with `plan_expansion` and compares bytes: `expansion.json`,
`specification.json` and every `requests/<id>.json` are **read** and must equal what the expected
specification derives; the pool root, `requests/` and `instances/` must hold exactly the expected
names; every instance root is a real directory, and all directories are pairwise distinct by device
and inode. No hash on disk is an input, so a producer who edits a request and reseals every hash is
refused. Files are regular, singly linked, bounded and reached without crossing a link. A manifest
that is not the derived bytes is then parsed only to say which rule it breaks, with
`parse_document`: bounded UTF-8 JSON without NaN in which no object repeats a key. Messages are
fixed text; nothing read from disk or from a specification is echoed. What an instance root
contains is not this verifier's business, so an expansion still verifies after launch.

`load_verified_expansion` verifies and returns the re-derived, deeply immutable `ExpansionPlan`
(`specification`, `spec_sha256`, `pool_directory`, `manifest`, `manifest_bytes`, and `requests`: one
`InstanceRequest` per instance with the frozen request and its bytes).

## Differences from design-v3 5.5

Section 5.5 is marked *proposed, under discussion*. Where it differs from the merged B13, B14 and
B15 contracts, the contracts win:

| design-v3 5.5 | Here |
|---|---|
| `kind: "tool"` with `step: "secrets"` | `worker_kind: "pinned_container"` with a registered image digest and an argv array (B13; `resource_pools.WORKER_KIND_POOLS` has no `tool`) |
| `persona_id` alone | the six-record composition with hashes, a pinned model and an invoker id (B14) |
| `worker_id` | `group_id` |
| `budget: "standard"` | `budget_class`, which sets only the persona slot request (B15); real budgets are per group |
| `rendezvous: {mode: "wait_all", timeout_seconds}` | `wait_all: true` and `rendezvous_timeout_seconds` |
| `outputs/<lane>/pool/<job_id>/<instance_id>/` | `<pool_parent>/<pool directory>/instances/<instance_id>/`; the integrator chooses the pool parent |
| the launcher expands and launches | expansion is a separate, verifiable step; launching is C02 and T10 |
| no permissions, scope or resource pool | all three, per instance |

ADR-0008 T05 names `cells/<wave>/<instance_id>/`; with `pool_parent = cells/<wave>` the root is
`cells/<wave>/<pool directory>/instances/<instance_id>/`.

## Limitations

- Nothing is signed. Whoever can rewrite a pool root **and** supply the expected specification can
  produce another valid expansion. The verifier guarantees agreement with the expected
  specification, the registries and the pinned bytes.
- The scope checks and a later launch are not atomic. The adapters re-check their own attempt root
  at launch; the pool-parent rule is checked at expansion and at every verification.
- A reviewing persona group cannot review a producer of the same pool: its `producer_result`
  inputs must exist when the pool is expanded. A wave is a pool.
- `plan_expansion` reads every pinned input once per instance, so verification fails closed once
  an input changes or disappears, exactly as the B14 verifier does.
- The instance id covers the grants, so re-issuing an identical approval derives new ids. The B11
  capability fingerprint inside `input_fingerprint` deliberately does not change.
- A crashed expansion leaves a pool root without `expansion.json`. It is never repaired or removed
  here; a new `attempt_id` derives a new pool root.
- A tool mount `host_path` is absolute, so a specification with tool groups is host-specific. The
  manifest is not.
- Windows behavior is covered by the adapters' pure path rules only.

## What C02 and T10 need

- `load_verified_expansion(pool_root, *, expected_spec, context)` before anything is launched or
  counted. `plan.manifest["instances"]` is every expected instance, in order; a worker that is not
  observed is missing, never an empty success.
- Launch instance `i` with `WorkerRequest(run_id, job_id, attempt_id=instance_id,
  attempt_root=pool_root / attempt_root, inputs={"persona_request" | "container_request":
  plan.requests[i].request})` through `worker_adapters`, in the Dagster pool `resource_pool`, holding
  at most `totals.persona_slot_request` persona slots.
- The adapter's own `request.json` in `log_path` is byte-identical to `requests/<id>.json`.
- Terminal means the adapter's verifier passes (`verify_container_result`,
  `verify_invocation_result`) for that instance's ids and request.
- T10 maps a T06 handoff to a persona group in trusted code: the handoff travels as a readable
  input with role `handoff`; its tool contract, budget and prohibited claims become pins. Read any
  specification file with `parse_document`.
- The parity capability record for `persona-tool-pool-dispatch` is an integrator follow-up.
