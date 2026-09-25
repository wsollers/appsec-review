#!/usr/bin/env python3
"""Request builder (D01 construction, Phase 5b item 3): builds the full
``appsec-review/persona-invocation-request/1.0`` object ``persona_invocation.resolve_request``
requires, for one unpooled discovery job template (``02-repository-partition-discovery`` today;
the same builder works for D02-D04 once their task prompts exist, since nothing here is specific
to repository partitioning beyond the job template id the caller names).

This module builds a request; it never dispatches one. The caller (Phase 5b item 5,
``discovery_gate.py``'s automatic-dispatch wiring, not yet built) is responsible for: creating the
attempt directory, supplying a ``source_snapshot_sha256`` from the run's accepted intake record
(``intake.py``'s ``source_identity()['fingerprint']``, ``sha256:``-prefixed), calling
``model_version_registry.resolve_run_model_versions(run_id)`` once early in the run so a pinned
model identity exists to read, and handing the built request plus a real ``PersonaInvoker`` (item
4, not yet built) to ``persona_invocation.run_invocation``.

Every pin this module writes into the request is independently re-derived by
``persona_invocation.resolve_request`` from the same registry, the same target checkout and the
same run's pinned model-versions record -- this module does not get to assert anything
``persona_invocation`` will not verify for itself.

**Readable-inputs walk, scoped for D01's construction (flagged, not silently assumed):** unlike
``intake.py``'s ``source_identity()`` (bounded by a 100,000-file / 120-second / 4-GiB deadline,
Windows reparse-point handling, git blob identity and dirty-tracking), this module's own
``_walk_target`` is a plain, unbounded read-every-regular-file walk: it skips ``.git`` (matching
``source_identity``'s own exclusion -- VCS internals are not review evidence) and refuses outright
if the checkout contains a symlink anywhere (``execution_state.beneath`` raises), rather than
recording it as `unavailable` the way intake does. This is a deliberate scope cut for proving the
discovery chain on the bounded hello-autotools fixture, not a claim that it is fit for an
arbitrary real target; the two walks reusing one shared, bounded implementation is a reasonable
follow-up once a real (non-fixture) target is in scope, not assumed here.

**Budget table (``PERSONA_BUDGETS``), scoped the same way:** ``persona_invocation``'s request
``budget`` object (input/output byte and unit limits, timeout) is a resource ceiling for one
persona invocation attempt -- a different axis from ``review_cli.resolve_model``'s dollar-cost
budget tier (``probe``/``standard``/``full``), though both happen to share those three tier names
here (following ``owasp_dispatch.py``'s ``cell_budgets`` precedent, which uses the same three
names for the same reason: reusing the vocabulary the job template's own ``budget_default`` field
already speaks). This table is deliberately D01's own, not shared with
``config/owasp-dispatch/default-v1.json``'s ``cell_budgets`` (a different, pooled-multi-cell
domain) or registered anywhere else; a shared registry-level budget-profiles record is a
reasonable follow-up once more than one unpooled job template exists, not assumed here.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import model_version_registry as mvr
import persona_invocation as pi
import persona_prompt_assembly as ppa
import permission_capabilities as pc
import review_cli as rc
from execution_state import beneath, identifier
from schema_validate import SchemaStore

ROOT = Path(__file__).resolve().parent
REGISTRY_DIR = ROOT / "registry"

DEFAULT_INVOKER_ID = "claude-cli"
DEFAULT_READABLE_ROOT = "target-repository"
# Second, optional readable root (D02 construction): an upstream job's already-accepted artifacts
# (today: the accepted repository-partition-map.json that scopes 02-dev-project-discovery), staged
# by the caller into one directory and pinned by sha256 exactly like target files. Deliberately a
# separate root id from the target checkout so a consumer of the request (claude_cli_invoker's
# citation resolution) can tell "evidence you may cite" from "scope you were handed" by root alone.
UPSTREAM_ROOT_ID = "upstream-artifacts"

# job template's own budget_default -> persona_invocation's request budget object. See this
# module's docstring for why this table is D01's own and not shared elsewhere yet.
PERSONA_BUDGETS: dict[str, dict[str, int]] = {
    "probe": {"input_byte_limit": 8 * 1024 * 1024, "input_unit_limit": 200_000,
              "output_byte_limit": 2 * 1024 * 1024, "output_unit_limit": 100_000,
              "output_file_limit": 8, "tool_call_limit": 0, "timeout_seconds": 900},
    "standard": {"input_byte_limit": 32 * 1024 * 1024, "input_unit_limit": 800_000,
                 "output_byte_limit": 4 * 1024 * 1024, "output_unit_limit": 200_000,
                 "output_file_limit": 8, "tool_call_limit": 0, "timeout_seconds": 1800},
    "full": {"input_byte_limit": 64 * 1024 * 1024, "input_unit_limit": 1_600_000,
             "output_byte_limit": 8 * 1024 * 1024, "output_unit_limit": 400_000,
             "output_file_limit": 8, "tool_call_limit": 0, "timeout_seconds": 3600},
}


class RequestBuildError(ValueError):
    """The job template, its composition, the target checkout, or a prerequisite pin (a run's
    pinned model version) was missing or invalid. Raised before any request is returned -- this
    module never hands back a partially built request."""


def _composition_block(job_template_id: str, template: dict[str, Any], store: SchemaStore) -> dict[str, str]:
    """The ``persona`` block's six id+sha256 pairs (job_template, persona, role, domain,
    tooling_profile, output_contract), read straight from the registry -- the exact records
    ``persona_invocation.load_composition`` will independently re-load and hash. The composition
    key is always ``<name>_id``/``<name>_sha256`` (``job-template.schema.json``'s fixed shape),
    even where the record's own id field differs (``output_contract`` -> ``contract_id``);
    ``pi.COMPOSITION_KINDS`` carries that asymmetry, this function does not need to."""
    block: dict[str, str] = {}
    for name, directory, _schema, _field in pi.COMPOSITION_KINDS:
        if name == "job_template":
            block["job_template_id"], block["job_template_sha256"] = job_template_id, pi._sha(template)
            continue
        record_id = template["composition"].get(name + "_id")
        if not isinstance(record_id, str) or not record_id:
            raise RequestBuildError(f"job template composition is missing {name}_id")
        path = REGISTRY_DIR / directory / f"{identifier(record_id)}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except OSError:
            raise RequestBuildError(f"{name} record {record_id!r} is missing") from None
        except ValueError:
            raise RequestBuildError(f"{name} record {record_id!r} is not valid JSON") from None
        block[name + "_id"], block[name + "_sha256"] = record_id, pi._sha(record)
    return block


def _walk_target(target_root: Path, root_id: str) -> list[dict[str, Any]]:
    """Every regular file under ``target_root`` (hidden CI/configuration directories included, per
    the job template's own instructions), excluding ``.git`` (VCS internals, matching
    ``intake.source_identity``'s exclusion), as ``readable_inputs`` entries with role
    ``evidence``. Raises if the checkout contains a symlink anywhere (this D01 construction scope
    cut is documented in the module docstring) or has no readable files at all."""
    target_root = Path(target_root).resolve()
    if not target_root.is_dir():
        raise RequestBuildError(f"target checkout is not a directory: {target_root}")
    entries: list[dict[str, Any]] = []
    for path in sorted(target_root.rglob("*")):
        relative = path.relative_to(target_root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if not path.is_file():
            continue
        try:
            checked = beneath(target_root, path)
        except ValueError as exc:
            raise RequestBuildError(f"target checkout: {exc}") from None
        data = checked.read_bytes()
        entries.append({
            "root": root_id, "path": relative.as_posix(), "sha256": pi._bytes_sha(data),
            "bytes": len(data), "role": "evidence", "producer_request_sha256": None,
        })
    if not entries:
        raise RequestBuildError(f"target checkout at {target_root} has no readable files")
    return entries


def _permission_block(job_id: str, *, run_id: str, source_snapshot_sha256: str, now: str) -> dict[str, Any]:
    """D01's tooling profile (``static-repo-project-inspector``) needs no B11 capability beyond
    the default-deny baseline -- there is no ``read-source`` capability definition in this
    registry at all (confirmed 2026-09-24 while researching this module: only credential-use,
    debugger-ptrace, dynamic-testing, fixed-network-destination, package-restore,
    target-execution and target-mutation exist), so an empty requirement is not a placeholder,
    it is the correct requirement for a static-only discovery job. ``pc.evaluate`` with an empty
    ``capabilities`` list and no grants always evaluates to GRANTED with an empty capability set;
    this function asserts that rather than assuming it, so a future capability added to this
    tooling profile's requirements fails loudly here instead of silently under-permissioning."""
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job_id, "capabilities": []}
    decision = pc.evaluate(requirement, [], {
        "run_id": run_id, "job_id": job_id, "source_snapshot_sha256": source_snapshot_sha256,
        "now": now, "registry_ceiling": None})
    if decision["decision"] != pc.GRANTED or decision["capabilities"]:
        raise RequestBuildError(
            "static-repo-project-inspector's empty capability requirement did not evaluate to an "
            "automatic GRANTED with no capabilities -- a capability was added to this tooling "
            "profile's requirements without updating this permission block")
    return {"requirement": requirement, "grants": [], "decision": decision}


def build_request(job_template_id: str, *, run_id: str, job_id: str, attempt_id: str,
                  target_root: Path, source_snapshot_sha256: str, now: str,
                  invoker_id: str = DEFAULT_INVOKER_ID, readable_root_id: str = DEFAULT_READABLE_ROOT,
                  store: SchemaStore | None = None,
                  upstream_root: Path | None = None) -> dict[str, Any]:
    """Builds one ``appsec-review/persona-invocation-request/1.0`` object for ``job_template_id``.

    ``job_id`` has no default -- it is a required, caller-chosen run-scoped invocation identity,
    deliberately kept a *separate* concept from ``job_template_id`` (which lives inside
    ``persona.job_template_id``, not as ``request.job_id``). This module originally defaulted
    ``job_id`` to ``job_template_id`` itself, on the assumption that it matched
    ``discovery_gate.py``'s existing ``root(run_id, 'jobs', job)`` directory-naming convention
    (where ``job`` already is the job template id). That default was a real bug, found and fixed
    while structurally testing this module: ``permission_capabilities.py``'s default-deny
    secret-scanner (``HIGH_ENTROPY_RE``, applied to every context field including ``job_id``)
    incidentally matches any string of 32+ characters that mixes letters, digits and separators
    the way most of this registry's descriptive kebab-case job template ids do --
    ``02-repository-partition-discovery`` (33 chars) is one of exactly two job template ids in the
    current registry that trip it (the other: ``02-api-collection-intelligence-ingest``, 37
    chars). Using it as ``request.job_id`` makes every ``pc.evaluate`` call for D01 raise
    ``PermissionModelError: context carries secret-like material`` before a decision is even
    reached -- not a false accusation about the target repository, a false accusation about this
    module's own identifiers. The test fixtures' own convention already keeps these separate
    (``tests/persona_invocation_support.py``'s ``JOB = "job-b14"`` is a short opaque id, distinct
    from ``TEMPLATE = "04-owasp-validation-worklist"``); this module now follows that convention
    instead of silently reintroducing the landmine through a convenient-looking default. The
    caller (Phase 5b item 5, ``discovery_gate.py``'s wiring, not yet built) picks the actual
    ``job_id`` it will use for the run-tree attempt/permission identity -- this module's job is
    only never to invent an unsafe one on its behalf.

    ``source_snapshot_sha256`` must already be ``sha256:``-prefixed (the caller's responsibility:
    the run's accepted intake record, not something this module may invent). Raises
    ``RequestBuildError`` before returning anything if the job template, its composition, the
    target checkout, or the run's pinned model version is missing or invalid; never partially
    builds a request.

    ``upstream_root`` (optional, D02): a directory of already-accepted upstream artifacts. Every
    regular file beneath it is pinned as an additional ``readable_inputs`` entry under root
    ``UPSTREAM_ROOT_ID`` (role ``evidence``, the only role a producing invocation may read -- these
    are not ``producer_output``: the upstream job is a different job's accepted result, not a
    producer this invocation reviews). The caller must also map ``UPSTREAM_ROOT_ID`` to this same
    directory in its ``PersonaRuntime.readable_roots``. Omitted (the default), the request is
    byte-for-byte what it was before this parameter existed -- D01 is unaffected."""
    store = store or SchemaStore()

    try:
        template = ppa.load_job_template(job_template_id, store)
    except ppa.PromptAssemblyError as exc:
        raise RequestBuildError(str(exc)) from exc
    budget_name = template.get("budget_default")
    limits = PERSONA_BUDGETS.get(budget_name)
    if limits is None:
        raise RequestBuildError(
            f"job template {job_template_id!r} names budget_default {budget_name!r}, which this "
            f"module's PERSONA_BUDGETS table does not define (known: {sorted(PERSONA_BUDGETS)})")

    composition = _composition_block(job_template_id, template, store)
    try:
        records = pi.load_composition(REGISTRY_DIR, composition, store)
    except pi.PersonaRequestError as exc:
        raise RequestBuildError(str(exc)) from exc
    ceiling = pi.claim_ceiling(records["role"], records["tooling_profile"])
    if not ceiling["allowed"]:
        raise RequestBuildError(f"job template {job_template_id!r} composition allows no claim class at all")

    resolved = rc.resolve_model(job_template_id, budget_name)
    alias = resolved.get("model")
    if not alias:
        raise RequestBuildError(f"job template {job_template_id!r} resolves to no model alias")
    try:
        model_identity = mvr.model_identity_for(run_id, alias)
    except mvr.ModelVersionError as exc:
        raise RequestBuildError(f"model identity unavailable: {exc}") from exc

    try:
        outer_prompt = ppa.assemble_outer_prompt(job_template_id, store=store)
    except ppa.PromptAssemblyError as exc:
        raise RequestBuildError(str(exc)) from exc
    readable_inputs = _walk_target(target_root, readable_root_id)
    if upstream_root is not None:
        if UPSTREAM_ROOT_ID == readable_root_id:
            raise RequestBuildError("the upstream root id must differ from the target readable root id")
        readable_inputs = readable_inputs + _walk_target(Path(upstream_root), UPSTREAM_ROOT_ID)
    permission = _permission_block(job_id, run_id=run_id, source_snapshot_sha256=source_snapshot_sha256, now=now)

    request = {
        "schema": pi.REQUEST_ID,
        "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
        "invocation_role": "produce", "invoker_id": invoker_id,
        "outer_prompt": outer_prompt,
        "persona": composition,
        "model": model_identity,
        "tools": [],
        "budget": dict(limits),
        "readable_inputs": readable_inputs,
        "output_root": "outputs/persona", "log_path": "logs/persona",
        "allowed_claim_classes": list(ceiling["allowed"]),
        "prohibited_claim_classes": list(ceiling["prohibited"]),
        "producers": [],
        "permission": permission,
        "permission_fingerprint_sha256": permission["decision"]["fingerprint_material"]["sha256"],
    }
    # Round-trip through plain JSON once, the same normalization persona_invocation.resolve_request
    # applies to every request it reads, so this function never hands back a value resolve_request
    # would itself transform (e.g. a tuple where a list belongs).
    return json.loads(json.dumps(request))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("job_template_id")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--source-snapshot-sha256", required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--job-id", required=True)
    args = parser.parse_args()

    built = build_request(
        args.job_template_id, run_id=args.run_id, job_id=args.job_id, attempt_id=args.attempt_id,
        target_root=Path(args.target_root), source_snapshot_sha256=args.source_snapshot_sha256,
        now=args.now)
    print(json.dumps(built, indent=2, sort_keys=True))
