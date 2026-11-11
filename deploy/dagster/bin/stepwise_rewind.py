"""Host-side rewind of operator decisions, never repair admission or job execution."""

from __future__ import annotations

from copy import deepcopy
import inspect
import json
from pathlib import PurePosixPath
import re

from appsec_review.acceptance.diff import diff_job_outputs, failing
from appsec_review.acceptance.normalize import digest as normalized_digest, normalize_job_output, normalize_value
from appsec_review.acceptance.state import StateError, valid_corpus_tag
from appsec_review.orchestration.topology import tagged_upstream_handoffs
from appsec_review.runtime.release import digest, read_document
from appsec_review.runtime.repair import (
    PLAN_SCHEMA, REPAIR_SCHEMA, current_binding, verify_publication,
)
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes, reference, safe_path, verify_reference

MODEL_PREFLIGHT_ARTIFACTS = {
    "job_model_connectivity": "steps/connectivity/tasks/verify_models/model-connectivity.json",
    "job_review_intake": "steps/model_preflight/tasks/verify_models/model-preflight.json",
}
SOURCE_HISTORY_EXECUTIONS = {
    "acquire.git_history": ("log", "messages"),
    "resolve_sources.bind_snapshot": ("tree",),
}
DESKTOP_BIND = re.compile(
    r"(/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/[A-Za-z0-9_.-]+/[0-9a-f]{64})/(.+)")


def inspect_runtime(config, run_root, topology, dispatch_ids, instance, *, verify_stops=False):
    """Inspect current liveness in the code location, optionally recording verified stops."""
    from appsec_review.runtime.release import load_release, read_document
    from appsec_review.runtime.repair import (
        code_server_worker_status, current_binding, deployment_identity, stopped_reasons, verify_dispatch_stop,
    )
    from dagster import RunsFilter
    import re

    reasons = []
    dispatch_ids = set(dispatch_ids)
    for path in sorted((run_root / "data/jobs").glob("*/attempts/*/claim.json")):
        claim = read_document(path)
        if claim.get("run_id") != run_root.name:
            raise ValueError("attempt claim belongs to another application run")
        orchestration = claim.get("orchestration", {})
        if orchestration.get("system") == "dagster":
            dispatch_ids.add(orchestration.get("run_id", ""))
    runs = {run.run_id: run for run in instance.get_runs(
        filters=RunsFilter(tags={"appsec/application_run_id": run_root.name}))}
    verified = []
    for dispatch_id in sorted(dispatch_ids | set(runs)):
        if not isinstance(dispatch_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", dispatch_id):
            raise ValueError("invalid Dagster dispatch identity")
        run = runs.get(dispatch_id) or instance.get_run_by_id(dispatch_id)
        if (run is None or run.tags.get("appsec/application_run_id") != run_root.name
                or not run.is_finished):
            reasons.append(f"dispatch {dispatch_id} is absent, foreign or nonterminal")
            continue
        launcher = instance.run_launcher
        if launcher.supports_check_run_worker_health:
            status = launcher.check_run_worker_health(run).status.value
        elif type(launcher).__name__ == "DefaultRunLauncher":
            status = code_server_worker_status(run)
        else:
            status = "UNKNOWN"
        if status not in {"SUCCESS", "NOT_FOUND"}:
            reasons.append(f"dispatch {dispatch_id} worker stop is uncertain: {status}")
            continue
        if verify_stops:
            # Existing immutable receipts remain evidence; live health was checked again above.
            if not (run_root / f"data/recovery/dispatches/{dispatch_id}.json").exists():
                verify_dispatch_stop(config, run_root, dispatch_id, instance=instance)
            verified.append(dispatch_id)
    reasons.extend(stopped_reasons(config, run_root))
    release = load_release(config.runtime.repository_root)
    return {
        "run_id": run_root.name, "binding": current_binding(run_root), "topology": topology,
        "resolved_config_sha256": config.resolved_sha256,
        "release_sha256": release["sha256"] if release else None,
        "deployment": deployment_identity(config.runtime.repository_root), "refusals": reasons,
        "verified_dispatches": verified,
    }


# Send only this operator probe; admission and worker-stop primitives remain the deployed runtime's.
RUNTIME_PROBE = inspect.getsource(inspect_runtime) + """
import json, os, sys
from pathlib import Path
from dagster import DagsterInstance
from appsec_review.config import load_config
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import RunStore
config = load_config(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml"))
root = RunStore(config.runtime.runs_dir).resolve(sys.argv[1])
with DagsterInstance.get() as instance:
    value = inspect_runtime(config, root, describe_wave1(config, builtin_registry()),
                            json.loads(sys.argv[2]), instance, verify_stops=len(sys.argv) > 3 and sys.argv[3] == "verify-stops")
print(json.dumps(value))
"""


def recorded_dispatches(walk, state):
    """Include archived dispatches even after rewind cleared the current launch list."""
    dispatches = {dispatch for item in state.jobs for dispatch in item["dagster_run_ids"]}
    for ref in sorted({json.dumps(replay["evidence"], sort_keys=True)
                       for item in state.jobs for replay in item.get("replays", [])}):
        evidence = read_evidence(walk, json.loads(ref))
        if evidence["state"]["app_run_id"] != state.app_run_id:
            raise StateError("rewind evidence belongs to another application run")
        dispatches.update(dispatch for item in evidence["state"]["jobs"] for dispatch in item["dagster_run_ids"])
    return sorted(dispatches)


def verify_plan(run_root, state, plan, runtime):
    value = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if (plan.get("schema") != PLAN_SCHEMA or plan.get("plan_sha256") != digest(value)
            or plan.get("admissible") is not True or plan.get("refusals")
            or plan.get("successor") is not False):
        raise StateError("rewind requires an intact, admissible, in-place repair plan")
    if plan["run_id"] != state.app_run_id or run_root.name != state.app_run_id:
        raise StateError("repair plan belongs to a different application run")
    binding = current_binding(run_root)
    if not binding or not binding.get("repair"):
        raise StateError("repair plan has not been admitted")
    admitted = read_document(verify_reference(run_root, binding["repair"]))
    if admitted != {**plan, "schema": REPAIR_SCHEMA, "admitted": True}:
        raise StateError("plan is stale or is not the currently admitted repair")
    if (runtime["run_id"] != state.app_run_id or runtime["binding"] != binding
            or runtime["release_sha256"] != binding["release_sha256"]
            or runtime["deployment"] != binding["deployment"]):
        raise StateError("current deployment or run binding differs from the admitted repair")
    if runtime["refusals"]:
        raise StateError("rewind requires verified stopped execution: " + "; ".join(runtime["refusals"]))
    topology = runtime["topology"]
    if topology["graph"] != state.graph or topology["jobs"] != state.topology:
        raise StateError("the packaged topology changed since this walk was initialized")
    ids = [item["job_id"] for item in state.topology]
    if ([item["job_id"] for item in plan["decisions"]] != ids
            or [(item["job_id"], item["name"]) for item in state.jobs]
            != [(item["job_id"], item["name"]) for item in state.topology]
            or plan["dependencies"] != {item["job_id"]: item["dependencies"] for item in state.topology}
            or any(item["action"] not in {"RUN", "INVALIDATE", "REUSE"} for item in plan["decisions"])):
        raise StateError("plan decisions/dependencies do not match the stepwise topology")
    manifest = read_document(run_root / "data/configuration/manifest.json")
    if (runtime["resolved_config_sha256"] != plan["resolved_config_sha256"]
            or manifest["resolved_sha256"] != plan["resolved_config_sha256"]
            or file_sha256(run_root / "data/configuration/resolved.json") != plan["resolved_config_sha256"]
            or file_sha256(run_root / "data/configuration/appsec-review.toml") != manifest["source_sha256"]):
        raise StateError("frozen configuration differs from the admitted repair")
    return binding


def verify_attempts(run_root, state, plan):
    snapshots = plan["attempt_snapshots"]
    for item in state.jobs:
        job_id = item["job_id"]
        attempts = sorted((run_root / f"data/jobs/{job_id}/attempts").glob("attempt_*"))
        snapshot = snapshots.get(job_id)
        if not attempts:
            if snapshot or item["status"] != "pending" or item["dagster_run_ids"]:
                raise StateError(f"{job_id}: state and planned attempts disagree")
            continue
        if not snapshot:
            raise StateError(f"{job_id}: unplanned attempt appeared after admission")
        claim_path = verify_reference(run_root, snapshot["claim"])
        status_path = verify_reference(run_root, snapshot["status"])
        claim = read_document(claim_path)
        if (claim_path.parent != attempts[-1] or status_path.parent != claim_path.parent
                or claim["run_id"] != state.app_run_id or claim["job_id"] != job_id
                or claim["orchestration"].get("system") != "dagster"
                or not item["dagster_run_ids"]
                or claim["orchestration"].get("run_id") != item["dagster_run_ids"][-1]
                or read_document(status_path)["status"] not in {"SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED"}):
            raise StateError(f"{job_id}: stale plan or mismatched current attempt/state")
        if item["status"] == "accepted":
            tagged_upstream_handoffs(run_root, json.dumps({job_id: item["handoff_sha256"]}))
            pointer = read_document(run_root / f"data/jobs/{job_id}/latest.json")
            handoff = read_document(safe_path(run_root, pointer["handoff_path"]))
            if safe_path(run_root, pointer["handoff_path"]).parent != claim_path.parent:
                raise StateError(f"{job_id}: acceptance points at an older attempt")
            verify_publication(run_root, handoff, item["handoff_sha256"])
        decision = next(entry for entry in plan["decisions"] if entry["job_id"] == job_id)
        if decision["action"] == "REUSE" and (
                item["status"] != "accepted" or decision["handoff_sha256"] != item["handoff_sha256"]):
            raise StateError(f"{job_id}: REUSE does not match an operator acceptance")


def read_evidence(walk, ref):
    evidence = read_document(verify_reference(walk, ref))
    for entry in evidence["baselines"].values():
        for value in entry.values():
            verify_reference(walk, value)
    for value in evidence["checks"].values():
        verify_reference(walk, value)
    return evidence


def apply_rewind(root, path, acceptance_root, state, plan, runtime, masks):
    run_root, walk = root / "runs" / state.app_run_id, path.parent
    binding = verify_plan(run_root, state, plan, runtime)
    plan_id = plan["plan_sha256"]
    evidence_path = f"rewinds/{plan_id}/evidence.json"
    existing = walk / evidence_path
    if existing.exists():
        ref = reference(walk, existing)
        evidence = read_evidence(walk, ref)
        if evidence["plan"] != plan or evidence["binding"] != binding:
            raise StateError("rewind evidence conflicts with this admission")
        if evidence["affected"] and all(
                any(entry["plan_sha256"] == plan_id and entry["evidence"] == ref
                    for entry in state.job(job_id).get("replays", []))
                for job_id in evidence["affected"]):
            return False
        if state.as_dict() != evidence["state"]:
            raise StateError("incomplete rewind conflicts with current operator state")
    verify_attempts(run_root, state, plan)
    affected = [entry["job_id"] for entry in plan["decisions"]
                if entry["action"] in {"RUN", "INVALIDATE"}
                and (state.job(entry["job_id"])["status"] != "pending"
                     or state.job(entry["job_id"])["dagster_run_ids"])]
    evidence = {"schema": "appsec-review/stepwise-rewind/1", "plan": plan, "binding": binding,
                "state": deepcopy(state.as_dict()), "affected": affected, "baselines": {}, "checks": {}}
    for job_id in affected:
        item = state.job(job_id)
        check_path = (item.get("check") or {}).get("report")
        if check_path:
            source = safe_path(root, check_path)
            evidence["checks"][job_id] = immutable_bytes(
                walk, f"rewinds/{plan_id}/{job_id}.check.json", source.read_bytes())
        if item["status"] != "accepted":
            continue
        tag = valid_corpus_tag(state.corpus_tag or "")
        key = safe_path(acceptance_root, f"{tag}/{job_id}.json")
        provenance = safe_path(acceptance_root, f"{tag}/{job_id}.provenance.json")
        origin = read_document(provenance)
        claim_path = verify_reference(run_root, plan["attempt_snapshots"][job_id]["claim"])
        identity = {"application_run_id": state.app_run_id, "job_id": job_id, "corpus_tag": tag,
                    "target": state.target, "dagster_run_id": item["dagster_run_ids"][-1],
                    "attempt": claim_path.parent.name, "handoff_sha256": item["handoff_sha256"]}
        document = normalize_job_output(run_root, job_id, masks, attempt_root=claim_path.parent)
        original_claim = claim_path.read_bytes()
        if any(origin.get(key) != value for key, value in identity.items()):
            # Reaccepted jobs retain the original baseline provenance; the new receipt binds their state.
            replay = (item.get("replays") or [{}])[-1]
            reaccepted = replay.get("acceptance")
            if not reaccepted:
                raise StateError(f"{job_id}: accepted key provenance does not match this walk")
            receipt = read_document(verify_reference(walk, reaccepted))
            prior = read_evidence(walk, replay["evidence"])
            baseline = receipt["comparison"]["baseline"]
            if (any(receipt["provenance"].get(key) != value for key, value in identity.items())
                    or receipt["output"] != document or not receipt["comparison"]["passed"]
                    or baseline != prior["baselines"].get(job_id)
                    or key.read_bytes() != verify_reference(walk, baseline["key"]).read_bytes()
                    or provenance.read_bytes() != verify_reference(walk, baseline["provenance"]).read_bytes()):
                raise StateError(f"{job_id}: reacceptance does not match this walk")
            admitted_claim_changes(walk, prior, baseline, job_id, read_document(claim_path),
                                   read_document(key), document, masks)
            advertised_inventory_changes(run_root, walk, baseline, job_id, read_document(claim_path),
                                         read_document(key), document, masks)
            verified_mount_path_changes(run_root, walk, baseline, job_id, read_document(claim_path),
                                        read_document(key), document, masks)
            original_claim = verify_reference(walk, baseline["claim"]).read_bytes()
        if failing(diff_job_outputs(read_document(key), document, job_id)):
            raise StateError(f"{job_id}: existing accepted key differs from the accepted attempt")
        evidence["baselines"][job_id] = {
            "key": immutable_bytes(walk, f"rewinds/{plan_id}/{job_id}.key.json", key.read_bytes()),
            "provenance": immutable_bytes(
                walk, f"rewinds/{plan_id}/{job_id}.provenance.json", provenance.read_bytes()),
            "claim": immutable_bytes(walk, f"rewinds/{plan_id}/{job_id}.claim.json", original_claim),
        }
    ref = immutable_bytes(walk, evidence_path, canonical_json(evidence))
    for job_id in affected:
        item = state.job(job_id)
        item.setdefault("replays", []).append({"plan_sha256": plan_id, "evidence": ref})
        item.update(status="pending", dagster_run_ids=[], check=None, handoff_sha256=None, accepted_at=None)
    state.save(path)
    return True


def admitted_claim_changes(walk, evidence, baseline, job_id, claim, expected, actual, masks):
    """Account only for verified repair bookkeeping in the published claim, not arbitrary hashes."""
    original = read_document(verify_reference(walk, baseline["claim"]))
    planned = evidence["plan"]["unit_decisions"][job_id]
    units = claim.get("unit_reuse", {})
    fallback = {"action": "RUN", "reason": "checkpoint was not eligible in the inspected repair plan"}
    if set(units) != set(planned) or any(
            value != planned[unit] and value != fallback for unit, value in units.items()):
        raise StateError("replay checkpoint decisions differ from the admitted plan")
    left, right = normalize_value(original, masks), normalize_value(claim, masks)
    changes = []
    for key in ("repair_admission_sha256", "unit_reuse"):
        if left.get(key) != right.get(key):
            changes.append({"field": key, "expected": left.get(key), "actual": right.get(key)})
            right[key] = left.get(key)
    if right != left:
        return []
    claim_path = masks.text(f"data/jobs/{job_id}/attempts/{original['attempt_id']}/claim.json")
    old_signature = next((entry for entry in expected["artifacts"] if entry["path"] == claim_path), None)
    new_signature = next((entry for entry in actual["artifacts"] if entry["path"] == claim_path), None)
    if (old_signature is None or new_signature is None
            or old_signature != {"path": claim_path, "kind": "json", "count": len(original),
                                 "sha256": normalized_digest(left)}
            or new_signature != {"path": claim_path, "kind": "json", "count": len(claim),
                                 "sha256": normalized_digest(normalize_value(claim, masks))}):
        raise StateError("claim artifact signature differs from its resolving evidence")
    new_signature.update(old_signature)
    return changes


def advertised_inventory_changes(run_root, walk, baseline, job_id, claim, expected, actual, masks):
    """Allow only unrelated advertised model names in the two model-preflight artifacts."""
    suffix = MODEL_PREFLIGHT_ARTIFACTS.get(job_id)
    if suffix is None:
        return []
    original_claim = read_document(verify_reference(walk, baseline["claim"]))
    documents, signatures, references = [], [], []
    for source_claim, output in ((original_claim, expected), (claim, actual)):
        if source_claim["run_id"] != run_root.name or source_claim["job_id"] != job_id:
            raise StateError("model inventory claim belongs to another run/job")
        path = f"data/jobs/{job_id}/attempts/{source_claim['attempt_id']}/{suffix}"
        masked = masks.text(path)
        found = [entry for entry in output["artifacts"] if entry["path"] == masked]
        if not found:
            return []  # Missing artifacts remain ordinary failing differences.
        raw = [entry for entry in output["volatile"]["artifacts"] if entry["path"] == masked]
        if len(found) != 1 or len(raw) != 1:
            raise StateError("model inventory artifact signatures are ambiguous")
        ref = {**raw[0], "path": path}
        document = read_document(verify_reference(run_root, ref))
        signature = {"path": masked, "kind": "json", "count": len(document),
                     "sha256": normalized_digest(normalize_value(document, masks))}
        if found[0] != signature:
            raise StateError("model inventory artifact signature differs from its resolving bytes")
        documents.append(document)
        signatures.append(found[0])
        references.append(ref)
    old, new = documents
    if old.get("schema") != "appsec-review/model-preflight/1" or new.get("schema") != old["schema"]:
        return []
    projected = deepcopy(new)
    providers = old.get("providers")
    if not isinstance(providers, dict) or set(providers) != set(new.get("providers", {})):
        return []
    configured = {}
    for field in ("required", "not_required"):
        if not isinstance(old.get(field), list) or old[field] != new.get(field):
            return []
        for setting in old[field]:
            if (not isinstance(setting, dict) or not isinstance(setting.get("provider"), str)
                    or not isinstance(setting.get("model"), str)):
                return []
            configured.setdefault(setting["provider"], set()).add(setting["model"])
    changes = []
    for provider, before in providers.items():
        after = new["providers"][provider]
        if not isinstance(before, dict) or not isinstance(after, dict):
            return []
        if before.get("listed") == after.get("listed"):
            continue
        left, right = before.get("listed"), after.get("listed")
        if (not isinstance(left, list) or not isinstance(right, list)
                or any(not isinstance(name, str) or not name for name in [*left, *right])
                or len(set(left)) != len(left) or len(set(right)) != len(right)):
            return []
        checked = before.get("models")
        if (not isinstance(checked, dict) or checked != after.get("models")
                or not configured.get(provider, set()) <= checked.keys()):
            return []
        added, removed = sorted(set(right) - set(left)), sorted(set(left) - set(right))
        if not added and not removed or (set(added) | set(removed)) & (checked.keys() | configured.get(provider, set())):
            return []
        projected["providers"][provider]["listed"] = left
        changes.append({"artifact": signatures[0]["path"], "provider": provider,
                        "added": added, "removed": removed, "previous_count": len(left), "current_count": len(right),
                        "expected_reference": references[0], "actual_reference": references[1]})
    if not changes or projected != old:
        return []  # No other report fields/results may be explained away by inventory drift.
    signatures[1].update(signatures[0])
    return changes


def _mount_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
            or "\\" in value or "\0" in value
            or str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts):
        raise StateError("mount evidence path is not canonical absolute POSIX")
    return PurePosixPath(value)


def _mount_artifact(run_root, output, handoff, path, masks, *, signature=True):
    """Resolve a key's masked path to the exact raw reference in its pinned publication."""
    masked = masks.text(path)
    raw = [entry for entry in output["volatile"]["artifacts"] if entry["path"] == masked]
    published = [entry for entry in handoff["artifacts"] if entry["path"] == path]
    if len(raw) != 1 or len(published) != 1 or {**raw[0], "path": path} != published[0]:
        raise StateError("mount artifact raw reference is missing, ambiguous or differs from publication")
    ref = published[0]
    document = read_document(verify_reference(run_root, ref))
    normalized = normalize_value(document, masks)
    found = [entry for entry in output["artifacts"] if entry["path"] == masked]
    if signature and (len(found) != 1 or found[0] != {
            "path": masked, "kind": "json", "count": len(document), "sha256": normalized_digest(normalized)}):
        raise StateError("mount artifact signature differs from its resolving bytes")
    return document, normalized, found[0] if signature else None, ref


def verified_mount_path_changes(run_root, walk, baseline, job_id, claim, expected, actual, masks):
    """Prove only source-history's Desktop/checkout bind aliases, atomically in a comparison copy."""
    if job_id != "job_source_history_analysis":
        return []
    if all(expected["outputs"].get(unit, {}).get("executions") == actual["outputs"].get(unit, {}).get("executions")
           for unit in SOURCE_HISTORY_EXECUTIONS):
        return []
    original = read_document(verify_reference(walk, baseline["claim"]))
    origin = read_document(verify_reference(walk, baseline["provenance"]))
    if read_document(verify_reference(walk, baseline["key"])) != expected:
        raise StateError("mount baseline key differs from its preserved evidence")
    for key in ("repository_root", "target_root", "source_fingerprint", "resolved_config_sha256"):
        if not original.get(key) or original[key] != claim.get(key):
            raise StateError(f"mount comparison requires unchanged claim {key}")
    if (origin.get("application_run_id") != run_root.name or origin.get("job_id") != job_id
            or origin.get("attempt") != original["attempt_id"]
            or origin.get("target") != original["target_root"]
            or origin.get("dagster_run_id") != original["orchestration"].get("run_id")):
        raise StateError("mount baseline provenance differs from the original claim")
    repository = _mount_path(original["repository_root"])
    target = _mount_path(original["target_root"])
    if target.parent != repository / "targets" or run_root.parent.name != "runs":
        return []
    native = _mount_path(run_root.parent.parent.as_posix())
    pointer = read_document(run_root / f"data/jobs/{job_id}/latest.json")
    handoffs, claim_refs = [], []
    for source_claim, output, sha in ((original, expected, origin["handoff_sha256"]),
                                      (claim, actual, pointer["handoff_sha256"])):
        attempt = f"data/jobs/{job_id}/attempts/{source_claim['attempt_id']}"
        if (source_claim["run_id"] != run_root.name or source_claim["job_id"] != job_id
                or not re.fullmatch(r"attempt_[0-9]{4}", source_claim["attempt_id"])
                or source_claim["attempt_path"] != attempt):
            raise StateError("mount claim belongs to a different run/job/attempt")
        handoff_path = safe_path(run_root, attempt + "/handoff.json")
        if file_sha256(handoff_path) != sha:
            raise StateError("mount publication digest differs from its provenance")
        handoff = read_document(handoff_path)
        if (handoff.get("status") != "ACCEPTED" or handoff["resolving_paths"]["attempt"] != attempt
                or any(handoff.get(key) != source_claim[key] for key in
                       ("run_id", "job_id", "attempt_id", "source_fingerprint", "resolved_config_sha256"))
                or (source_claim is claim and pointer["handoff_path"] != attempt + "/handoff.json")):
            raise StateError("mount publication differs from the claimed attempt")
        verify_publication(run_root, handoff, sha)
        raw_claim, _, _, claim_ref = _mount_artifact(
            run_root, output, handoff, attempt + "/claim.json", masks, signature=False)
        if raw_claim != source_claim:
            raise StateError("mount claim differs from its published raw reference")
        handoffs.append(handoff)
        claim_refs.append(claim_ref)

    aliases, changes, signatures, output_mounts = ({}, {}), [], [], []

    def project_execution(before, after, projected, unit, name):
        step, task = unit.split(".")
        mounts = []
        for source_claim, execution in ((original, before), (claim, after)):
            receipt = (f"{source_claim['attempt_path']}/steps/{step}/tasks/{task}"
                       f"/scratch/executions/{name}/execution.json")
            if (execution.get("schema") != "appsec-review/container-execution/1"
                    or execution.get("tool_id") != "tool-git" or execution.get("receipt_path") != receipt
                    or not isinstance(execution.get("mounts"), list) or len(execution["mounts"]) != 3):
                return None
        for index, (destination, readonly) in enumerate((("/target", True), ("/scratch", False), ("/gitdir", True))):
            suffixes = []
            for source_claim, execution in ((original, before), (claim, after)):
                mount = execution["mounts"][index]
                root = repository / ("targets" if destination == "/target" else "runs")
                suffix = (target.name if destination == "/target" else
                          f"{run_root.name}/{source_claim['attempt_path']}/steps/{step}/tasks/{task}/scratch/"
                          + (f"executions/{name}" if destination == "/scratch" else "gitdir"))
                if (not isinstance(mount, dict)
                        or set(mount) != {"source", "runtime_source", "target", "read_only"}
                        or mount["source"] != str(root / suffix) or mount["target"] != destination
                        or mount["read_only"] is not readonly):
                    return None
                _mount_path(mount["source"])
                _mount_path(mount["runtime_source"])
                suffixes.append(suffix)
            left, right = before["mounts"][index], after["mounts"][index]
            host_root = str(native / ("targets" if destination == "/target" else "runs"))
            runtime_roots = []
            for side, (mount, suffix) in enumerate(zip((left, right), suffixes)):
                runtime_root = host_root
                if mount["runtime_source"] != f"{host_root}/{suffix}":
                    match = DESKTOP_BIND.fullmatch(mount["runtime_source"])
                    if not match or match[2] != suffix:
                        return None
                    runtime_root = match[1]
                if aliases[side].setdefault(str(root), runtime_root) != runtime_root:
                    return None
                runtime_roots.append(runtime_root)
            if runtime_roots[0] != runtime_roots[1] and host_root not in runtime_roots:
                # This proof does not authorize remapping one Desktop alias to another.
                return None
            projected["mounts"][index]["runtime_source"] = masks.text(left["runtime_source"])
            mounts.append({"field": f"mounts[{index}].runtime_source", "source": left["source"],
                           "actual_source": right["source"], "target": destination, "read_only": readonly,
                           "expected_runtime_source": left["runtime_source"],
                           "actual_runtime_source": right["runtime_source"], "logical_root": str(root),
                           "expected_runtime_root": runtime_roots[0], "actual_runtime_root": runtime_roots[1],
                           "expected_relative_suffix": suffixes[0], "actual_relative_suffix": suffixes[1]})
        return mounts

    def account(before, after, projected, mounts):
        if projected != before[1]:
            return False
        signatures.append((after[2], before[2]))
        changes.append({"artifact": before[2]["path"], "expected_reference": before[3], "actual_reference": after[3],
                        "expected_signature": deepcopy(before[2]), "actual_signature": deepcopy(after[2]),
                        "expected_claim_reference": claim_refs[0], "actual_claim_reference": claim_refs[1],
                        "provenance": baseline["provenance"], "mounts": mounts})
        return True

    for unit, names in SOURCE_HISTORY_EXECUTIONS.items():
        step, task = unit.split(".")
        suffix = f"steps/{step}/tasks/{task}/result.json"
        pair = [_mount_artifact(run_root, output, handoff, f"{source_claim['attempt_path']}/{suffix}", masks)
                for source_claim, output, handoff in ((original, expected, handoffs[0]), (claim, actual, handoffs[1]))]
        before, after = pair
        for value, output in ((before, expected), (after, actual)):
            executions = value[0].get("executions")
            if not isinstance(executions, list) or len(executions) != len(names):
                return []
            if normalize_value(executions, masks) != output["outputs"].get(unit, {}).get("executions"):
                raise StateError("mount output execution copy differs from its raw artifact")
        projected, mounts = deepcopy(after[1]), []
        for index, name in enumerate(names):
            left, right = before[0]["executions"][index], after[0]["executions"][index]
            mapped = project_execution(left, right, projected["executions"][index], unit, name)
            if not mapped:
                return []
            mounts.extend({**entry, "field": f"executions[{index}].{entry['field']}"} for entry in mapped)
            for mount_index in range(3):
                output_mounts.append((actual["outputs"][unit]["executions"][index]["mounts"][mount_index],
                                      masks.text(left["mounts"][mount_index]["runtime_source"])))
            if unit == "acquire.git_history":
                copies = [_mount_artifact(run_root, output, handoff, execution["receipt_path"], masks)
                          for output, handoff, execution in ((expected, handoffs[0], left), (actual, handoffs[1], right))]
                for value, execution in zip(copies, (left, right)):
                    if any(value[0][key] != execution[key] for key in value[0].keys() & execution.keys()):
                        raise StateError("mount execution receipt differs from its result copy")
                copy_projection = deepcopy(copies[1][1])
                copy_mapped = project_execution(copies[0][0], copies[1][0], copy_projection, unit, name)
                if not copy_mapped or not account(*copies, copy_projection, copy_mapped):
                    return []
        if not account(before, after, projected, mounts):
            return []
    native_roots = {str(native / "targets"), str(native / "runs")}
    for side in aliases:
        roots = [value for value in side.values() if value not in native_roots]
        if len(set(roots)) != len(roots) or len({PurePosixPath(root).parent for root in roots}) > 1:
            return []
    # No mutation until every copy, raw pin, suffix and remaining normalized byte has matched.
    for new_signature, old_signature in signatures:
        new_signature.update(old_signature)
    for mount, value in output_mounts:
        mount["runtime_source"] = value
    return changes


def replay_comparison(run_root, walk, state, item, attempt, document, masks):
    """Use the archived key, not a mutable corpus file; never reclass semantic differences."""
    replays = item.get("replays", [])
    if not replays:
        return None
    evidence = read_evidence(walk, replays[-1]["evidence"])
    if (evidence["state"]["app_run_id"] != state.app_run_id
            or item["job_id"] not in evidence["affected"]
            or current_binding(run_root) != evidence["binding"]):
        raise StateError("replay belongs to a different walk or superseded repair binding")
    if attempt is None:
        raise StateError("replay has no current attempt")
    claim = read_document(attempt / "claim.json")
    previous = next(job for job in evidence["state"]["jobs"] if job["job_id"] == item["job_id"])
    if (claim["run_id"] != state.app_run_id or claim["job_id"] != item["job_id"]
            or claim["repair_admission_sha256"] != evidence["binding"]["repair"]["sha256"]
            or claim["orchestration"].get("run_id") != item["dagster_run_ids"][-1]
            or item["dagster_run_ids"][-1] in previous["dagster_run_ids"]):
        raise StateError("check requires a fresh dispatch/attempt under the admitted repair")
    pointer = read_document(run_root / f"data/jobs/{item['job_id']}/latest.json")
    tagged_upstream_handoffs(run_root, json.dumps({item["job_id"]: pointer["handoff_sha256"]}))
    handoff_path = safe_path(run_root, pointer["handoff_path"])
    if handoff_path.parent != attempt:
        raise StateError("replay is not the current accepted runtime publication")
    verify_publication(run_root, read_document(handoff_path), pointer["handoff_sha256"])
    for entry in reversed(replays):
        archived = read_evidence(walk, entry["evidence"])
        baseline = archived["baselines"].get(item["job_id"])
        if baseline:
            expected = read_document(verify_reference(walk, baseline["key"]))
            actual = deepcopy(document)
            control_changes = admitted_claim_changes(
                walk, evidence, baseline, item["job_id"], claim, expected, actual, masks)
            inventory_changes = advertised_inventory_changes(
                run_root, walk, baseline, item["job_id"], claim, expected, actual, masks)
            mount_changes = verified_mount_path_changes(
                run_root, walk, baseline, item["job_id"], claim, expected, actual, masks)
            differences = diff_job_outputs(expected, actual, item["job_id"])
            return {"baseline": baseline, "evidence": entry["evidence"],
                    "admitted_control_changes": control_changes,
                    "advertised_inventory_changes": inventory_changes,
                    "verified_mount_path_changes": mount_changes,
                    "passed": not failing(differences),
                    "differences": [difference.as_dict() for difference in differences],
                    "unadjusted_differences": [
                        difference.as_dict() for difference in diff_job_outputs(expected, document, item["job_id"])]}
    return None
