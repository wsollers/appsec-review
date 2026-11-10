"""Host-side rewind of operator decisions, never repair admission or job execution."""

from __future__ import annotations

from copy import deepcopy
import inspect
import json

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


def inspect_runtime(config, run_root, topology, dispatch_ids, instance):
    """Read in the code-location namespace; a receipt alone cannot establish current liveness."""
    from appsec_review.runtime.release import load_release
    from appsec_review.runtime.repair import (
        code_server_worker_status, current_binding, deployment_identity, stopped_reasons,
    )
    from dagster import RunsFilter

    reasons = list(stopped_reasons(config, run_root))
    runs = {run.run_id: run for run in instance.get_runs(
        filters=RunsFilter(tags={"appsec/application_run_id": run_root.name}))}
    for dispatch_id in sorted(set(dispatch_ids) | set(runs)):
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
    release = load_release(config.runtime.repository_root)
    return {
        "run_id": run_root.name, "binding": current_binding(run_root), "topology": topology,
        "resolved_config_sha256": config.resolved_sha256,
        "release_sha256": release["sha256"] if release else None,
        "deployment": deployment_identity(config.runtime.repository_root), "refusals": reasons,
    }


# Send only this read-only probe to the existing code location, not the host module or new runtime code.
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
                            json.loads(sys.argv[2]), instance)
print(json.dumps(value))
"""


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
            differences = diff_job_outputs(expected, actual, item["job_id"])
            return {"baseline": baseline, "evidence": entry["evidence"],
                    "admitted_control_changes": control_changes,
                    "passed": not failing(differences),
                    "differences": [difference.as_dict() for difference in differences]}
    return None
