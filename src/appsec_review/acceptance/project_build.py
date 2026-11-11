"""Content gate for the explicitly scoped case-094 project-build walk."""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.jobs.artifact_kinds import binary_role
from appsec_review.jobs.job_project_build.enforcement import validate_enforcement
from appsec_review.jobs.job_project_build.job import SCHEMA
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import safe_path


ROOT = "projects/native/case-094"


def _read(run_root, identity):
    path = safe_path(run_root, identity["path"])
    if not path.is_file() or file_sha256(path) != identity["sha256"]:
        raise ValueError("project-build content artifact identity changed")
    return path


def project_build_content_problems(run_root: Path, attempt: Path | None) -> list[str]:
    if attempt is None:
        return ["project-build attempt is unavailable"]
    try:
        published = accepted_upstream(run_root, "job_project_build")
        if (run_root / published.path).parent.resolve() != attempt.resolve():
            raise ValueError("project-build check does not name the accepted attempt")
        handoff = published.handoff
        outputs = handoff["outputs"]
        accepted = accepted_upstream(run_root, "job_target_analysis_plan")
        if accepted.sha256 != handoff["upstream_handoff_sha256"]["job_target_analysis_plan"]:
            raise ValueError("project-build planning input changed")
        plan = json.loads(_read(
            run_root, accepted.handoff["outputs"]["plan_acceptance.publish_handoff"]["artifact"]).read_bytes())
        actions = plan["build_topology"]["build_actions"]
        scoped = [action for action in actions if action.get("root") == ROOT
                  and action.get("family") == "native" and action.get("build_system") == "cmake"]
        if not scoped or any(action["root"] != ROOT for action in actions):
            return []
        document = json.loads(_read(
            run_root, outputs["acceptance.publish_handoff"]["artifact"]).read_bytes())
        if document["schema"] != SCHEMA:
            raise ValueError("project-build content schema is unsupported")
        receipts = [receipt for receipt in document["probe_receipts"]
                    if receipt["build_unit_id"] == scoped[0]["build_unit_id"]]
        if len(receipts) != 1:
            return ["case-094 requires exactly one accepted native build receipt"]
        receipt = receipts[0]
        problems = []
        binaries = [item for item in receipt["artifacts"] if item.get("kind") == "executable"
                    and item.get("artifact_origin") == "build-output"
                    and item.get("workspace_path", "").startswith(ROOT + "/")]
        if not binaries or not any(binary_role(_read(run_root, item))[0] == "executable" for item in binaries):
            problems.append("case-094 binary is absent from accepted build artifacts")
        proofs = receipt.get("enforcement", [])
        if len(proofs) != 1:
            problems.append("case-094 requires exactly one native enforcement record")
        else:
            validate_enforcement(proofs[0], dispatch=receipt)
            if proofs[0]["status"] != "proven":
                problems.append("case-094 captured invocation enforcement is not proven")
        database = json.loads(_read(run_root, receipt["native_compile_database"]).read_bytes())
        declared = json.loads(_read(run_root, receipt["declared_compile_database"]).read_bytes())
        if not database["entries"] or not declared or any(
                not entry.get("capture_record_sha256") for entry in database["entries"]):
            problems.append("case-094 compile database is empty or lacks captured invocation evidence")
        return problems
    except (OSError, ValueError, KeyError, TypeError) as error:
        return [f"case-094 project-build content is unavailable: {error}"]
