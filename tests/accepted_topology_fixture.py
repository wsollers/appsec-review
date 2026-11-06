"""Publish a real accepted plan and bound refinement for a directly executed synthetic dispatch."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from appsec_review.config import load_config
from appsec_review.jobs.build_topology import (
    compile_build_topology, refine_build_topology, topology_evidence_bundle,
)
from appsec_review.jobs.build_topology_artifacts import bind_actions
from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference
from tests.test_job_runtime import write_config


def accept_isolated_dispatch(root: Path, target: Path, dispatch: Mapping[str, Any],
                             descriptors: Sequence[str], *,
                             releases: Mapping[str, str]) -> tuple[Path, dict[str, Any]]:
    """Return the accepting run root and the dispatch bound to its accepted refinement.

    Direct execution is admitted only through ``guard_action``; the plan is produced by a real
    ``job_target_analysis_plan`` handoff whose descriptor evidence resolves to target bytes.
    """
    documents = []
    for relative in descriptors:
        data = (target / relative).read_bytes()
        documents.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(),
                          "content": data.decode("utf-8"), "size_bytes": len(data)})
    source = {key: copy.deepcopy(value) for key, value in dispatch.items() if key != "image"}
    source.update(recipe=None,
                  markers=[{key: documents[0][key] for key in ("path", "sha256", "size_bytes")}],
                  descriptor_package={"documents": documents, "bounds": {}, "gaps": []})
    fingerprint = dispatch["source_fingerprint"]
    graph = compile_build_topology([source], source_fingerprint=fingerprint)
    plan = {
        "schema": PLAN_SCHEMA, "source_fingerprint": fingerprint,
        "build_topology": {
            "executable_graph": graph, "build_actions": [source],
            "evidence_bundle": topology_evidence_bundle([source], source_fingerprint=fingerprint),
            "planning_refinement": refine_build_topology(graph, [source]),
        },
    }
    root.mkdir(parents=True)
    config_path = write_config(root)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write('\n[jobs.job_target_analysis_plan]\nname = "synthetic accepted source producer"\n')
    config = load_config(config_path)

    def publish(context):
        path = context.job.attempt_root / "source-plan.json"
        atomic_json(path, plan)
        return {"artifact": reference(context.job.run_root, path), "terminal_status": "SUCCEEDED"}

    job = Job("job_target_analysis_plan", "synthetic accepted source producer", lambda _: {},
              units=(Unit("plan_acceptance.publish_handoff", publish),))
    outcome = JobRunner(config).run(job, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    return run_root, rebind_dispatch(run_root, dispatch, releases=releases)


def rebind_dispatch(run_root: Path, dispatch: Mapping[str, Any], *,
                    releases: Mapping[str, str]) -> dict[str, Any]:
    """Accept a new refinement when release identities change, as a replanned run would."""
    return bind_actions(run_root, [dispatch], releases=dict(releases))[0]
