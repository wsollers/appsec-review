"""Manual process-boundary inventory check; no containers, targets or model services.

Prerequisites: Linux/private test storage and repository test dependencies.
Explicit invocation only; each spawned publication must stop within 15 seconds.
"""

import json
import multiprocessing
import os
from pathlib import Path

import pytest

from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import accepted_handoff
from appsec_review.runtime.datasets import read_dataset_contract
from appsec_review.storage import atomic_json
from tests.test_inventory_publication import SNAPSHOT, _fixture


def _publish(root: str, interrupted: bool) -> None:
    import appsec_review.runtime.runner as module

    path = Path(root)
    path.mkdir()
    runner, job, target = _fixture(path, "strict")
    original = module.atomic_json

    def write(destination, value):
        original(destination, value)
        if interrupted and destination.name == "latest.json":
            os._exit(71)

    module.atomic_json = write
    runner.run(job, target_root=target, source_fingerprint=SNAPSHOT)


@pytest.mark.time_budget(30, reason="One spawned inert publication and a parent-process strict audit")
@pytest.mark.parametrize("interrupted", (False, True), ids=("committed", "pointer-interrupted"))
def test_fresh_process_inventory_accounts_for_publication_crash(tmp_path, interrupted):
    process = multiprocessing.get_context("spawn").Process(
        target=_publish, args=(str(tmp_path / "child"), interrupted))
    process.start()
    process.join(15)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("publication exceeded the declared process bound")
    assert process.exitcode == (71 if interrupted else 0)
    root, = (tmp_path / "child/runs").glob("????-??-??-????")
    attempt = root / "data/jobs/job_fixture/attempts/attempt_0001"
    claim = json.loads((attempt / "claim.json").read_bytes())
    steps, declarations = read_dataset_contract(claim["dataset_contract"], "job_fixture")
    assert (attempt / "published.json").exists() is not interrupted
    inputs = InventoryInputs(
        root, root.name, SNAPSHOT,
        {} if interrupted else {"job_fixture": steps},
        {} if interrupted else {"job_fixture": declarations}, {},
        {} if interrupted else {"job_fixture": accepted_handoff(root, "job_fixture")}, {}, (),
        file_job_steps={"job_fixture": steps}, file_declarations={"job_fixture": declarations})
    report = build_inventory(inputs)
    assert report["audit"]["status"] == "PASSED", report["audit"]["violations"]
    assert report["run_tree"]["scratch_audited"]
    assert report["file_ownership"]
    if interrupted:
        assert not any(row["job_id"] == "job_fixture" for row in report["rows"])
    atomic_json(root / "data/recovery/unknown.json", {})
    assert build_inventory(inputs)["audit"]["status"] == "FAILED"
