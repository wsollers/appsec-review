"""Replay a signed-tool recording and check the unit tier's unchanged diagnostic example."""

from __future__ import annotations

import ast
import hashlib
import json

from .fixture_recording import FIXTURE, diagnostic_recording, normalized_diagnostic
from .support import ROOT, assert_declared_files, boundary_run, executor_for


def test_pinned_compiler_matches_recorded_unit_diagnostic(tmp_path):
    executor = executor_for("native")
    unit_source = ROOT / "tests/unit/job_project_build/test_repair.py"
    tree = ast.parse(unit_source.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "test_stderr_classification_never_proposes_an_image_repair")
    parameters, = function.decorator_list
    recorded = ast.literal_eval(parameters.args[1].elts[1].elts[0])
    provenance_path = FIXTURE.with_name(FIXTURE.name + ".provenance.json")
    provenance = json.loads(provenance_path.read_bytes())
    assert provenance["image_id"] == executor.profile.image_id, "image changed: regenerate the fixture explicitly"
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == provenance["output_sha256"]
    assert normalized_diagnostic(FIXTURE.read_bytes()) == recorded
    run = boundary_run(tmp_path)
    stderr, observed = diagnostic_recording(executor, run.workspace)
    assert observed == provenance
    assert normalized_diagnostic(stderr) == recorded
    assert_declared_files(run)
