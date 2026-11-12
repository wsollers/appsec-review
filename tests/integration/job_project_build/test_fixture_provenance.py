"""Drift check for the unit tier's inline compiler diagnostic; provenance is never invented."""

from __future__ import annotations

import ast
import hashlib
import json
import tomllib

import pytest

from .support import ROOT, assert_declared_files, boundary_run, executor_for


def test_pinned_compiler_matches_recorded_unit_diagnostic(tmp_path):
    executor = executor_for("native")
    unit_source = ROOT / "tests/unit/job_project_build/test_repair.py"
    tree = ast.parse(unit_source.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "test_stderr_classification_never_proposes_an_image_repair")
    parameters, = function.decorator_list
    recorded = ast.literal_eval(parameters.args[1].elts[1].elts[0])
    provenance_path = unit_source.with_name(unit_source.name + ".provenance.json")
    if not provenance_path.is_file():
        pytest.skip(
            "missing verified compiler diagnostic provenance: "
            "tests/unit/job_project_build/test_repair.py.provenance.json; unit fixtures are owned by the unit walk"
        )
    provenance = json.loads(provenance_path.read_bytes())
    source = b"int main() { return 0; }\n"
    command = ("clang++", "-fno-such", "-c", "main.cpp", "-o", "main.o")
    input_bytes = json.dumps(
        {"argv": command, "main.cpp": source.decode()}, sort_keys=True, separators=(",", ":"),
    ).encode()
    catalog = tomllib.loads((ROOT / "containers/catalog.toml").read_text())
    image = next(item for item in catalog["images"] if item["id"] == "audit-buildenv-cpp")
    assert provenance == {
        "tool_id": image["id"], "image_id": executor.profile.image_id,
        "tool_version": image["version"], "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "output_sha256": hashlib.sha256(recorded.encode()).hexdigest(),
    }
    run = boundary_run(tmp_path)
    (run.workspace / "main.cpp").write_bytes(source)
    result = executor.execute(command, workspace=run.workspace, working_directory=".", environment={})
    assert result.exit_code != 0 and not result.timed_out
    normalized = result.stderr.decode().strip().replace("clang++:", "clang:", 1)
    assert normalized == recorded
    assert hashlib.sha256(normalized.encode()).hexdigest() == provenance["output_sha256"]
    assert_declared_files(run)
