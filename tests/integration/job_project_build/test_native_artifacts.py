"""The job's binary parser and publication handler consume actual compiler products, not magic bytes."""

from __future__ import annotations

import pytest

from appsec_review.jobs.job_project_build.job import _kind, _outputs, _snapshot, _validate_expected_outputs
from appsec_review.storage import file_sha256

from .support import BUILD_UNIT, boundary_run, executor_for, publish_receipt


@pytest.mark.parametrize(("name", "commands", "kind"), [
    ("main.o", (("clang++", "-c", "main.cpp", "-o", "main.o"),), "object"),
    ("app", (("clang++", "main.cpp", "-o", "app"),), "executable"),
    ("libmain.so", (("clang++", "-shared", "-fPIC", "main.cpp", "-o", "libmain.so"),), "shared-library"),
    ("libmain.a", (("clang++", "-c", "main.cpp", "-o", "main.o"),
                   ("ar", "rcs", "libmain.a", "main.o")), "static-library"),
], ids=["object", "executable", "shared-library", "static-library"])
def test_real_native_output_is_parsed_and_published_inside_declared_datasets(tmp_path, name, commands, kind):
    executor = executor_for("native")
    run = boundary_run(tmp_path)
    source = run.workspace / "main.cpp"
    source.write_text("int main() { return 0; }\n", encoding="utf-8")
    before = _snapshot(run.workspace, 10)
    for command in commands:
        result = executor.execute(
            command, workspace=run.workspace, working_directory=".", environment={},
        )
        assert result.exit_code == 0 and not result.timed_out, result.stderr.decode(errors="replace")
    assert file_sha256(source) == before["main.cpp"]
    output = run.workspace / name
    assert _kind(output) == (kind, "ar" if kind == "static-library" else "elf")
    assert _validate_expected_outputs(run.workspace, {"expected_outputs": [name]}) == []
    artifacts = _outputs(run.root, run.workspace, before, 10)
    retained = next(item for item in artifacts if item["workspace_path"] == name)
    assert retained["kind"] == kind and retained["sha256"] == file_sha256(output)
    result, document = publish_receipt(run, {
        "build_unit_id": BUILD_UNIT, "family": "native", "terminal_status": "SUCCEEDED",
        "artifacts": artifacts, "gaps": [],
    })
    assert result["terminal_status"] == "SUCCEEDED"
    assert document["probe_artifact_count"] == len(commands)
