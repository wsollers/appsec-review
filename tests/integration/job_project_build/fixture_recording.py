"""Explicit regeneration of the signed-image diagnostic recording, never during a test."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import tomllib

from appsec_review.container_runtime import BuildContainerExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json

from .support import ROOT, boundary_run, executor_for


FIXTURE = Path(__file__).with_name("fixtures") / "compiler-unknown-argument.stderr"
SOURCE = "int main() { return 0; }\n"
COMMAND = ("clang++", "-fno-such", "-c", "main.cpp", "-o", "main.o")


def normalized_diagnostic(raw: bytes) -> str:
    return raw.decode("utf-8").strip().replace("clang++:", "clang:", 1)


def diagnostic_recording(executor: BuildContainerExecutor, workspace: Path) -> tuple[bytes, dict]:
    (workspace / "main.cpp").write_text(SOURCE, encoding="utf-8")
    version = executor.execute(
        ("clang++", "--version"), workspace=workspace, working_directory=".", environment={},
    )
    assert version.exit_code == 0 and not version.timed_out, version.stderr
    assert not version.stdout_truncated
    result = executor.execute(COMMAND, workspace=workspace, working_directory=".", environment={})
    assert result.exit_code != 0 and not result.timed_out
    assert not result.stderr_truncated and result.stdout == b""
    assert not (workspace / "main.o").exists()
    catalog = tomllib.loads((ROOT / "containers/catalog.toml").read_text())
    image = next(item for item in catalog["images"] if item["id"] == "audit-buildenv-cpp")
    assert executor.profile.tag == image["tag"]
    inputs = canonical_json({"argv": COMMAND, "main.cpp": SOURCE})
    return result.stderr, {
        "tool_id": image["id"], "image_id": executor.profile.image_id,
        "tool_version": version.stdout.decode("utf-8").splitlines()[0],
        "catalog_version": image["version"],
        "input_sha256": hashlib.sha256(inputs).hexdigest(),
        "output_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "normalization": "clang-driver-name/1",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.parse_args()
    executor = executor_for("native")
    with tempfile.TemporaryDirectory(prefix="project-build-recording-", dir=ROOT / "test/tmp") as scratch:
        run = boundary_run(Path(scratch))
        stderr, provenance = diagnostic_recording(executor, run.workspace)
        atomic_bytes(FIXTURE, stderr)
        atomic_json(FIXTURE.with_name(FIXTURE.name + ".provenance.json"), provenance)
    print(json.dumps(provenance, indent=2))


if __name__ == "__main__":
    main()
