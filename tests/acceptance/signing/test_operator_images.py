"""Operator story: sign a container image with the CLI and launch it only while its signature holds.

``keygen`` creates the operator key and trust anchor, ``sign-image`` signs a freshly built image,
and ``verify-image`` (reading ``[signing]`` from the configuration) accepts it. A rebuild with other
content under the same tag fails ``verify-image``. A separate interpreter whose configuration is
selected only by ``APPSEC_REVIEW_CONFIG`` launches through ``ContainerExecutor`` with the policy
default verifier: it runs the signed image and refuses the unsigned one before any ``docker run``.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

from tests.integration.signing.test_image_signing_docker import (
    EXECUTABLE, TOOL_ID, _image_context, _pin, _synthetic_repository,
)


LAUNCHER = f'''
import json
from pathlib import Path
import sys

from appsec_review.container_runtime import executor as executor_module
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest
from appsec_review.signing import SignatureVerificationError
from appsec_review.signing.policy import default_image_verifier

repository, run_root, target, name = (Path(value) for value in sys.argv[1:5])
runs = []

def runner(argv, timeout):
    if tuple(argv[:2]) == ("docker", "run"):
        runs.append(list(argv))
    return executor_module._default_runner(argv, timeout)

verifier = default_image_verifier()
report = {{"verifier": type(verifier).__name__,
          "signatures_dir": str(getattr(verifier, "signatures_dir", "")),
          "trusted_keys_dir": str(getattr(verifier, "trusted_keys_dir", ""))}}
executor = ContainerExecutor(load_catalog(repository), run_root, runner=runner)
try:
    result = executor.execute(ExecutionRequest({TOOL_ID!r}, ({EXECUTABLE!r}, "/marker"), target,
                                               run_root / str(name) / "scratch"))
except SignatureVerificationError as error:
    report.update(status="refused", error=str(error), runs=runs)
else:
    report.update(status="launched", exit_code=result.exit_code, image_id=result.image_id,
                  stdout=(run_root / result.stdout_path).read_text(encoding="utf-8"), runs=runs)
print(json.dumps(report))
'''


def _launch(operator, repository: Path, name: str) -> dict:
    """Launch the catalog tool in a new interpreter that finds ``[signing]`` via APPSEC_REVIEW_CONFIG."""
    script = operator.root / "launch.py"
    script.write_text(LAUNCHER, encoding="utf-8")
    run_root, target = operator.root / "run", operator.root / "target"
    run_root.mkdir(exist_ok=True)
    target.mkdir(exist_ok=True)
    environment = {**operator.environment, "APPSEC_REVIEW_CONFIG": str(operator.config)}
    completed = operator.run(sys.executable, str(script), str(repository), str(run_root), str(target), name,
                             environment=environment)
    assert completed.returncode == 0, completed.stderr[-3000:]
    report = json.loads(completed.stdout)
    assert report["verifier"] == "EnvelopeImageVerifier"
    assert report["signatures_dir"] == str(operator.image_signatures_dir)
    assert report["trusted_keys_dir"] == str(operator.trusted_keys_dir)
    return report


def test_operator_signs_verifies_and_launches_only_the_signed_image(tmp_path, docker, docker_operator,
                                                                    operator_key):
    operator = docker_operator
    markers = {name: f"{name}-{uuid.uuid4().hex}" for name in ("signed", "rebuilt")}
    tag, signed_id = docker.build(_image_context(tmp_path / "context-signed", markers["signed"]), "operator")

    code, report = operator.signing("sign-image", tag, "--private-key", str(operator.private_key),
                                    "--signatures-dir", str(operator.image_signatures_dir))
    assert code == 0, report
    [row] = report["images"]
    assert row["status"] == "signed" and row["image_id"] == signed_id
    envelope = json.loads(Path(row["envelope"]).read_text(encoding="utf-8"))
    assert [item["key_id"] for item in envelope["signatures"]] == [operator_key]

    # verify-image takes its signature and trust directories from [signing] of the configuration.
    code, report = operator.signing("verify-image", tag)
    assert code == 0, report
    assert report["signatures_dir"] == str(operator.image_signatures_dir)
    assert report["images"][0]["status"] == "verified" and report["images"][0]["image_id"] == signed_id

    repository = _synthetic_repository(tmp_path / "repository")
    _pin(repository, tag, signed_id)
    launched = _launch(operator, repository, "signed")
    assert launched["status"] == "launched", launched
    assert launched["exit_code"] == 0 and launched["image_id"] == signed_id
    assert launched["stdout"] == markers["signed"] + "\n"
    assert len(launched["runs"]) == 1 and signed_id in launched["runs"][0]

    # Different content rebuilt under the same tag has no signature.
    rebuilt_tag, rebuilt_id = docker.build(_image_context(tmp_path / "context-rebuilt", markers["rebuilt"]),
                                           "operator")
    assert rebuilt_tag == tag and rebuilt_id != signed_id
    code, report = operator.signing("verify-image", tag)
    assert code != 0
    [row] = report["images"]
    assert row["status"] == "failed" and row["image_id"] == rebuilt_id
    assert "has no signature envelope" in row["error"]

    # Even with the catalog re-pinned to the rebuilt image, the configured policy refuses to run it.
    _pin(repository, tag, rebuilt_id)
    refused = _launch(operator, repository, "rebuilt")
    assert refused["status"] == "refused", refused
    assert "refusing to launch" in refused["error"] and "has no signature envelope" in refused["error"]
    assert refused["runs"] == []
