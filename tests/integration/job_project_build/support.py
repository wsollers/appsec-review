"""Resolve signed local test images without rewriting production host bindings."""

from __future__ import annotations

from dataclasses import dataclass, replace
from fnmatch import fnmatch
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.config import AppConfig, load_config
from appsec_review.config.host_pins import host_pins_path
from appsec_review.container_runtime import BuildContainerExecutor, load_catalog, profiles_from_settings
from appsec_review.container_runtime.build_executor import _run
from appsec_review.jobs.job_image_pin_verification.pins import inspect_image
from appsec_review.jobs.job_project_build.datasets import DATASETS
from appsec_review.jobs.job_project_build.job import BUILD_FAMILIES, STATIC_LANES, build_job
from appsec_review.signing import EnvelopeImageVerifier, OpenSSL, SignatureVerificationError
from appsec_review.storage import file_sha256


ROOT = Path(__file__).resolve().parents[3]
BUILD_UNIT = "build-unit-" + "a" * 20
PROFILES = ("android", "dotnet", "go", "java", "native", "node", "php", "python", "rust", "wasm")


def host_config() -> AppConfig:
    if not host_pins_path(ROOT).is_file():
        pytest.skip("missing operator-owned deploy/dagster/host-pins.toml")
    return load_config(ROOT / "appsec-review.toml")


def require_image(config: AppConfig, tag: str) -> tuple[str, EnvelopeImageVerifier]:
    if shutil.which("docker") is None:
        pytest.skip(f"missing Docker CLI for {tag}")
    inspected = inspect_image(_run, tag)
    if inspected["state"] != "present":
        pytest.skip(f"test image {tag} is {inspected['state']}: {inspected['detail']}")
    image_id = inspected["resolved_image_id"]
    assert isinstance(image_id, str)
    signing = config.signing
    verifier = EnvelopeImageVerifier(
        signatures_dir=signing.image_signatures_dir, trusted_keys_dir=signing.trusted_keys_dir,
        openssl=OpenSSL(str(signing.openssl)),
    )
    try:
        verifier.verify(image_id, reference=tag)
    except SignatureVerificationError as error:
        pytest.skip(f"missing valid signature for {tag}: {error}")
    return image_id, verifier


def executor_for(family: str, *, timeout: int = 60) -> BuildContainerExecutor:
    config = host_config()
    profile = profiles_from_settings(config.job("job_project_build").settings["profiles"])[family]
    image_id, verifier = require_image(config, profile.tag)
    profile = replace(profile, image_id=image_id)
    executor = BuildContainerExecutor(
        profile, timeout_seconds=timeout, output_bytes=1024 * 1024,
        network="none", network_offline=True, image_verifier=verifier,
    )
    executor.resolve()
    return executor


def require_capture_scanner() -> str:
    config = host_config()
    catalog = load_catalog(ROOT, resolved_config={"configuration_host_pins": config.host_pins.record()})
    tool = catalog.tool("tool-gitleaks")
    image_id, _verifier = require_image(config, tool.tag)
    return image_id


@dataclass(frozen=True)
class BoundaryRun:
    root: Path
    workspace: Path
    attempt: Path

    def context(self):
        config = host_config().job("job_project_build")
        return SimpleNamespace(job=SimpleNamespace(
            run_root=self.root, run_id="2026-01-01-0001", attempt_id="attempt_0001",
            attempt_root=self.attempt, config=config, source_fingerprint="f" * 64,
        ))


def boundary_run(tmp_path: Path) -> BoundaryRun:
    root = tmp_path / "run"
    workspace = root / "data/build/probes" / BUILD_UNIT / "attempts/attempt_0001/probe-001/workspace"
    workspace.mkdir(parents=True)
    attempt = root / "data/jobs/job_project_build/attempts/attempt_0001"
    return BoundaryRun(root, workspace, attempt)


def assert_declared_files(run: BoundaryRun) -> None:
    for path in run.root.rglob("*"):
        if path.is_file():
            assert not path.is_symlink(), path
            relative = path.relative_to(run.root).as_posix()
            assert any(fnmatch(relative, pattern) for dataset in DATASETS for pattern in dataset.artifacts), relative
    assert set(run.root.parent.iterdir()) == {run.root}


def publish_receipt(run: BoundaryRun, receipt):
    context = run.context()
    outputs = {"plan.load_recipes": {
        "actions": [], "execution_graph": {"edges": []}, "processing_decisions": [],
    }}
    for family in BUILD_FAMILIES:
        outputs[f"image.{family}"] = {"entries": [], "gaps": []}
        outputs[f"probe.{family}"] = {
            "receipts": [receipt] if family == "native" else [],
            "gaps": receipt["gaps"] if family == "native" else [],
        }
        outputs[f"build_dispatch.{family}"] = {"dispatches": [], "gaps": []}
    for lane in STATIC_LANES:
        outputs[f"static_dispatch.{lane}"] = {"dispatches": [], "gaps": []}
    context.unit_id = "acceptance.publish_handoff"
    context.output = outputs.__getitem__
    handler = next(unit.handler for unit in build_job().units if unit.unit_id == context.unit_id)
    result = handler(context)
    artifact = result["artifact"]
    path = run.root / artifact["path"]
    assert file_sha256(path) == artifact["sha256"]
    document = json.loads(path.read_bytes())
    declaration = next(item for item in DATASETS if item.output_kind == "project_build_dispatch")
    assert document["schema"] == declaration.schema
    assert any(fnmatch(artifact["path"], pattern) for pattern in declaration.artifacts)
    assert document["probe_receipts"] == [receipt]
    assert_declared_files(run)
    return result, document
