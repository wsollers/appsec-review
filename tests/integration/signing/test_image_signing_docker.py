"""A real ContainerExecutor launches only images whose Docker image ID carries a trusted signature.

Builds two tiny local images, signs one with ``sign_image`` and resolves and launches it through a
synthetic catalog loaded by ``load_catalog`` and the real Docker runner. Then retags a second,
different image to the same tag (a substituted image) and checks that the existing pin check, the
signature check and the subject binding each refuse it before any ``docker run``.
"""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import shutil
import tomllib
import uuid

import pytest

from appsec_review.container_runtime import executor as executor_module
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest
from appsec_review.signing import (
    EnvelopeImageVerifier, SignatureVerificationError, image_envelope_path, sign_image,
)

from .conftest import BASE_IMAGE, REPOSITORY_ROOT


TOOL_ID = "tool-signing-fixture"
EXECUTABLE = "/bin/cat"


class RecordingRunner:
    """The executor's real Docker runner, recording every command it is asked to run."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str], timeout: int):
        self.calls.append(tuple(argv))
        return executor_module._default_runner(argv, timeout)

    @property
    def runs(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:2] == ("docker", "run")]


def _image_context(root: Path, marker: str) -> Path:
    root.mkdir(parents=True)
    (root / "marker").write_text(marker + "\n", encoding="utf-8")
    (root / "Dockerfile").write_text(f"FROM {BASE_IMAGE}\nCOPY --chmod=0644 marker /marker\n", encoding="utf-8")
    return root


def _synthetic_repository(root: Path) -> Path:
    (root / "containers" / "tools" / "signing-fixture").mkdir(parents=True)
    policy = REPOSITORY_ROOT / "containers" / "runtime-policy.toml"
    shutil.copyfile(policy, root / "containers" / "runtime-policy.toml")
    values = tomllib.loads(policy.read_text(encoding="utf-8"))
    (root / "containers" / "tools" / "signing-fixture" / "tool.toml").write_text(
        'schema = "appsec-review/tool/1"\n'
        f'id = "{TOOL_ID}"\nname = "signing-fixture"\nversion = "1.0.0"\n'
        f'executable = "{EXECUTABLE}"\n'
        f'network = "{values["network"]}"\nuser = "{values["user"]}"\nmemory = "{values["memory"]}"\n'
        f'cpus = "{values["cpus"]}"\npids_limit = {values["pids_limit"]}\n'
        f'timeout_seconds = {values["timeout_seconds"]}\noutput_bytes = {values["output_bytes"]}\n',
        encoding="utf-8")
    return root


def _pin(repository: Path, tag: str, image_id: str) -> None:
    (repository / "containers" / "catalog.toml").write_text(
        'schema = "appsec-review/container-catalog/1"\n'
        'runtime_policy = "containers/runtime-policy.toml"\n\n'
        f'[[images]]\nid = "{TOOL_ID}"\nstate = "enabled"\nkind = "tool"\nversion = "1.0.0"\n'
        f'tag = "{tag}"\nimage_id = "{image_id}"\n'
        'tool_manifest = "containers/tools/signing-fixture/tool.toml"\n',
        encoding="utf-8")


def _scan(executor: ContainerExecutor, tmp_path: Path, name: str):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    return executor.execute(ExecutionRequest(TOOL_ID, (EXECUTABLE, "/marker"), target,
                                             executor.run_root / name / "scratch"))


def test_executor_launches_only_the_signed_pinned_image(tmp_path, docker, signing_key):
    markers = {name: f"{name}-{uuid.uuid4().hex}" for name in ("a", "b")}
    tag, image_a = docker.build(_image_context(tmp_path / "context-a", markers["a"]), "executor")
    _, image_b = docker.build(_image_context(tmp_path / "context-b", markers["b"]), "executor-substitute")
    assert image_a != image_b

    signatures = tmp_path / "image-signatures"
    envelope_a = sign_image(signing_key.openssl, signing_key.private_key, image_a, signatures)
    verifier = EnvelopeImageVerifier(signatures_dir=signatures, trusted_keys_dir=signing_key.trusted_keys_dir,
                                     openssl=signing_key.openssl)
    repository = _synthetic_repository(tmp_path / "repository")
    run_root = tmp_path / "run"
    run_root.mkdir()
    runner = RecordingRunner()

    def executor() -> ContainerExecutor:
        return ContainerExecutor(load_catalog(repository), run_root, runner=runner, image_verifier=verifier)

    # The signed, pinned image resolves and runs under the real Docker daemon.
    _pin(repository, tag, image_a)
    scanner = executor()
    assert scanner.resolve_image(scanner.catalog.tool(TOOL_ID)) == image_a
    result = _scan(scanner, tmp_path, "signed")
    assert result.exit_code == 0 and result.image_id == image_a and result.image_tag == tag
    assert (run_root / result.stdout_path).read_text(encoding="utf-8") == markers["a"] + "\n"
    assert len(runner.runs) == 1 and image_a in runner.runs[0]

    # A different image now answers to the same tag.
    docker.retag(image_b, tag)
    assert docker.image_id(tag) == image_b

    # The pin still names A: the existing identity check refuses B.
    scanner = executor()
    with pytest.raises(ValueError, match="local image digest mismatch"):
        scanner.resolve_image(scanner.catalog.tool(TOOL_ID))
    with pytest.raises(ValueError, match="local image digest mismatch"):
        _scan(scanner, tmp_path, "pin-mismatch")

    # Whoever moved the pin to B still has no trusted signature over B.
    _pin(repository, tag, image_b)
    scanner = executor()
    with pytest.raises(SignatureVerificationError, match="has no signature envelope"):
        scanner.resolve_image(scanner.catalog.tool(TOOL_ID))
    with pytest.raises(SignatureVerificationError, match="refusing to launch"):
        _scan(scanner, tmp_path, "unsigned")

    # A's genuine envelope stored under B's file name signs A's ID, not B's.
    envelope_b = image_envelope_path(signatures, image_b)
    shutil.copyfile(envelope_a, envelope_b)
    with pytest.raises(SignatureVerificationError, match="signs a different subject"):
        _scan(executor(), tmp_path, "copied-envelope")
    assert len(runner.runs) == 1

    # Control: once B itself is signed by the trusted key, the same configuration launches it.
    envelope_b.unlink()
    sign_image(signing_key.openssl, signing_key.private_key, image_b, signatures)
    result = _scan(executor(), tmp_path, "resigned")
    assert result.exit_code == 0 and result.image_id == image_b
    assert (run_root / result.stdout_path).read_text(encoding="utf-8") == markers["b"] + "\n"
    assert len(runner.runs) == 2 and image_b in runner.runs[1]
