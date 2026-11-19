"""Bounded failure diagnosis over real admitted controller transactions, without tools."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from appsec_review.jobs.build_iterations import BuildIterations, IterationOutcome, read_reference
from appsec_review.jobs.build_topology_artifacts import bind_actions
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import immutable_bytes
from tests.accepted_topology_fixture import accept_isolated_dispatch
from tests.test_build_topology_refinement import accepted_native
from tests.unit.job_build_iteration.test_workspace_resume import _invoke, _iterations
from tests.unit.job_language_build.support import RELEASES, real_job


def _controller(tmp_path, family, bound, *, invalid_setting=None):
    settings = deepcopy(dict(real_job().settings))
    key = "jvm" if family == "java" else family
    if bound is not None:
        settings[key] = {**settings[key], "diagnostic_tail_bytes": bound}
    if invalid_setting == "missing-family":
        settings.pop(key)
    elif invalid_setting == "missing-option":
        settings[key].pop("diagnostic_tail_bytes")
    elif invalid_setting == "negative":
        settings[key]["diagnostic_tail_bytes"] = -1
    elif invalid_setting == "boolean":
        settings[key]["diagnostic_tail_bytes"] = True
    if family == "native":
        runner, root, graph, action = accepted_native(tmp_path)
        original = _iterations(runner, root, graph, action)
        target = original.target
        configuration = {**original.configuration, "settings": settings}
        releases = runner.config.review_policy.releases.view()
    else:
        system, descriptor, contents, command = {
            "python": ("pyproject", "pyproject.toml", '[build-system]\nbuild-backend="setuptools.build_meta"\n',
                       ["python3", "-m", "build"]),
            "php": ("composer", "composer.json", '{"name":"example/app"}', ["composer", "install"]),
            "node": ("node", "package.json", '{"name":"app","scripts":{"build":"tsc"}}',
                     ["npm", "run", "build"]),
            "java": ("maven", "pom.xml", "<project><modelVersion>4.0.0</modelVersion>"
                     "<groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>",
                     ["mvn", "-B", "-DskipTests", "package"]),
            "go": ("go", "go.mod", "module example.test/app\n\ngo 1.23\n", ["go", "build", "."]),
            "dotnet": ("dotnet", "App.csproj", '<Project Sdk="Microsoft.NET.Sdk">'
                       '<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                       ["dotnet", "build", "App.csproj"]),
        }[family]
        target = tmp_path / "source"
        target.mkdir()
        (target / descriptor).write_text(contents)
        uid = "build-unit-" + "1" * 20
        action = {
            "build_unit_id": uid, "family": family, "root": ".", "build_system": system,
            "source_fingerprint": source_fingerprint(target),
            "image": {"image_id": "sha256:" + "a" * 64},
            "recipe": {
                "schema": "appsec-review/build-recipe/1", "build_unit_id": uid,
                "image_profile": family, "source_dir": ".", "build_dir": "build",
                "system_packages": [], "environment": (
                    {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"} if family == "go" else {}),
                "dependency_files": [descriptor], "configure_commands": [],
                "build_commands": [command], "expected_outputs": ["build"],
                "network_required": False, "reason": "synthetic failed build"},
        }
        releases = RELEASES
        root, action = accept_isolated_dispatch(
            tmp_path / "admission", target, action, [descriptor], releases=releases)
        if family == "go":
            policy = {
                "schema": "appsec-review/build-selection-policy/1", "policy_id": "fixture/1",
                "ambiguity_policy": "block", "rules": [{
                    "selectors": {"build_system": "go"}, "axes": {"os": "linux", "isa": "x86_64"},
                    "provenance": "synthetic offline test"}]}
            action, = bind_actions(root, [action], policy=policy, releases=releases)
        graph = load_accepted_plan(root)["build_topology"]["executable_graph"]
        configuration = {"settings": settings}
    return BuildIterations(
        root, target, graph, [action], configuration=configuration, releases=releases,
        execution_identity="synthetic-failure-reader/1", output_policy_identity="synthetic-outputs/1"), action


class _ObservedReader:
    def __init__(self, stream, mode, observations):
        self.stream, self.mode, self.observations = stream, mode, observations
        self.positioned = False

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def seek(self, offset, whence=0):
        self.positioned = True
        return self.stream.seek(offset, whence)

    def read(self, size=-1):
        position = self.stream.tell()
        value = self.stream.read(size)
        # Integrity hashing streams the complete file separately; observe only diagnostic reads.
        if self.positioned or "b" not in self.mode:
            self.observations.append((self.mode, position, size, value))
        return value


@pytest.mark.parametrize("family,bound,data,kind", [
    ("python", 7, b"unknown option\nquiet ending", "UNKNOWN"),
    ("php", 0, b"unknown option", "UNKNOWN"),
    ("python", 40000, b"unknown option\n" + b"x" * 35000, "COMMAND_RECIPE"),
    ("node", 15, b"unknown option" + ("é" * 8).encode(), "UNKNOWN"),
    ("java", 6, b"unknown option", "UNKNOWN"),
    ("go", 5, b"unknown option", "UNKNOWN"),
    ("native", None, b"unknown option\n" + ("é" * 18000).encode(), "UNKNOWN"),
    ("dotnet", None, b"unknown option\n" + ("é" * 18000).encode(), "UNKNOWN"),
], ids=["small", "zero", "larger-than-default", "multibyte", "java-jvm", "go", "native-default", "dotnet-default"])
def test_controller_diagnosis_reads_only_the_frozen_family_tail(tmp_path, monkeypatch, family, bound, data, kind):
    controller, action = _controller(tmp_path, family, bound)
    root = controller.run_root
    stderr = immutable_bytes(root, "artifacts/synthetic/stderr", data)
    stdout = immutable_bytes(root, "artifacts/synthetic/stdout", b"full stdout")
    observations = []
    real_open = Path.open

    def observed_open(path, mode="r", *args, **kwargs):
        stream = real_open(path, mode, *args, **kwargs)
        return _ObservedReader(stream, mode, observations) if path == root / stderr["path"] else stream

    monkeypatch.setattr(Path, "open", observed_open)
    requests = []

    def fail(request, _run_id):
        requests.append(request)
        return IterationOutcome({
            "build_unit_id": request["node_id"], "terminal_status": "FAILED",
            "family": "untrusted-receipt-family", "gaps": ["synthetic failure"],
            "commands": [{"exit_code": 1, "timed_out": False, "stdout": stdout, "stderr": stderr}],
        }, (), True)

    result = controller.run(fail, invoke=_invoke)
    assert len(requests) == 1
    assert result["states"] == {action["build_unit_id"]: "FAILED"}
    pointer = root / "data/build/iterations/failures" / f"{action['build_unit_id']}.json"
    failure = read_reference(root, json.loads(pointer.read_bytes())["failure"])
    assert failure["diagnosis"]["kind"] == kind
    limit = 32768 if bound is None else bound
    assert observations == [("rb", max(0, len(data) - limit), limit, data[-limit:] if limit else b"")]
    assert stderr in failure["evidence"] and stdout in failure["evidence"]
    assert read_reference(root, failure["receipt"])["commands"][0]["stderr"] == stderr
    assert (root / stderr["path"]).read_bytes() == data
    assert file_sha256(root / stderr["path"]) == stderr["sha256"]
    with controller.workspace.writer() as writer:
        assert writer.state()["attempt"] is None
        assert writer.committed_generation()["accepted"] == {}


@pytest.mark.parametrize("bound", [0, 7])
def test_controller_still_verifies_full_stream_when_tail_is_small_or_disabled(tmp_path, bound):
    controller, action = _controller(tmp_path, "php", bound)
    root = controller.run_root
    stderr = immutable_bytes(root, "artifacts/synthetic/stderr", b"original unknown option")

    def corrupt(request, _run_id):
        path = root / stderr["path"]
        path.chmod(0o600)
        path.write_bytes(b"tampered unknown option")
        return IterationOutcome({
            "build_unit_id": request["node_id"], "terminal_status": "FAILED", "gaps": ["failed"],
            "commands": [{"exit_code": 1, "stderr": stderr}],
        }, (), True)

    result = controller.run(corrupt, invoke=_invoke)
    assert result["states"] == {action["build_unit_id"]: "FAILED"}
    pointer = root / "data/build/iterations/failures" / f"{action['build_unit_id']}.json"
    assert not pointer.exists()
    assert any("integrity" in str(gap).lower() for gap in result["receipts"][0]["gaps"])
    prepared_path, = (root / "data/build/iterations/prepared").glob("*.json")
    prepared = read_reference(root, json.loads(prepared_path.read_bytes())["prepared"])
    assert read_reference(root, prepared["receipt"])["commands"][0]["stderr"] == stderr
    with controller.workspace.writer() as writer:
        assert writer.state()["attempt"] is None
        assert writer.committed_generation()["accepted"] == {}


@pytest.mark.parametrize("invalid", ["missing-family", "missing-option", "negative", "boolean"])
def test_controller_does_not_default_a_configurable_family_with_invalid_frozen_settings(tmp_path, invalid):
    controller, action = _controller(tmp_path, "java", 6, invalid_setting=invalid)
    root = controller.run_root
    stderr = immutable_bytes(root, "artifacts/synthetic/stderr", b"unknown option")

    def fail(request, _run_id):
        return IterationOutcome({
            "build_unit_id": request["node_id"], "terminal_status": "FAILED", "gaps": ["failed"],
            "commands": [{"exit_code": 1, "stderr": stderr}],
        }, (), True)

    result = controller.run(fail, invoke=_invoke)
    assert result["states"] == {action["build_unit_id"]: "FAILED"}
    assert any("diagnostic_tail_bytes is missing or invalid" in str(gap)
               for gap in result["receipts"][0]["gaps"])
    assert not (root / "data/build/iterations/failures" / f"{action['build_unit_id']}.json").exists()
    assert result["receipts"][0]["commands"][0]["stderr"] == stderr
    assert (root / stderr["path"]).read_bytes() == b"unknown option"
