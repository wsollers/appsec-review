"""Live Node project builds of the multivuln Node fixtures through the real pipeline path.

Each case runs intake, catalog, analysis planning (with a deterministic recipe provider standing in
for the model), project build (derived dependency image, captured probe), and language build with
the configured ``node`` build profile image, the real ``ProjectImageResolver``, and the real
``BuildContainerExecutor``. Run explicitly with a unique ``--basetemp=test/tmp/<session>``:

    python -m pytest tests/integration/test_node_project_builds.py --basetemp=test/tmp/node-live

The configured ``node`` profile pin must name the local ``audit-buildenv-typescript:local`` image
(see ``containers/buildenv/typescript/README.md``). Dependency-bearing cases also need registry
egress from build containers; when the image cannot reach the npm registry they are skipped with
the observed failure, which is an environment gap, never a passing build.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import profiles_from_settings
from appsec_review.inference import ModelResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[2]
PROJECTS = ROOT / "targets" / "appsec-multi-vuln" / "projects"
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")

pytestmark = pytest.mark.requires_target("appsec-multi-vuln")


@dataclass(frozen=True)
class UnitExpectation:
    root: str
    outputs: tuple[str, ...] = ()  # relative to the project (target) root
    artifact_kinds: tuple[str, ...] = ()
    compiler_artifacts: str = "SUCCEEDED"
    language_status: str = "SUCCEEDED"
    language_gap: str | None = None
    native_compile: str | None = None


@dataclass(frozen=True)
class NodeCase:
    project: str
    units: tuple[UnitExpectation, ...]


def _typescript(case: str) -> NodeCase:
    return NodeCase(f"typescript/{case}", (UnitExpectation(
        ".", ("dist/index.js",), ("generated-code",)),))


def _syntax_only(project: str) -> NodeCase:
    return NodeCase(project, (UnitExpectation(".", compiler_artifacts="SKIPPED_NA"),))


CASES = (
    *(_typescript(case) for case in ("case-012", "case-013", "case-032", "case-048",
                                      "case-057", "case-067")),
    *(_syntax_only(f"javascript/{case}") for case in ("case-031", "case-047", "case-056", "case-066")),
    NodeCase("javascript-bundler/case-086", (UnitExpectation(
        ".", ("dist/bundle.js",), ("generated-code",)),)),
    NodeCase("node-addon/case-087", (UnitExpectation(
        ".", ("build/Release/case087.node",), ("native-addon",), native_compile="src/addon.cc"),)),
    _syntax_only("node-lifecycle/case-088"),
    NodeCase("northwinds-v1", (
        UnitExpectation(".", ("backend/dist/index.js", "frontend/dist/index.html"),
                        ("generated-code",)),
        # backend's build script ends with `node scripts/copy-assets.mjs`. The language build's
        # lifecycle policy cannot distinguish a build helper from running the application, so it
        # must record that truthfully instead of executing it.
        UnitExpectation("backend", language_status="BLOCKED", compiler_artifacts="GAP",
                        language_gap="package lifecycle script build may execute a target application"),
        UnitExpectation("frontend", ("frontend/dist/index.html",), ("generated-code",)),
    )),
)


class _RecipeProvider:
    """Deterministic stand-in for recipe inference, shaped like the live run's accepted recipes.

    A lockfile-bound unit installs with `npm ci` (as its README says); a lockless unit only runs
    `npm run build` and declares no network need, exactly the shape that hid devDependencies in
    the live TS2688 failures. Pipeline normalization, not this provider, must correct it.
    """

    def __init__(self, target: Path, case: NodeCase) -> None:
        self.target = target
        self.outputs = {unit.root: list(unit.outputs) for unit in case.units}

    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            if unit.get("family") != "node":
                continue
            root = str(unit["root"])
            prefix = "" if root == "." else root + "/"
            source = self.target / Path(*PurePosixPath(root).parts)
            locks = [name for name in LOCKFILES if (source / name).is_file()]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "node", "source_dir": root, "build_dir": root,
                "system_packages": [], "environment": {},
                "dependency_files": [f"{prefix}package.json", *(f"{prefix}{name}" for name in locks)],
                "configure_commands": [["npm", "ci"]] if "package-lock.json" in locks else [],
                "build_commands": [["npm", "run", "build"]],
                "expected_outputs": self.outputs.get(root, []),
                "network_required": bool(locks),
                "reason": "deterministic integration-test recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


def _docker(*argv: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *argv], capture_output=True, text=True, timeout=timeout,
                          check=False)


@pytest.fixture(scope="module")
def node_image() -> dict[str, str]:
    if shutil.which("docker") is None or _docker("info", timeout=60).returncode != 0:
        pytest.skip("Docker daemon is unavailable")
    config = load_config(ROOT / "appsec-review.toml")
    profile = profiles_from_settings(config.job("job_project_build").settings["profiles"])["node"]
    inspected = _docker("image", "inspect", profile.tag, "--format", "{{.Id}}")
    if inspected.returncode != 0:
        pytest.skip(f"live Node build image is unavailable: {profile.tag}")
    assert inspected.stdout.strip() == profile.image_id, (
        f"{profile.tag} resolves to {inspected.stdout.strip()}, but the node profile pins "
        f"{profile.image_id}; rebuild and re-pin per containers/buildenv/typescript/README.md")
    ping = _docker("run", "--rm", "--network", "bridge", "--read-only", "--tmpfs", "/tmp",
                   "--entrypoint", "npm", profile.image_id, "ping", timeout=180)
    registry_error = None if ping.returncode == 0 else (ping.stdout + ping.stderr)[-600:]
    return {"image_id": profile.image_id, "registry_error": registry_error or ""}


def _needs_registry(source: Path) -> bool:
    for manifest in source.rglob("package.json"):
        if "node_modules" in manifest.parts:
            continue
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if any(document.get(field) for field in ("dependencies", "devDependencies",
                                                  "optionalDependencies")):
            return True
    return False


def _probe_events(run_root: Path, probe: dict) -> list[dict]:
    """Events of the project-build probe's verified ptrace captures (one record per command)."""
    rows = []
    for command in probe.get("commands", ()):
        capture = command.get("execution_capture")
        assert capture, f"probe command {command.get('ordinal')} has no execution capture"
        assert capture.get("complete") is True, capture
        path = (run_root / capture["path"]).parent / "events.jsonl"
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)
    return rows


def _diagnostics(run_root: Path, receipt: dict) -> str:
    text = []
    for command in receipt.get("commands", ()):
        for stream in ("stdout", "stderr"):
            identity = command.get(stream) or {}
            path = run_root / str(identity.get("path", ""))
            if path.is_file():
                text.append(path.read_text(encoding="utf-8", errors="replace")[-4000:])
    return "\n".join(text)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.project)
def test_node_project_builds_through_the_pipeline(tmp_path: Path, case: NodeCase,
                                                  node_image: dict[str, str]) -> None:
    source = PROJECTS / Path(*PurePosixPath(case.project).parts)
    assert source.is_dir(), f"multivuln Node project is missing: {case.project}"
    if node_image["registry_error"] and _needs_registry(source):
        pytest.skip("environment gap: build containers cannot reach the npm registry: "
                    + node_image["registry_error"])
    config_path = tmp_path / "appsec-review.toml"
    shutil.copyfile(ROOT / "appsec-review.toml", config_path)
    target = tmp_path / "target" / Path(*PurePosixPath(case.project).parts)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("node_modules", ".git"))
    config = load_config(config_path)
    fingerprint = source_fingerprint(target)

    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=_RecipeProvider(target, case).complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    run_id = upstream["run_id"]
    run_root = config.runtime.runs_dir / run_id
    GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    GraphRunner(config, [build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)

    accepted = load_accepted_builds(run_root)
    probes = {str(item.get("root")): item for item in accepted.get("probe_receipts", ())
              if item.get("family") == "node"}
    receipts = {str(item.get("root")): item
                for item in load_accepted_language_build(run_root)["receipts"]
                if item.get("family") == "node"}
    assert set(probes) == {unit.root for unit in case.units}, probes.keys()
    blocked_native = [item for item in accepted.get("probe_receipts", ())
                      if item.get("family") == "native" and item.get("terminal_status") == "BLOCKED"]

    for unit in case.units:
        probe = probes[unit.root]
        assert probe["terminal_status"] == "SUCCEEDED", (
            f"probe {unit.root}: {probe.get('gaps')}\n{_diagnostics(run_root, probe)}")
        events = _probe_events(run_root, probe)
        assert any(event.get("kind") == "process_exec" for event in events)
        receipt = receipts[unit.root]
        assert receipt["terminal_status"] == unit.language_status, (
            f"language build {unit.root}: {receipt.get('gaps')}\n{_diagnostics(run_root, receipt)}")
        decisions = {item["feature"]: item for item in receipt.get("processing_decisions", ())}
        assert decisions["compiler-artifact-collection"]["disposition"] == unit.compiler_artifacts, (
            receipt.get("gaps"))
        if unit.language_gap is not None:
            assert any(unit.language_gap in gap for gap in receipt["gaps"]), receipt["gaps"]
            continue
        assert receipt["gaps"] == [], receipt["gaps"]
        assert receipt["commands"] and all(command["exit_code"] == 0 for command in receipt["commands"])
        assert all((command.get("execution_capture") or {}).get("complete") is True
                   for command in receipt["commands"]), "language build ran without complete capture"
        workspace = run_root / receipt["workspace"]
        produced = {item["workspace_path"]: item for item in receipt["artifacts"]
                    if item.get("artifact_origin") == "build-output"}
        for output in unit.outputs:
            path = workspace / Path(*PurePosixPath(output).parts)
            assert path.is_file() and path.stat().st_size > 0, f"missing build output {output}"
        assert set(unit.artifact_kinds) <= {item["kind"] for item in produced.values()}, produced
        if unit.compiler_artifacts == "SKIPPED_NA":
            assert not [item for item in produced.values() if item["kind"] != "package-metadata"]
        if unit.native_compile is not None:
            # node-gyp's C++ compiles are captured for native analysis.
            compiles = [event for event in events if event.get("kind") == "process_exec"
                        and PurePosixPath(str(event.get("executable", ""))).name in {"g++", "c++"}
                        and any(str(value).endswith(unit.native_compile)
                                for value in event.get("argv", ()))]
            assert compiles, "node-gyp g++ compile invocation was not captured"
            # The language build publishes the same compiles as the unit's native components.
            assert receipt.get("native_components"), receipt.keys()
            addon = workspace / "build" / "Release" / "case087.node"
            assert addon.read_bytes()[:4] == b"\x7fELF"
    if case.project == "node-addon/case-087":
        # Coordination contract: a node-gyp addon is owned by the node unit, so the native
        # family must not emit a second, unbuildable direct-native unit for its sources.
        assert not blocked_native, [item.get("gaps") for item in blocked_native]
