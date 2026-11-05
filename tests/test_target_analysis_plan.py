from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.job import publish_guidance_bundle
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PLAN_SCHEMA, PROPOSAL_SCHEMA, deterministic_plan, merge_proposal, summarize_catalog, validate_plan, validate_proposal,
)
from appsec_review.jobs.build_topology import topological_order, topology_identity
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.retrieval import RunIndexBackend, SearchRequest
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]


@pytest.mark.integration
def test_actual_catalog_offline_feedback_replay(tmp_path, request):
    """Manual external-capture replay, NOT part of the finite focused unit admission."""
    import hashlib
    import os
    import subprocess
    import inspect
    import sys
    import time
    from dataclasses import replace
    from pathlib import Path
    import json
    import pytest
    from appsec_review.config import load_config
    from appsec_review.inference import ModelResult
    from appsec_review.jobs.job_target_analysis_plan import build_job, load_accepted_plan
    from appsec_review.jobs.job_target_analysis_plan.job import _accepted_catalog
    from appsec_review.jobs.job_project_build import build_job as project_job
    from appsec_review.jobs.job_project_build.job import load_accepted_builds
    from appsec_review.retrieval import write_manifest
    from appsec_review.runtime import GraphRunner, Job, Unit, UnitExecutor
    from appsec_review.runtime.datasets import artifact_only
    from appsec_review.storage import atomic_bytes, canonical_json, file_sha256
    from appsec_review.storage.shared import safe_path
    from tests.test_project_build import FakeBuildExecutor, FakeImageResolver

    baseline = "acf973f8a0d7ca78548ad619ba4b5691c5b93678"
    expected = os.environ.get("APPSEC_TOPOLOGY_R8_SOURCE")
    kind = os.environ.get("APPSEC_TOPOLOGY_R8_KIND")
    capture_name = os.environ.get("APPSEC_TOPOLOGY_R8_CAPTURE_RUN")
    assert expected and kind in {"baseline", "candidate"} and capture_name, "R8 requires explicit admitted custody"
    repository = Path(subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True).strip())
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    assert head == expected and (head == baseline if kind == "baseline" else head != baseline)
    assert request.config.rootpath.resolve() == repository.resolve()
    assert request.config.inipath.resolve() == repository / "pyproject.toml"
    assert hashlib.sha256((repository / "pyproject.toml").read_bytes()).hexdigest() == (
        "5693debd5c38e47ec32680ec8aa2bbe23de3cc957b56f1c46bc2f0c966cb0090")
    assert hashlib.sha256((repository / "tests/conftest.py").read_bytes()).hexdigest() == (
        "e8b6393a0b73bf56e41b12df4da358e96740501deaae22939e99150c561f8b49")
    plugins = {Path(plugin.__file__).resolve() for plugin in request.config.pluginmanager.get_plugins()
               if getattr(plugin, "__file__", None)}
    assert (repository / "tests/conftest.py").resolve() in plugins, "retain this checkout's unit safety fixtures"
    assert Path(sys.prefix).resolve().parent == repository.resolve(), "use this checkout's separately admitted venv"
    for symbol in (_accepted_catalog, load_accepted_plan, project_job, GraphRunner):
        assert (repository / "src").resolve() in Path(inspect.getfile(symbol)).resolve().parents
    assert (repository / "tests").resolve() in Path(inspect.getfile(FakeBuildExecutor)).resolve().parents
    capture = Path(capture_name)
    source = "93019fb687995fb267a5342d17a9d40f58e11e70000718868b2bbc3d5c90bbee"
    prefix = "data/jobs/job_target_catalog/attempts/attempt_0001/"
    pins = {
        "data/jobs/job_target_catalog/latest.json": (
            237, "86453e36e94793603432c60ae2d447da270a5f70c7573df8458d2acf977640da"),
        prefix + "handoff.json": (
            18678442, "129b08ee1c67b4d85b20088f597d0bc0446be1e62a6521eb6376e35d7a1a0e7d"),
        prefix + "claim.json": (
            6099, "265c6fe6070861e58e2906e4e6e6f3db516f18604e0f8f166c289b1515fabd23"),
        prefix + "artifacts/catalog/build-targets.json": (
            3228085, "823e0f4959cb719ecf464bf0b11386d4ea54284d66c9377e444a773948559d43"),
        prefix + "artifacts/catalog/target-catalog.json": (
            18650569, "5f613405cde3e538575d488f4ff90dbbb65f87b9b654c014fcf7834447cb4770"),
        prefix + "artifacts/catalog/repository-partition.json": (
            30007393, "54157417a97e15a0414d346a2d8055c599d3055862ad8aba66f3e4b28580f6ef"),
        prefix + "artifacts/catalog/projects.json": (
            80706, "8d784f8b1f2eee1ddd00a17a19497e4ee668cbc76bf4ea5a17a71efc4af45afa"),
        prefix + "artifacts/catalog/components.json": (
            75733, "0efa22f20c120e8f881204d047dcac1dfff613e4332bc60bb57e8e244df792f3"),
        prefix + "artifacts/catalog/build-systems.json": (
            287693, "c62918a907da47ad9354550c19c6739d8a2f1a746c6074bc4478304a29a47d85"),
        prefix + "artifacts/catalog/compile-commands.json": (
            102, "bab0acaa828bf81d08a1166dfe10b966d94f9f06a9151a11464c45ab681a3cef"),
    }
    metrics = {"classification": "manual offline external-capture replay; not an integration acceptance",
               "kind": kind, "source_commit": head, "capture_source": source, "pins": pins,
               "pytest_root": str(request.config.rootpath), "pytest_config": str(request.config.inipath),
               "package_root": str(repository / "src"), "python_prefix": sys.prefix,
               "model_calls": 0, "request_bytes": 0, "response_bytes": 0, "executor_calls": 0,
               "retrieval_boundary": "empty fixture upstream manifest; actual planner shard publication",
               "target_boundary": "only exact captured descriptor bytes, not a complete target checkout"}
    started = time.monotonic()
    try:
        payloads = {}
        for relative, (size, digest) in pins.items():
            path = safe_path(capture, relative)
            assert path.stat().st_size == size <= 33554432
            payload = path.read_bytes()
            assert len(payload) == size and hashlib.sha256(payload).hexdigest() == digest
            payloads[relative] = payload
        handoff = json.loads(payloads[prefix + "handoff.json"])
        claim = json.loads(payloads[prefix + "claim.json"])
        pointer = json.loads(payloads["data/jobs/job_target_catalog/latest.json"])
        assert (pointer["handoff_path"], pointer["handoff_sha256"]) == (
            prefix + "handoff.json", pins[prefix + "handoff.json"][1])
        identity = handoff["outputs"]["build_discovery.catalog_build_targets"]["artifact"]
        assert handoff["status"] == "ACCEPTED" and handoff["source_fingerprint"] == claim["source_fingerprint"] == source
        assert identity["path"] == prefix + "artifacts/catalog/build-targets.json"
        assert (identity["size_bytes"], identity["sha256"]) == pins[identity["path"]]
        assert {key: handoff["artifacts"][91][key] for key in ("path", "sha256", "size_bytes")} == {
            key: identity[key] for key in ("path", "sha256", "size_bytes")}
        # Exercise the REAL accepted reader with its complete, large original intake.
        original = _accepted_catalog(capture)
        assert len(original["build_units"]) == len({unit["build_unit_id"] for unit in original["build_units"]}) == 295
        target = tmp_path / "captured-descriptors"
        target.mkdir()
        documents = {}
        for unit in original["build_units"]:
            for document in unit["descriptor_package"]["documents"]:
                path = document["path"]
                data = document["content"].encode()
                assert hashlib.sha256(data).hexdigest() == document["sha256"]
                assert path not in documents or documents[path] == data
                documents[path] = data
        for relative, data in documents.items():
            path = safe_path(target, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        config_path = tmp_path / "appsec-review.toml"
        config_path.write_bytes((repository / "appsec-review.toml").read_bytes())
        config = load_config(config_path)
        config = replace(config, runtime=replace(config.runtime, runs_dir=tmp_path / "runs",
                                                metadata_dir=tmp_path / "metadata"))

        def replay_catalog(unit):
            root = unit.job.run_root
            for relative, payload in payloads.items():
                if "/artifacts/catalog/" in relative:
                    atomic_bytes(safe_path(root, relative), payload)
            manifest = root / "data/indices/manifests/captured-external-boundary.json"
            write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=source, target_root=target, indexes=[])
            catalog_path = prefix + "artifacts/catalog/target-catalog.json"
            return {"schema": "appsec-review/target-catalog/1",
                    "artifact": {"path": catalog_path, "sha256": pins[catalog_path][1],
                                 "size_bytes": pins[catalog_path][0]},
                    "index_manifest": {"path": manifest.relative_to(root).as_posix(),
                                       "sha256": file_sha256(manifest), "size_bytes": manifest.stat().st_size},
                    "gaps": ["offline capture fixture: external upstream retrieval is not replayed"]}

        units = (Unit("publish_catalog.publish_handoff", replay_catalog),)
        catalog_fixture = Job("job_target_catalog", "target_catalog", UnitExecutor(units).execute,
            units=units, datasets=(
                artifact_only("captured_catalog", "publish_catalog", "catalog",
                    "appsec-review/target-catalog/1", "Exact pinned catalog replay fixture",
                    artifacts=("data/jobs/job_target_catalog/attempts/*/artifacts/catalog/*.json",),
                    reason="accepted external capture boundary, not a new target discovery"),
                artifact_only("external_index_boundary", "publish_catalog", "catalog",
                    "appsec-review/retrieval-manifest/2", "Explicit empty upstream retrieval fixture",
                    artifacts=("data/indices/manifests/captured-external-boundary.json",),
                    reason="real planner index publication runs; upstream retrieval is outside this replay")))

        def scripted(request, *, timeout_seconds):
            from dataclasses import asdict
            recipes = []
            for unit in request.summary["build_units"]:
                root, system = unit["root"], unit["build_system"]
                build = root + "/build" if root != "." else "build"
                marker = unit["markers"][0]["path"]
                commands = {
                    "maven": [["mvn", "--file=" + marker, "-DskipTests", "package"]],
                    "gradle": [["gradle", "assembleDebug"]],
                    "go": [["go", "build", "./..."]],
                    "dotnet": [["dotnet", "build", marker]],
                    "node": [["npm", "run", "build"]],
                    "python": [["python", "-m", "build"]],
                    "composer": [["composer", "install", "--no-scripts"]],
                    "msbuild": [["msbuild", marker, "/p:Configuration=Release", "/p:Platform=x64"]],
                    "vcbuild": [["vcbuild", marker, "Release|x64"]],
                }.get(system, [["cmake", "--build", "build"]] if system == "cmake" else [["make"]])
                recipes.append({"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                    "image_profile": unit["required_image_profile"], "source_dir": root, "build_dir": build,
                    "system_packages": [], "environment": (
                        {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"} if system == "go" else {}),
                    "dependency_files": [item["path"] for item in unit["markers"]],
                    "configure_commands": [["cmake", "-S", ".", "-B", "build"]] if system == "cmake" else [],
                    "build_commands": commands, "expected_outputs": [build],
                    "network_required": system in {"maven", "gradle", "go", "dotnet", "node", "python", "composer"},
                    "reason": "offline scripted proposal; validators retain unsupported or unresolved cases"})
            proposal = {"schema": request.schema, "component_proposals": [], "build_recipes": recipes}
            if request.schema.endswith("/3"):
                proposal.update(action="final", hints=[], abstentions=[])
            metrics["model_calls"] += 1
            metrics["request_bytes"] += len(canonical_json(asdict(request)))
            metrics["response_bytes"] += len(canonical_json(proposal))
            return ModelResult(proposal)

        outcome = GraphRunner(config, [catalog_fixture, build_job(infer=scripted)]).run(
            target_root=target, source_fingerprint=source)
        run_root = config.runtime.runs_dir / outcome["run_id"]
        accepted = load_accepted_plan(run_root)
        assert len(accepted["build_topology"]["build_actions"]) == 295
        calls = []
        project = project_job(executor_factory=lambda *_: FakeBuildExecutor(calls),
                              image_resolver_factory=lambda *_: FakeImageResolver())
        GraphRunner(config, [project]).run(target_root=target, source_fingerprint=source, run_id=outcome["run_id"])
        builds = load_accepted_builds(run_root)
        metrics["executor_calls"] = len(calls)
        metrics["dispatches"] = len(builds.get("build_dispatches", ()))
        metrics["graph_bytes"] = len(canonical_json(accepted["build_topology"]["executable_graph"]))
        metrics["graph_identity"] = accepted["build_topology"]["executable_graph"]["topology_id"]
        metrics["coverage_gaps"] = len(accepted["coverage_gaps"])
        metrics["artifact_sizes"] = {}
        for path in run_root.rglob("*.json"):
            if any(part in {"topology", "job_target_analysis_plan", "job_project_build"} for part in path.parts):
                size = path.stat().st_size
                metrics["artifact_sizes"][path.relative_to(run_root).as_posix()] = size
                if path.name in {"accepted-analysis-plan.json", "handoff.json"} or "topology" in path.parts:
                    assert size <= 33554432, "whole produced artifact exceeds its real reader bound"
        assert metrics["graph_bytes"] <= 16 * 1024 * 1024
        metrics["outcome"] = "completed offline replay, not live or whole-target acceptance"
    except Exception as error:
        metrics["outcome"] = "FAILED"
        metrics["error_type"] = type(error).__name__
        raise
    finally:
        metrics["elapsed_seconds"] = time.monotonic() - started
        (tmp_path / "actual-catalog-replay-metrics.json").write_bytes(canonical_json(metrics))
    assert metrics["elapsed_seconds"] <= 120, "R8 provisional whole-feedback budget exceeded"


def test_guidance_bundles_are_group_scoped_immutable_and_reusable(tmp_path: Path) -> None:
    model = {"provider": "claude-cli", "model": "example", "reasoning": "low"}
    arguments = {"persona": "persona", "role": "role", "guidance": "task", "model": model,
                 "family": "native"}
    cmake = publish_guidance_bundle(tmp_path, build_system="cmake", **arguments)
    make = publish_guidance_bundle(tmp_path, build_system="make", **arguments)
    assert cmake != make
    assert publish_guidance_bundle(tmp_path, build_system="cmake", **arguments) == cmake
    root = tmp_path / "data" / "guidance"
    assert json.loads((root / cmake / "model-identity.json").read_text())["build_system"] == "cmake"
    assert json.loads((root / make / "model-identity.json").read_text())["build_system"] == "make"
    (root / cmake / "role.md").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="guidance bundle changed"):
        publish_guidance_bundle(tmp_path, build_system="cmake", **arguments)


def _fixture(tmp_path: Path, files: dict[str, str], *, model_enabled: bool = False):
    config_path = tmp_path / "appsec-review.toml"
    config_text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if not model_enabled:
        config_text = config_text.replace("[jobs.job_target_analysis_plan.settings.model]\nenabled = true",
                                          "[jobs.job_target_analysis_plan.settings.model]\nenabled = false")
    config_path.write_text(config_text, encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    for name, content in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return load_config(config_path), target


def _run(config, target, planner=None):
    outcome = GraphRunner(config, [build_intake(), build_catalog(), planner or build_job()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    return outcome, load_accepted_plan(config.runtime.runs_dir / outcome["run_id"])


def test_buildable_project_names_disabled_model_as_a_gap(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {"pyproject.toml": "[project]\nname='fixture'\n", "src/main.py": "print('ok')\n"})
    outcome, plan = _run(config, target)
    assert plan["schema"] == PLAN_SCHEMA
    assert plan["model"]["status"] == "DISABLED"
    assert all(action["recipe"] is None and action["requires_inference"]
               for action in plan["build_topology"]["build_actions"])
    assert {item["scanner_id"] for item in plan["scanner_selections"]} >= {
        "tool-gitleaks", "tool-semgrep", "tool-syft"
    }
    assert {item["build_system"] for item in plan["build_topology"]["build_systems"]} == {"python"}
    assert outcome["jobs"]["job_target_analysis_plan"]["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    publication = outcome["jobs"]["job_target_analysis_plan"]["result"]["outputs"]["plan_acceptance.publish_handoff"]
    assert publication["disposition_counts"]["selected_scanners"] == len(plan["scanner_selections"])
    assert "dispositions" not in publication


class _Model:
    def __init__(self, proposal):
        self.proposal = proposal
        self.calls = 0

    def complete(self, request, *, timeout_seconds):
        self.calls += 1
        assert request.persona and request.role and request.guidance and timeout_seconds > 0
        assert set(request.allowed_image_profiles) == {
            unit["required_image_profile"] for unit in request.summary["build_units"]}
        summarized_paths = {
            item["path"] for prefix in request.summary["prefixes"] for item in prefix["sample"]
        } | {
            item["path"]
            for key in ("recognized_build_files", "compile_databases", "accepted_artifacts")
            for item in request.summary[key]
        } | {
            item["path"] for unit in request.summary.get("build_units", ())
            for item in (*unit.get("markers", ()),
                         *unit.get("descriptor_package", {}).get("documents", ()))
        }
        offered = {item["path"] for item in request.summary.get("evidence_inventory", ())}
        assert set(request.allowed_paths) == summarized_paths | offered
        assert len(summarized_paths) <= request.summary["bounds"]["max_items"]
        assert request.summary["evidence_inventory_omitted"] >= 0
        from dataclasses import asdict
        from appsec_review.storage import canonical_json
        assert len(canonical_json(asdict(request))) <= request.summary["feedback_limits"]["max_request_bytes"]
        proposal = self.proposal(request) if callable(self.proposal) else self.proposal
        return ModelResult(proposal, input_tokens=20, output_tokens=10)


def _proposal(request, component_proposals=()):
    recipes = []
    for unit in request.summary["build_units"]:
        root = unit["root"]
        source_dir = root
        build_dir = f"{root}/build" if root != "." else "build"
        system = unit["build_system"]
        commands = {
            "cmake": ([["cmake", "-S", source_dir, "-B", build_dir]], [["cmake", "--build", build_dir]]),
            "cargo": ([], [["cargo", "build", "--manifest-path", f"{root}/Cargo.toml"]]),
            "go": ([], [["go", "build", "./..."]]),
            "maven": ([], [["mvn", f"--file={root}/pom.xml", "-DskipTests", "package"]]),
            "node": ([], [["npm", "--prefix", root, "run", "build"]]),
            "python": ([], [["python", "-m", "build", root]]),
        }.get(system, ([], [[{
            "make": "make", "autotools": "make", "gradle": "gradle",
            "dotnet": "dotnet", "composer": "composer", "meson": "meson",
        }.get(system, system)]]))
        dependencies = [item["path"] for item in unit["markers"]]
        if system == "node":
            dependencies.extend(item["path"] for item in unit.get("descriptor_package", {}).get("documents", ())
                                if Path(item["path"]).name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"})
        recipes.append({
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": unit["required_image_profile"],
            "source_dir": source_dir, "build_dir": build_dir,
            "system_packages": [], "environment": {},
            "dependency_files": list(dict.fromkeys(dependencies)),
            "configure_commands": commands[0], "build_commands": commands[1],
            "expected_outputs": [build_dir], "network_required": system in {
                "cargo", "go", "maven", "gradle", "dotnet", "node", "composer", "python"},
            "reason": "fixture recipe derived from accepted descriptors",
        })
    return {"schema": PROPOSAL_SCHEMA, "action": "final",
            "component_proposals": list(component_proposals), "build_recipes": recipes,
            "hints": [], "abstentions": []}


def test_mixed_monorepo_uses_injected_model_and_validates_allowlists(tmp_path: Path) -> None:
    files = {
        "web/package.json": "{}", "web/package-lock.json": '{"lockfileVersion":3}',
        "web/tsconfig.json": "{}", "web/src/app.ts": "export const x=1;\n",
        "api/go.mod": "module fixture\n", "api/main.go": "package main\n",
        "native/CMakeLists.txt": "project(fixture)\n", "native/main.cpp": "int main(){}\n",
        "jvm/pom.xml": "<project/>", "jvm/Main.java": "class Main {}\n",
        "ops/tool.sh": "echo ok\n",
    }
    config, target = _fixture(tmp_path, files, model_enabled=True)
    model = _Model(lambda request: _proposal(request))
    outcome, plan = _run(config, target, build_job(infer=model.complete))
    assert model.calls == 4
    assert plan["model"]["status"] == "ACCEPTED"
    assert plan["provenance"] == "model-assisted"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    events = [json.loads(line) for line in (run_root / "data/logs/pipeline.jsonl").read_text().splitlines()]
    model_events = [item for item in events if item["event_type"].startswith("MODEL_CALL_")]
    assert len([item for item in model_events if item["event_type"] == "MODEL_CALL_STARTED"]) == 4
    assert len([item for item in model_events if item["event_type"] == "MODEL_CALL_COMPLETED"]) == 4
    assert all(item["details"]["input_tokens"] == 20 for item in model_events
               if item["event_type"] == "MODEL_CALL_COMPLETED")
    assert not {"prompt", "response", "model_output", "source_text"} & set(model_events[-1]["details"])
    assert list((run_root / "data/guidance").glob("*/persona.md"))
    assert list((run_root / "data/guidance").glob("*/role.md"))


@pytest.mark.parametrize("with_grunt", (False, True))
def test_node_rejection_preserves_descriptor_backed_builds_and_names_each_unresolved_unit(tmp_path: Path, with_grunt) -> None:
    files = {
        "static/package.json": '{"devDependencies":{"grunt":"0.4.5"}}',
        "copy-static/package.json": '{"devDependencies":{"grunt":"0.4.5"}}',
        "minify/package.json": '{"scripts":{"minify":"fixture-minifier"}}',
        "copy-minify/package.json": '{"scripts":{"minify":"fixture-minifier"}}',
        "dashboard/package.json": '{"scripts":{"build":"gulp build","start":"server","test":"tests"}}',
    }
    if with_grunt:
        for root in ("static", "copy-static"):
            files[f"{root}/Gruntfile.js"] = "grunt.registerTask('buildApp', ['clean:dist', 'concat', 'uglify']);"
    config, target = _fixture(tmp_path, files, model_enabled=True)

    def proposal(request):
        value = _proposal(request)
        for recipe in value["build_recipes"]:
            recipe["build_commands"] = (
                [["npm", "ci", "--ignore-scripts"]] if recipe["source_dir"] == "dashboard" else []
            )
        if request.repair_errors and not with_grunt:
            missing = [unit for unit in request.summary["build_units"]
                       if unit["root"] in {"static", "copy-static"}]
            value["abstentions"] = [{"build_unit_id": unit["build_unit_id"],
                "reason": "build_commands have no captured Grunt task: " + unit["markers"][0]["sha256"]}
                for unit in missing]
            value["build_recipes"] = [recipe for recipe in value["build_recipes"]
                                     if recipe["source_dir"] not in {"static", "copy-static"}]
        return value

    model = _Model(proposal)
    _outcome, plan = _run(config, target, build_job(infer=model.complete))
    actions = {action["root"]: action for action in plan["build_topology"]["build_actions"]}
    assert plan["model"]["status"] == ("ACCEPTED" if with_grunt else "PARTIAL")
    assert model.calls == (1 if with_grunt else 2)
    for root, script in (("minify", "minify"), ("copy-minify", "minify"), ("dashboard", "build")):
        assert actions[root]["recipe"]["build_commands"] == [["npm", "run", script]]
    for root in ("static", "copy-static"):
        if with_grunt:
            assert actions[root]["recipe"]["build_commands"] == [["npx", "--no-install", "grunt", "buildApp"]]
            assert f"{root}/Gruntfile.js" in actions[root]["recipe"]["dependency_files"]
        else:
            assert actions[root]["recipe"] is None
            assert any(actions[root]["build_unit_id"] in gap and "build_commands" in gap
                       for gap in plan["coverage_gaps"])
    assert not any(command[-1] in {"start", "test"}
                   for action in actions.values() if action["recipe"] is not None
                   for command in action["recipe"]["build_commands"])


def test_lockless_node_inference_is_normalized_before_plan_acceptance(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "web/package.json": '{"scripts":{"build":"node --check index.js"}}',
        "web/index.js": "export const value = 1;\n",
    }, model_enabled=True)

    def proposal(request):
        value = _proposal(request)
        value["build_recipes"][0]["configure_commands"] = [["npm", "ci"]]
        return value

    model = _Model(proposal)
    _outcome, plan = _run(config, target, build_job(infer=model.complete))
    recipe = plan["build_topology"]["build_actions"][0]["recipe"]
    assert recipe["configure_commands"] == []
    assert plan["model"]["status"] == "ACCEPTED"


@pytest.mark.parametrize("with_grunt", (False, True))
def test_optional_node_recipes_recover_full_authority_after_summary_trimming(tmp_path: Path, with_grunt) -> None:
    padding = "x" * 18000
    files = {
        "static/package.json": json.dumps({"devDependencies": {"grunt": "0.4.5"}, "padding": padding}),
        "copy-static/package.json": json.dumps({"devDependencies": {"grunt": "0.4.5"}, "padding": padding}),
        "minify/package.json": json.dumps({
            "scripts": {"minify": "fixture-minifier"},
            "devDependencies": {"fixture-minifier": "1.0.0"}, "padding": padding,
        }),
        "copy-minify/package.json": json.dumps({
            "scripts": {"minify": "fixture-minifier"},
            "devDependencies": {"fixture-minifier": "1.0.0"}, "padding": padding,
        }),
        "dashboard/package.json": json.dumps({
            "scripts": {"build": "gulp build", "start": "server", "test": "tests"},
            "devDependencies": {"gulp": "4.0.0"}, "padding": padding,
        }),
        "dashboard/gulpfile.js": "//" + padding + "\ngulp.task('build', function () {});",
    }
    if with_grunt:
        for root in ("static", "copy-static"):
            files[f"{root}/Gruntfile.js"] = (
                "//" + padding + "\ngrunt.registerTask('buildApp', ['clean:dist', 'concat', 'uglify']);"
            )
    config, target = _fixture(tmp_path, files, model_enabled=True)
    job = config.job("job_target_analysis_plan")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(config_path.read_text(encoding="utf-8").replace(
        f"summary_max_bytes = {job.settings['summary_max_bytes']}", "summary_max_bytes = 12288"),
        encoding="utf-8")
    config = load_config(config_path)

    def proposal(request):
        assert request.summary["bounds"]["truncated"]
        assert request.summary["bounds"]["actual_bytes"] <= 12288
        assert all(not unit["descriptor_package"]["documents"] for unit in request.summary["build_units"])
        value = _proposal(request)
        for recipe in value["build_recipes"]:
            recipe["build_commands"] = [["npm", "run", "build", "--if-present"]]
            recipe["expected_outputs"] = []
            recipe["network_required"] = recipe["source_dir"] == "dashboard"
        if request.repair_errors and not with_grunt:
            missing = [unit for unit in request.summary["build_units"]
                       if unit["root"] in {"static", "copy-static"}]
            value["abstentions"] = [{"build_unit_id": unit["build_unit_id"],
                "reason": "--if-present does not establish a captured task: " + unit["markers"][0]["sha256"]}
                for unit in missing]
            value["build_recipes"] = [recipe for recipe in value["build_recipes"]
                                     if recipe["source_dir"] not in {"static", "copy-static"}]
        return value

    model = _Model(proposal)
    _outcome, plan = _run(config, target, build_job(infer=model.complete))
    actions = {action["root"]: action for action in plan["build_topology"]["build_actions"]}
    assert len(actions) == 5
    assert plan["model"]["status"] == ("ACCEPTED" if with_grunt else "PARTIAL")
    assert model.calls == (1 if with_grunt else 2)
    expected = {
        "minify": ["npm", "run", "minify"], "copy-minify": ["npm", "run", "minify"],
        "dashboard": ["npm", "run", "build"],
    }
    if with_grunt:
        expected.update({root: ["npx", "--no-install", "grunt", "buildApp"]
                         for root in ("static", "copy-static")})
    for root, command in expected.items():
        action = actions[root]
        assert action["descriptor_package"]["documents"]
        assert action["recipe"]["build_commands"] == [command]
        assert action["recipe"]["expected_outputs"] == []
        assert action["recipe"]["network_required"] is True
        if root in {"static", "copy-static"}:
            assert f"{root}/Gruntfile.js" in action["recipe"]["dependency_files"]
    if not with_grunt:
        for root in ("static", "copy-static"):
            assert actions[root]["recipe"] is None
            assert any(actions[root]["build_unit_id"] in gap and "--if-present" in gap
                       and actions[root]["markers"][0]["sha256"] in gap
                       for gap in plan["coverage_gaps"])


def test_native_nonbuild_recipes_are_gaps_without_erasing_real_make_and_cmake_builds(tmp_path: Path) -> None:
    files = {f"vendor/fragment-{index}/Makefile.am": "include_HEADERS = header.h\n" for index in range(27)}
    for index in range(4):
        root = f"vendor/project-{index}"
        files[f"{root}/configure.ac"] = "AC_INIT([fixture], [1])\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n"
        files[f"{root}/Makefile.am"] = "bin_PROGRAMS = fixture\n"
    portable = {f"server/proj/{name}" for name in ("center", "db", "game", "gateway", "log", "login", "object")}
    for root in portable:
        files[f"{root}/makefile"] = "all: depend program\ndepend:\n\t$(CC) -MM entry.cpp\nprogram:\n\t$(CC) entry.cpp -o program\n"
    for root in ("infra-one", "infra-two"):
        files[f"{root}/Makefile"] = "all:\n\t$(CC) entry.cpp -o entry\n"
    files["wrapper/Makefile"] = "all: native\nnative:\n\tif not exist bin mkdir bin\n\tpowershell build.ps1\n\t$(MSBUILD) native.sln\n"
    files["migrator/Makefile"] = "db-docker:\n\tdocker build -f Dockerfile .\n"
    files["compiled/CMakeLists.txt"] = "project(fixture)\n"
    for root, project_type, extension in (
            ("native-solution", "8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942", "vcxproj"),
            ("managed-solution", "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC", "csproj")):
        files[f"{root}/app.sln"] = (
            f'Project("{{{project_type}}}") = "app", "app\\app.{extension}", '
            '"{00000000-0000-0000-0000-000000000001}"\nEndProject\n'
        )
    config, target = _fixture(tmp_path, files, model_enabled=True)

    def proposal(request):
        value = _proposal(request)
        for recipe in value["build_recipes"]:
            root = recipe["source_dir"]
            if root.startswith("vendor/fragment-"):
                recipe["build_commands"] = [["make", "--version"]]
            elif root.startswith("vendor/project-"):
                recipe["build_commands"] = [["autoreconf", "-fi"]]
            elif root in {"infra-one", "infra-two"}:
                recipe["build_commands"] = [["make", "-n"]]
            elif root in {"native-solution", "managed-solution"}:
                recipe["build_commands"] = [["dotnet", "build", "app.sln"]]
            recipe["expected_outputs"] = []
        if request.repair_errors:
            supported = portable | {"compiled", "managed-solution"}
            missing = [unit for unit in request.summary["build_units"] if unit["root"] not in supported]
            value["abstentions"] = [{"build_unit_id": unit["build_unit_id"],
                "reason": unit["markers"][0]["sha256"] + ": " + "; ".join(request.repair_errors)[:1400]}
                for unit in missing]
            value["build_recipes"] = [recipe for recipe in value["build_recipes"]
                                     if recipe["source_dir"] in supported]
        return value

    model = _Model(proposal)
    _outcome, plan = _run(config, target, build_job(infer=model.complete))
    actions = {action["root"]: action for action in plan["build_topology"]["build_actions"]}
    assert plan["model"]["status"] == "PARTIAL"
    assert len(actions) == 45
    assert {root for root, action in actions.items() if action["recipe"] is not None} == portable | {"compiled", "managed-solution"}
    for root, action in actions.items():
        if root in portable:
            assert action["recipe"]["build_commands"] == [["make"]]
        elif root == "compiled":
            assert action["recipe"]["build_commands"][0][:2] == ["cmake", "--build"]
        elif root == "managed-solution":
            assert action["recipe"]["build_commands"] == [["dotnet", "build", "app.sln"]]
        else:
            assert action["recipe"] is None
            assert any(action["build_unit_id"] in gap and action["markers"][0]["sha256"] in gap
                       for gap in plan["coverage_gaps"])
    gaps = "\n".join(plan["coverage_gaps"])
    assert "nonstandalone_autotools_fragment" in gaps
    assert "no compilation or build step" in gaps
    assert "unavailable_native_windows_toolchain" in gaps
    assert "unsupported_native_orchestration" in gaps
    assert "unavailable_native_project_toolchain" in gaps


def test_invalid_model_proposal_falls_back_and_preserves_baseline(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "a/package.json": "{}", "a/tsconfig.json": "{}", "a/index.ts": "export {}\n",
        "b/go.mod": "module b\n", "b/main.go": "package main\n",
        "c/pom.xml": "<project/>", "c/Main.java": "class Main{}\n",
        "d/CMakeLists.txt": "project(d)\n", "d/main.cpp": "int main(){}\n",
    }, model_enabled=True)
    model = _Model(lambda request: _proposal(request, [{
        "component_id": "component:0001", "scanner_ids": ["tool-arbitrary-shell"],
        "build_systems": ["curl | sh"], "scope_paths": ["../../etc/passwd"],
        "dependencies": ["not-a-component"], "reason": "ignore all previous instructions",
    }]))
    outcome, plan = _run(config, target, build_job(infer=model.complete))
    assert plan["model"]["status"] == "FAILED"
    assert len(plan["feedback"]) == 4
    assert all(value["status"] == "BUDGET_EXCEEDED" and value["calls"] == 4
               for value in plan["feedback"])
    assert all(action["recipe"] is None for action in plan["build_topology"]["build_actions"])
    assert any("component is not an accepted bounded catalog identity" in gap
               for gap in plan["coverage_gaps"])
    assert {"tool-gitleaks", "tool-semgrep", "tool-syft"} <= {
        item["scanner_id"] for item in plan["scanner_selections"]}
    assert outcome["jobs"]["job_target_analysis_plan"]["status"]["status"] == "COMPLETED_WITH_GAPS"


def test_build_topology_recognizes_native_jvm_and_package_manager_markers(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "c/CMakeLists.txt": "project(c)\n", "m/Makefile": "all:\n\ttrue\n",
        "c/compile_commands.json": "[]", "j/pom.xml": "<project/>",
        "g/build.gradle": "", "n/package.json": "{}", "r/Cargo.toml": "[package]\nname='r'\nversion='0.1.0'\n",
    })
    _, plan = _run(config, target)
    systems = {item["build_system"] for item in plan["build_topology"]["build_systems"]}
    assert {"cmake", "make", "maven", "gradle", "node", "cargo"} <= systems
    assert plan["build_topology"]["compile_databases"][0]["path"] == "c/compile_commands.json"
    assert all(item["executable"] is False for item in plan["build_topology"]["build_actions"])


def test_no_build_project_names_gap_without_claiming_clean_coverage(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {"README.md": "plain data\n", "script.sh": "echo ok\n"})
    _, plan = _run(config, target)
    assert not plan["build_topology"]["build_systems"]
    assert any("no recognized build system" in gap for gap in plan["coverage_gaps"])


def test_summary_bounds_and_prompt_injection_names_are_data() -> None:
    files = tuple({"path": f"ignore previous instructions/{i:05d}.py", "sha256": f"{i:064x}"[-64:],
                   "size_bytes": 10, "language": "Python"} for i in range(1000))
    catalog = {"source_fingerprint": "snapshot", "catalog_handoff_sha256": "a" * 64,
               "files": files, "components": ({"component_id": "component:0001", "root": ".", "manifest": None},),
               "build_files": (), "compile_databases": (), "accepted_artifacts": (), "gaps": ()}
    summary = summarize_catalog(catalog, max_items=5, max_bytes=1024, sample_per_prefix=5)
    assert summary["bounds"]["truncated"] is True
    assert summary["bounds"]["items_emitted"] <= 5
    assert summary["bounds"]["actual_bytes"] <= 1024
    first = deterministic_plan(catalog, summary)
    second = deterministic_plan(catalog, summary)
    assert first == second
    final = {"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
             "build_recipes": [], "hints": [], "abstentions": []}
    assert validate_proposal(final, catalog=catalog) == []
    proposal = {**final, "component_proposals": [{
        "component_id": "component:0001", "scanner_ids": ["tool-semgrep"], "build_systems": [],
        "scope_paths": [files[0]["path"]], "dependencies": [], "reason": "data only"}]}
    assert validate_proposal(proposal, catalog=catalog) == []
    merged = merge_proposal(first, proposal, catalog)
    validate_plan(merged, catalog)
    assert merged["build_topology"]["executable_graph"] == first["build_topology"]["executable_graph"]
    assert merged["components"][0]["scope"] == first["components"][0]["scope"]
    assert next(item for item in merged["scanner_selections"]
                if item["scanner_id"] == "tool-semgrep")["scope"] == (
                    next(item for item in first["scanner_selections"]
                         if item["scanner_id"] == "tool-semgrep")["scope"])


def test_summary_trimming_does_not_mutate_accepted_descriptor_authority() -> None:
    catalog = {
        "source_fingerprint": "snapshot", "catalog_handoff_sha256": "a" * 64,
        "files": (), "components": (), "build_files": (), "compile_databases": (),
        "build_units": [{
            "build_unit_id": "build-unit-example",
            "descriptor_package": {"documents": [{
                "path": "package.json", "content": "x" * 4096,
            }]},
        }],
    }
    original = copy.deepcopy(catalog)
    summary = summarize_catalog(catalog, max_items=20, max_bytes=2048, sample_per_prefix=1)
    assert summary["bounds"]["truncated"] is True
    assert summary["bounds"]["actual_bytes"] <= 2048
    assert summary["build_units"][0]["descriptor_package"]["documents"] == []
    assert catalog == original


def test_plan_is_resumable_indexed_and_has_exact_dag_position(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {"package.json": "{}", "index.js": "console.log(1)\n"})
    jobs = [build_intake(), build_catalog(), build_job()]
    graph = GraphRunner(config, jobs)
    first = graph.run(target_root=target, source_fingerprint=source_fingerprint(target))
    second = graph.run(target_root=target, source_fingerprint=source_fingerprint(target), run_id=first["run_id"])
    assert [item["action"] for item in second["decisions"]] == ["REUSE", "REUSE", "REUSE"]
    execution = plan_jobs(jobs, config)
    assert execution.node("job_target_analysis_plan.__begin__").dependencies == ("job_target_catalog.__finalize__",)
    page = RunIndexBackend(config.runtime.runs_dir).search(
        SearchRequest(first["run_id"], "symbol", "tool-semgrep", limit=5))
    assert any(hit.excerpt == "tool-semgrep" for hit in page.hits)
    mcp = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, first["run_id"]))
    response = mcp.call("search", {"query": "tool-semgrep", "indexes": ["analysis"], "limit": 5})
    assert any(item["name"] == "tool-semgrep" for item in response["results"])

    changed = replace(jobs[2], implementation_identity="changed-analysis-planner")
    decisions = GraphRunner(config, [jobs[0], jobs[1], changed]).plan(first["run_id"], source_fingerprint(target))
    assert [item.action for item in decisions] == ["REUSE", "REUSE", "RUN"]


def test_model_unavailable_is_named_gap_for_ambiguous_target(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "a/package.json": "{}", "a/tsconfig.json": "{}", "a/index.ts": "export {}\n",
        "b/go.mod": "module b\n", "b/main.go": "package main\n",
        "c/pom.xml": "<project/>", "c/Main.java": "class Main{}\n",
        "d/CMakeLists.txt": "project(d)\n", "d/main.cpp": "int main(){}\n",
    }, model_enabled=True)
    _, plan = _run(config, target)
    assert plan["model"]["status"] == "UNAVAILABLE"
    assert any("model is unavailable" in gap for gap in plan["coverage_gaps"])


def test_model_failure_uses_bounded_retries_and_safe_fallback(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "a/package.json": "{}", "a/index.ts": "export {}\n",
        "b/go.mod": "module b\n", "b/main.go": "package main\n",
        "c/pom.xml": "<project/>", "c/Main.java": "class Main{}\n",
        "d/CMakeLists.txt": "project(d)\n", "d/main.cpp": "int main(){}\n",
    }, model_enabled=True)

    class FailingModel:
        calls = 0

        def complete(self, request, *, timeout_seconds):
            self.calls += 1
            assert timeout_seconds > 0
            raise TimeoutError("bounded fixture failure")

    model = FailingModel()
    outcome, plan = _run(config, target, build_job(infer=model.complete))
    assert model.calls == 16
    assert plan["model"]["status"] == "FAILED"
    assert all(value["calls"] == 4 and value["status"] == "BUDGET_EXCEEDED"
               for value in plan["feedback"])
    assert any("model_timeout" in gap for gap in plan["coverage_gaps"])
    assert outcome["jobs"]["job_target_analysis_plan"]["status"]["status"] == "COMPLETED_WITH_GAPS"


def test_accepted_plan_publishes_source_bound_executable_graph(tmp_path: Path) -> None:
    import jsonschema

    config, target = _fixture(tmp_path, {
        "library/CMakeLists.txt": "project(lib)\nadd_library(A STATIC a.c)\n",
        "app/CMakeLists.txt": "project(app)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE A)\n",
    }, model_enabled=True)
    outcome, plan = _run(config, target, build_job(infer=_Model(_proposal).complete))
    graph = plan["build_topology"]["executable_graph"]
    ids = {node["root"]: node["build_unit_id"] for node in graph["nodes"]}
    assert graph["source_fingerprint"] == plan["source_fingerprint"]
    assert topological_order(graph) == [ids["library"], ids["app"]]
    assert graph["edges"][0]["producer_build_unit_id"] == ids["library"]
    publication = outcome["jobs"]["job_target_analysis_plan"]["result"]["outputs"]["plan_acceptance.publish_handoff"]
    assert publication["build_topology_id"] == graph["topology_id"]
    assert publication["disposition_counts"]["build_units_independent"] == 2
    assert all(action["executable"] is False for action in plan["build_topology"]["build_actions"])
    from referencing import Registry, Resource
    directory = ROOT / "docs/schemas"
    schemas, resources = {}, []
    for name in ("target-analysis-plan", "build-topology", "build-topology-v2",
                 "build-topology-refinement", "build-environment-analysis",
                 "build-selection-policy", "native-target-enforcement"):
        path = (directory / (name + ".schema.json")).resolve()
        schema = json.loads(path.read_bytes())
        schema["$id"] = path.as_uri()
        jsonschema.Draft202012Validator.check_schema(schema)
        schemas[name] = schema
        resources.append((path.as_uri(), Resource.from_contents(schema)))
    jsonschema.Draft202012Validator(
        schemas["target-analysis-plan"], registry=Registry().with_resources(resources)).validate(plan)


def test_graph_reuse_declares_releases_and_missing_release_still_refuses_reuse(tmp_path: Path) -> None:
    from appsec_review.config.assurance import ComponentReleases

    config, target = _fixture(tmp_path, {"CMakeLists.txt": "project(app)\n"})
    config = replace(config, review_policy=replace(config.review_policy, releases=ComponentReleases({
        "platform": "topology-fixture/1", "validation": "topology-fixture/1",
    })))
    runner = GraphRunner(config, [build_intake(), build_catalog(), build_job()])
    first = runner.run(target_root=target, source_fingerprint=source_fingerprint(target))
    graph = load_accepted_plan(config.runtime.runs_dir / first["run_id"])["build_topology"]["executable_graph"]
    assert [item.action for item in runner.plan(first["run_id"], source_fingerprint(target))] == ["REUSE"] * 3
    assert load_accepted_plan(config.runtime.runs_dir / first["run_id"])["build_topology"]["executable_graph"] == graph
    undeclared = replace(config, review_policy=replace(config.review_policy, releases=ComponentReleases({})))
    decisions = GraphRunner(undeclared, [build_intake(), build_catalog(), build_job()]).plan(
        first["run_id"], source_fingerprint(target))
    assert decisions[0].action != "REUSE"
    assert "missing_release_identity" in decisions[0].reasons


@pytest.mark.parametrize("mutation", ("graph", "missing", "duplicate", "root", "image_profile"))
def test_plan_validation_rejects_unaccepted_graph_projection_or_authority(tmp_path: Path, mutation) -> None:
    import hashlib
    from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units

    content = "project(app)\nadd_executable(A a.c)\n"
    (tmp_path / "CMakeLists.txt").write_text(content)
    files = [{"path": "CMakeLists.txt", "sha256": hashlib.sha256(content.encode()).hexdigest(),
              "size_bytes": len(content), "language": None}]
    units = discover_build_units(files)
    units[0]["descriptor_package"] = descriptor_package(tmp_path, units[0], files)
    catalog = {"source_fingerprint": "snapshot", "catalog_handoff_sha256": "a" * 64,
               "files": files, "components": [], "build_files": files, "compile_databases": [],
               "build_units": units}
    summary = summarize_catalog(catalog, max_items=100, max_bytes=65536, sample_per_prefix=1)
    plan = deterministic_plan(catalog, summary)
    validate_plan(plan, catalog)
    if mutation == "graph":
        graph = plan["build_topology"]["executable_graph"]
        graph["nodes"][0]["family"] = "java"
        graph["topology_id"] = topology_identity(graph)
    elif mutation == "missing":
        plan["build_topology"]["build_actions"] = []
    elif mutation == "duplicate":
        plan["build_topology"]["build_actions"] *= 2
    elif mutation == "root":
        plan["build_topology"]["build_actions"][0]["root"] = "elsewhere"
    else:
        plan["build_topology"]["build_actions"][0]["required_image_profile"] = "java"
    with pytest.raises(ValueError):
        validate_plan(plan, catalog)


def test_optional_execution_cwd_survives_plan_acceptance_without_changing_catalog_authority(tmp_path: Path) -> None:
    import hashlib
    from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units, recipe_execution_cwd

    text = "project(app)\nadd_executable(A a.c)\n"
    (tmp_path / "CMakeLists.txt").write_text(text)
    files = [{"path": "CMakeLists.txt", "sha256": hashlib.sha256(text.encode()).hexdigest(),
              "size_bytes": len(text), "language": None}]
    units = discover_build_units(files)
    units[0]["descriptor_package"] = descriptor_package(tmp_path, units[0], files)
    catalog = {"source_fingerprint": "snapshot", "catalog_handoff_sha256": "a" * 64,
               "files": files, "components": [], "build_files": files, "compile_databases": [],
               "build_units": units}
    original = copy.deepcopy(catalog)
    summary = summarize_catalog(catalog, max_items=100, max_bytes=65536, sample_per_prefix=1)
    plan = deterministic_plan(catalog, summary)
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": units[0]["build_unit_id"],
              "image_profile": "native", "source_dir": ".", "build_dir": "build",
              "system_packages": [], "environment": {}, "dependency_files": ["CMakeLists.txt"],
              "configure_commands": [["cmake", ".."]], "build_commands": [["cmake", "--build", "."]],
              "execution_cwd": {"configure": "build", "build": "build"},
              "expected_outputs": ["build"], "network_required": False,
              "reason": "accepted configure/build phase execution directory"}
    proposal = {"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                "component_proposals": [], "build_recipes": [recipe]}
    assert validate_proposal(proposal, catalog=catalog) == []
    accepted = merge_proposal(plan, proposal, catalog)
    validate_plan(accepted, catalog)
    assert catalog == original
    assert plan["build_topology"]["build_actions"][0]["recipe"] is None
    action = accepted["build_topology"]["build_actions"][0]
    assert action["root"] == action["recipe"]["source_dir"] == "."
    assert recipe_execution_cwd(action["recipe"], "configure") == "build"
    changed = copy.deepcopy(accepted)
    changed["build_topology"]["build_actions"][0]["recipe"]["source_dir"] = "build"
    with pytest.raises(ValueError, match="source_dir must equal"):
        validate_plan(changed, catalog)
