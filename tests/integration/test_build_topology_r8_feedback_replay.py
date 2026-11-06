"""Manual R8 actual-catalog offline feedback replay.

Requires explicit external capture custody (APPSEC_TOPOLOGY_R8_SOURCE, APPSEC_TOPOLOGY_R8_KIND and
APPSEC_TOPOLOGY_R8_CAPTURE_RUN). It lives under tests/integration so implicit unit collection
excludes it; run it only on explicit request.
"""
from __future__ import annotations

import pytest


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
