from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.build_topology import topological_order
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA, PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore, RunIndexBackend, SearchRequest
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).resolve().parents[3]


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
        "native/CMakeLists.txt": "project(fixture)\nadd_executable(fixture main.cpp)\n", "native/main.cpp": "int main(){}\n",
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
    files["compiled/CMakeLists.txt"] = "project(fixture)\nadd_executable(fixture main.cpp)\n"
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
    assert len(actions) == 18
    assert not any(root.startswith("vendor/fragment-") for root in actions)
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
    assert "no compilation or build step" in gaps
    assert "unavailable_native_windows_toolchain" in gaps
    assert "unsupported_native_orchestration" in gaps
    assert "unavailable_native_project_toolchain" in gaps


def test_invalid_model_proposal_falls_back_and_preserves_baseline(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "a/package.json": "{}", "a/tsconfig.json": "{}", "a/index.ts": "export {}\n",
        "b/go.mod": "module b\n", "b/main.go": "package main\n",
        "c/pom.xml": "<project/>", "c/Main.java": "class Main{}\n",
        "d/CMakeLists.txt": "project(d)\nadd_executable(d main.cpp)\n", "d/main.cpp": "int main(){}\n",
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
        "c/CMakeLists.txt": "project(c)\nadd_executable(c main.cpp)\n", "m/Makefile": "all:\n\ttrue\n",
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
        "d/CMakeLists.txt": "project(d)\nadd_executable(d main.cpp)\n", "d/main.cpp": "int main(){}\n",
    }, model_enabled=True)
    _, plan = _run(config, target)
    assert plan["model"]["status"] == "UNAVAILABLE"
    assert any("model is unavailable" in gap for gap in plan["coverage_gaps"])


def test_model_failure_uses_bounded_retries_and_safe_fallback(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, {
        "a/package.json": "{}", "a/index.ts": "export {}\n",
        "b/go.mod": "module b\n", "b/main.go": "package main\n",
        "c/pom.xml": "<project/>", "c/Main.java": "class Main{}\n",
        "d/CMakeLists.txt": "project(d)\nadd_executable(d main.cpp)\n", "d/main.cpp": "int main(){}\n",
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

    config, target = _fixture(tmp_path, {"CMakeLists.txt": "project(app)\nadd_executable(app main.cpp)\n"})
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


def test_genuine_graph1_accepted_publication_index_and_audit_have_no_graph2_execution_authority(tmp_path):
    from appsec_review.jobs.build_topology import _compile_graph1, ready_build_units, validate_build_topology
    from appsec_review.jobs.build_topology_artifacts import guard_action, guard_build_cache, publish_refinement
    from appsec_review.jobs.job_target_analysis_plan.job import _artifact
    from appsec_review.retrieval.model import EntityKind
    from appsec_review.runtime import UnitExecutor
    config, target = _fixture(tmp_path, {"CMakeLists.txt": "project(app)\nadd_executable(A a.c)\n",
                                       "a.c": "int main(void) { return 0; }\n"}, model_enabled=True)
    planner = build_job(infer=_Model(_proposal).complete)

    def historical_acceptance(unit):
        resolution = unit.output("analysis_decisions.resolve_ambiguity")
        plan = copy.deepcopy(resolution["plan"])
        topology = plan["build_topology"]
        topology["executable_graph"] = _compile_graph1(
            topology["build_actions"], source_fingerprint=plan["source_fingerprint"])
        topology.pop("evidence_bundle")
        topology.pop("planning_refinement")
        validate_build_topology(topology["executable_graph"])
        return {"status": "VALID", "plan": plan, "artifact": _artifact(unit, "historical-plan.json", plan),
                "gaps": plan["coverage_gaps"], "terminal_status": resolution["terminal_status"]}

    units = tuple(replace(unit, handler=historical_acceptance)
                  if unit.unit_id == "plan_acceptance.validate_plan" else unit for unit in planner.units)
    planner = replace(planner, units=units, handler=UnitExecutor(units).execute)
    outcome, accepted = _run(config, target, planner)
    run = config.runtime.runs_dir / outcome["run_id"]
    graph = accepted["build_topology"]["executable_graph"]
    assert graph["schema"] == "appsec-review/build-topology/1"
    publication = outcome["jobs"]["job_target_analysis_plan"]["result"]["outputs"]["plan_acceptance.publish_handoff"]
    assert publication["build_topology_schema"] == graph["schema"]
    assert publication["build_topology_id"] == graph["topology_id"]
    assert publication["index_identity"]["sha256"]
    response = RetrievalCore(config.runtime.runs_dir, run.name).search(
        query="cmake", indexes=("analysis",), kinds=(EntityKind.BUILD_ACTION.value,), limit=10)
    assert any(item["native_id"].startswith("planned-build:") for item in response["results"])
    before = (run / "data/jobs/job_target_analysis_plan/latest.json").read_bytes()
    readiness = ready_build_units(graph, {})
    assert readiness["ready"] == [] and readiness["blocked"]
    assert all(item["reasons"] == ["legacy_graph_requires_accepted_replanning"] for item in readiness["blocked"])
    action = accepted["build_topology"]["build_actions"][0]
    with pytest.raises(ValueError, match="graph/1"):
        guard_action(run, action, graph=graph)
    with pytest.raises(ValueError, match="graph/1"):
        guard_build_cache(run, "job_project_build", {"dispatches": [action]})
    with pytest.raises(ValueError, match="graph/1"):
        publish_refinement(run, [action])
    assert load_accepted_plan(run) == accepted
    assert (run / "data/jobs/job_target_analysis_plan/latest.json").read_bytes() == before
    assert not (run / "data/build/topology/accepted-refinements.json").exists()


def test_real_planner_requests_and_publishes_exact_additive_evidence(tmp_path: Path) -> None:
    from tests.test_build_topology_feedback import _inputs

    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native/CMakeLists.txt").write_bytes(b"project(control)\nadd_executable(control main.c)\n")
    (target / "native/main.c").write_bytes(b"int main(void) { return 0; }\n")
    (target / "native/note.txt").write_bytes(b"explicitly synthetic additive evidence\r\n")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_bytes((ROOT / "appsec-review.toml").read_bytes())
    config = load_config(config_path)
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        if len(calls) == 1:
            identity = next(item for item in request.summary["evidence_inventory"]
                            if item["path"] == "native/note.txt")
            return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
                "path": identity["path"], "sha256": identity["sha256"], "reason": "read exact accepted notes"}]})
        assert request.summary["evidence"][0]["content"].endswith("\r\n")
        _, _, final, _ = _inputs()
        unit = request.summary["build_units"][0]
        final["build_recipes"][0]["build_unit_id"] = unit["build_unit_id"]
        return ModelResult(final)

    result = GraphRunner(config, [build_intake(), build_catalog(), build_job(infer=infer)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / result["run_id"]
    plan = load_accepted_plan(run_root)
    assert len(calls) == 2 and plan["feedback"][0]["calls"] == 2
    assert plan["feedback"][0]["metrics"]["evidence_bytes"] == len(
        b"explicitly synthetic additive evidence\r\n")
    assert plan["planning_evidence"][0]["path"] == "native/note.txt"
    assert plan["planning_evidence"][0]["sha256"] == hashlib.sha256(
        b"explicitly synthetic additive evidence\r\n").hexdigest()
    assert plan["build_environment"]["mode"] == "NOT_RUN"
    assert plan["build_environment"]["availability"] == "ABSENT"
    pointer = json.loads((run_root / "data/jobs/job_target_analysis_plan/latest.json").read_bytes())
    claim = json.loads((run_root / Path(pointer["handoff_path"]).parent / "claim.json").read_bytes())
    launch = json.loads(claim["orchestration"]["build_environment_contract"])
    assert launch == {key: plan["build_environment"][key] for key in launch}
    assert set(launch) == {"schema", "workflow", "expected_producer", "mode", "reference", "reason"}
