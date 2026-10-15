"""Regression tests for the mandatory tool-image rebuild gate (``job_tool_image_rebuild``).

The builder is always a fake: no test reaches Docker or writes under the repository's ``runs/``.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from appsec_review.cli import GRAPH_JOB_IDS
from appsec_review.config import load_config, parse_tool_image_rebuild_settings
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_tool_image_rebuild import build_job
from appsec_review.jobs.job_tool_image_rebuild.job import configured_pins, dependency_order
from appsec_review.runtime import GraphRunner, active_job_ids
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).parents[1]
SECTION = "[jobs.job_tool_image_rebuild.settings]"
CATALOG = """
[[images]]
id = "base-a"
state = "enabled"
kind = "base"
tag = "fixture/base-a:1"
dependencies = []

[[images]]
id = "tool-x"
state = "enabled"
kind = "tool"
tag = "fixture/tool-x:1"
dependencies = ["base-a"]

[[images]]
id = "tool-y"
state = "enabled"
kind = "tool"
tag = "fixture/tool-y:1"
dependencies = ["base-a", "base-b"]

[[images]]
id = "base-b"
state = "enabled"
kind = "base"
tag = "fixture/base-b:1"
dependencies = []

[[images]]
id = "retired-z"
state = "retired"
kind = "retired"
reason = "fixture"
"""
# Catalog order lists tool-y before its base-b dependency; the builder order must not.
ALL_ORDER = ["base-a", "tool-x", "base-b", "tool-y"]
DEPENDENCIES = {"base-a": [], "tool-x": ["base-a"], "tool-y": ["base-a", "base-b"], "base-b": []}


def _settings_source(**overrides: str) -> str:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    head, rest = source.split(SECTION + "\n", 1)
    body, tail = rest.split("\n[", 1)
    for key, value in overrides.items():
        body, count = re.subn(rf"(?m)^{key} = .*$", f"{key} = {value}", body)
        if count == 0:
            body += f"\n{key} = {value}"
    return head + SECTION + "\n" + body + "\n[" + tail


def _fixture(tmp_path: Path, **overrides: str):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(**overrides), encoding="utf-8")
    containers = tmp_path / "containers"
    containers.mkdir()
    (containers / "catalog.toml").write_text(CATALOG, encoding="utf-8")
    (containers / "build.py").write_text("# fixture builder; tests inject the runner\n", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    return load_config(config_path), target


class FakeBuilder:
    """Imitate ``containers/build.py build`` output: summary file, per-image logs, exit status."""

    def __init__(self, root: Path, *, fail: tuple[str, ...] = (), returncode: int | None = None,
                 stderr: str = "", no_digest: tuple[str, ...] = (), timed_out: bool = False,
                 summary: bool = True, raises: Exception | None = None, order: list[str] | None = None):
        self.root, self.fail, self.no_digest = root, set(fail), set(no_digest)
        self.returncode, self.stderr, self.timed_out = returncode, stderr, timed_out
        self.summary, self.raises, self.order = summary, raises, order
        self.calls: list[dict] = []

    def __call__(self, argv, *, cwd, timeout_seconds):
        self.calls.append({"argv": list(argv), "cwd": cwd, "timeout_seconds": timeout_seconds})
        if self.raises is not None:
            raise self.raises
        requested = list(argv[argv.index("build") + 1:argv.index("--jobs")])
        ordered = self.order or [image for image in ALL_ORDER if image in self._closure(requested)]
        output = self.root / "builder-output"
        (output / "logs").mkdir(parents=True, exist_ok=True)
        results, failed = [], set()
        for image in ordered:
            log = f"builder-output/logs/{image}.build.log"
            if any(dependency in failed for dependency in DEPENDENCIES[image]):
                failed.add(image)
                results.append({"id": image, "tag": f"fixture/{image}:1", "status": "blocked",
                                "digest": None, "error": "dependency failed", "duration_seconds": 0,
                                "fetch_log": None, "build_log": None})
                continue
            (self.root / log).write_text(f"step 1/2 {image}\nERROR: {image} compile broke\n", encoding="utf-8")
            if image in self.fail:
                failed.add(image)
                results.append({"id": image, "tag": f"fixture/{image}:1", "status": "failed",
                                "digest": None, "error": "docker build exited 1", "duration_seconds": 1.5,
                                "fetch_log": f"builder-output/logs/{image}.fetch.log", "build_log": log})
            else:
                results.append({"id": image, "tag": f"fixture/{image}:1", "status": "passed",
                                "digest": None if image in self.no_digest else "sha256:" + image.encode().hex(),
                                "duration_seconds": 2.25, "dockerfile_sha256": "d" * 64,
                                "assets_lock_sha256": None, "base_identity": None,
                                "fetch_log": f"builder-output/logs/{image}.fetch.log", "build_log": log})
        stdout = "".join(f"{item['status'].upper():7} {item['id']}\n" for item in results)
        if self.summary:
            (output / "summary.json").write_text(json.dumps({
                "schema": "appsec-review/container-build-summary/1", "run_id": "fixture-build",
                "catalog": "containers/catalog.toml", "jobs": 2, "continue_on_error": True,
                "results": results}), encoding="utf-8")
            stdout += "summary=builder-output/summary.json\n"
        returncode = self.returncode if self.returncode is not None else (1 if failed else 0)
        return {"returncode": returncode, "stdout": stdout, "stderr": self.stderr, "timed_out": self.timed_out}

    @staticmethod
    def _closure(requested):
        seen: set[str] = set()
        pending = list(requested)
        while pending:
            image = pending.pop()
            if image not in seen:
                seen.add(image)
                pending.extend(DEPENDENCIES[image])
        return seen


def _run(config, target, builder, *jobs):
    return GraphRunner(config, [build_job(run_builder=builder), *jobs]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))


def _unit_root(config, run_id: str, step: str, task: str) -> Path:
    attempts = config.runtime.runs_dir / run_id / "data/jobs/job_tool_image_rebuild/attempts"
    attempt = sorted(attempts.iterdir())[-1]
    return attempt / "steps" / step / "tasks" / task


def _only_run_id(config) -> str:
    return next(path.name for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")


# ---------------------------------------------------------------- success path

def test_success_rebuilds_every_enabled_image_in_dependency_order_and_writes_receipts(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    builder = FakeBuilder(tmp_path)
    outcome = _run(config, target, builder)
    assert outcome["status"] == "SUCCEEDED"

    (call,) = builder.calls
    argv = call["argv"]
    assert argv[1] == str(tmp_path / "containers" / "build.py") and argv[2] == "build"
    assert argv[3:7] == ["base-a", "tool-x", "tool-y", "base-b"]          # enabled, catalog order
    assert argv[argv.index("--jobs") + 1] == "2"
    assert argv[argv.index("--timeout-seconds") + 1] == "1800"
    assert "--continue-on-error" in argv and "retired-z" not in argv
    assert call["cwd"] == tmp_path and call["timeout_seconds"] == 14400

    build_root = _unit_root(config, outcome["run_id"], "build", "build_images")
    receipts = {path.stem: json.loads(path.read_text()) for path in (build_root / "receipts").glob("*.json")}
    assert sorted(receipts) == sorted(ALL_ORDER)
    assert [image for image, _ in sorted(receipts.items(), key=lambda item: item[1]["order"])] == ALL_ORDER
    for image, receipt in receipts.items():
        assert receipt["schema"] == "appsec-review/tool-image-receipt/1"
        assert receipt["tag"] == f"fixture/{image}:1"
        assert receipt["image_digest"] == "sha256:" + image.encode().hex()
        assert receipt["duration_seconds"] == 2.25
        assert receipt["build_log"] == f"builder-output/logs/{image}.build.log"
        assert all(receipts[dependency]["order"] < receipt["order"] for dependency in receipt["dependencies"])

    summary = json.loads((build_root / "tool-image-rebuild.json").read_text())
    assert summary["exit_status"] == 0 and [item["image_id"] for item in summary["images"]] == ALL_ORDER
    assert summary["builder_summary"]["source"] == "builder-output/summary.json"
    assert (build_root / "builder-summary.json").is_file()
    handoff = json.loads((_unit_root(config, outcome["run_id"], "publication", "publish_handoff") /
                          "tool-image-rebuild-handoff.json").read_text())
    assert [item["image_id"] for item in handoff["images"]] == ALL_ORDER
    events = (config.runtime.runs_dir / outcome["run_id"] / "data/jobs/job_tool_image_rebuild/attempts")
    assert "TOOL_IMAGE_REBUILD_COMPLETED" in "".join(
        path.read_text() for path in events.rglob("*.jsonl"))


def test_configured_images_build_their_dependencies_first(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, images='["tool-y"]', parallelism="4", image_timeout_seconds="600",
                              continue_on_error="false")
    builder = FakeBuilder(tmp_path)
    outcome = _run(config, target, builder)
    argv = builder.calls[0]["argv"]
    assert argv[3:argv.index("--jobs")] == ["tool-y"]
    assert argv[argv.index("--jobs") + 1] == "4" and argv[argv.index("--timeout-seconds") + 1] == "600"
    assert "--continue-on-error" not in argv
    plan = json.loads((_unit_root(config, outcome["run_id"], "selection", "resolve_images") /
                       "tool-image-plan.json").read_text())
    assert plan["selection"] == "configured"
    assert [item["id"] for item in plan["ordered"]] == ["base-a", "base-b", "tool-y"]


def test_dependency_order_places_every_image_after_its_dependencies() -> None:
    by_id = {image: {"id": image, "state": "enabled", "dependencies": deps} for image, deps in DEPENDENCIES.items()}
    assert dependency_order(["base-a", "tool-x", "tool-y", "base-b"], by_id) == ALL_ORDER
    by_id["base-b"]["dependencies"] = ["tool-y"]
    with pytest.raises(ValueError, match="cycle"):
        dependency_order(["tool-y"], by_id)


def test_the_gate_always_executes_and_does_not_propagate_its_handoff(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    builder = FakeBuilder(tmp_path)
    first = _run(config, target, builder)
    second = GraphRunner(config, [build_job(run_builder=builder)]).run(
        run_id=first["run_id"], target_root=target, source_fingerprint=source_fingerprint(target))
    assert second["status"] == "SUCCEEDED" and len(builder.calls) == 2
    job = builtin_registry().build("job_tool_image_rebuild")
    assert job.always_execute is True and job.propagate_handoff is False


# ---------------------------------------------------------------- failures fail the run

def test_a_failed_image_fails_the_run_with_a_bounded_actionable_report(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    builder = FakeBuilder(tmp_path, fail=("base-b",), stderr="docker: daemon said no\n")
    with pytest.raises(RuntimeError) as raised:
        _run(config, target, builder, build_intake())
    run_id = _only_run_id(config)
    assert not (config.runtime.runs_dir / run_id / "data/jobs/job_review_intake").exists()

    build_root = _unit_root(config, run_id, "build", "build_images")
    status = json.loads((build_root / "status.json").read_text())
    assert status["status"] == "FAILED"
    message = status["error"]["message"]
    for expected in ("base-b (failed: docker build exited 1; build log builder-output/logs/base-b.build.log)",
                     "tool-y (blocked: dependency failed)",
                     "exit status: 1", "command: ", "build.py build base-a tool-x tool-y base-b",
                     "docker: daemon said no", "builder summary: builder-output/summary.json",
                     "ERROR: base-b compile broke"):
        assert expected in message
    assert f"failure record: {build_root / 'tool-image-rebuild-failure.json'}" in message
    assert not (build_root / "receipts").exists()

    record = json.loads((build_root / "tool-image-rebuild-failure.json").read_text())
    assert record["exit_status"] == 1
    assert [item["image_id"] for item in record["failures"] if item["image_id"]] == ["base-b", "tool-y"]
    assert "ERROR: base-b compile broke" in record["failures"][0]["build_log_tail"]

    pipeline_log = config.runtime.runs_dir / run_id / "data" / "logs" / "pipeline.jsonl"
    events = [json.loads(line) for line in pipeline_log.read_text().splitlines()]
    (failure,) = [event for event in events if event["event_type"] == "TOOL_IMAGE_REBUILD_FAILED"]
    assert failure["level"] == "ERROR" and failure["job_id"] == "job_tool_image_rebuild"
    assert failure["details"]["failed_images"] == ["base-b", "tool-y"]
    assert failure["details"]["exit_status"] == 1 and "docker: daemon said no" in failure["details"]["stderr_tail"]
    assert not any("WITH_GAPS" in event["event_type"] for event in events)
    assert "build.build_images" in str(raised.value)


@pytest.mark.parametrize("builder_options, expected", [
    ({"no_digest": ("tool-x",)}, "tool-x (passed: built image digest is missing"),
    ({"returncode": 2}, "builder: builder_failed: builder exited 2"),
    ({"timed_out": True, "returncode": -15}, "builder: timed_out: builder exceeded total_timeout_seconds=14400"),
    ({"summary": False, "returncode": 1}, "builder: no_summary"),
    ({"raises": FileNotFoundError("python vanished")}, "FileNotFoundError: python vanished"),
    ({"order": ["tool-x", "base-a", "base-b", "tool-y"]}, "builder: order_mismatch"),
], ids=["missing-digest", "nonzero-exit", "timeout", "no-summary", "runner-raises", "order-mismatch"])
def test_every_builder_failure_mode_fails_instead_of_becoming_a_gap(
        tmp_path: Path, builder_options, expected: str) -> None:
    config, target = _fixture(tmp_path)
    with pytest.raises(RuntimeError):
        _run(config, target, FakeBuilder(tmp_path, **builder_options))
    status = json.loads((_unit_root(config, _only_run_id(config), "build", "build_images") /
                         "status.json").read_text())
    assert status["status"] == "FAILED" and expected in status["error"]["message"]


def test_failure_report_tails_are_bounded_by_log_tail_bytes(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, log_tail_bytes="256")
    noise = "".join(f"noise line {index}\n" for index in range(2000))
    with pytest.raises(RuntimeError):
        _run(config, target, FakeBuilder(tmp_path, fail=("base-a",), stderr=noise + "LAST LINE\n"))
    message = json.loads((_unit_root(config, _only_run_id(config), "build", "build_images") /
                          "status.json").read_text())["error"]["message"]
    assert "LAST LINE" in message and "[...truncated...]" in message and "noise line 0\n" not in message
    assert len(message.encode()) < 4096


def test_unknown_or_disabled_configured_image_fails_before_building(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, images='["retired-z"]')
    builder = FakeBuilder(tmp_path)
    with pytest.raises(RuntimeError):
        _run(config, target, builder)
    assert builder.calls == []
    status = json.loads((_unit_root(config, _only_run_id(config), "selection", "resolve_images") /
                         "status.json").read_text())
    assert "retired-z is retired, not enabled" in status["error"]["message"]


def test_an_unwired_job_refuses_to_claim_images_were_built(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    with pytest.raises(RuntimeError):
        GraphRunner(config, [build_job()]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    status = json.loads((_unit_root(config, _only_run_id(config), "build", "build_images") /
                         "status.json").read_text())
    assert "not wired" in status["error"]["message"]


# ---------------------------------------------------------------- settings

def test_repository_settings_are_typed_and_enabled_by_default() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = config.job("job_tool_image_rebuild").typed_settings
    assert settings == parse_tool_image_rebuild_settings(config.job("job_tool_image_rebuild").settings)
    assert settings.enabled is True and settings.images == ()
    assert 1 <= settings.parallelism <= 8 and settings.total_timeout_seconds >= settings.image_timeout_seconds


@pytest.mark.parametrize("key, value, message", [
    ("enabled", '"yes"', "enabled must be a boolean"),
    ("images", '"all"', "images must be a list"),
    ("images", '["Bad_Id"]', "images must be a list"),
    ("images", '["base-a", "base-a"]', "must not repeat"),
    ("parallelism", "0", "parallelism must be an integer"),
    ("parallelism", "9", "parallelism must be an integer"),
    ("parallelism", '"2"', "parallelism must be an integer"),
    ("parallelism", "true", "parallelism must be an integer"),
    ("image_timeout_seconds", "10", "image_timeout_seconds must be an integer"),
    ("total_timeout_seconds", "600", "total_timeout_seconds must be at least image_timeout_seconds"),
    ("continue_on_error", "1", "continue_on_error must be a boolean"),
    ("log_tail_bytes", "10", "log_tail_bytes must be an integer"),
    ("unexpected", "1", "unknown settings: unexpected"),
    ("pin_mismatch", '"ignore"', "pin_mismatch must be one of: fail, report"),
])
def test_settings_validation_rejects_bad_values(tmp_path: Path, key: str, value: str, message: str) -> None:
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(**{key: value}), encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(message)):
        load_config(config_path)


def test_settings_validation_rejects_a_missing_setting() -> None:
    settings = dict(load_config(ROOT / "appsec-review.toml").job("job_tool_image_rebuild").settings)
    del settings["log_tail_bytes"]
    with pytest.raises(ValueError, match="missing settings: log_tail_bytes"):
        parse_tool_image_rebuild_settings(settings)


# ---------------------------------------------------------------- topology

def test_direct_graph_places_the_rebuild_between_the_model_gate_and_intake(tmp_path: Path) -> None:
    order = list(GRAPH_JOB_IDS)
    assert order.index("job_model_connectivity") + 1 == order.index("job_tool_image_rebuild")
    assert order.index("job_tool_image_rebuild") + 1 == order.index("job_review_intake")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(enabled="false"), encoding="utf-8")
    selected = active_job_ids(load_config(config_path), GRAPH_JOB_IDS)
    assert "job_tool_image_rebuild" not in selected
    assert selected[:2] == ("job_model_connectivity", "job_review_intake")


COMPOSITES = {"wave1_review": "", "ci_configuration_review": "ci_review__",
              "project_build_review": "project_build_review__"}


def _upstream(graph, node: str) -> set[str]:
    mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
    return {output.node_name for outputs in mapping.values() for output in outputs}


def test_every_composite_graph_runs_the_rebuild_after_the_model_gate_and_before_intake() -> None:
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import build_definitions

    definitions = build_definitions(ROOT / "appsec-review.toml")
    assert definitions.get_job_def("tool_image_rebuild").name == "tool_image_rebuild"
    for name, prefix in COMPOSITES.items():
        graph = definitions.get_job_def(name).graph
        assert _upstream(graph, f"{prefix}tool_image_rebuild__begin") == {f"{prefix}model_connectivity__finalize"}
        assert _upstream(graph, f"{prefix}review_intake__begin") == {f"{prefix}tool_image_rebuild__finalize"}
        assert f"{prefix}tool_image_rebuild__build__build_images" in {node.name for node in graph.node_defs}


def test_a_disabled_rebuild_is_transparent_to_every_composite_graph(tmp_path: Path) -> None:
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import build_definitions

    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(enabled="false"), encoding="utf-8")
    definitions = build_definitions(config_path)
    assert "tool_image_rebuild" not in {job.name for job in definitions.get_repository_def().get_all_jobs()}
    for name, prefix in COMPOSITES.items():
        graph = definitions.get_job_def(name).graph
        assert not any("tool_image_rebuild__" in node.name for node in graph.node_defs)
        assert _upstream(graph, f"{prefix}review_intake__begin") == {f"{prefix}model_connectivity__finalize"}


def test_the_default_runner_reports_exit_status_output_and_timeouts(tmp_path: Path) -> None:
    import sys
    from appsec_review.jobs.job_tool_image_rebuild.job import run_builder

    done = run_builder([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
                       cwd=tmp_path, timeout_seconds=30)
    assert done == {"returncode": 3, "stdout": "out\n", "stderr": "err\n", "timed_out": False}
    slow = run_builder([sys.executable, "-c", "import time; print('started', flush=True); time.sleep(60)"],
                       cwd=tmp_path, timeout_seconds=1)
    assert slow["timed_out"] is True and slow["returncode"] != 0 and "started" in slow["stdout"]


# ---------------------------------------------------------------- image-ID pins

def _pin_catalog(tmp_path: Path, image_id: str) -> None:
    catalog = tmp_path / "containers" / "catalog.toml"
    catalog.write_text(catalog.read_text().replace(
        'tag = "fixture/tool-x:1"\n', f'tag = "fixture/tool-x:1"\nimage_id = "{image_id}"\n'))


def test_configured_pins_cover_catalog_and_enabled_job_settings_only() -> None:
    document = {"jobs": {
        "job_project_build": {"settings": {"profiles": {"native": {
            "tag": "audit-buildenv-cpp:local", "image_id": "sha256:" + "a" * 64, "user": "10001:10001"}}}},
        "job_codeql_analysis": {"settings": {"source_image_tag": "audit-codeql:x",
                                             "source_image_id": "sha256:" + "b" * 64}},
        "job_off": {"settings": {"enabled": False, "tag": "t", "image_id": "sha256:" + "c" * 64}},
    }}
    catalog = [{"id": "tool-x", "tag": "fixture/tool-x:1", "image_id": "sha256:" + "d" * 64},
               {"id": "tool-y", "tag": "fixture/tool-y:1"}]
    pins = configured_pins(catalog, document)
    assert [(pin["source"], pin["tag"]) for pin in pins] == [
        ("containers/catalog.toml images.tool-x.image_id", "fixture/tool-x:1"),
        ("jobs.job_codeql_analysis.settings.source_image_id", "audit-codeql:x"),
        ("jobs.job_project_build.settings.profiles.native.image_id", "audit-buildenv-cpp:local"),
    ]


def test_a_matching_pin_is_recorded_on_the_receipt(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    _pin_catalog(tmp_path, "sha256:" + "tool-x".encode().hex())
    outcome = _run(config, target, FakeBuilder(tmp_path))
    receipt = json.loads((_unit_root(config, outcome["run_id"], "build", "build_images") /
                          "receipts" / "tool-x.json").read_text())
    assert [pin["status"] for pin in receipt["pins"]] == ["matched"]


def test_a_rebuild_that_invalidates_a_pin_fails_the_run_naming_the_stale_pin(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    _pin_catalog(tmp_path, "sha256:" + "0" * 64)
    with pytest.raises(RuntimeError):
        _run(config, target, FakeBuilder(tmp_path), build_intake())
    run_id = _only_run_id(config)
    assert not (config.runtime.runs_dir / run_id / "data/jobs/job_review_intake").exists()
    build_root = _unit_root(config, run_id, "build", "build_images")
    message = json.loads((build_root / "status.json").read_text())["error"]["message"]
    assert ("containers/catalog.toml images.tool-x.image_id pins fixture/tool-x:1 to sha256:" + "0" * 64 +
            " but the rebuild produced sha256:" + "tool-x".encode().hex()) in message
    assert json.loads((build_root / "tool-image-rebuild.json").read_text())["pins"][0]["status"] == "mismatched"


def test_report_mode_records_a_stale_pin_and_leaves_enforcement_to_the_consumer(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, pin_mismatch='"report"')
    _pin_catalog(tmp_path, "sha256:" + "0" * 64)
    outcome = _run(config, target, FakeBuilder(tmp_path))
    assert outcome["status"] == "SUCCEEDED"
    handoff = json.loads((_unit_root(config, outcome["run_id"], "publication", "publish_handoff") /
                          "tool-image-rebuild-handoff.json").read_text())
    assert [pin["source"] for pin in handoff["pin_mismatches"]] == [
        "containers/catalog.toml images.tool-x.image_id"]
