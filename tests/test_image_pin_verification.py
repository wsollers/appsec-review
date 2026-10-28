"""Regression tests for the pre-intake image-pin verification gate (``job_image_pin_verification``).

The command runner is always a fake: no test reaches Docker or writes under the repository's ``runs/``.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

import pytest

from appsec_review.cli import GRAPH_JOB_IDS
from appsec_review.config import load_config, parse_image_pin_verification_settings
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_image_pin_verification import build_job
from appsec_review.jobs.job_image_pin_verification.pins import configured_pins
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.runtime import GraphRunner, active_job_ids
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).parents[1]
JOB_ID = "job_image_pin_verification"
SECTION = f"[jobs.{JOB_ID}.settings]"
PIN_X = "sha256:" + "1" * 64
CATALOG = f"""
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
image_id = "{PIN_X}"
dependencies = ["base-a"]

[[images]]
id = "retired-z"
state = "retired"
kind = "retired"
reason = "fixture"
"""


def _id(seed: str) -> str:
    return "sha256:" + seed.encode().hex().ljust(64, "0")[:64]


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
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    return load_config(config_path), target


def _expected_pins(tmp_path: Path) -> list[dict]:
    document = tomllib.loads((tmp_path / "appsec-review.toml").read_text(encoding="utf-8"))
    catalog = tomllib.loads(CATALOG)["images"]
    return configured_pins(catalog, document)


class FakeDocker:
    """Imitate ``docker image inspect <tag> --format {{.Id}}`` for a fixed local image table."""

    def __init__(self, images: dict[str, str | None], *, errors: dict[str, str] | None = None):
        self.images, self.errors = dict(images), dict(errors or {})
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        assert argv[:3] == ("docker", "image", "inspect") and argv[4:] == ("--format", "{{.Id}}")
        assert timeout == 60
        tag = argv[3]
        if tag in self.errors:
            return 1, b"", self.errors[tag].encode(), False
        image = self.images.get(tag)
        if image is None:
            return 1, b"", f"Error: No such image: {tag}\n".encode(), False
        return 0, (image + "\n").encode(), b"", False


def _all_matching(tmp_path: Path) -> FakeDocker:
    """A daemon on which every configured pin resolves to exactly its pinned image."""
    images = {}
    for pin in _expected_pins(tmp_path):
        images[pin["tag"]] = pin["image_id"] or _id(pin["tag"])
    return FakeDocker(images)


def _run(config, target, docker, *jobs):
    return GraphRunner(config, [build_job(runner=docker), *jobs]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))


def _unit_root(config, run_id: str, step: str, task: str) -> Path:
    attempts = config.runtime.runs_dir / run_id / f"data/jobs/{JOB_ID}/attempts"
    attempt = sorted(attempts.iterdir())[-1]
    return attempt / "steps" / step / "tasks" / task


def _only_run_id(config) -> str:
    return next(path.name for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")


def _failure_message(config) -> str:
    root = _unit_root(config, _only_run_id(config), "verification", "inspect_images")
    status = json.loads((root / "status.json").read_text())
    assert status["status"] == "FAILED"
    return status["error"]["message"]


# ---------------------------------------------------------------- pin selection

def test_repository_pins_cover_catalog_images_build_profiles_and_codeql_source() -> None:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    catalog = tomllib.loads((ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8"))["images"]
    sources = {pin["source"] for pin in configured_pins(catalog, document)}
    enabled = {item["id"] for item in catalog if item.get("state") == "enabled" and not item.get("manual")}
    assert {f"containers/catalog.toml images.{image}.image_id" for image in enabled} <= sources
    assert not any(".tool-report-latex." in source for source in sources)  # manual: no pipeline job runs it
    profiles = document["jobs"]["job_project_build"]["settings"]["profiles"]
    assert {f"jobs.job_project_build.settings.profiles.{name}.image_id" for name in profiles} <= sources
    assert "jobs.job_codeql_analysis.settings.source_image_id" in sources


def test_configured_pins_cover_enabled_catalog_images_and_enabled_job_settings_only() -> None:
    document = {"jobs": {
        "job_project_build": {"settings": {"profiles": {"native": {
            "tag": "audit-buildenv-cpp:local", "image_id": "sha256:" + "a" * 64, "user": "10001:10001"}}}},
        "job_codeql_analysis": {"settings": {"source_image_tag": "audit-codeql:x",
                                             "source_image_id": "sha256:" + "b" * 64}},
        "job_off": {"settings": {"enabled": False, "tag": "t", "image_id": "sha256:" + "c" * 64}},
    }}
    catalog = [{"id": "tool-x", "state": "enabled", "tag": "fixture/tool-x:1", "image_id": "sha256:" + "d" * 64},
               {"id": "tool-y", "state": "enabled", "tag": "fixture/tool-y:1"},
               {"id": "tool-z", "state": "deferred", "tag": "fixture/tool-z:1"},
               {"id": "tool-m", "state": "enabled", "manual": True, "tag": "fixture/tool-m:1"}]
    pins = configured_pins(catalog, document)
    assert [(pin["source"], pin["tag"], pin["image_id"]) for pin in pins] == [
        ("containers/catalog.toml images.tool-x.image_id", "fixture/tool-x:1", "sha256:" + "d" * 64),
        ("containers/catalog.toml images.tool-y.image_id", "fixture/tool-y:1", None),
        ("jobs.job_codeql_analysis.settings.source_image_id", "audit-codeql:x", "sha256:" + "b" * 64),
        ("jobs.job_project_build.settings.profiles.native.image_id", "audit-buildenv-cpp:local",
         "sha256:" + "a" * 64),
    ]


# ---------------------------------------------------------------- success path

def test_all_pins_matching_succeeds_and_records_every_pin(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    docker = _all_matching(tmp_path)
    outcome = _run(config, target, docker)
    assert outcome["status"] == "SUCCEEDED"

    expected = _expected_pins(tmp_path)
    # One inspection per distinct tag, and nothing but ``docker image inspect``.
    assert sorted(call[3] for call in docker.calls) == sorted({pin["tag"] for pin in expected})
    record = json.loads((_unit_root(config, outcome["run_id"], "verification", "inspect_images") /
                         "image-pin-verification.json").read_text())
    assert record["status"] == "PASSED"
    assert [pin["source"] for pin in record["pins"]] == [pin["source"] for pin in expected]
    statuses = {pin["source"]: pin["status"] for pin in record["pins"]}
    assert statuses["containers/catalog.toml images.tool-x.image_id"] == "matched"
    assert statuses["containers/catalog.toml images.base-a.image_id"] == "present"
    assert statuses["jobs.job_codeql_analysis.settings.source_image_id"] == "matched"
    assert "containers/catalog.toml images.retired-z.image_id" not in statuses

    handoff = json.loads((_unit_root(config, outcome["run_id"], "publication", "publish_handoff") /
                          "image-pin-verification-handoff.json").read_text())
    assert len(handoff["images"]) == len(expected)
    plan = json.loads((_unit_root(config, outcome["run_id"], "selection", "resolve_pins") /
                       "image-pin-plan.json").read_text())
    assert plan["catalog"]["path"] == "containers/catalog.toml" and len(plan["catalog"]["sha256"]) == 64
    events = config.runtime.runs_dir / outcome["run_id"] / f"data/jobs/{JOB_ID}/attempts"
    assert "IMAGE_PIN_VERIFICATION_COMPLETED" in "".join(path.read_text() for path in events.rglob("*.jsonl"))


def test_the_gate_never_needs_the_builder_or_dockerfiles(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    assert not (tmp_path / "containers" / "build.py").exists()
    assert _run(config, target, _all_matching(tmp_path))["status"] == "SUCCEEDED"
    assert sorted(path.name for path in (tmp_path / "containers").iterdir()) == ["catalog.toml"]


def test_the_gate_always_executes_and_does_not_propagate_its_handoff(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    docker = _all_matching(tmp_path)
    first = _run(config, target, docker)
    calls = len(docker.calls)
    second = GraphRunner(config, [build_job(runner=docker)]).run(
        run_id=first["run_id"], target_root=target, source_fingerprint=source_fingerprint(target))
    assert second["status"] == "SUCCEEDED" and len(docker.calls) == 2 * calls
    job = builtin_registry().build(JOB_ID)
    assert job.always_execute is True and job.propagate_handoff is False


# ---------------------------------------------------------------- failures fail the run

def test_missing_image_moved_tag_and_codeql_source_mismatch_fail_naming_every_mismatch(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    docker = _all_matching(tmp_path)
    moved = _id("moved")
    codeql = next(pin for pin in _expected_pins(tmp_path)
                  if pin["source"] == "jobs.job_codeql_analysis.settings.source_image_id")
    docker.images["fixture/base-a:1"] = None                     # missing, unpinned catalog image
    docker.images["fixture/tool-x:1"] = moved                    # catalog pin, tag moved
    docker.images[codeql["tag"]] = _id("codeql-rebuilt")          # CodeQL source pin, tag moved
    with pytest.raises(RuntimeError):
        _run(config, target, docker, build_intake())
    run_id = _only_run_id(config)
    assert not (config.runtime.runs_dir / run_id / "data/jobs/job_review_intake").exists()

    message = _failure_message(config)
    assert "image pin verification failed: 3 of" in message
    for expected in (
            "containers/catalog.toml images.base-a.image_id: tag fixture/base-a:1 pinned <unpinned> resolved missing",
            f"containers/catalog.toml images.tool-x.image_id: tag fixture/tool-x:1 pinned {PIN_X} resolved {moved}",
            f"jobs.job_codeql_analysis.settings.source_image_id: tag {codeql['tag']} pinned {codeql['image_id']} "
            f"resolved {_id('codeql-rebuilt')}",
            "verification record: "):
        assert expected in message

    root = _unit_root(config, run_id, "verification", "inspect_images")
    record = json.loads((root / "image-pin-verification.json").read_text())
    assert record["status"] == "FAILED"
    failed = {pin["source"]: pin["status"] for pin in record["pins"] if pin["status"] not in {"matched", "present"}}
    assert failed == {"containers/catalog.toml images.base-a.image_id": "missing",
                      "containers/catalog.toml images.tool-x.image_id": "mismatched",
                      "jobs.job_codeql_analysis.settings.source_image_id": "mismatched"}

    pipeline_log = config.runtime.runs_dir / run_id / "data" / "logs" / "pipeline.jsonl"
    events = [json.loads(line) for line in pipeline_log.read_text().splitlines()]
    (failure,) = [event for event in events if event["event_type"] == "IMAGE_PIN_VERIFICATION_FAILED"]
    assert failure["level"] == "ERROR" and failure["job_id"] == JOB_ID
    assert len(failure["details"]["failures"]) == 3
    assert not any("WITH_GAPS" in event["event_type"] for event in events)


def test_a_missing_build_profile_image_fails_the_run(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    docker = _all_matching(tmp_path)
    profile = next(pin for pin in _expected_pins(tmp_path)
                   if pin["source"].startswith("jobs.job_project_build.settings.profiles."))
    docker.images[profile["tag"]] = None
    with pytest.raises(RuntimeError):
        _run(config, target, docker)
    message = _failure_message(config)
    assert f"{profile['source']}: tag {profile['tag']} pinned {profile['image_id']} resolved missing" in message


def test_an_uninspectable_tag_is_a_failure_not_a_missing_image(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    docker = _all_matching(tmp_path)
    docker.errors["fixture/tool-x:1"] = "Cannot connect to the Docker daemon"
    with pytest.raises(RuntimeError):
        _run(config, target, docker)
    message = _failure_message(config)
    assert ("tag fixture/tool-x:1 pinned " + PIN_X + " resolved not inspectable "
            "(docker image inspect exited 1: Cannot connect to the Docker daemon)") in message


def test_a_runner_that_raises_fails_with_the_tag_named(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)

    def broken(argv, timeout):
        raise FileNotFoundError("docker")

    with pytest.raises(RuntimeError):
        _run(config, target, broken)
    assert "tag fixture/tool-x:1 pinned" in _failure_message(config)


def test_an_unwired_job_refuses_to_claim_images_were_verified(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    with pytest.raises(RuntimeError):
        GraphRunner(config, [build_job()]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    assert "not wired" in _failure_message(config)


# ---------------------------------------------------------------- settings

def test_repository_settings_are_typed_and_enabled_by_default() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = config.job(JOB_ID).typed_settings
    assert settings == parse_image_pin_verification_settings(config.job(JOB_ID).settings)
    assert settings.enabled is True


@pytest.mark.parametrize("key, value, message", [
    ("enabled", '"yes"', "enabled must be a boolean"),
    ("unexpected", "1", "unknown settings: unexpected"),
    ("parallelism", "2", "unknown settings: parallelism"),
    ("pin_mismatch", '"report"', "unknown settings: pin_mismatch"),
])
def test_settings_validation_rejects_bad_values(tmp_path: Path, key: str, value: str, message: str) -> None:
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(**{key: value}), encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(message)):
        load_config(config_path)


def test_settings_validation_rejects_a_missing_switch() -> None:
    with pytest.raises(ValueError, match="missing settings: enabled"):
        parse_image_pin_verification_settings({})


# ---------------------------------------------------------------- topology

def test_direct_graph_places_the_gate_between_the_model_gate_and_intake(tmp_path: Path) -> None:
    order = list(GRAPH_JOB_IDS)
    assert order.index("job_model_connectivity") + 1 == order.index(JOB_ID)
    assert order.index(JOB_ID) + 1 == order.index("job_target_acquisition")
    assert order.index("job_target_acquisition") + 1 == order.index("job_review_intake")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(enabled="false"), encoding="utf-8")
    selected = active_job_ids(load_config(config_path), GRAPH_JOB_IDS)
    assert JOB_ID not in selected
    assert selected[:3] == ("job_model_connectivity", "job_target_acquisition", "job_review_intake")


COMPOSITES = {"wave1_review": "", "ci_configuration_review": "ci_review__",
              "project_build_review": "project_build_review__"}


def _upstream(graph, node: str) -> set[str]:
    mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
    return {output.node_name for outputs in mapping.values() for output in outputs}


def test_every_composite_graph_runs_the_gate_after_the_model_gate_and_before_intake() -> None:
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import build_definitions

    definitions = build_definitions(ROOT / "appsec-review.toml")
    assert definitions.get_job_def("image_pin_verification").name == "image_pin_verification"
    for name, prefix in COMPOSITES.items():
        graph = definitions.get_job_def(name).graph
        assert _upstream(graph, f"{prefix}image_pin_verification__begin") == {
            f"{prefix}model_connectivity__finalize"}
        assert _upstream(graph, f"{prefix}target_acquisition__begin") == {
            f"{prefix}image_pin_verification__finalize"}
        assert _upstream(graph, f"{prefix}review_intake__begin") == {f"{prefix}target_acquisition__finalize"}
        assert f"{prefix}image_pin_verification__verification__inspect_images" in {
            node.name for node in graph.node_defs}


def test_a_disabled_gate_is_transparent_to_every_composite_graph(tmp_path: Path) -> None:
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import build_definitions

    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_settings_source(enabled="false"), encoding="utf-8")
    definitions = build_definitions(config_path)
    assert "image_pin_verification" not in {job.name for job in definitions.get_repository_def().get_all_jobs()}
    for name, prefix in COMPOSITES.items():
        graph = definitions.get_job_def(name).graph
        assert not any("image_pin_verification__" in node.name for node in graph.node_defs)
        assert _upstream(graph, f"{prefix}target_acquisition__begin") == {f"{prefix}model_connectivity__finalize"}
