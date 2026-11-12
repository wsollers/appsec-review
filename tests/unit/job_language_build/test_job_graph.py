"""job_language_build: the unit graph, configuration validation and the handler wiring of job.py,
with the accepted-dispatch loader and the per-family executors faked at the module boundary.

No graph run, no container, no image resolver: each handler is called with a context over the
shipped configuration and the values a regression would change are asserted."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_language_build import job as language_job
from appsec_review.jobs.job_language_build import jvm, wasm
from appsec_review.jobs.job_language_build.job import (
    CAPTURE_IDENTITIES, RECEIPT_SCHEMA, SCHEMA, FrameworkIntegrityError, _validate_config, build_job,
    iteration_controller,
)
from tests.unit.job_language_build.support import (
    FAMILIES, HANDOFF_SHA, SOURCE_FINGERPRINT, accepted, dispatch, real_job, unit_context, units,
)


# --- graph shape -----------------------------------------------------------------------------------

def test_graph_has_one_dispatch_unit_a_load_and_execute_lane_per_family_and_one_publication() -> None:
    graph = units()
    assert set(graph) == {"iterations.dispatch", "acceptance.publish_handoff",
                          *(f"load.{f}" for f in FAMILIES), *(f"execute.{f}" for f in FAMILIES)}
    assert len(graph) == 20
    assert graph["iterations.dispatch"].dependencies == ()
    for family in FAMILIES:
        assert graph[f"load.{family}"].dependencies == ("iterations.dispatch",)
        assert graph[f"execute.{family}"].dependencies == (f"load.{family}",)
    assert graph["acceptance.publish_handoff"].dependencies == tuple(f"execute.{f}" for f in FAMILIES)
    assert [unit.unit_id for unit in build_job().units][:3] == ["iterations.dispatch", "load.native", "load.go"]


def test_job_identity_validators_and_capture_identities() -> None:
    job = build_job()
    assert (job.job_id, job.name, job.schema_identity) == ("job_language_build", "language_build", SCHEMA)
    assert job.input_validators == (_validate_config,)
    assert job.implementation_identity is None and job.validation_identity is None
    assert set(CAPTURE_IDENTITIES) == set(FAMILIES)
    assert CAPTURE_IDENTITIES["java"] == jvm.JVM_CAPTURE_IDENTITY
    assert CAPTURE_IDENTITIES["wasm"] == "appsec-review/protected-build-capture/3"
    assert RECEIPT_SCHEMA == "appsec-review/language-build-receipt/1"


# --- _validate_config ------------------------------------------------------------------------------

def _config(job=None, **changes) -> SimpleNamespace:
    job = job or real_job()
    fields = {"steps": job.steps, "step": job.step, "settings": job.settings, "build_capture": job.build_capture,
              "typed_settings": job.typed_settings}
    fields.update(changes)
    return SimpleNamespace(config=SimpleNamespace(**fields))


def _settings(**changes) -> dict:
    settings = dict(real_job().settings)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(settings.get(key), dict):
            merged = {**settings[key], **value}
            settings[key] = {k: v for k, v in merged.items() if v is not ...}
        else:
            settings[key] = value
    return settings


def test_shipped_configuration_passes_validation_and_declares_every_lane() -> None:
    _validate_config(_config(), None)
    job = real_job()
    assert tuple(job.steps) == ("iterations", "load", "execute", "acceptance")
    assert tuple(job.step("load").tasks) == tuple(job.step("execute").tasks) == FAMILIES
    assert job.step("execute").workers >= 1 and job.build_capture is not None


def test_validation_refuses_a_changed_topology_or_task_order() -> None:
    job = real_job()
    reordered = {k: job.steps[k] for k in reversed(list(job.steps))}
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate_config(_config(job, steps=reordered), None)

    def step(step_id):
        value = job.step(step_id)
        if step_id == "execute":
            return SimpleNamespace(tasks={k: value.tasks[k] for k in reversed(list(value.tasks))})
        return value
    with pytest.raises(ValueError, match="task order mismatch: execute"):
        _validate_config(_config(job, step=step), None)


@pytest.mark.parametrize(("changes", "message"), [
    ({"command_timeout_seconds": 0}, "bound is invalid: command_timeout_seconds"),
    ({"output_bytes": "8"}, "bound is invalid: output_bytes"),
    ({"artifact_count_limit": True}, "bound is invalid: artifact_count_limit"),
    ({"dotnet": {"allow_aot": ...}}, "dotnet settings are invalid"),
    ({"dotnet": {"allow_aot": "yes"}}, "dotnet settings are invalid"),
    ({"go": {"offline": True}}, "Go settings are invalid"),
    ({"go": {"package_catalog": False}}, "Go settings are invalid"),
    ({"go": {"diagnostic_tail_bytes": 1024 * 1024 + 1}}, "Go settings are invalid"),
    ({"rust": {"locked": "no"}}, "Rust settings are invalid"),
    ({"rust": {"extra": 1}}, "Rust settings are invalid"),
    ({"node": {"package_managers": ["npm"]}}, "Node settings are invalid"),
    ({"node": {"network": "none"}}, "Node settings are invalid"),
    ({"node": {"lifecycle_scripts": "allowed"}}, "Node settings are invalid"),
    ({"python": {"frontend": "poetry"}}, "Python settings are invalid"),
    ({"python": {"offline": True}}, "Python settings are invalid"),
    ({"jvm": {"trace_bytes": 0}}, "JVM bound is invalid: trace_bytes"),
    ({"jvm": {"system_paths": {"java": "relative/bin"}}}, "JVM system_paths are invalid"),
    ({"wasm": {"workspace_file_limit": 0}}, "WASM workspace bound is invalid"),
    ({"wasm": {"producers": {}}}, "producers configuration is required"),
    ({"wasm": {"producers": {"Bad Name": {"families": ["rust"], "tools": ["cargo"], "indicators": []}}}},
     "producer configuration is invalid: Bad Name"),
    ({"wasm": {"producers": {"x": {"families": ["python"], "tools": ["cargo"], "indicators": []}}}},
     "producer configuration is invalid: x"),
], ids=["timeout-zero", "output-string", "count-bool", "dotnet-missing", "dotnet-string", "go-offline",
        "go-catalog-off", "go-tail-high", "rust-string", "rust-extra", "node-managers", "node-network",
        "node-lifecycle", "python-frontend", "python-offline", "jvm-trace", "jvm-path", "wasm-limit",
        "wasm-no-producers", "wasm-producer-name", "wasm-producer-family"])
def test_validation_refuses_malformed_settings(changes, message) -> None:
    with pytest.raises(ValueError, match=message):
        _validate_config(_config(settings=_settings(**changes)), None)


def test_validation_requires_execution_capture_and_typed_settings() -> None:
    with pytest.raises(ValueError, match="execution capture configuration is unavailable"):
        _validate_config(_config(build_capture=None), None)
    with pytest.raises(ValueError, match="Go settings are invalid"):
        _validate_config(_config(typed_settings=None), None)


# --- load.<family> ---------------------------------------------------------------------------------

def _fake_dispatches(monkeypatch, *dispatches, accepted_document=None, calls=None):
    document = accepted_document or accepted(*dispatches)

    def _dispatches(unit, *, families=None):
        if calls is not None:
            calls.append(families)
        return [dict(item) for item in document["build_dispatches"]
                if families is None or item["family"] in families], document
    monkeypatch.setattr(language_job, "_dispatches", _dispatches)
    return document


def test_load_selects_the_lane_family_and_records_run_decisions(tmp_path: Path, monkeypatch) -> None:
    calls: list = []
    native = dispatch("build-unit-" + "a" * 20)
    go = dispatch("build-unit-" + "b" * 20, "go", build_system="go", commands=[["go", "build", "./..."]])
    _fake_dispatches(monkeypatch, native, go, calls=calls)
    result = units()["load.native"].handler(unit_context(tmp_path, "load.native"))
    assert calls == [frozenset({"native"})]
    assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
    assert [item["build_unit_id"] for item in result["dispatches"]] == [native["build_unit_id"]]
    selected = result["dispatches"][0]
    assert selected["processing_facts"]["family"] == "native"
    assert selected["processing_facts"]["material_build_facts"] == ("compiled-descriptor:cmake",
                                                                     "declared-compiled-project:native")
    features = [(d["feature"], d["action"], d["reason_code"]) for d in selected["processing_decisions"]]
    assert features == [("build-execution-capture", "RUN", "POLICY_REQUIRED"),
                        ("compiler-artifact-collection", "RUN", "POLICY_REQUIRED")]
    assert result["processing_decisions"] == selected["processing_decisions"]
    assert result["non_run_receipts"] == [] and result["unavailable"] == [] and result["engine_receipts"] == []
    assert result["accepted"]["project_build_handoff_sha256"] == HANDOFF_SHA


def test_load_reads_the_run_owned_resolved_configuration_identity(tmp_path: Path, monkeypatch) -> None:
    _fake_dispatches(monkeypatch, dispatch("build-unit-" + "a" * 20))
    context = unit_context(tmp_path, "load.native")
    manifest = context.job.run_root / "data" / "configuration" / "manifest.json"
    identity = json.loads(manifest.read_text(encoding="utf-8"))["resolved_sha256"]
    result = units()["load.native"].handler(context)
    assert {d["configuration_sha256"] for d in result["processing_decisions"]} == {identity}
    manifest.write_text(json.dumps({"resolved_sha256": "0" * 64}), encoding="utf-8")
    with pytest.raises(ValueError, match="resolved configuration"):
        units()["load.native"].handler(context)


def test_load_turns_an_incomplete_inventory_into_a_gap_receipt_not_a_dispatch(tmp_path: Path, monkeypatch) -> None:
    unit_id = "build-unit-" + "c" * 20
    _fake_dispatches(monkeypatch, dispatch(unit_id, complete_inventory=False))
    result = units()["load.native"].handler(unit_context(tmp_path, "load.native"))
    assert result["dispatches"] == [] and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    [receipt] = result["non_run_receipts"]
    assert (receipt["schema"], receipt["build_unit_id"], receipt["terminal_status"]) == (RECEIPT_SCHEMA, unit_id, "GAP")
    assert receipt["gaps"] == ["INVENTORY_UNAVAILABLE: build execution was not available"]
    assert result["gaps"] == [f"{unit_id}: INVENTORY_UNAVAILABLE: build execution was not available"]


def test_load_reports_a_planned_unit_project_build_could_not_build_as_a_blocked_receipt(
        tmp_path: Path, monkeypatch) -> None:
    built = dispatch("build-unit-" + "a" * 20)
    failed_probe = {"build_unit_id": "build-unit-" + "d" * 20, "family": "native", "root": "lib", "build_system": "make",
                    "terminal_status": "FAILED", "gaps": ["build-unit-" + "d" * 20 + ": make exited 2"]}
    skipped_probe = {"build_unit_id": "build-unit-" + "e" * 20, "family": "native", "root": "x",
                     "terminal_status": "SKIPPED_POLICY", "gaps": []}
    other_family = {"build_unit_id": "build-unit-" + "f" * 20, "family": "go", "root": "y",
                    "terminal_status": "FAILED", "gaps": ["go failed"]}
    document = accepted(built, probe_receipts=[
        {"build_unit_id": built["build_unit_id"], "family": "native", "root": ".", "terminal_status": "SUCCEEDED",
         "gaps": []}, failed_probe, skipped_probe, other_family])
    _fake_dispatches(monkeypatch, built, accepted_document=document)
    result = units()["load.native"].handler(unit_context(tmp_path, "load.native"))
    assert [item["build_unit_id"] for item in result["dispatches"]] == [built["build_unit_id"]]
    [blocked] = result["non_run_receipts"]
    assert blocked["terminal_status"] == "BLOCKED" and blocked["build_unit_id"] == failed_probe["build_unit_id"]
    assert blocked["upstream_failure"] == {"job_id": "job_project_build", "terminal_status": "FAILED",
                                           "reason": "make exited 2"}
    assert blocked["gaps"] == ["native build unit at lib was not built: job_project_build reported FAILED: make exited 2"]
    assert result["gaps"] == [f"{failed_probe['build_unit_id']}: {blocked['gaps'][0]}"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_load_dotnet_keeps_unbuilt_probes_as_unavailable_and_forwards_unity_engine_receipts(
        tmp_path: Path, monkeypatch) -> None:
    unity = {"build_unit_id": "build-unit-" + "1" * 20, "family": "dotnet", "root": "game", "build_system": "unity",
             "terminal_status": "SUCCEEDED", "gaps": []}
    unbuilt = {"build_unit_id": "build-unit-" + "2" * 20, "family": "dotnet", "root": "svc", "build_system": "dotnet",
               "terminal_status": "FAILED", "gaps": ["restore failed"]}
    document = accepted(probe_receipts=[unity, unbuilt])
    _fake_dispatches(monkeypatch, accepted_document=document)
    result = units()["load.dotnet"].handler(unit_context(tmp_path, "load.dotnet"))
    assert result["dispatches"] == [] and result["non_run_receipts"] == []
    assert result["unavailable"] == [unbuilt]
    assert result["engine_receipts"] == [unity]
    assert result["gaps"] == [f"{unbuilt['build_unit_id']}: restore failed"]


def test_load_wasm_lane_claims_producer_matched_units_and_other_lanes_release_them(
        tmp_path: Path, monkeypatch) -> None:
    calls: list = []
    emscripten = dispatch("build-unit-" + "a" * 20, "native", build_system="cmake",
                          commands=[["emcc", "main.c", "-o", "main.wasm"]], expected_outputs=("main.wasm",))
    plain = dispatch("build-unit-" + "b" * 20, "native")
    unmatched = dispatch("build-unit-" + "c" * 20, "wasm", build_system="wasm",
                         commands=[["unknown-tool", "x"]], expected_outputs=("out.wasm",))
    _fake_dispatches(monkeypatch, emscripten, plain, unmatched, calls=calls)
    wasm_result = units()["load.wasm"].handler(unit_context(tmp_path, "load.wasm"))
    assert calls == [frozenset({"native", "rust", "node", "wasm"})]
    assert [(d["build_unit_id"], d["wasm_producer"]) for d in wasm_result["dispatches"]] == [
        (emscripten["build_unit_id"], "emscripten")]
    assert wasm_result["gaps"] == [f"{unmatched['build_unit_id']}: no configured WebAssembly producer matched accepted recipe"]
    native_result = units()["load.native"].handler(unit_context(tmp_path, "load.native"))
    assert [d["build_unit_id"] for d in native_result["dispatches"]] == [plain["build_unit_id"]]


@pytest.mark.parametrize(("family", "build_system", "commands", "message"), [
    ("rust", "cargo", [["cargo", "test"]], "accepted Rust dispatch is invalid: Cargo subcommand is unsupported: test"),
    ("go", "go", [["go", "run", "."]], "accepted Go dispatch is invalid"),
], ids=["rust", "go"])
def test_load_rechecks_the_family_command_policy_of_an_accepted_dispatch(
        tmp_path: Path, monkeypatch, family, build_system, commands, message) -> None:
    _fake_dispatches(monkeypatch, dispatch("build-unit-" + "a" * 20, family, build_system=build_system, commands=commands))
    with pytest.raises(ValueError, match=message):
        units()[f"load.{family}"].handler(unit_context(tmp_path, f"load.{family}"))


def test_load_requires_typed_settings(tmp_path: Path, monkeypatch) -> None:
    _fake_dispatches(monkeypatch)
    context = unit_context(tmp_path, "load.native")
    context.job.config = SimpleNamespace(typed_settings=None, settings=real_job().settings)
    with pytest.raises(ValueError, match="typed language-build settings are unavailable"):
        units()["load.native"].handler(context)


# --- execute.<family> ------------------------------------------------------------------------------

def _loaded(tmp_path: Path, monkeypatch, *dispatches, family="native", probe_receipts=(), **extra):
    """The real load.<family> output for these dispatches, as execute.<family> receives it."""
    document = accepted(*dispatches, probe_receipts=probe_receipts) if probe_receipts else accepted(*dispatches)
    _fake_dispatches(monkeypatch, *dispatches, accepted_document=document)
    loaded = dict(units()[f"load.{family}"].handler(unit_context(tmp_path, f"load.{family}")))
    loaded.update(extra)
    return loaded


def _receipt(dispatch_item, status="SUCCEEDED", *, gaps=(), artifacts=None):
    return {"schema": RECEIPT_SCHEMA, "build_unit_id": dispatch_item["build_unit_id"], "family": dispatch_item["family"],
            "root": dispatch_item["root"], "fingerprint": "9" * 64, "terminal_status": status, "gaps": list(gaps),
            "artifacts": [{"workspace_path": "build/app", "kind": "executable", "artifact_origin": "build-output"}]
            if artifacts is None else artifacts, "commands": []}


def test_execute_runs_ready_units_in_dependency_order_and_blocks_on_a_failed_dependency(
        tmp_path: Path, monkeypatch) -> None:
    a = dispatch("build-unit-" + "a" * 20)
    b = dispatch("build-unit-" + "b" * 20, root="lib", dependencies=(a["build_unit_id"],))
    c = dispatch("build-unit-" + "c" * 20, root="app", dependencies=(b["build_unit_id"],))
    loaded = _loaded(tmp_path, monkeypatch, a, b, c)
    order: list[tuple[str, dict]] = []

    def execute_one(unit, item, accepted_document, executor_factory=None, **kwargs):
        order.append((item["build_unit_id"], kwargs))
        failed = item["build_unit_id"] == b["build_unit_id"]
        return _receipt(item, "FAILED" if failed else "SUCCEEDED", gaps=["cmake exited 2"] if failed else ())
    monkeypatch.setattr(language_job, "_execute_one", execute_one)
    context = unit_context(tmp_path, "execute.native", {"load.native": loaded})
    result = units()["execute.native"].handler(context)
    assert [item for item, _ in order] == [a["build_unit_id"], b["build_unit_id"]]
    assert order[1][1] == {}
    by_id = {item["build_unit_id"]: item for item in result["receipts"]}
    assert [r["build_unit_id"] for r in result["receipts"]] == sorted(by_id)
    assert by_id[a["build_unit_id"]]["terminal_status"] == "SUCCEEDED"
    assert by_id[b["build_unit_id"]]["terminal_status"] == "FAILED"
    assert by_id[c["build_unit_id"]]["terminal_status"] == "BLOCKED"
    assert by_id[c["build_unit_id"]]["gaps"] == ["dependency build unavailable: " + b["build_unit_id"]]
    decisions = {d["feature"]: d["disposition"] for d in by_id[a["build_unit_id"]]["processing_decisions"]}
    assert decisions == {"build-execution-capture": "SUCCEEDED", "compiler-artifact-collection": "SUCCEEDED"}
    failed = {d["feature"]: d["disposition"] for d in by_id[b["build_unit_id"]]["processing_decisions"]}
    assert failed == {"build-execution-capture": "GAP", "compiler-artifact-collection": "GAP"}
    assert by_id[b["build_unit_id"]]["gaps"] == ["cmake exited 2", "build-execution-capture: PROCESSING_FAILED",
                                                 "compiler-artifact-collection: PROCESSING_FAILED"]
    assert result["receipt_count"] == 3 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert all(gap.startswith("build-unit-") for gap in result["gaps"])


def test_execute_a_successful_build_without_produced_output_is_an_artifact_gap(tmp_path: Path, monkeypatch) -> None:
    a = dispatch("build-unit-" + "a" * 20)
    loaded = _loaded(tmp_path, monkeypatch, a)
    monkeypatch.setattr(language_job, "_execute_one", lambda unit, item, acc, factory=None, **kw: _receipt(
        item, artifacts=[{"workspace_path": "in.o", "kind": "object", "artifact_origin": "accepted-input"}]))
    result = units()["execute.native"].handler(unit_context(tmp_path, "execute.native", {"load.native": loaded}))
    [receipt] = result["receipts"]
    dispositions = {d["feature"]: (d["disposition"], d["reason_code"]) for d in receipt["processing_decisions"]}
    assert dispositions["build-execution-capture"] == ("SUCCEEDED", "PROCESSING_SUCCEEDED")
    assert dispositions["compiler-artifact-collection"] == ("GAP", "ARTIFACT_VALIDATION_FAILED")
    assert receipt["gaps"] == ["compiler-artifact-collection: ARTIFACT_VALIDATION_FAILED"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_execute_turns_a_build_exception_into_a_failed_receipt_but_lets_integrity_errors_through(
        tmp_path: Path, monkeypatch) -> None:
    a = dispatch("build-unit-" + "a" * 20)
    loaded = _loaded(tmp_path, monkeypatch, a)

    def boom(unit, item, acc, factory=None, **kw):
        raise RuntimeError("container exited 137")
    monkeypatch.setattr(language_job, "_execute_one", boom)
    result = units()["execute.native"].handler(unit_context(tmp_path, "execute.native", {"load.native": loaded}))
    [receipt] = result["receipts"]
    assert receipt["terminal_status"] == "FAILED"
    assert receipt["gaps"][0] == "bounded native build failed: RuntimeError: container exited 137"

    def integrity(unit, item, acc, factory=None, **kw):
        raise FrameworkIntegrityError("accepted identity changed")
    monkeypatch.setattr(language_job, "_execute_one", integrity)
    with pytest.raises(FrameworkIntegrityError):
        units()["execute.native"].handler(unit_context(tmp_path, "execute.native", {"load.native": loaded}))


def test_execute_refuses_unknown_dependencies_and_cycles(tmp_path: Path, monkeypatch) -> None:
    a = dispatch("build-unit-" + "a" * 20, dependencies=("build-unit-" + "9" * 20,))
    loaded = _loaded(tmp_path, monkeypatch, a)
    monkeypatch.setattr(language_job, "_execute_one", lambda *args, **kw: pytest.fail("must not execute"))
    with pytest.raises(ValueError, match="references an unknown dependency"):
        units()["execute.native"].handler(unit_context(tmp_path, "execute.native", {"load.native": loaded}))
    x = dispatch("build-unit-" + "a" * 20, dependencies=("build-unit-" + "b" * 20,))
    y = dispatch("build-unit-" + "b" * 20, root="lib", dependencies=("build-unit-" + "a" * 20,))
    loaded = _loaded(tmp_path, monkeypatch, x, y)
    with pytest.raises(ValueError, match="dependencies contain a cycle"):
        units()["execute.native"].handler(unit_context(tmp_path, "execute.native", {"load.native": loaded}))


def test_execute_routes_java_and_wasm_to_their_family_executors(tmp_path: Path, monkeypatch) -> None:
    java = dispatch("build-unit-" + "a" * 20, "java", build_system="maven", commands=[["mvn", "package"]])
    loaded = _loaded(tmp_path, monkeypatch, java, family="java")
    seen: list[str] = []
    monkeypatch.setattr(jvm, "execute_jvm_one", lambda unit, item, acc, factory: (seen.append("jvm"), _receipt(item))[1])
    monkeypatch.setattr(language_job, "_execute_one", lambda *a, **k: pytest.fail("generic executor must not run"))
    result = units()["execute.java"].handler(unit_context(tmp_path, "execute.java", {"load.java": loaded}))
    assert seen == ["jvm"] and result["terminal_status"] == "SUCCEEDED"

    rust_wasm = dispatch("build-unit-" + "b" * 20, "rust", build_system="cargo",
                         commands=[["cargo", "build", "--target", "wasm32-unknown-unknown"]], expected_outputs=("pkg/a.wasm",))
    loaded = _loaded(tmp_path, monkeypatch, rust_wasm, family="wasm")
    assert loaded["dispatches"][0]["wasm_producer"] == "rust"

    def wasm_one(unit, item, acc, producer, upstream, factory):
        seen.append(producer)
        raise wasm.ProducerUnavailable("wasm-pack is not installed")
    monkeypatch.setattr(wasm, "_execute_one", wasm_one)
    result = units()["execute.wasm"].handler(unit_context(tmp_path, "execute.wasm", {"load.wasm": loaded}))
    assert seen == ["jvm", "rust"]
    [receipt] = result["receipts"]
    assert (receipt["terminal_status"], receipt["producer"], receipt["source_family"]) == ("FAILED", "rust", "rust")
    assert receipt["gaps"][0] == "bounded WebAssembly producer failed: wasm-pack is not installed"


def test_execute_in_iterative_mode_takes_its_family_receipts_from_the_dispatch_unit(tmp_path: Path) -> None:
    native_receipt = {"build_unit_id": "build-unit-" + "a" * 20, "family": "native", "terminal_status": "SUCCEEDED",
                      "gaps": [], "delivery_gaps": ["scope unresolved"]}
    go_receipt = {"build_unit_id": "build-unit-" + "b" * 20, "family": "go", "terminal_status": "FAILED", "gaps": ["x"]}
    unity = {"build_unit_id": "build-unit-" + "c" * 20, "family": "dotnet", "build_system": "unity",
             "terminal_status": "SUCCEEDED", "gaps": []}
    outputs = {"iterations.dispatch": {"receipts": [native_receipt, go_receipt], "graph": {}, "gaps": []},
               "load.native": {"accepted": {"execution_mode": "iterative"}, "engine_receipts": []},
               "load.dotnet": {"accepted": {"execution_mode": "iterative"}, "engine_receipts": [unity]},
               "load.php": {"accepted": {"execution_mode": "iterative"}, "engine_receipts": []}}
    graph = units()
    native = graph["execute.native"].handler(unit_context(tmp_path, "execute.native", outputs))
    assert native["receipts"] == [native_receipt] and native["gaps"] == [f"{native_receipt['build_unit_id']}: scope unresolved"]
    assert native["terminal_status"] == "COMPLETED_WITH_GAPS"
    dotnet = graph["execute.dotnet"].handler(unit_context(tmp_path, "execute.dotnet", outputs))
    assert dotnet["receipts"] == [unity] and dotnet["terminal_status"] == "SUCCEEDED"
    php = graph["execute.php"].handler(unit_context(tmp_path, "execute.php", outputs))
    assert php == {"receipts": [], "receipt_count": 0, "gaps": [], "terminal_status": "NOT_APPLICABLE"}


def test_execute_dotnet_turns_unavailable_probes_into_blocked_or_not_applicable_receipts(
        tmp_path: Path, monkeypatch) -> None:
    unbuilt = {"build_unit_id": "build-unit-" + "2" * 20, "family": "dotnet", "root": "svc", "build_system": "dotnet",
               "terminal_status": "FAILED", "gaps": ["restore failed"]}
    windows = {"build_unit_id": "build-unit-" + "3" * 20, "family": "dotnet", "root": "win", "build_system": "dotnet",
               "terminal_status": "NOT_APPLICABLE", "gaps": []}
    loaded = _loaded(tmp_path, monkeypatch, family="dotnet", probe_receipts=[unbuilt, windows])
    monkeypatch.setattr(language_job.dotnet, "selected_project_topology",
                        lambda run_root, probe, **kw: ([{"project": probe["root"]}], [],
                                                       ["windows-only project"] if probe is windows else []))
    result = units()["execute.dotnet"].handler(unit_context(tmp_path, "execute.dotnet", {"load.dotnet": loaded}))
    by_id = {item["build_unit_id"]: item for item in result["receipts"]}
    assert by_id[unbuilt["build_unit_id"]]["terminal_status"] == "BLOCKED"
    assert by_id[unbuilt["build_unit_id"]]["gaps"] == ["restore failed"]
    assert by_id[windows["build_unit_id"]]["terminal_status"] == "NOT_APPLICABLE"
    assert by_id[windows["build_unit_id"]]["gaps"] == ["windows-only project"]
    assert all(r["capture_identity"] == CAPTURE_IDENTITIES["dotnet"] and r["project_topology"] == [{"project": r["root"]}]
               for r in by_id.values())
    assert all(len(r["fingerprint"]) == 64 and r["upstream_handoff_sha256"] == HANDOFF_SHA for r in by_id.values())


# --- acceptance.publish_handoff --------------------------------------------------------------------

def _publish_outputs(receipts_by_family: dict[str, list], *, dispatch_gaps=(), extra_dispatches=()) -> dict:
    outputs = {f"execute.{family}": {"receipts": list(receipts_by_family.get(family, [])),
                                     "gaps": [f"{r['build_unit_id']}: {g}" for r in receipts_by_family.get(family, [])
                                              for g in r.get("gaps", ())]} for family in FAMILIES}
    outputs["iterations.dispatch"] = {"graph": {"edges": [["a", "b"]]}, "gaps": list(dispatch_gaps), "receipts": []}
    outputs["load.native"] = {"accepted": {"project_build_handoff_sha256": HANDOFF_SHA, "execution_mode": "legacy",
                                           "build_dispatches": list(extra_dispatches)}}
    return outputs


def test_publish_writes_the_receipt_set_records_the_event_and_builds_the_index(tmp_path: Path, monkeypatch) -> None:
    index_calls: list = []
    monkeypatch.setattr(language_job, "_publish_build_index",
                        lambda unit, receipts: (index_calls.append(receipts), {"path": "data/indices/manifests/x.json",
                                                                               "sha256": "1" * 64})[1])
    decision = {"feature": "build-execution-capture", "disposition": "SUCCEEDED"}
    native = {"schema": RECEIPT_SCHEMA, "build_unit_id": "build-unit-" + "a" * 20, "family": "native",
              "terminal_status": "SUCCEEDED", "gaps": [], "processing_decisions": [decision]}
    go = {"schema": RECEIPT_SCHEMA, "build_unit_id": "build-unit-" + "b" * 20, "family": "go",
          "terminal_status": "FAILED", "gaps": ["go build exited 1"], "processing_decisions": []}
    context = unit_context(tmp_path, "acceptance.publish_handoff", _publish_outputs(
        {"native": [native], "go": [go]}, dispatch_gaps=["build-unit-" + "b" * 20 + ": go build exited 1", "selection stale"],
        extra_dispatches=[{"build_unit_id": "build-unit-" + "c" * 20, "family": "swift"}]))
    result = units()["acceptance.publish_handoff"].handler(context)
    assert index_calls == [[native, go]]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["build_count"] == 2
    assert result["gaps"] == ["build-unit-" + "b" * 20 + ": go build exited 1", "selection stale",
                              "build-unit-" + "c" * 20 + ": accepted swift execution is not implemented"]
    assert result["index_manifest"] == {"path": "data/indices/manifests/x.json", "sha256": "1" * 64}
    assert result["processing_decisions"] == result["dispositions"] == [decision]
    artifact = result["artifact"]
    assert artifact["path"] == ("data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/"
                                "accepted-language-builds.json")
    document = json.loads((context.job.run_root / artifact["path"]).read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA and document["source_fingerprint"] == SOURCE_FINGERPRINT
    assert document["upstream_project_build_handoff_sha256"] == HANDOFF_SHA
    assert document["receipts"] == [native, go] and document["execution_graph"] == {"edges": [["a", "b"]]}
    assert document["gaps"] == result["gaps"]
    [(event, fields)] = context.job.events.written
    assert event == "LANGUAGE_BUILDS_RECORDED"
    assert (fields["unit_id"], fields["build_count"], fields["gap_count"]) == ("acceptance.publish_handoff", 2, 3)
    assert fields["receipt"] == artifact
    assert fields["metrics_semantics"] == "appsec-review/review-metrics-semantics/1"


def test_publish_without_receipts_or_gaps_succeeds_with_an_empty_receipt_set(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(language_job, "_publish_build_index", lambda unit, receipts: {"path": "m", "sha256": "0" * 64})
    context = unit_context(tmp_path, "acceptance.publish_handoff", _publish_outputs({}))
    result = units()["acceptance.publish_handoff"].handler(context)
    assert (result["terminal_status"], result["build_count"], result["gaps"]) == ("SUCCEEDED", 0, [])
    document = json.loads((context.job.run_root / result["artifact"]["path"]).read_text(encoding="utf-8"))
    assert document["receipts"] == [] and document["processing_decisions"] == []


# --- iterations.dispatch ---------------------------------------------------------------------------

class _Controller:
    instances: list = []

    def __init__(self, run_root, target, graph, dispatches, **kwargs):
        self.args = (run_root, target, graph, dispatches)
        self.kwargs = kwargs
        _Controller.instances.append(self)


def test_iteration_controller_selects_runnable_units_and_records_every_skipped_one(
        tmp_path: Path, monkeypatch) -> None:
    import appsec_review.jobs.build_iterations as iterations_module
    runnable = dispatch("build-unit-" + "a" * 20)
    owned = {**dispatch("build-unit-" + "b" * 20, root="lib"), "execution_owner": "job_project_build"}
    incomplete = dispatch("build-unit-" + "c" * 20, root="x", complete_inventory=False)
    owned_receipt = {"build_unit_id": owned["build_unit_id"], "family": "native", "root": "lib",
                     "terminal_status": "SUCCEEDED", "gaps": [], "captured": True}
    document = accepted(runnable, owned, incomplete, execution_mode="iterative",
                        probe_receipts=[owned_receipt, {"build_unit_id": runnable["build_unit_id"], "family": "native",
                                                        "root": ".", "terminal_status": "SUCCEEDED", "gaps": []}])
    failed_preparation = {"action": {"build_unit_id": "build-unit-" + "d" * 20, "family": "native", "root": "img",
                                     "build_system": "make"}, "terminal_status": "FAILED", "gaps": ["image build failed"]}
    document["images"] = {"native": {"entries": [failed_preparation, {"action": {}, "terminal_status": "SUCCEEDED"}]}}
    _fake_dispatches(monkeypatch, runnable, owned, incomplete, accepted_document=document)
    monkeypatch.setattr(iterations_module, "selected_revisions",
                        lambda run_root, acc, dispatches: ({"edges": ["g"]}, list(dispatches), {"o": []}))
    monkeypatch.setattr(language_job, "BuildIterations", _Controller)
    _Controller.instances.clear()
    context = unit_context(tmp_path, "iterations.dispatch")
    controller, accepted_document, skipped = iteration_controller(context)
    assert accepted_document is document and controller is _Controller.instances[-1]
    run_root, target, graph, selected = controller.args
    assert (run_root, target, graph) == (context.job.run_root, context.job.target_root, {"edges": ["g"]})
    assert [item["build_unit_id"] for item in selected] == [runnable["build_unit_id"]]
    assert selected[0]["processing_facts"]["project_id"] == runnable["build_unit_id"]
    assert [d["action"] for d in selected[0]["processing_decisions"]] == ["RUN", "RUN"]
    statuses = [(item["build_unit_id"], item["terminal_status"]) for item in skipped]
    assert statuses == [("build-unit-" + "d" * 20, "BLOCKED"), (owned["build_unit_id"], "SUCCEEDED"),
                        (incomplete["build_unit_id"], "GAP")]
    assert skipped[0]["upstream_failure"]["reason"] == "image build failed"
    assert skipped[1] == owned_receipt and skipped[1] is not owned_receipt
    assert skipped[2]["gaps"] == ["INVENTORY_UNAVAILABLE"]
    kwargs = controller.kwargs
    assert kwargs["execution_identity"] == language_job.EXECUTOR_IDENTITY
    assert kwargs["releases"] == dict(sorted(context.job.review_policy.releases.values.items()))
    assert kwargs["configuration"]["settings"] == dict(context.job.config.settings)
    assert kwargs["configuration"]["capture"]["mode"] == context.job.config.build_capture.mode.value
    assert kwargs["product_overrides"] == {"o": []}
    assert set(kwargs["omitted_receipts"]) == {item["build_unit_id"] for item in skipped}
    assert callable(kwargs["validate_receipt"]) and isinstance(kwargs["output_policy_identity"], str)


def test_iteration_controller_refuses_a_legacy_dispatch_document(tmp_path: Path, monkeypatch) -> None:
    _fake_dispatches(monkeypatch, dispatch("build-unit-" + "a" * 20))
    with pytest.raises(ValueError, match="legacy probe/rebuild dispatches require replanning"):
        iteration_controller(unit_context(tmp_path, "iterations.dispatch"))


def test_iterations_unit_runs_the_controller_with_the_production_iteration_callback(tmp_path: Path, monkeypatch) -> None:
    calls: dict = {}

    def fake_controller(unit):
        class Controller:
            def run(self, produce, invoke=None):
                calls["produce"], calls["invoke"] = produce, invoke
                return {"receipts": [], "graph": {}, "gaps": []}
        return Controller(), {"execution_mode": "iterative"}, []
    monkeypatch.setattr(language_job, "iteration_controller", fake_controller)
    result = units(executor_factory=lambda *a, **k: None)["iterations.dispatch"].handler(
        unit_context(tmp_path, "iterations.dispatch"))
    assert result == {"receipts": [], "graph": {}, "gaps": []}
    assert calls["invoke"] is None and callable(calls["produce"])
    units()["iterations.dispatch"].handler(unit_context(tmp_path, "iterations.dispatch"))
    assert callable(calls["invoke"]), "without an executor factory, registered Dagster iterations are invoked"
