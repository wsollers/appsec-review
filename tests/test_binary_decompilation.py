"""Pre-run binary decompilation: configuration, runner, publication store, efficacy, and CLI.

These tests never invoke Docker. ``tests/binary_decompilation_fakes.py`` stands in for the Ghidra
container and writes the export tree the real script produces.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re

import pytest

from appsec_review import cli
from appsec_review.binary_decompilation import (
    DecompilationError, PublicationError, decompilation_identity, decompile_binary, export_argv,
    load_table, resolve_current, verify_binary, verify_publication,
)
from appsec_review.binary_decompilation import efficacy
from appsec_review.config import (
    BinaryDecompilationSettings, BinaryRequest, load_config, parse_binary_decompilation,
)
from appsec_review.container_runtime.executor import CommandOutcome
from tests.binary_decompilation_fakes import IMAGE_ID, FakeDocker, mount_source, write_export


ROOT = Path(__file__).resolve().parents[1]
BINARY = b"\x7fELF synthetic third-party binary"
SHA256 = hashlib.sha256(BINARY).hexdigest()


def _request(tmp_path: Path, **overrides) -> BinaryRequest:
    path = tmp_path / "inputs" / "lib vendor.so"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(BINARY)
    return BinaryRequest(**{"binary_id": "vendor", "path": path, "sha256": SHA256,
                            "authorization": "owned test input", **overrides})


def _decompile(tmp_path: Path, docker: FakeDocker, **overrides):
    arguments = {"repository_root": ROOT, "data_dir": tmp_path / "data",
                 "settings": BinaryDecompilationSettings(), "request": _request(tmp_path),
                 "runner": docker}
    return decompile_binary(**{**arguments, **overrides})


def _option(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


# Configuration


def test_repository_configuration_declares_the_ghidra_tool_and_no_binaries() -> None:
    settings = load_config(ROOT / "appsec-review.toml").binary_decompilation
    assert settings.tool_id == "tool-ghidra" and settings.binaries == ()
    assert settings == BinaryDecompilationSettings()


def test_an_absent_table_yields_the_defaults() -> None:
    assert parse_binary_decompilation(None, ROOT) == BinaryDecompilationSettings()


def test_binaries_are_typed_and_resolved_against_the_repository(tmp_path: Path) -> None:
    settings = parse_binary_decompilation({
        "memory": "4g", "max_heap": "2g",
        "binaries": [{"id": "codec", "path": "inputs/libcodec.so", "sha256": "ab" * 32,
                      "authorization": "contract 7", "processor": "x86:LE:64:default",
                      "compiler_spec": "gcc"}],
    }, tmp_path)
    binary = settings.binary("codec")
    assert binary.path == (tmp_path / "inputs" / "libcodec.so").resolve()
    assert binary.processor == "x86:LE:64:default" and binary.loader is None
    with pytest.raises(KeyError, match="not configured"):
        settings.binary("absent")


@pytest.mark.parametrize(("document", "message"), [
    ({"surprise": 1}, "unknown settings: surprise"),
    ({"memory": "4g", "max_heap": "4g"}, "leave 1g"),
    ({"memory": "lots"}, "size must look like"),
    ({"timeout_seconds": 600, "analysis_timeout_seconds": 600}, "must exceed"),
    ({"cpus": "4"}, "cpus must be an integer"),
    ({"decompile_timeout_seconds": 0}, "decompile_timeout_seconds"),
    ({"tool_id": "ghidra"}, "catalog tool"),
    ({"binaries": {"id": "x"}}, "array of tables"),
    ({"binaries": [{"id": "x", "path": "p", "sha256": "ab" * 32}]}, "authorization"),
    ({"binaries": [{"id": "x", "path": "p", "sha256": "AB" * 32, "authorization": "ok"}]}, "SHA-256"),
    ({"binaries": [{"id": "Bad Id", "path": "p", "sha256": "ab" * 32, "authorization": "ok"}]}, "slug"),
    ({"binaries": [{"id": "x", "path": "p", "sha256": "ab" * 32, "authorization": "ok",
                    "compiler_spec": "gcc"}]}, "without processor"),
    ({"binaries": [{"id": "x", "path": "p", "sha256": "ab" * 32, "authorization": "ok",
                    "processor": "x86; rm -rf /"}]}, "invalid processor"),
    ({"binaries": [{"id": "x", "path": "p", "sha256": "ab" * 32, "authorization": "ok",
                    "extra": True}]}, "unknown settings: extra"),
    ({"binaries": [{"id": "x", "path": "p", "sha256": "ab" * 32, "authorization": "ok"}] * 2}, "unique"),
])
def test_invalid_configuration_is_rejected(document: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_binary_decompilation(document, ROOT)


def test_identity_tracks_output_affecting_inputs_but_not_capacity(tmp_path: Path) -> None:
    settings, request = BinaryDecompilationSettings(), _request(tmp_path)
    base = {"binary_sha256": SHA256, "image_id": IMAGE_ID, "tool_version": "12.1.4",
            "settings": settings, "request": request}
    identity = decompilation_identity(**base)
    assert re.fullmatch(r"[0-9a-f]{64}", identity)
    assert identity == decompilation_identity(**{**base, "settings": replace(
        settings, memory="16g", max_heap="12g", cpus=8, pids_limit=2048, timeout_seconds=9000)})
    assert identity == decompilation_identity(**{**base, "request": replace(
        request, binary_id="renamed", authorization="another statement")})
    for changed in (
        {"image_id": "sha256:" + "b" * 64}, {"tool_version": "12.1.5"}, {"binary_sha256": "cd" * 32},
        {"settings": replace(settings, decompile_timeout_seconds=30)},
        {"settings": replace(settings, max_functions=10)},
        {"request": replace(request, processor="ARM:LE:32:v8")},
    ):
        assert decompilation_identity(**{**base, **changed}) != identity


# Runner


def test_decompile_runs_ghidra_with_raised_capacity_and_the_scanner_isolation(tmp_path: Path) -> None:
    docker = FakeDocker()
    settings = BinaryDecompilationSettings(memory="12g", max_heap="8g", cpus=6, pids_limit=2048)
    _decompile(tmp_path, docker, settings=settings)
    (run,) = docker.runs
    assert _option(run, "--memory") == "12g" and _option(run, "--cpus") == "6"
    assert _option(run, "--pids-limit") == "2048"
    assert _option(run, "--network") == "none" and _option(run, "--user") == "10001:10001"
    assert "--read-only" in run and _option(run, "--cap-drop") == "ALL"
    assert _option(run, "--security-opt") == "no-new-privileges"
    assert _option(run, "--ulimit") == f"fsize={settings.output_file_bytes}:{settings.output_file_bytes}"
    assert _option(run, "--entrypoint") == "/opt/appsec/bin/ghidra-export" and IMAGE_ID in run
    mounts = [run[index + 1] for index, value in enumerate(run) if value == "--mount"]
    assert len(mounts) == 2 and mounts[0].endswith(",dst=/target,readonly")
    assert mounts[1].endswith(",dst=/scratch")
    # The file name is sanitized; the original path never reaches the container.
    assert _option(run, "--input") == "/target/lib_vendor.so"
    assert _option(run, "--max-heap") == "8g" and _option(run, "--max-cpu") == "6"
    assert "--processor" not in run


def test_loader_overrides_reach_the_wrapper(tmp_path: Path) -> None:
    docker = FakeDocker()
    request = _request(tmp_path, processor="ARM:LE:32:v8", compiler_spec="default", loader="BinaryLoader")
    _decompile(tmp_path, docker, request=request)
    (run,) = docker.runs
    assert (_option(run, "--processor"), _option(run, "--cspec"), _option(run, "--loader")) == (
        "ARM:LE:32:v8", "default", "BinaryLoader")


def test_publication_is_content_addressed_hash_chained_and_binary_derived(tmp_path: Path) -> None:
    result = _decompile(tmp_path, FakeDocker())
    root = Path(result["path"])
    assert root == tmp_path / "data" / "binary-decompilation" / SHA256 / result["identity"][:16]
    assert result["reused"] is False and result["binary_id"] == "vendor"
    manifest = verify_publication(root)
    assert manifest["schema"] == "appsec-review/binary-decompilation/1"
    assert manifest["provenance"] == "binary-derived" and "never instructions" in manifest["authority"]
    assert manifest["binary"] == {"sha256": SHA256, "bytes": len(BINARY), "name": "lib_vendor.so"}
    assert manifest["request"]["authorization"] == "owned test input"
    assert manifest["tool"]["image_id"] == IMAGE_ID and manifest["tool"]["ghidra_version"] == "12.1.4"
    assert manifest["coverage"]["decompile_status"] == {"ok": 2, "skipped_thunk": 1}
    assert manifest["coverage"]["decompiled_functions"] == manifest["coverage"]["decompilable_functions"] == 2
    assert manifest["gaps"] == {} and manifest["coverage"]["managed_code"] is False
    assert set(manifest["datasets"]) == {"functions", "calls", "imports", "exports", "strings", "gaps",
                                         "program"}
    assert result["manifest_sha256"] == hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()

    functions = {row["address"]: row for row in load_table(root, "functions")}
    sink = functions["0x1011b0"]
    text = (root / sink["pseudo_c"]["path"]).read_text(encoding="utf-8")
    # Leading blank lines are dropped so stored line numbers are stable evidence anchors.
    assert text.startswith("void print_label(char *input)\n") and text.endswith("}\n")
    assert sink["pseudo_c"]["lines"] == text.count("\n") == 6
    assert sink["pseudo_c"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    operations = [json.loads(line) for line in (root / sink["pcode"]["path"]).read_text().splitlines()]
    assert [item["mnemonic"] for item in operations] == ["CALL", "RETURN"]
    assert sink["pcode"]["operations"] == 2
    assert "pseudo_c" not in functions["0x101030"] and "pcode" not in functions["0x101030"]

    execution = json.loads((root / "execution" / "execution.json").read_text())
    assert execution["terminal_status"] == "COMPLETED" and execution["limits"]["memory"] == "8g"
    assert manifest["execution"]["receipt_sha256"] == hashlib.sha256(
        (root / "execution" / "execution.json").read_bytes()).hexdigest()
    assert (root / "execution" / "stdout.bin").read_bytes().startswith(b"INFO")
    # Nothing transient survives: no staged binary copy, no Ghidra project, no staging directory.
    store = tmp_path / "data" / "binary-decompilation"
    assert not any((store / ".staging").iterdir()) and not (store / ".failed").exists()
    assert not list(store.rglob("lib_vendor.so"))


def test_manifest_conforms_to_the_published_schema(tmp_path: Path) -> None:
    import jsonschema

    schema = json.loads((ROOT / "docs/schemas/binary-decompilation.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    gaps = [{"kind": "decompile_timeout", "address": "0x101150", "detail": "timed out"}]
    for docker in (FakeDocker(), FakeDocker(export=lambda root, sha256: write_export(root, sha256, gaps=gaps),
                                            image_id="sha256:" + "c" * 64)):
        manifest = verify_publication(Path(_decompile(tmp_path, docker)["path"]))
        assert sorted(error.message for error in validator.iter_errors(manifest)) == []
    assert list(validator.iter_errors({**manifest, "provenance": "source"}))


def test_a_verified_publication_is_reused_without_running_ghidra(tmp_path: Path) -> None:
    docker = FakeDocker()
    first = _decompile(tmp_path, docker)
    second = _decompile(tmp_path, docker)
    assert len(docker.runs) == 1
    assert second["reused"] is True and second["identity"] == first["identity"]
    assert second["manifest_sha256"] == first["manifest_sha256"]
    verified = verify_binary(repository_root=ROOT, data_dir=tmp_path / "data",
                             settings=BinaryDecompilationSettings(), request=_request(tmp_path),
                             runner=docker)
    assert verified["path"] == first["path"] and len(docker.runs) == 1

    forced = _decompile(tmp_path, docker, force=True)
    assert len(docker.runs) == 2 and forced["reused"] is False
    assert forced["identity"] == first["identity"]


def test_a_new_image_publishes_beside_the_old_publication(tmp_path: Path) -> None:
    first = _decompile(tmp_path, FakeDocker())
    second = _decompile(tmp_path, FakeDocker(image_id="sha256:" + "b" * 64))
    assert first["identity"] != second["identity"]
    assert Path(first["path"]).is_dir() and Path(second["path"]).is_dir()
    assert Path(first["path"]).parent == Path(second["path"]).parent


def test_a_review_resolves_the_current_publication_by_binary_hash_without_docker(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with pytest.raises(PublicationError, match="no current decompilation publication"):
        resolve_current(data, SHA256)
    first = _decompile(tmp_path, FakeDocker())
    resolved = resolve_current(data, SHA256)
    assert {key: resolved[key] for key in ("identity", "manifest_sha256", "path", "binary_sha256")} == {
        key: first[key] for key in ("identity", "manifest_sha256", "path", "binary_sha256")}
    pointer_path = data / "binary-decompilation" / SHA256 / "current.json"
    assert json.loads(pointer_path.read_text()) == {
        "schema": "appsec-review/binary-decompilation-pointer/1", "binary_sha256": SHA256,
        "identity": first["identity"], "publication": first["identity"][:16],
        "manifest_sha256": first["manifest_sha256"]}

    # A rebuilt image publishes beside the old publication and moves the pointer; decompiling
    # with the old image again moves it back. The older publication is never deleted.
    newer = FakeDocker(image_id="sha256:" + "b" * 64)
    second = _decompile(tmp_path, newer)
    assert resolve_current(data, SHA256)["identity"] == second["identity"] != first["identity"]
    assert _decompile(tmp_path, FakeDocker())["reused"] is True
    assert resolve_current(data, SHA256)["identity"] == first["identity"]

    # The pointer cannot redirect a review to another binary, a foreign path, or an edited manifest.
    pointer = json.loads(pointer_path.read_text())
    for forged in ({"binary_sha256": "cd" * 32}, {"publication": "../" + "0" * 13},
                   {"identity": "ef" * 32}, {"manifest_sha256": "00" * 32}, {"schema": "other/1"}):
        pointer_path.write_text(json.dumps({**pointer, **forged}))
        with pytest.raises(PublicationError):
            resolve_current(data, SHA256)
    with pytest.raises(PublicationError, match="not a SHA-256"):
        resolve_current(data, "../" + SHA256)


def test_verify_only_reports_a_missing_publication(tmp_path: Path) -> None:
    with pytest.raises(PublicationError, match="no publication"):
        verify_binary(repository_root=ROOT, data_dir=tmp_path / "data",
                      settings=BinaryDecompilationSettings(), request=_request(tmp_path),
                      runner=FakeDocker())


@pytest.mark.parametrize("tamper", ["pseudo_c", "table", "extra_file", "manifest_schema"])
def test_a_tampered_publication_is_refused_and_never_silently_replaced(tmp_path: Path, tamper: str) -> None:
    docker = FakeDocker()
    root = Path(_decompile(tmp_path, docker)["path"])
    if tamper == "pseudo_c":
        (root / "pseudo-c" / "0x1011b0.c").write_text("void print_label(void) { }\n", encoding="utf-8")
    elif tamper == "table":
        with (root / "calls.jsonl").open("a", encoding="utf-8") as stream:
            stream.write('{"from_function":"0x1","kind":"call"}\n')
    elif tamper == "extra_file":
        (root / "pseudo-c" / "0xdead.c").write_text("int injected;\n", encoding="utf-8")
    else:
        manifest = json.loads((root / "manifest.json").read_text())
        (root / "manifest.json").write_text(json.dumps({**manifest, "provenance": "source"}))
    with pytest.raises(PublicationError):
        verify_publication(root)
    with pytest.raises(PublicationError):
        _decompile(tmp_path, docker)
    assert len(docker.runs) == 1


def test_the_binary_must_match_its_configured_hash_and_bounds(tmp_path: Path) -> None:
    docker = FakeDocker()
    with pytest.raises(ValueError, match="does not match its configured SHA-256"):
        _decompile(tmp_path, docker, request=_request(tmp_path, sha256="00" * 32))
    with pytest.raises(ValueError, match="max_binary_bytes"):
        _decompile(tmp_path, docker, settings=BinaryDecompilationSettings(max_binary_bytes=4))
    missing = replace(_request(tmp_path), path=tmp_path / "absent.so")
    with pytest.raises(FileNotFoundError):
        _decompile(tmp_path, docker, request=missing)
    assert docker.calls == []


@pytest.mark.parametrize(("outcome", "status"), [
    (CommandOutcome(1, b"", b"ERROR import failed"), "FAILED"),
    (CommandOutcome(None, b"", b"", timed_out=True), "TIMEOUT"),
    (CommandOutcome(137, b"", b"", oom_killed=True), "OOM"),
])
def test_a_failed_container_publishes_nothing_and_keeps_its_evidence(
        tmp_path: Path, outcome: CommandOutcome, status: str) -> None:
    with pytest.raises(DecompilationError) as caught:
        _decompile(tmp_path, FakeDocker(outcome=outcome))
    assert caught.value.status == status
    evidence = caught.value.evidence
    store = tmp_path / "data" / "binary-decompilation"
    assert evidence is not None and evidence.parent == store / ".failed"
    receipt = json.loads((evidence / "scratch" / "execution.json").read_text())
    assert receipt["terminal_status"] == ("COMPLETED" if status == "FAILED" else status)
    assert not (evidence / "input").exists()
    assert not (store / SHA256).exists()


@pytest.mark.parametrize(("export", "message"), [
    (lambda root, sha256: write_export(root, sha256, complete=False), "complete.json is absent"),
    (lambda root, sha256: write_export(root, "ee" * 32), "other than the verified binary"),
    (lambda root, sha256: write_export(root, sha256, program={"schema": "other/1"}), "unsupported export"),
    (lambda root, sha256: (write_export(root, sha256),
                           (root / "functions.jsonl").write_text('{"address": "../../etc"}\n')), "address"),
    (lambda root, sha256: (write_export(root, sha256),
                           (root / "strings.jsonl").write_text("not json\n")), "is not JSON"),
    (lambda root, sha256: (write_export(root, sha256),
                           (root / "decompiled.jsonl").write_text("")), "disagrees with stored pseudo-C"),
])
def test_an_unusable_export_is_a_failure_not_a_publication(tmp_path: Path, export, message: str) -> None:
    with pytest.raises(DecompilationError, match=message) as caught:
        _decompile(tmp_path, FakeDocker(export=export))
    assert caught.value.status == "INVALID_EXPORT"
    assert caught.value.evidence is not None and caught.value.evidence.is_dir()
    assert not (tmp_path / "data" / "binary-decompilation" / SHA256).exists()


def test_tool_gaps_and_managed_code_are_named_in_the_manifest(tmp_path: Path) -> None:
    gaps = [{"kind": "decompile_timeout", "address": "0x101150", "detail": "timed out"},
            {"kind": "analysis_timeout", "address": None, "detail": "analysis hit its limit"}]
    docker = FakeDocker(export=lambda root, sha256: write_export(
        root, sha256, gaps=gaps, program={"compiler": "cli", "analysis_timed_out": True,
                                          "executable_format": "Portable Executable (PE)"}))
    result = _decompile(tmp_path, docker)
    assert result["gaps"] == {"analysis_timeout": 1, "decompile_timeout": 1, "managed_code": 1}
    assert result["coverage"]["managed_code"] is True and result["coverage"]["analysis_timed_out"] is True
    kinds = [row["kind"] for row in load_table(Path(result["path"]), "gaps")]
    assert kinds == ["decompile_timeout", "analysis_timeout", "managed_code"]


def test_every_runner_option_is_one_the_wrapper_and_export_script_accept() -> None:
    request = BinaryRequest("x", ROOT / "x", "ab" * 32, "ok", "x86:LE:64:default", "gcc", "ElfLoader")
    argv = export_argv("/opt/appsec/bin/ghidra-export", "x", BinaryDecompilationSettings(), request)
    wrapper = (ROOT / "containers/tools/ghidra/ghidra-export").read_text(encoding="utf-8")
    accepted = set(re.findall(r"^\s+(--[a-z-]+)\) ", wrapper, re.MULTILINE))
    assert set(argv[1::2]) <= accepted and len(argv) % 2 == 1
    script = (ROOT / "containers/tools/ghidra/scripts/AppsecExportProgram.java").read_text(encoding="utf-8")
    passed = set(re.findall(r'"([a-z_]+)=\$', wrapper))
    assert passed == set(re.findall(r'case "([a-z_]+)":', script))
    assert "\r" not in wrapper, "the wrapper must keep LF line endings to run in the image"


# Efficacy


def test_expectations_are_valid_and_pinned_to_the_committed_fixture_source() -> None:
    expectations = efficacy.load_expectations(ROOT)
    source = ROOT / expectations["source"]["fixture_path"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == expectations["source"]["sha256"]
    assert re.fullmatch(r"[0-9a-f]{40}", expectations["source"]["commit"])
    assert set(expectations["variants"]) == {"symbols", "stripped"}
    assert "-s" in expectations["variants"]["stripped"]["flags"]
    # No binary is committed: the fixture is source only and compiled on demand.
    committed = [path.name for path in source.parent.parent.rglob("*") if path.is_file()]
    assert sorted(committed) == ["README.md", "expectations.json", "main.c"]


def test_fixture_compile_runs_offline_under_the_runtime_boundary(tmp_path: Path) -> None:
    expectations = efficacy.load_expectations(ROOT)
    docker = FakeDocker()
    binary = efficacy.build_fixture(ROOT, expectations, "stripped", tmp_path / "binaries", runner=docker)
    assert binary.name == "case083-stripped" and binary.is_file()
    (run,) = docker.runs
    assert _option(run, "--network") == "none" and "--read-only" in run
    assert _option(run, "--entrypoint") == "/usr/bin/clang-18" and IMAGE_ID in run
    assert run[-5:] == ["-O2", "-s", "-o", "/scratch/case083-stripped", "/target/main.c"]
    assert mount_source(run, "/target") == (ROOT / "containers/fixtures/ghidra/case-083").resolve()


def test_unsafe_or_unknown_expectations_are_rejected(tmp_path: Path, monkeypatch) -> None:
    document = json.loads((ROOT / efficacy.EXPECTATIONS).read_text(encoding="utf-8"))
    path = tmp_path / "expectations.json"
    monkeypatch.setattr(efficacy, "EXPECTATIONS", path)
    for mutate, message in (
        (lambda d: d["variants"]["symbols"]["flags"].append("; rm -rf /"), "unsafe compiler flag"),
        (lambda d: d["variants"]["symbols"]["checks"].append({"id": "x", "kind": "magic"}), "unknown check"),
        (lambda d: d["variants"]["symbols"]["checks"].append(d["variants"]["symbols"]["checks"][0]), "unique"),
        (lambda d: d.update(schema="other/1"), "unsupported"),
    ):
        changed = json.loads(json.dumps(document))
        mutate(changed)
        path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            efficacy.load_expectations(tmp_path)


def test_evaluation_scores_required_checks_and_reports_optional_losses(tmp_path: Path) -> None:
    root = Path(_decompile(tmp_path, FakeDocker())["path"])
    expectations = efficacy.load_expectations(ROOT)
    outcome = efficacy.evaluate(root, expectations["variants"]["symbols"]["checks"])
    # The synthetic export mirrors the real symbols-variant export, so every check passes.
    assert [check["id"] for check in outcome["checks"] if not check["passed"]] == []
    by_id = {check["id"]: check for check in outcome["checks"]}
    assert by_id["call-print-label-to-strcpy"]["observed"] == ["print_label"]
    assert by_id["string-default-in-main"]["observed"] == ["main"]
    assert by_id["decompile-coverage"]["observed"] == 1.0
    assert (outcome["required_passed"], outcome["required_total"], outcome["score"]) == (12, 12, 1.0)

    checks = [
        {"id": "caller-by-edge", "kind": "call", "callee": "strcpy"},
        {"id": "sink-by-edge", "kind": "pseudo_c", "function": {"calls": "strcpy"}, "contains": ["[32]"]},
        {"id": "absent", "kind": "function", "name": "memcpy"},
        {"id": "lost", "kind": "import", "name": "gets", "required": False},
        {"id": "coverage", "kind": "decompile_coverage", "minimum": 1.0},
    ]
    outcome = efficacy.evaluate(root, checks)
    assert [check["passed"] for check in outcome["checks"]] == [True, True, False, False, True]
    # The import stub is a thunk, so it is not reported as a caller of its own import.
    assert outcome["checks"][0]["observed"] == ["print_label"]
    assert (outcome["required_passed"], outcome["required_total"]) == (3, 4)
    assert (outcome["optional_passed"], outcome["optional_total"]) == (0, 1)
    assert outcome["score"] == 0.75


def test_efficacy_run_builds_decompiles_scores_and_reuses(tmp_path: Path, monkeypatch) -> None:
    docker = FakeDocker()
    arguments = {"repository_root": ROOT, "config_path": ROOT / "appsec-review.toml",
                 "work_root": tmp_path / "work", "variants": ["stripped"], "runner": docker}
    report = efficacy.run_efficacy(**arguments)
    stripped = report["variants"]["stripped"]
    assert report["schema"] == "appsec-review/binary-decompilation-efficacy/1"
    assert stripped["reused"] is False and Path(stripped["publication"]).is_dir()
    assert json.loads((tmp_path / "work" / "report.json").read_text()) == report
    assert report["accepted"] is (stripped["score"] >= stripped["minimum_score"])
    assert len(docker.runs) == 2  # one compile, one decompile
    again = efficacy.run_efficacy(**arguments)
    assert again["variants"]["stripped"]["reused"] is True and len(docker.runs) == 3
    with pytest.raises(ValueError, match="unknown fixture variants"):
        efficacy.run_efficacy(**{**arguments, "variants": ["absent"]})


# CLI


def _configured(monkeypatch, tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = replace(config.binary_decompilation, binaries=(_request(tmp_path),))
    monkeypatch.setattr(cli, "load_config", lambda path: replace(config, binary_decompilation=settings))


def test_cli_decompiles_configured_binaries_and_prints_publications(monkeypatch, tmp_path, capsys) -> None:
    import appsec_review.binary_decompilation as package
    _configured(monkeypatch, tmp_path)
    seen = []
    monkeypatch.setattr(package, "decompile_binary", lambda **kwargs: seen.append(kwargs) or {
        "binary_id": kwargs["request"].binary_id, "identity": "f" * 64, "reused": False})
    assert cli.main(["binary-decompile", "--binary", "vendor", "--force"]) == 0
    (result,) = json.loads(capsys.readouterr().out)
    assert result == {"status": "PUBLISHED", "binary_id": "vendor", "identity": "f" * 64, "reused": False}
    assert seen[0]["force"] is True and seen[0]["settings"].binaries[0].binary_id == "vendor"

    monkeypatch.setattr(package, "verify_binary", lambda **kwargs: {"binary_id": "vendor", "reused": True})
    assert cli.main(["binary-decompile", "--verify-only"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["reused"] is True
    with pytest.raises(KeyError, match="not configured"):
        cli.main(["binary-decompile", "--binary", "absent"])


def test_cli_reports_failures_with_their_evidence_and_exits_nonzero(monkeypatch, tmp_path, capsys) -> None:
    import appsec_review.binary_decompilation as package
    _configured(monkeypatch, tmp_path)

    def fail(**kwargs):
        raise DecompilationError("Ghidra export ended TIMEOUT", status="TIMEOUT", evidence=tmp_path / "failed")

    monkeypatch.setattr(package, "decompile_binary", fail)
    assert cli.main(["binary-decompile"]) == 1
    (result,) = json.loads(capsys.readouterr().out)
    assert result["status"] == "TIMEOUT" and result["evidence"] == str(tmp_path / "failed")
    assert result["binary_sha256"] == SHA256

    monkeypatch.setattr(package, "decompile_binary", lambda **kwargs: (_ for _ in ()).throw(
        ValueError("binary vendor does not match its configured SHA-256")))
    assert cli.main(["binary-decompile"]) == 1
    assert json.loads(capsys.readouterr().out)[0]["status"] == "REFUSED"


def test_cli_refuses_to_run_with_no_configured_binaries(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--config", str(ROOT / "appsec-review.toml"), "binary-decompile"])
    assert "no binaries are configured" in capsys.readouterr().err
