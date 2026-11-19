"""Code-level static script analysis, redaction, schema validation, reader bounds, and settings tests."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from appsec_review.config import BuildEnvironmentSettings, PlanningFeedbackSettings, parse_bounded_settings
from appsec_review.jobs.job_build_environment_analysis.job import (
    _read,
    analyze_environment,
    gap_records,
    redact,
    validate_environment,
)

ROOT = Path(__file__).resolve().parents[3]


def _static(files: dict[str, str | bytes], *, reads=None, **limits):
    payloads = {
        path: (data if isinstance(data, bytes) else data.encode("utf-8"))
        for path, data in files.items()
    }
    catalog = {
        "source_fingerprint": "synthetic-source",
        "catalog_handoff_sha256": "c" * 64,
        "files": [
            {
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
            for path, data in payloads.items()
        ],
    }
    def read_document(item, bound):
        if reads is not None:
            reads.append(item["path"])
        return payloads[item["path"]][: bound + 1]

    return analyze_environment(
        catalog,
        read_document,
        replace(BuildEnvironmentSettings(), **limits),
    )


def test_static_literals_are_advisory_redacted_and_source_resolving():
    raw_text = "SDK_ROOT=tools/sdk\nAPI_TOKEN=do-not-retain\nURL=https://u:p@host/a\n"
    value = _static({"setup.sh": raw_text})
    assert value["availability"] == "AVAILABLE"
    assert value["declarations"][0]["value"] == "tools/sdk"
    assert value["declarations"][0]["reason"] == "static_literal_advisory_only"
    assert [item["status"] for item in value["declarations"]] == ["declared", "redacted", "redacted"]
    assert all(
        item["sha256"] == hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        for item in value["declarations"]
    )
    assert "do-not-retain" not in json.dumps(value)
    assert "u:p@" not in json.dumps(value)


@pytest.mark.parametrize(
    "path,text",
    [
        ("setup.sh", "set CC=clang\n"),
        ("setup.bash", '@set "CC=clang"\n'),
        ("setup.cmd", "CC=clang\n"),
        ("setup.bat", "export CC=clang\n"),
        ("setup.sh", "EXPORT CC=clang\n"),
        ("setup.BASH", "Set CC=clang\n"),
    ],
    ids=["shell-set", "shell-at-set", "batch-bare", "batch-export", "shell-EXPORT", "shell-Set"],
)
def test_assignment_grammar_rejects_other_dialects(path, text):
    value = _static({path: text})
    assert value["declarations"] == []
    assert value["coverage"] == "partial"
    assert f"{path}: unsupported_script_statement" in value["gaps"]
    assert "secret-sentinel" not in redact(text.replace("CC=clang", "API_TOKEN=secret-sentinel"))


@pytest.mark.parametrize(
    "path,text",
    [
        ("setup.sh", "CC=clang\n"),
        ("setup.BASH", "export CC=clang\n"),
        ("setup.cmd", "SET CC=clang\n"),
        ("setup.BAT", '@SeT "CC=clang"\n'),
    ],
    ids=["shell-bare", "shell-export", "batch-SET", "batch-quoted"],
)
def test_assignment_grammar_retains_supported_dialect_literals(path, text):
    value = _static({path: text})
    assert value["coverage"] == "complete" and not value["gaps"]
    assert value["declarations"] == [{
        "path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(), "line": 1,
        "name": "CC", "value": "clang", "status": "declared",
        "reason": "static_literal_advisory_only",
    }]


@pytest.mark.parametrize(
    "path,text",
    [
        ("setup.sh", "until true\ndo\nCC=clang\ndone\n"),
        ("setup.cmd", "@if exist flag (\nset CC=clang\n)\n"),
        ("setup.cmd", "@FOR /L %%i IN (1,1,2) DO (\nSET CC=clang\n)\n"),
        ("setup.cmd", "@setlocal\nset CC=clang\n"),
    ],
    ids=["shell-until", "batch-at-if", "batch-at-FOR", "batch-at-setlocal"],
)
def test_unsupported_control_contexts_withhold_literal_values(path, text):
    value = _static({path: text})
    assert [(d["name"], d["status"], d["value"]) for d in value["declarations"]] == [
        ("CC", "unknown", None),
    ]
    assert value["coverage"] == "partial"
    assert f"{path}: unresolved_script_context_or_condition" in value["gaps"]


@pytest.mark.parametrize(
    "path,text",
    [
        ("setup.sh", "CC=clang\necho \\\nCXX=clang++\necho \\\nsource child.sh\n"),
        ("setup.cmd", "set CC=clang\necho ^\nset CXX=clang++\necho ^\ncall child.sh\n"),
    ],
    ids=["shell-backslash", "batch-caret"],
)
def test_continued_command_arguments_are_not_independent_assignments(path, text):
    reads = []
    value = _static({path: text, "child.sh": "UNRELATED=1\n"}, reads=reads)
    assert [(d["name"], d["line"], d["status"], d["value"]) for d in value["declarations"]] == [
        ("CC", 1, "unknown", None),
    ]
    assert f"{path}: unresolved_script_context_or_condition" in value["gaps"]
    assert f"{path}: unsupported_script_statement" in value["gaps"]
    assert reads == [path]


@pytest.mark.parametrize(
    "text",
    [
        "if test -f flag; then\nCC=clang\nfi\n",
        "source other.sh\nCC=clang\n",
        'SDK=$(dirname "$0")\nCC=clang\n',
        "call other.cmd\nCC=clang\n",
        "cd child\nCC=clang\n",
        "CC=clang;make\n",
        "CC=clang args\n",
        "pushd child\nCC=clang\n",
        "function setup {\nCC=clang\n}\n",
        "setup() {\nCC=clang\n}\n",
    ],
    ids=[
        "if-block",
        "source-missing",
        "subshell",
        "call-missing",
        "cd",
        "semicolon",
        "space-value",
        "pushd",
        "function-kw",
        "function-parens",
    ],
)
def test_uncertain_script_context_never_becomes_a_known_value(text):
    value = _static({"setup.sh": text})
    assert value["declarations"]
    assert all(item["value"] is None and item["status"] == "unknown" for item in value["declarations"])


def test_literal_sourced_inventory_and_taint_preserve_redacted_and_other_paths():
    value = _static(
        {
            "a-setup.sh": "HOST_VAR=1\nsource z-env.sh\n",
            "z-env.sh": "# comment\n\nCC=clang\nAPI_TOKEN=secret with spaces\n",
            "unselected.sh": "UNRELATED=1\n",
        }
    )
    assert value["bounds"]["inspected_scripts"] == 2
    z_decls = [item for item in value["declarations"] if item["path"] == "z-env.sh"]
    assert [(d["name"], d["status"], d["value"]) for d in z_decls] == [
        ("CC", "unknown", None),
        ("[REDACTED]", "redacted", None),
    ]
    assert all(item["name"] != "UNRELATED" for item in value["declarations"])

    reverse = _static({"setup.sh": "source env-child.sh\n", "env-child.sh": "CC=clang\n"})
    child_decls = [item for item in reverse["declarations"] if item["path"] == "env-child.sh"]
    assert len(child_decls) == 1 and child_decls[0]["status"] == "unknown"


@pytest.mark.parametrize("max_scripts", [2, 64], ids=["tight", "default"])
@pytest.mark.parametrize("child", ["env.sh", "z-env.sh"], ids=["seen", "pending"])
def test_sourcing_taints_selected_scripts_without_another_read_slot(max_scripts, child):
    files = {child: "CC=clang\nAPI_TOKEN=sentinel\n", "setup.sh": f"source {child}\n"}
    files.update({f"env-padding-{i:02}.sh": "# inert\n" for i in range(max_scripts - 2)})
    reads = []
    value = _static(files, reads=reads, max_scripts=max_scripts)
    declarations = [d for d in value["declarations"] if d["path"] == child]
    assert [(d["name"], d["status"], d["value"]) for d in declarations] == [
        ("CC", "unknown", None), ("[REDACTED]", "redacted", None),
    ]
    assert declarations[0]["sha256"] == hashlib.sha256(files[child].encode()).hexdigest()
    assert sorted(reads) == sorted(files)
    assert value["bounds"]["inspected_scripts"] == max_scripts
    assert f"{child}: unresolved_script_context_or_condition" in value["gaps"]
    assert not any("source_depth_or_script_bound" in gap for gap in value["gaps"])
    if max_scripts == 2:
        looser = _static(files, max_scripts=3)
        assert value["declarations"] == looser["declarations"]


def test_source_depth_bound_still_taints_previously_inspected_target():
    reads = []
    value = _static({
        "env.sh": "CC=clang\n",
        "setup.sh": "source a.sh\n",
        "a.sh": "source env.sh\nsource unread.sh\n",
        "unread.sh": "UNREAD=1\n",
    }, reads=reads, max_scripts=4, max_depth=1)
    assert reads == ["env.sh", "setup.sh", "a.sh"]
    assert value["bounds"]["inspected_scripts"] == 3
    assert [(d["name"], d["status"], d["value"]) for d in value["declarations"]] == [
        ("CC", "unknown", None),
    ]
    assert "env.sh: unresolved_script_context_or_condition" in value["gaps"]
    assert "a.sh: source_depth_or_script_bound" in value["gaps"]


@pytest.mark.parametrize("command", ["call", "@call", "@CALL"], ids=["call", "at-call", "at-CALL"])
@pytest.mark.parametrize("child", ["env.cmd", "z-env.cmd"], ids=["seen", "pending"])
def test_batch_call_taints_selected_scripts_at_count_bound(command, child):
    files = {child: "set CC=clang\nset API_TOKEN=sentinel\n", "setup.cmd": f"{command} {child}\n"}
    reads = []
    value = _static(files, reads=reads, max_scripts=2)
    declarations = [d for d in value["declarations"] if d["path"] == child]
    assert [(d["name"], d["status"], d["value"]) for d in declarations] == [
        ("CC", "unknown", None), ("[REDACTED]", "redacted", None),
    ]
    assert declarations[0]["sha256"] == hashlib.sha256(files[child].encode()).hexdigest()
    assert sorted(reads) == sorted(files)
    assert value["bounds"]["inspected_scripts"] == 2
    assert f"{child}: unresolved_script_context_or_condition" in value["gaps"]
    assert not any("source_depth_or_script_bound" in gap for gap in value["gaps"])
    assert "sentinel" not in json.dumps(value)


def test_batch_call_taints_known_target_at_source_depth_bound():
    reads = []
    value = _static({
        "env.cmd": "set CC=clang\n",
        "setup.cmd": "@call child.cmd\n",
        "child.cmd": "@CALL env.cmd\n@call unread.cmd\n",
        "unread.cmd": "set UNREAD=1\n",
    }, reads=reads, max_scripts=3, max_depth=1)
    assert reads == ["env.cmd", "setup.cmd", "child.cmd"]
    assert [(d["name"], d["status"], d["value"]) for d in value["declarations"]] == [
        ("CC", "unknown", None),
    ]
    assert "env.cmd: unresolved_script_context_or_condition" in value["gaps"]
    assert "child.cmd: source_depth_or_script_bound" in value["gaps"]


def test_batch_call_new_reads_still_obey_script_count_bound():
    reads = []
    value = _static({
        "setup.cmd": "@call child.cmd\n@CALL child.cmd\n@call unread.cmd\n",
        "child.cmd": "set CC=clang\n", "unread.cmd": "set UNREAD=1\n",
    }, reads=reads, max_scripts=2)
    assert reads == ["setup.cmd", "child.cmd"]
    assert value["bounds"]["inspected_scripts"] == 2
    assert [(d["name"], d["status"], d["value"]) for d in value["declarations"]] == [
        ("CC", "unknown", None),
    ]
    assert "setup.cmd: source_depth_or_script_bound" in value["gaps"]
    assert not any("unsupported_script_statement" in gap for gap in value["gaps"])


@pytest.mark.parametrize(
    "suffix,command",
    [
        (".sh", "call"), (".sh", "@call"), (".bash", "@CALL"),
        (".sh", "SOURCE"), (".sh", "@source"),
        (".cmd", "source"), (".cmd", "."), (".cmd", "@source"),
    ],
    ids=["shell-call", "shell-at-call", "shell-at-CALL", "shell-SOURCE", "shell-at-source",
         "batch-source", "batch-dot", "batch-at-source"],
)
def test_unsupported_source_commands_do_not_read_or_taint_targets(suffix, command):
    child, selected, root = "child" + suffix, "env" + suffix, "setup" + suffix
    assignment = "set CC=clang\n" if suffix == ".cmd" else "CC=clang\n"
    reads = []
    value = _static({
        root: f"{command} {selected}\n{command} {child}\n",
        selected: assignment, child: assignment,
    }, reads=reads, max_scripts=3)
    assert sorted(reads) == sorted([selected, root])
    assert [(d["path"], d["status"], d["value"]) for d in value["declarations"]] == [
        (selected, "declared", "clang"),
    ]
    assert f"{root}: unsupported_script_statement" in value["gaps"]
    assert not any(gap.startswith(f"{selected}:") for gap in value["gaps"])


@pytest.mark.parametrize("command", ["source", "."], ids=["source", "dot"])
def test_supported_shell_source_commands_retain_bounded_reads(command):
    reads = []
    value = _static({"setup.bash": f"{command} child.sh\n", "child.sh": "CC=clang\n"},
                    reads=reads, max_scripts=2)
    assert reads == ["setup.bash", "child.sh"]
    assert [(d["path"], d["status"], d["value"]) for d in value["declarations"]] == [
        ("child.sh", "unknown", None),
    ]
    assert not any("unsupported_script_statement" in gap for gap in value["gaps"])


def test_repeated_source_edges_do_not_consume_script_slots():
    reads = []
    files = {
        "setup.sh": "source setup.sh\nsource child.sh\nsource child.sh\nsource other.sh\n",
        "child.sh": "CC=clang\n", "other.sh": "CXX=clang++\n",
    }
    value = _static(files, reads=reads, max_scripts=3)
    assert reads == ["setup.sh", "child.sh", "other.sh"]
    assert [(d["name"], d["status"]) for d in value["declarations"]] == [
        ("CC", "unknown"), ("CXX", "unknown"),
    ]
    assert not any("source_depth_or_script_bound" in gap for gap in value["gaps"])
    limited_reads = []
    limited = _static(files, reads=limited_reads, max_scripts=2)
    assert limited_reads == ["setup.sh", "child.sh"]
    assert limited["bounds"]["inspected_scripts"] == 2
    assert "setup.sh: source_depth_or_script_bound" in limited["gaps"]


@pytest.mark.parametrize(
    "limit,files,expected",
    [
        ({"max_scripts": 1}, {"env-a.sh": "A=1", "env-b.sh": "B=2"}, "script_count_exhausted"),
        ({"max_script_bytes": 1}, {"setup.sh": "A=1"}, "script_byte_bound"),
        ({"max_assignments": 1}, {"setup.sh": "A=1\nB=2\n"}, "assignment_count_exhausted"),
        ({"max_depth": 1}, {"setup.sh": "source a.sh", "a.sh": "source b.sh", "b.sh": "B=2"}, "source_depth_or_script_bound"),
    ],
    ids=["script-count", "script-bytes", "assignment-count", "source-depth"],
)
def test_static_exhaustion_publishes_partial_coverage(limit, files, expected):
    value = _static(files, **limit)
    assert value["coverage"] == "partial"
    assert any(expected in gap for gap in value["gaps"])


def test_encoding_value_bounds_powershell_and_deadlines():
    bad_utf8 = _static({"setup.sh": b"\xff\xfe"})
    assert bad_utf8["gaps"] == ["setup.sh: unsupported_script_encoding"]

    huge_val = _static({"setup.sh": "BIG=" + "a" * 2049 + "\necho trailing\n"})
    assert "setup.sh: declaration_value_byte_bound" in huge_val["gaps"]
    assert "setup.sh: unsupported_script_statement" in huge_val["gaps"]
    assert huge_val["declarations"][0]["status"] == "unknown"

    unsupported = _static({"setup.ps1": "$env:CC='cl'"})
    assert unsupported["availability"] == "UNAVAILABLE" and unsupported["coverage"] == "partial"
    assert _static({})["coverage"] == "not_applicable"

    catalog = {
        "source_fingerprint": "s",
        "catalog_handoff_sha256": "c" * 64,
        "files": [{"path": "setup.sh", "sha256": hashlib.sha256(b"A=1\nB=2\n").hexdigest(), "size_bytes": 8}],
    }
    outer_times = iter((0, 31))
    outer = analyze_environment(
        catalog,
        lambda *_: pytest.fail("outer deadline must prevent read"),
        BuildEnvironmentSettings(),
        clock=lambda: next(outer_times),
    )
    assert outer["availability"] == "UNAVAILABLE"
    assert outer["gaps"] == ["internal_environment_deadline"]

    inner_times = iter((0, 1, 31))
    inner = analyze_environment(
        catalog,
        lambda *_: b"A=1\nB=2\n",
        BuildEnvironmentSettings(),
        clock=lambda: next(inner_times),
    )
    assert inner["gaps"] == ["internal_environment_deadline"]
    assert inner["declarations"] == []


def test_source_corruption_reader_contract_and_unexpected_bugs_propagate():
    catalog = {
        "source_fingerprint": "s",
        "catalog_handoff_sha256": "c" * 64,
        "files": [{"path": "setup.sh", "sha256": "a" * 64, "size_bytes": 3}],
    }
    with pytest.raises(ValueError, match="source bytes changed"):
        analyze_environment(catalog, lambda *_: b"A=1", BuildEnvironmentSettings())
    with pytest.raises(ValueError, match="exceeded its byte contract"):
        analyze_environment(catalog, lambda *_: "not-bytes", BuildEnvironmentSettings())
    with pytest.raises(ValueError, match="exceeded its byte contract"):
        analyze_environment(catalog, lambda *_: b"x" * 10, replace(BuildEnvironmentSettings(), max_script_bytes=4))

    def broken(*_):
        raise RuntimeError("synthetic unexpected bug")

    with pytest.raises(RuntimeError, match="synthetic unexpected bug"):
        analyze_environment(catalog, broken, BuildEnvironmentSettings())


@pytest.mark.parametrize(
    "kind,key,value",
    [
        ("environment", "max_scripts", 65),
        ("environment", "max_script_bytes", 262145),
        ("environment", "max_assignments", 4097),
        ("environment", "max_depth", 5),
        ("environment", "enabled", "true"),
        ("feedback", "max_calls", 5),
        ("feedback", "max_evidence_rounds", 4),
        ("feedback", "max_documents", 9),
        ("feedback", "max_request_bytes", 131073),
        ("feedback", "max_response_bytes", 65537),
        ("feedback", "units_per_scope", 0),
        ("feedback", "max_scopes", True),
    ],
)
def test_typed_bounds_reject_loosening_and_nonintegers(kind, key, value):
    with pytest.raises(ValueError):
        parse_bounded_settings(
            {key: value},
            BuildEnvironmentSettings if kind == "environment" else PlanningFeedbackSettings,
        )


def test_redaction_and_quoted_batch_assignments():
    assert redact("") == ""
    assert redact("TOKEN=abc\nENV password secret\nURL=https://u:p@host/x\n") == (
        "[REDACTED assignment]\n[REDACTED assignment]\nURL=https://[REDACTED]@host/x\n"
    )
    text = "FROM pinned-base\r\nENV SDK=tools/sdk\r\n"
    assert redact(text) == text
    assert redact("ENV API_TOKEN=value\r\n") == "[REDACTED assignment]\r\n"

    for prefix in ('@set "', 'set "', "@set "):
        for ending in ("\n", "\r\n"):
            quote_tail = '"' if prefix.endswith('"') else ""
            safe = f"{prefix}SDK_ROOT=tools/sdk{quote_tail}{ending}"
            sensitive = f"{prefix}API_TOKEN=SYNTHETIC_BOUNDARY_SENTINEL{quote_tail}{ending}"
            assert redact(safe) == safe
            assert redact(sensitive) == "[REDACTED assignment]" + ending
            value = _static({"setup.cmd": safe + sensitive})
            first, second = value["declarations"]
            assert first["name"] == "SDK_ROOT" and first["value"] == "tools/sdk"
            assert first["status"] == "declared"
            assert second["status"] == "redacted" and second["value"] is None
            assert "SYNTHETIC_BOUNDARY_SENTINEL" not in json.dumps(value)


def test_validate_environment_and_offline_json_schema():
    schema = json.loads((ROOT / "docs/schemas/build-environment-analysis.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for files in (
        {},
        {"setup.ps1": "unsupported"},
        {"setup.sh": "SDK=tools/sdk\n"},
        {"setup.sh": "source missing.sh\nSDK=tools/sdk\n"},
    ):
        validator.validate(_static(files))

    for mutator, match in (
        (lambda v: v.update(extra=True), "invalid bounded environment schema"),
        (lambda v: v.update(gaps=["unexpected"]), "invalid bounded environment schema"),
        (lambda v: v["bounds"].update(extra=True), "invalid environment coverage bounds"),
        (lambda v: v["bounds"].update(max_scripts=65), "max_scripts"),
        (lambda v: v["bounds"].update(inspected_scripts=True), "does not match its bounded outcome"),
        (lambda v: v.update(coverage="not_applicable"), "does not match its bounded outcome"),
        (lambda v: v["declarations"][0].update(path="dir\\setup.sh"), "invalid bounded environment declaration"),
        (lambda v: v["declarations"][0].update(name="API_TOKEN"), "invalid bounded environment declaration"),
        (
            lambda v: v.update(availability="UNAVAILABLE", coverage="partial", gaps=["PowerShell environment scripts are not supported"]),
            "unavailable environment cannot carry imported declarations",
        ),
    ):
        sample = _static({"setup.sh": "SDK=tools/sdk\n"})
        mutator(sample)
        with pytest.raises(ValueError, match=match):
            validate_environment(sample)


def test_read_bounds_object_check_and_gap_records(tmp_path):
    assert gap_records([], "environment_analysis.publish_handoff") == []
    gaps = [
        "tools/env.sh: unresolved_sourcing",
        "setup.bat: unsupported_script_statement",
        "notes.txt: odd_note",
        "script_count_exhausted",
    ]
    records = gap_records(gaps, "environment_analysis.publish_handoff")
    assert [r["scope_id"] for r in records] == ["tools/env.sh", "setup.bat", None, None]
    assert all(r["code"] == "producer_reported_gap" and r["retryable"] is False for r in records)

    sub = tmp_path / "subdir"
    sub.mkdir()
    with pytest.raises(ValueError, match="missing or exceeds its bound"):
        _read(tmp_path, {"path": "subdir", "sha256": "a" * 64})

    arr_path = tmp_path / "array.json"
    arr_bytes = b"[]"
    arr_path.write_bytes(arr_bytes)
    with pytest.raises(ValueError, match="must be an object"):
        _read(tmp_path, {"path": "array.json", "size_bytes": 2, "sha256": hashlib.sha256(arr_bytes).hexdigest()})

    big = b'{"padding":"' + b"x" * (16 * 1024 * 1024) + b'"}'
    big_path = tmp_path / "bounded.json"
    big_path.write_bytes(big)
    identity = {"path": "bounded.json", "size_bytes": len(big), "sha256": hashlib.sha256(big).hexdigest()}
    assert len(_read(tmp_path, identity, byte_limit=32 * 1024 * 1024)["padding"]) == 16 * 1024 * 1024
    with pytest.raises(ValueError, match="exceeds its bound"):
        _read(tmp_path, identity)
    with pytest.raises(ValueError, match="identity mismatch"):
        _read(tmp_path, {**identity, "sha256": "f" * 64}, byte_limit=32 * 1024 * 1024)
    with pytest.raises(ValueError, match="unsupported environment reader byte limit"):
        _read(tmp_path, identity, byte_limit=33554433)
