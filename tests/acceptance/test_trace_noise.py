from __future__ import annotations

import json
from pathlib import Path

from appsec_review.acceptance.content import content_differences
from appsec_review.acceptance.normalize import Masks, normalize_value

RUN = "2026-10-19-0001"
MASKS = Masks.for_run(RUN, runs_roots=["/opt/app/runs"], repository_roots=["/opt/app"], target_roots=[])


def test_trace_measurements_are_masked_but_exit_codes_and_commands_are_kept() -> None:
    record = {
        "execution_capture": {"exit_code": 2, "events": {"counts": {"file_open": 8054}, "observed": 8346},
                              "commands": ["cmake", "--build"]},
        "raw_traces": {"observed_bytes": 534900, "records": [{"source": "trace.13", "bytes": 82820}]},
        "capture_provenance": {"event_records_observed": 10815, "event_records_retained": 10815},
        "files": 12,
    }
    other = json.loads(json.dumps(record))
    other["execution_capture"]["events"] = {"counts": {"file_open": 8059}, "observed": 8351}
    other["raw_traces"] = {"observed_bytes": 534952, "records": [{"source": "trace.14", "bytes": 82846}]}
    other["capture_provenance"] = {"event_records_observed": 10820, "event_records_retained": 10820}

    assert normalize_value(record, MASKS) == normalize_value(other, MASKS)
    assert normalize_value(record, MASKS)["execution_capture"]["exit_code"] == 2
    other["execution_capture"]["exit_code"] = 0
    other["files"] = 13
    assert normalize_value(record, MASKS) != normalize_value(other, MASKS)


def test_event_numbers_in_receipts_and_random_build_temp_names_are_masked() -> None:
    left = {"origin": "execution-capture:command-002:event-7894",
            "argv": ["c++", "-fresolution=/workspace/.appsec-review-build-scratch.vM3KGf/ccKSzJPO.res",
                     "/workspace/build/CMakeFiles/CMakeScratch/TryCompile-e3FJsm/x", "cmTC_24658.dir"]}
    right = {"origin": "execution-capture:command-002:event-7899",
             "argv": ["c++", "-fresolution=/workspace/.appsec-review-build-scratch.wXIkXM/ccl0zImT.res",
                      "/workspace/build/CMakeFiles/CMakeScratch/TryCompile-Nga9AC/x", "cmTC_6e6e6.dir"]}
    assert normalize_value(left, MASKS) == normalize_value(right, MASKS)
    right["origin"] = "execution-capture:command-001:event-7899"
    assert normalize_value(left, MASKS) != normalize_value(right, MASKS)


def test_concurrent_build_lists_compare_without_order_but_not_without_members() -> None:
    first, second = {"tool": "c++"}, {"tool": "as"}
    assert (normalize_value({"rows": [first, second]}, MASKS) == normalize_value({"rows": [second, first]}, MASKS))
    assert (normalize_value({"rows": [first, second]}, MASKS) != normalize_value({"rows": [first]}, MASKS))
    assert normalize_value({"steps": [first, second]}, MASKS) != normalize_value({"steps": [second, first]}, MASKS)


def _event(kind: str, **fields) -> dict:
    return {"kind": kind, "pid": 1, "tid": 1, "ordinal": 1, "timestamp_ns": 1, **fields}


def _capture(tmp_path: Path, name: str, events: list[dict]) -> tuple[Path, dict]:
    run_root = tmp_path / name
    relative = "data/build/units/u/execution-capture/command-001/events.jsonl"
    path = run_root / relative
    path.parent.mkdir(parents=True)
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    return run_root, {"artifacts": [{"path": relative}]}


def _compare(left, right):
    return content_differences("job_language_build", left[0], left[1], MASKS, right[0], right[1], MASKS)


def test_execution_capture_compares_executed_commands_not_file_level_events(tmp_path: Path) -> None:
    exec_ = {"argv": ["c++", "-c", "a.cpp"], "executable": "/usr/bin/c++",
             "envp": [{"name": "HOSTNAME", "value": "3e1528843aab"}]}
    left = _capture(tmp_path, "left", [
        _event("process_exec", **exec_), _event("file_open", path="/capture"), _event("process_exit")])
    other_exec = {**exec_, "envp": [{"name": "HOSTNAME", "value": "1781caece12e"}]}
    right = _capture(tmp_path, "right", [
        _event("file_open", path="/capture"), _event("file_open", path="/capture"),
        _event("process_exec", **other_exec), _event("file_unlink", path="/tmp/x")])
    assert _compare(left, right) == []

    different = _capture(tmp_path, "different", [_event("process_exec", **{**exec_, "argv": ["c++", "-c", "b.cpp"]})])
    missing = _capture(tmp_path, "missing", [])
    assert [item.path.endswith("#process_exec") for item in _compare(left, different)] == [True, True]
    assert len(_compare(left, missing)) == 1


def test_unit_outputs_get_the_same_trace_and_ordering_rules() -> None:
    from collections import Counter

    from appsec_review.acceptance.normalize import _extract

    def unit(count: int, rows: list) -> dict:
        return {"receipts": [{"commands": [{"execution_capture": {"events": {"observed": count, "retained": count,
                                                                             "counts": {"file_open": count - 3}}}}],
                              "rows": rows}]}

    def extract(value: dict) -> dict:
        return _extract(value, MASKS, Counter(), Counter(), "execute.native")

    assert extract(unit(8346, [{"tool": "c++"}, {"tool": "as"}])) == extract(unit(8348, [{"tool": "as"}, {"tool": "c++"}]))
    assert extract(unit(8346, [{"tool": "c++"}])) != extract(unit(8346, [{"tool": "as"}]))


def test_parenthesized_tool_durations_are_masked() -> None:
    assert (normalize_value("-- Configuring done (0.7s)", MASKS) == normalize_value("-- Configuring done (12s)", MASKS))
    assert normalize_value("-- Configuring done (0.7s)", MASKS) != normalize_value("-- Generating done (0.7s)", MASKS)


def test_compiler_pointer_addresses_are_masked() -> None:
    assert normalize_value("ParmVarDecl 0x56b473e31d50 id", MASKS) == normalize_value("ParmVarDecl 0x5581cc07aa10 id", MASKS)
    assert normalize_value("flags 0x1f", MASKS) != normalize_value("flags 0x2f", MASKS)


def test_codeql_log_names_stamps_and_sarif_timings_are_masked() -> None:
    first = {"files": {"log/database-init-20261020.175419.010.log": "a",
                       "diagnostic/cli-diagnostics-add-20261020T175420.979Z.json": "b",
                       "log/extractor/04/13/e4470.log": "c"},
             "receipt": {"stderr_total_bytes": 57195}}
    second = {"files": {"log/database-init-20261020.180019.788.log": "a",
                        "diagnostic/cli-diagnostics-add-20261020T180020.365Z.json": "b",
                        "log/extractor/07/26/a2f41.log": "c"},
              "receipt": {"stderr_total_bytes": 57192}}
    assert normalize_value(first, MASKS) == normalize_value(second, MASKS)
    assert normalize_value(first, MASKS) != normalize_value({**second, "files": {}}, MASKS)


def test_package_ids_hashed_over_the_retrieval_manifest_are_masked_but_their_content_is_not() -> None:
    first = {"package_id": "package-ac30fc5651ff3c7374154428", "row_id": "r1", "control": {"id": "V1.1"}}
    second = {"package_id": "package-2c2bd9d986ac43e14fc77cff", "row_id": "r1", "control": {"id": "V1.1"}}
    assert normalize_value(first, MASKS) == normalize_value(second, MASKS)
    assert normalize_value(first, MASKS) != normalize_value({**second, "row_id": "r2"}, MASKS)
