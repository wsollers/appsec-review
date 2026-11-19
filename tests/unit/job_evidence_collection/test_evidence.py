"""Code-level unit tests for src/appsec_review/jobs/job_evidence_collection/evidence.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appsec_review.jobs.job_evidence_collection.evidence import (
    EvidenceBounds,
    NORMALIZER_IDENTITY,
    _rule_mapping,
    _text,
    build_envelope,
    redact_structure,
    safe_location,
    severity,
    write_envelope,
)
from appsec_review.provenance import json_selector, retain_native_output, select_native


def test_text_redacts_assignments_and_enforces_utf8_byte_bounds() -> None:
    assert NORMALIZER_IDENTITY == "static-evidence/5"
    assert _text(None, 32) == ("", False)
    rendered, truncated = _text("api_key = 's3cr3tValue' and token: abc123", 200)
    assert not truncated
    assert "s3cr3tValue" not in rendered and "abc123" not in rendered
    assert "api_key=<redacted>" in rendered and "token=<redacted>" in rendered

    short, was_truncated = _text("é" * 20, 11)
    assert was_truncated is True
    assert len(short.encode("utf-8")) <= 11


def test_redact_structure_hashes_secret_fields_and_recurses_lists_and_strings() -> None:
    raw = {
        "secret": "hunter2",
        "Match": "tok_live_999",
        "empty_secret": "",
        "none_token": None,
        "nested": [{"password": "pw1", "note": "passwd=inline_secret"}, 42],
    }
    redacted = redact_structure(raw)
    assert redacted["secret"] == {
        "redacted": True,
        "correlation_sha256": hashlib.sha256(b"hunter2").hexdigest(),
    }
    assert redacted["Match"] == {
        "redacted": True,
        "correlation_sha256": hashlib.sha256(b"tok_live_999").hexdigest(),
    }
    # Empty/None values are left as-is rather than hashed
    assert redacted["empty_secret"] == ""
    assert redacted["none_token"] is None
    assert redacted["nested"][0]["password"]["redacted"] is True
    assert redacted["nested"][0]["note"] == "passwd=<redacted>"
    assert redacted["nested"][1] == 42


def test_severity_normalizes_all_scanner_vocabularies() -> None:
    assert severity("critical") == "CRITICAL"
    assert severity("HIGH") == "HIGH"
    assert severity("error") == "HIGH"
    assert severity("medium") == "MEDIUM"
    assert severity("Moderate") == "MEDIUM"
    assert severity("warning") == "MEDIUM"
    assert severity("WARN") == "MEDIUM"
    assert severity("low") == "LOW"
    assert severity("info") == "LOW"
    assert severity("informational") == "LOW"
    assert severity("style") == "LOW"
    assert severity(None) == "UNKNOWN"
    assert severity("") == "UNKNOWN"
    assert severity("unclassified") == "UNKNOWN"


def test_rule_mapping_retains_bounded_strings_and_string_lists_only() -> None:
    assert _rule_mapping(None) is None
    assert _rule_mapping(["not", "a", "mapping"]) is None
    assert _rule_mapping({"numeric": 123, "mixed_list": ["a", 2]}) is None

    mapped = _rule_mapping({
        "cert": "ERR34-C",
        "long": "x" * 600,
        "cwe": [f"CWE-{i}" for i in range(40)],
        "ignored_int": 7,
    })
    assert mapped is not None
    assert mapped["cert"] == "ERR34-C"
    assert len(mapped["long"]) == 512
    assert len(mapped["cwe"]) == 32
    assert "ignored_int" not in mapped


def test_safe_location_strips_target_prefix_rejects_escapes_and_clamps_lines() -> None:
    cataloged = {"src/app.py", "sub/main.c"}
    assert safe_location(None, 1, 1, cataloged) is None
    assert safe_location("/etc/passwd", 1, 1, cataloged) is None
    assert safe_location("../src/app.py", 1, 1, cataloged) is None
    assert safe_location("/target/unlisted.py", 1, 1, cataloged) is None

    assert safe_location("/target/src/app.py", 10, 5, cataloged) == {
        "path": "src/app.py",
        "start_line": 10,
        "end_line": 10,
    }
    assert safe_location("target\\sub\\main.c", "not-an-int", None, cataloged) == {
        "path": "sub/main.c",
        "start_line": 1,
        "end_line": 1,
    }


def _native_ref(tmp_path: Path, idx: int = 0) -> tuple[Path, Path, list[dict[str, object]]]:
    from .support import attempt_scope, make_unit_context

    unit, _, _ = make_unit_context(tmp_path)
    run_root = unit.job.run_root
    scratch = unit.unit_root / "scratch"
    raw = scratch / "output.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    if not raw.is_file():
        raw.write_text('{"results": [{"id": 1}, {"id": 2}]}', encoding="utf-8")
    exec_json = scratch / "execution.json"
    if not exec_json.is_file():
        exec_json.write_text("{}", encoding="utf-8")
    with attempt_scope(unit):
        retained = retain_native_output(
            run_root,
            raw,
            parser_identity="undeclared",
            complete=True,
            native_result_count=2,
            execution_reference={
                "path": exec_json.relative_to(run_root).as_posix(),
                "sha256": hashlib.sha256(b"{}").hexdigest(),
                "size_bytes": 2,
            },
        )
    return run_root, raw, [select_native(retained, json_selector("results", idx)).as_dict()]


def test_build_envelope_deduplicates_merges_refs_handles_bounds_and_writes(tmp_path: Path) -> None:
    run_root, raw_file, ref0 = _native_ref(tmp_path, 0)
    _, _, ref1 = _native_ref(tmp_path, 1)

    obs_dup_a = {
        "rule_id": "R1",
        "severity": "ERROR",
        "category": "source_sast",
        "message": "password=topsecret found",
        "path": "/target/src/app.py",
        "start_line": 4,
        "end_line": 6,
        "rule_mapping": {"cert": "MSC30-C", "cwe": ["CWE-338"]},
        "_native_refs": ref0,
    }
    obs_dup_b = {**obs_dup_a, "_native_refs": ref1}
    obs_missing_ref_and_unresolved = {
        "rule_id": "software-component",
        "severity": "INFO",
        "category": "software_inventory",
        "message": "m" * 200,
        "path": "/target/not_in_catalog.py",
        "version": "1.2.3",
        "purl": "p" * 200,
    }

    envelope = build_envelope(
        tool={"id": "tool-semgrep", "version": "1.0"},
        target_fingerprint="f" * 64,
        applicability={"applicable": True},
        coverage_scope={"kind": "source_files", "paths": ["src/app.py"], "path_count": 1},
        gaps=["initial gap"],
        raw_artifacts=[raw_file],
        parser_identity="undeclared",
        observations=[obs_dup_a, obs_dup_b, obs_missing_ref_and_unresolved],
        cataloged_paths=["src/app.py"],
        terminal_status="PARTIAL",
        run_root=run_root,
        bounds=EvidenceBounds(max_records=5, max_field_bytes=64, max_total_bytes=65536),
        source_hashes={"src/app.py": "1" * 64},
    )

    assert envelope["schema"] == "appsec-review/static-tool-evidence/2"
    assert envelope["record_count"] == 2
    first, second = envelope["records"]
    assert first["severity"] == "HIGH"
    assert "topsecret" not in first["message"] and "password=<redacted>" in first["message"]
    assert first["location"] == {
        "path": "src/app.py",
        "start_line": 4,
        "end_line": 6,
        "source_sha256": "1" * 64,
    }
    assert first["rule_mapping"] == {"cert": "MSC30-C", "cwe": ["CWE-338"]}
    assert len(first["common"]["evidence_refs"]) == 2
    assert first["common"]["record_kind"] == "finding"

    assert second["artifact_evidence"] is True
    assert second["version"] == "1.2.3"
    assert "purl" not in second
    assert second["common"]["record_kind"] == "observation"
    assert len(second["common"]["gap_ids"]) == 2

    gaps = envelope["exclusions_and_gaps"]
    assert "initial gap" in gaps
    assert "provenance_unavailable: observation has no retained native result" in gaps
    assert "one or more normalized fields were truncated" in gaps
    assert "normalized purl exceeded its field bound" in gaps
    assert "location_unresolved: native source path is not in the accepted catalog" in gaps
    assert len(envelope["raw_artifacts"]) == 1

    out_path = tmp_path / "evidence.json"
    written = write_envelope(out_path, envelope)
    assert written["size_bytes"] == out_path.stat().st_size
    assert json.loads(out_path.read_text(encoding="utf-8"))["record_count"] == 2


def test_build_envelope_enforces_max_records_and_max_total_bytes(tmp_path: Path) -> None:
    run_root, _, ref0 = _native_ref(tmp_path, 0)
    _, _, ref1 = _native_ref(tmp_path, 1)

    rec_cap = build_envelope(
        tool={"id": "tool-semgrep"},
        target_fingerprint="f" * 64,
        applicability={"applicable": True},
        coverage_scope={"kind": "source_files"},
        gaps=(),
        raw_artifacts=(),
        parser_identity="undeclared",
        observations=[
            {"rule_id": "R1", "message": "one", "_native_refs": ref0},
            {"rule_id": "R2", "message": "two", "_native_refs": ref1},
        ],
        cataloged_paths=(),
        terminal_status="PARTIAL",
        run_root=run_root,
        bounds=EvidenceBounds(max_records=1, max_field_bytes=512, max_total_bytes=65536),
    )
    assert rec_cap["record_count"] == 1
    assert "normalized record count bound reached" in rec_cap["exclusions_and_gaps"]

    # Tiny byte cap blocks new record and duplicate ref merge exceeding max_total_bytes
    first_only = build_envelope(
        tool={"id": "tool-semgrep"},
        target_fingerprint="f" * 64,
        applicability={"applicable": True},
        coverage_scope={"kind": "source_files"},
        gaps=(),
        raw_artifacts=(),
        parser_identity="undeclared",
        observations=[{"rule_id": "R1", "message": "one", "_native_refs": ref0}],
        cataloged_paths=(),
        terminal_status="PARTIAL",
        run_root=run_root,
    )
    first_size = len(json.dumps(first_only["records"][0], sort_keys=True, separators=(",", ":")).encode("utf-8"))
    byte_cap = build_envelope(
        tool={"id": "tool-semgrep"},
        target_fingerprint="f" * 64,
        applicability={"applicable": True},
        coverage_scope={"kind": "source_files"},
        gaps=(),
        raw_artifacts=(),
        parser_identity="undeclared",
        observations=[
            {"rule_id": "R1", "message": "one", "_native_refs": ref0},
            {"rule_id": "R1", "message": "one", "_native_refs": ref1},
            {"rule_id": "R2", "message": "two", "_native_refs": ref1},
        ],
        cataloged_paths=(),
        terminal_status="PARTIAL",
        run_root=run_root,
        bounds=EvidenceBounds(max_records=10, max_field_bytes=512, max_total_bytes=first_size + 5),
    )
    assert byte_cap["record_count"] == 1
    assert len(byte_cap["records"][0]["common"]["evidence_refs"]) == 1
    assert "normalized total byte bound reached" in byte_cap["exclusions_and_gaps"]
