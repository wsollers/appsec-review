"""Unit tests for T-170 SAST taint dataflow_trace / SARIF codeFlows and pre-cap corroboration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema

from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS
from appsec_review.jobs.job_evidence_collection.evidence import (
    EvidenceBounds,
    build_envelope,
    corroborate_sast_records,
    extract_cwe_family,
)
from appsec_review.provenance import json_selector, retain_native_output, select_native


def _retained_refs(tmp_path: Path, count: int) -> tuple[Path, list[list[dict[str, object]]]]:
    from .support import attempt_scope, make_unit_context

    unit, _, _ = make_unit_context(tmp_path)
    run_root = unit.job.run_root
    scratch = unit.unit_root / "scratch"
    raw = scratch / "output.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(json.dumps({"results": [{"id": i} for i in range(count)]}), encoding="utf-8")
    exec_json = scratch / "execution.json"
    exec_json.write_text("{}", encoding="utf-8")
    with attempt_scope(unit):
        retained = retain_native_output(
            run_root,
            raw,
            parser_identity="undeclared",
            complete=True,
            native_result_count=count,
            execution_reference={
                "path": exec_json.relative_to(run_root).as_posix(),
                "sha256": hashlib.sha256(b"{}").hexdigest(),
                "size_bytes": 2,
            },
        )
    return run_root, [
        [select_native(retained, json_selector("results", idx)).as_dict()] for idx in range(count)
    ]


def test_semgrep_and_opengrep_preserve_taint_dataflow_trace_and_cwe_mapping(tmp_path: Path) -> None:
    payload = json.dumps({
        "results": [
            {
                "check_id": "appsec-review.python.sql-injection-taint",
                "path": "/target/src/db.py",
                "start": {"line": 42},
                "end": {"line": 43},
                "extra": {
                    "message": "User input flows into raw SQL query",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"], "category": "security"},
                    "dataflow_trace": {
                        "taint_source": [
                            "CliLoc",
                            [
                                {"path": "/target/src/routes.py", "start": {"line": 12}, "end": {"line": 12}},
                                "request.args.get('id')",
                            ],
                        ],
                        "intermediate_vars": [
                            {
                                "location": {
                                    "path": "/target/src/service.py",
                                    "start": {"line": 25},
                                    "end": {"line": 25},
                                },
                                "content": "user_id",
                            }
                        ],
                        "taint_sink": [
                            "CliLoc",
                            [
                                {"path": "/target/src/db.py", "start": {"line": 42}, "end": {"line": 43}},
                                "cursor.execute(query)",
                            ],
                        ],
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["/target/src/db.py"], "skipped": []},
    }).encode("utf-8")

    run_root, refs = _retained_refs(tmp_path, 1)
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        parsed = ADAPTERS[tool_id].parse(payload)
        assert len(parsed) == 1
        rec = {**parsed[0], "_native_refs": refs[0]}
        assert rec["rule_mapping"] == {"cwe": ["CWE-89: SQL Injection"], "category": "security"}
        assert rec["dataflow_trace"]["source_location"]["path"] == "/target/src/routes.py"
        assert len(rec["dataflow_trace"]["intermediate_vars"]) == 1
        assert rec["dataflow_trace"]["sink_location"]["start_line"] == 42

        env = build_envelope(
            tool={"id": tool_id},
            target_fingerprint="f" * 64,
            applicability={"applicable": True},
            coverage_scope={"kind": "source_files"},
            gaps=(),
            raw_artifacts=(),
            parser_identity="undeclared",
            observations=[rec],
            cataloged_paths={"src/routes.py", "src/service.py", "src/db.py"},
            terminal_status="SUCCEEDED",
            run_root=run_root,
        )
        norm = env["records"][0]
        trace = norm["dataflow_trace"]
        assert trace["source_location"] == {
            "path": "src/routes.py",
            "start_line": 12,
            "end_line": 12,
            "label": "request.args.get('id')",
        }
        assert trace["intermediate_vars"] == [
            {"path": "src/service.py", "start_line": 25, "end_line": 25, "symbol": "user_id"}
        ]
        assert trace["sink_location"] == {
            "path": "src/db.py",
            "start_line": 42,
            "end_line": 43,
            "label": "cursor.execute(query)",
        }
        assert [step["kind"] for step in trace["steps"]] == ["source", "step", "sink"]
        assert env["telemetry"]["taint_traces_preserved"] == 1


def test_semgrep_sarif_code_flows_preserved_and_unescaped_paths_sanitized(tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [
                            {"id": "go.exec.cmd-inject", "properties": {"tags": ["security", "CWE-78"]}}
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "go.exec.cmd-inject",
                        "level": "error",
                        "message": {"text": "Command injection via exec.Command"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "file:///target/cmd/runner.go"},
                                    "region": {"startLine": 30, "endLine": 31},
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "/target/cmd/http.go"},
                                                        "region": {"startLine": 10},
                                                    },
                                                    "message": {"text": "r.URL.Query().Get('cmd')"},
                                                }
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "../../etc/passwd"},
                                                        "region": {"startLine": 4},
                                                    },
                                                    "message": {"text": "escaped hop"},
                                                }
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "/target/cmd/runner.go"},
                                                        "region": {"startLine": 30, "endLine": 31},
                                                    },
                                                    "message": {"text": "exec.Command('sh', '-c', arg)"},
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }
    parsed = ADAPTERS["tool-semgrep"].parse(json.dumps(sarif).encode("utf-8"))
    assert len(parsed) == 1
    run_root, refs = _retained_refs(tmp_path, 1)
    env = build_envelope(
        tool={"id": "tool-semgrep"},
        target_fingerprint="f" * 64,
        applicability={"applicable": True},
        coverage_scope={"kind": "source_files"},
        gaps=(),
        raw_artifacts=(),
        parser_identity="undeclared",
        observations=[{**parsed[0], "_native_refs": refs[0]}],
        cataloged_paths={"cmd/http.go", "cmd/runner.go"},
        terminal_status="SUCCEEDED",
        run_root=run_root,
    )
    rec = env["records"][0]
    assert extract_cwe_family(rec) == "CWE-78"
    trace = rec["dataflow_trace"]
    assert trace["source_location"]["path"] == "cmd/http.go"
    # Traversal URI is rejected to None rather than leaking outside catalog
    assert trace["intermediate_vars"][0]["path"] is None
    assert trace["sink_location"]["path"] == "cmd/runner.go"


def test_pre_cap_cross_scanner_corroboration_prevents_eviction_and_validates_schema(tmp_path: Path) -> None:
    run_root, refs = _retained_refs(tmp_path, 6)
    cataloged = {"svc/exec.go", "svc/native.c", "svc/Controller.java"}

    # Envelope cap check: 3 overlapping findings at svc/exec.go:21-23 (CWE-78) + 1 distinct finding at svc/native.c:88.
    # With max_records=2, pre-cap clustering keeps BOTH distinct vulnerability sites instead of evicting svc/native.c!
    pre_cap_env = build_envelope(
        tool={"id": "tool-semgrep"},
        target_fingerprint="f" * 64,
        applicability={"applicable": True},
        coverage_scope={"kind": "source_files"},
        gaps=(),
        raw_artifacts=(),
        parser_identity="undeclared",
        observations=[
            {
                "tool_id": "tool-semgrep",
                "rule_id": "semgrep.go.cmd-injection",
                "severity": "WARNING",
                "category": "source_sast",
                "message": "tainted exec",
                "path": "svc/exec.go",
                "start_line": 21,
                "end_line": 22,
                "rule_mapping": {"cwe": "CWE-78"},
                "dataflow_trace": {
                    "source_location": {"path": "svc/exec.go", "start_line": 10, "end_line": 10, "label": "req.FormValue"},
                    "intermediate_vars": [],
                    "sink_location": {"path": "svc/exec.go", "start_line": 21, "end_line": 22, "label": "exec.Command"},
                },
                "_native_refs": refs[0],
            },
            {
                "tool_id": "tool-opengrep",
                "rule_id": "opengrep.go.os-exec",
                "severity": "ERROR",
                "category": "source_sast",
                "message": "command execution",
                "path": "svc/exec.go",
                "start_line": 22,
                "end_line": 23,
                "rule_mapping": {"cwe": "CWE-88"},
                "_native_refs": refs[1],
            },
            {
                "tool_id": "tool-gosec",
                "rule_id": "G204",
                "severity": "HIGH",
                "category": "source_sast",
                "message": "Subprocess launched with variable",
                "path": "svc/exec.go",
                "start_line": 22,
                "end_line": 22,
                "_native_refs": refs[2],
            },
            {
                "tool_id": "tool-cppcheck",
                "rule_id": "deallocuse",
                "severity": "ERROR",
                "category": "source_sast",
                "message": "Use after free",
                "path": "svc/native.c",
                "start_line": 88,
                "end_line": 88,
                "rule_mapping": {"cwe": "CWE-416"},
                "_native_refs": refs[3],
            },
        ],
        cataloged_paths=cataloged,
        terminal_status="SUCCEEDED",
        run_root=run_root,
        bounds=EvidenceBounds(max_records=2),
    )
    assert pre_cap_env["record_count"] == 2
    first = pre_cap_env["records"][0]
    assert first["corroborating_scanners"] == ["tool-gosec", "tool-opengrep", "tool-semgrep"]
    assert first["corroboration_count"] == 3
    assert len(first["scanner_rule_ids"]) == 3
    assert first["severity"] == "HIGH"
    assert first["dataflow_trace"] is not None
    assert pre_cap_env["records"][1]["location"]["path"] == "svc/native.c"
    assert pre_cap_env["telemetry"] == {
        "raw_scanner_findings": 4,
        "corroborated_clusters": 1,
        "taint_traces_preserved": 1,
        "post_dedupe_capped_count": 2,
    }

    # Cross-envelope corroboration across Semgrep + OpenGrep + Gosec + Bandit + Cppcheck + PMD
    tool_envelopes = {
        "tool-semgrep": {
            "records": [
                {
                    "native_rule_id": "semgrep.java.sqli",
                    "severity": "MEDIUM",
                    "category": "source_sast",
                    "message": "SQL query built from user input",
                    "location": {"path": "svc/Controller.java", "start_line": 51, "end_line": 52},
                    "rule_mapping": {"cwe": "CWE-89"},
                    "dataflow_trace": first["dataflow_trace"],
                }
            ],
            "telemetry": {"raw_scanner_findings": 1},
        },
        "tool-opengrep": {
            "records": [
                {
                    "native_rule_id": "opengrep.java.sqli",
                    "severity": "HIGH",
                    "category": "source_sast",
                    "message": "Tainted SQL sink",
                    "location": {"path": "svc/Controller.java", "start_line": 52, "end_line": 53},
                    "rule_mapping": {"cwe": "CWE-564"},
                }
            ],
            "telemetry": {"raw_scanner_findings": 1},
        },
        "tool-pmd": {
            "records": [
                {
                    "native_rule_id": "SqlInjection",
                    "severity": "HIGH",
                    "category": "source_sast",
                    "message": "Potential SQL injection",
                    "location": {"path": "svc/Controller.java", "start_line": 52, "end_line": 52},
                }
            ],
            "telemetry": {"raw_scanner_findings": 1},
        },
        "tool-bandit": {
            "records": [
                {
                    "native_rule_id": "B608",
                    "severity": "MEDIUM",
                    "category": "source_sast",
                    "message": "Hardcoded SQL expression",
                    "location": {"path": "svc/query.py", "start_line": 14, "end_line": 14},
                }
            ],
            "telemetry": {"raw_scanner_findings": 1},
        },
    }
    corroborated = corroborate_sast_records(
        tool_envelopes, target_fingerprint="f" * 64, max_findings_per_scope=2
    )
    schema_path = (
        Path(__file__).resolve().parents[3]
        / "docs"
        / "schemas"
        / "evidence-collection"
        / "corroborated-sast-evidence.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(corroborated, schema)

    assert corroborated["cluster_count"] == 2
    top_cluster = corroborated["clusters"][0]
    assert top_cluster["corroborating_scanners"] == ["tool-opengrep", "tool-pmd", "tool-semgrep"]
    assert top_cluster["corroboration_count"] == 3
    assert top_cluster["cwe_family"] == "CWE-89"
    assert top_cluster["dataflow_trace"] is not None
    assert corroborated["telemetry"] == {
        "raw_scanner_findings": 4,
        "corroborated_clusters": 1,
        "taint_traces_preserved": 1,
        "post_dedupe_capped_count": 2,
    }
