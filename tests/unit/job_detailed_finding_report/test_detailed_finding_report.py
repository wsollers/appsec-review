"""End-to-end unit tests for job_detailed_finding_report and detailed_finding_report rendering."""
from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.indexing.store import accepted_handoff
from appsec_review.interchange import GapCode, ProducerStatus
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json
from appsec_review.jobs.completion_contracts import DOSSIER_PUBLICATION_SCHEMA, nonexecution_assurance
from appsec_review.jobs.engineering_contracts import (
    DETAILED_FINDING_REPORT_HANDOFF_SCHEMA,
    DETAILED_FINDING_REPORT_SCHEMA,
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
    FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_code_graph_index.datasets import DATASETS as CODE_GRAPH_DATASETS
from appsec_review.jobs.job_detailed_finding_report import JOB_ID, build_job
from appsec_review.jobs.job_detailed_finding_report.datasets import DATASETS
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate.attachments import _dossiers, capability
from appsec_review.jobs.job_final_publication_gate.datasets import DATASETS as GATE_DATASETS
from appsec_review.reporting.detailed_finding_report import (
    assert_no_redaction_markers,
    build_detailed_finding_report,
    flow_diagram_from_exe_viewer_json,
)
from appsec_review.reporting.dossier_render import render_dossier
from appsec_review.reporting.dossiers import build_dossier
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.contracts import JobContract
from appsec_review.storage import atomic_bytes, atomic_json
from tests.dossier_fixture import settings as dossier_settings
from tests.release_support import write_release
from tests.test_job_runtime import write_config
from tests.unit.review_decision_audit_wiring.helpers import package, put, verified_document

ROOT = Path(__file__).resolve().parents[3]
GATE_JOB = "job_final_publication_gate"
CODE_GRAPH_JOB = "job_code_graph_index"
SNAPSHOT = "a" * 64
IMAGE_TAG = "appsec-review/tool-report-latex:1.0.0"
PDF_BYTES = b"%PDF-1.5\n" + b"detailed finding report vector tikz pdf " * 3 + b"\n%%EOF\n"


def _fake_pdf_executor(
    seen: list[tuple[str, ...]],
    *,
    image_id: str,
    render_status: int = 0,
    pdf: bytes | None = PDF_BYTES,
    timed_out: bool = False,
):
    class FixtureExecutor(ContainerExecutor):
        def _docker_bind_source(self, path):
            return path

    def factory(catalog, root):
        def runner(argv, timeout):
            seen.append(tuple(argv))
            if argv[1:3] == ("image", "inspect"):
                return CommandOutcome(0, image_id.encode("utf-8"), b"")
            if "run" in argv:
                mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
                spec = next(item for item in mounts if "dst=/scratch" in item)
                scratch = Path(spec.split("src=", 1)[1].split(",dst=")[0])
                if pdf is not None:
                    (scratch / "report.pdf").write_bytes(pdf)
                (scratch / "report.log").write_bytes(b"xelatex compilation ok\n")
                (scratch / "report.pdfinfo.txt").write_bytes(b"Pages: 4\n")
                return CommandOutcome(render_status, b"stdout", b"stderr", timed_out=timed_out)
            if "inspect" in argv:
                return CommandOutcome(1, b"", b"No such container")
            return CommandOutcome(0, b"", b"")

        return FixtureExecutor(catalog, root, runner=runner)

    return factory


def _make_dossier(
    finding: dict[str, Any],
    run_id: str,
    *,
    path: str = "src/parser.c",
    start_line: int = 42,
    end_line: int = 48,
    cwe: str = "CWE-120",
    statement: str = "Attacker-controlled packet length reaches memcpy without bounds validation.",
    multi_hop: bool = True,
) -> dict[str, Any]:
    excerpts = [
        {
            "identity": "asr:source_file:" + "f" * 64,
            "location": {
                "path": path,
                "source_id": "src-1",
                "file_sha256": "f" * 64,
                "target_snapshot": SNAPSHOT,
                "mapping_method": "exact",
                "ambiguous": False,
            },
            "excerpt_start_line": start_line,
            "excerpt_end_line": end_line,
            "excerpt": "memcpy(dst, packet_payload, user_len);",
        }
    ]
    if multi_hop:
        excerpts.insert(
            0,
            {
                "identity": "asr:source_file:" + "e" * 64,
                "location": {
                    "path": path,
                    "source_id": "src-0",
                    "file_sha256": "e" * 64,
                    "target_snapshot": SNAPSHOT,
                    "mapping_method": "exact",
                    "ambiguous": False,
                },
                "excerpt_start_line": 12,
                "excerpt_end_line": 18,
                "excerpt": "uint32_t user_len = read_be32(sock_buf);",
            },
        )
    is_confirmed = finding["state"] == "confirmed"
    kind = "confirmed_finding" if is_confirmed else "poc"
    poc_payload = None
    if not is_confirmed:
        poc_payload = {
            "status": "compile_verified",
            "reason": "Compile-checked statically.",
            "description": "Static harness exercising config include path.",
            **nonexecution_assurance(),
        }
    return build_dossier(
        run_id=run_id,
        kind=kind,
        finding=finding,
        claim={
            "claim_id": finding["claim_id"],
            "state": finding["state"],
            "statement": statement,
            "weakness_cwe": cwe,
            "security_predicate": "memory_corruption",
            "preconditions": ["network packet arrives on untrusted socket"],
        },
        relations=[
            {
                "relation_id": key,
                "claim_id": finding["claim_id"],
                "kind": "supports",
                "admissibility": "direct",
                "complete": True,
            }
            for key in finding["direct_evidence"] + finding["analyst_assessed_evidence"]
        ],
        excerpts=excerpts,
        poc=poc_payload,
        provenance={},
    )


def _runner_environment(
    tmp_path: Path,
    *,
    include_backlog: bool = False,
    render_pdf: bool = True,
    enabled: bool = True,
    max_fanout_nodes: int = 12,
    max_cfg_nodes: int = 14,
) -> tuple[Any, JobRunner]:
    job_ids = (GATE_JOB, CODE_GRAPH_JOB, JOB_ID)
    write_release(tmp_path, ("job_fixture", *job_ids))
    cfg_path = write_config(tmp_path)
    with cfg_path.open("a", encoding="utf-8") as stream:
        stream.write('\n[review_policy.releases]\nplatform = "fixture/1"\nvalidation = "fixture/1"\n')
        for jid in (GATE_JOB, CODE_GRAPH_JOB):
            stream.write(
                f'\n[jobs.{jid}]\nname = "{jid.removeprefix("job_")}"\nworkers = 1\n'
                f'\n[jobs.{jid}.steps.acceptance]\nworkers = 1\n'
                f'\n[jobs.{jid}.steps.acceptance.tasks.publish_handoff]\n'
            )
        stream.write(
            f'\n[jobs.{JOB_ID}]\nname = "detailed_finding_report"\nworkers = 1\n'
            f'\n[jobs.{JOB_ID}.settings]\n'
            f'enabled = {"true" if enabled else "false"}\n'
            f'include_backlog = {"true" if include_backlog else "false"}\n'
            f'max_fanout_nodes = {max_fanout_nodes}\n'
            f'max_cfg_nodes = {max_cfg_nodes}\n'
            f'render_pdf = {"true" if render_pdf else "false"}\n'
            f'image_tag = "{IMAGE_TAG}"\n'
            f'render_timeout_seconds = 600\n'
            f'max_pdf_bytes = 33554432\n'
            f'\n[jobs.{JOB_ID}.steps.load]\nworkers = 1\n'
            f'[jobs.{JOB_ID}.steps.load.tasks.accepted_inputs]\n'
            f'\n[jobs.{JOB_ID}.steps.report]\nworkers = 1\n'
            f'[jobs.{JOB_ID}.steps.report.tasks.assemble]\n'
            f'[jobs.{JOB_ID}.steps.report.tasks.render]\n'
            f'[jobs.{JOB_ID}.steps.report.tasks.render_pdf]\n'
            f'\n[jobs.{JOB_ID}.steps.acceptance]\nworkers = 1\n'
            f'[jobs.{JOB_ID}.steps.acceptance.tasks.publish_handoff]\n'
        )
    config = load_config(cfg_path)
    return config, JobRunner(config)


def _publish_gate_and_cpg(
    runner: JobRunner,
    config: Any,
    *,
    with_cpg: bool = True,
    cpg_with_gaps: bool = False,
    attach_dossiers: bool = True,
    attach_backlog_dossier: bool = True,
    extra_confirmed_without_dossier: bool = False,
) -> dict[str, Any]:
    run_id, run_root = runner.runs.create(datetime(2026, 11, 27, tzinfo=UTC))

    def gate_unit(unit):
        root = unit.job.run_root
        verified = verified_document()
        verified["run_id"] = root.name
        pkg2 = None
        if extra_confirmed_without_dossier:
            pkg2 = package(2, "confirmed")
            pkg2["title"] = "Sparse confirmed defect without bound dossier"
            verified["packages"].append(pkg2)
            verified["partition"]["confirmed"].append(pkg2["finding_package_id"])
            verified["accounting"]["claims_total"] = 3
            verified["accounting"]["claims_by_state"]["confirmed"] = 2

        for name in verified["inputs"]:
            verified["inputs"][name] = put(root, f"data/{name}.json", {"input": name})
        verified["bindings"] = list(verified["inputs"].values())

        items = []
        if attach_dossiers:
            d0 = _make_dossier(
                verified["packages"][0],
                root.name,
                path="src/parser.c",
                start_line=42,
                end_line=48,
                cwe="CWE-120",
                multi_hop=True,
            )
            base0 = "data/jobs/job_dossier_publication/attempts/attempt_0001/steps/dossiers/tasks/create/d0"
            item0 = render_dossier(
                root,
                root / base0,
                d0,
                settings=dossier_settings(render_pdf=False),
                repository_root=ROOT,
                executor_factory=lambda *_: pytest.fail("dossier PDF disabled"),
            )
            items.append(item0)

            if attach_backlog_dossier:
                d1 = _make_dossier(
                    verified["packages"][1],
                    root.name,
                    path="src/config_loader.py",
                    start_line=15,
                    end_line=19,
                    cwe="CWE-22",
                    statement="Supported path traversal lead in config include directive.",
                    multi_hop=False,
                )
                base1 = "data/jobs/job_dossier_publication/attempts/attempt_0001/steps/dossiers/tasks/create/d1"
                item1 = render_dossier(
                    root,
                    root / base1,
                    d1,
                    settings=dossier_settings(render_pdf=False),
                    repository_root=ROOT,
                    executor_factory=lambda *_: pytest.fail("dossier PDF disabled"),
                )
                items.append(item1)

            omitted = []
            if pkg2 is not None:
                omitted.append({
                    "kind": "confirmed_finding",
                    "finding": {
                        "claim_id": pkg2["claim_id"],
                        "finding_package_id": pkg2["finding_package_id"],
                        "sha256": pkg2["sha256"],
                    },
                    "reason": "max_dossiers",
                })
            poc_records = (
                [{"claim_id": verified["packages"][1]["claim_id"]}]
                if attach_backlog_dossier
                else []
            )
            all_dossier_rows = [*items, *omitted]
            by_kind = {
                "confirmed_finding": sum(1 for it in all_dossier_rows if it.get("kind") == "confirmed_finding"),
                "poc": sum(1 for it in all_dossier_rows if it.get("kind") == "poc"),
            }
            pub_doc = {
                "schema": DOSSIER_PUBLICATION_SCHEMA,
                "run_id": root.name,
                "items": items,
                "omitted": omitted,
                "counts": {
                    "admitted": len(all_dossier_rows),
                    "items": len(items),
                    "omitted": len(omitted),
                    "by_kind": by_kind,
                    "by_status": {"rendered": 0, "render_failed": 0, "latex_only": len(items)},
                },
                "caps": {"max_dossiers": len(items)},
            }
            verified["attachments"]["dossiers"] = _dossiers(
                root,
                pub_doc,
                {row["finding_package_id"]: row for row in verified["packages"]},
                poc_records,
                verified["bindings"],
            )
            handoff_ref = put(
                root,
                "data/jobs/job_dossier_publication/attempts/attempt_0001/handoff.json",
                {"job": "dossiers"},
            )
            summary_ref = put(
                root,
                "data/jobs/job_dossier_publication/attempts/attempt_0001/summary.json",
                pub_doc,
            )
            verified["capabilities"]["dossiers"] = capability(
                True,
                handoff=handoff_ref,
                summary=summary_ref,
                count=len(items),
            )
            verified["bindings"] += [handoff_ref, summary_ref]

        cfg_ref = artifact_ref(root, root / "data/configuration/resolved.json")
        verified["bindings"].append(cfg_ref)
        verified["bindings"] = [
            {"path": path, "sha256": digest}
            for path, digest in sorted({(row["path"], row["sha256"]) for row in verified["bindings"]})
        ]

        classification = gate_classify.classify(verified)
        gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, classification)
        gate_path = unit.unit_root / "final-publication-gate.json"
        atomic_json(gate_path, gate)
        return {
            "schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
            "artifact": artifact_ref(root, gate_path),
            "item_count": gate["package_counts"]["total"],
            "gaps": [],
            "terminal_status": ProducerStatus.SUCCEEDED.value,
        }

    gate_job = Job(
        GATE_JOB,
        "final_publication_gate",
        lambda _ctx: {},
        units=(Unit("acceptance.publish_handoff", gate_unit),),
        datasets=GATE_DATASETS,
        contract=JobContract(),
        strict_gaps=True,
    )
    gate_outcome = runner.run(gate_job, run_id=run_id, source_fingerprint=SNAPSHOT)
    assert gate_outcome["status"]["status"] in ("SUCCEEDED", "COMPLETED")

    cpg_sha = None
    if with_cpg:
        def cpg_unit(unit):
            root = unit.job.run_root
            nodes = [
                {"id": "fn:dispatch", "node_kind": "function", "name": "dispatch_packet",
                 "qualified_name": "net::dispatch_packet", "path": "src/net.c", "start_line": 10, "end_line": 30},
                {"id": "fn:parse_frame", "node_kind": "function", "name": "parse_frame",
                 "qualified_name": "parser::parse_frame", "path": "src/parser.c", "start_line": 10, "end_line": 60,
                 "cyclomatic_complexity": 4},
                {"id": "fn:memcpy", "node_kind": "function", "name": "memcpy",
                 "qualified_name": "libc::memcpy", "path": "include/string.h", "start_line": 1, "end_line": 2},
                {"id": "fn:validate_header", "node_kind": "function", "name": "validate_header",
                 "qualified_name": "parser::validate_header", "path": "src/parser.c", "start_line": 2, "end_line": 8},
                {"id": "cfg:entry", "node_kind": "cfg_block", "function_id": "fn:parse_frame", "path": "src/parser.c",
                 "block_index": 0, "kind": "entry", "start_line": 10, "end_line": 19,
                 "calls": ["read_be32"], "guard_dominators": []},
                {"id": "cfg:guard", "node_kind": "cfg_block", "function_id": "fn:parse_frame", "path": "src/parser.c",
                 "block_index": 1, "kind": "if_statement", "start_line": 20, "end_line": 28,
                 "guard_expression": "hdr_magic == FRAME_OK", "calls": ["validate_header"], "guard_dominators": []},
                {"id": "cfg:sink", "node_kind": "cfg_block", "function_id": "fn:parse_frame", "path": "src/parser.c",
                 "block_index": 2, "kind": "statement_block", "start_line": 40, "end_line": 50,
                 "calls": ["memcpy"],
                 "guard_dominators": [{"guard_id": "cfg:guard", "expression": "hdr_magic == FRAME_OK", "branch": "true"}]},
                {"id": "cfg:ret", "node_kind": "cfg_block", "function_id": "fn:parse_frame", "path": "src/parser.c",
                 "block_index": 3, "kind": "return_statement", "start_line": 51, "end_line": 58,
                 "calls": [], "guard_dominators": []},
            ]
            edges = [
                {"source": "fn:dispatch", "target": "fn:parse_frame", "edge_kind": "CALLS"},
                {"source": "fn:parse_frame", "target": "fn:validate_header", "edge_kind": "CALLS"},
                {"source": "fn:parse_frame", "target": "fn:memcpy", "edge_kind": "FN_TO_SINK", "sink_class": "memory_copy"},
                {"source": "cfg:entry", "target": "cfg:guard", "edge_kind": "CFG"},
                {"source": "cfg:guard", "target": "cfg:sink", "edge_kind": "GUARDS", "branch": "true"},
                {"source": "cfg:guard", "target": "cfg:ret", "edge_kind": "GUARDS", "branch": "false"},
                {"source": "cfg:sink", "target": "cfg:ret", "edge_kind": "CFG"},
            ]
            acpg_dir = unit.unit_root / "alternate-cpg"
            acpg_dir.mkdir(parents=True, exist_ok=True)
            nodes_path = acpg_dir / "cpg-nodes.jsonl"
            edges_path = acpg_dir / "cpg-edges.jsonl"
            atomic_bytes(nodes_path, b"".join(json.dumps(row).encode("utf-8") + b"\n" for row in nodes))
            atomic_bytes(edges_path, b"".join(json.dumps(row).encode("utf-8") + b"\n" for row in edges))
            summary = {
                "schema": "appsec-review/alternate-cpg/1",
                "run_id": root.name,
                "status": "COMPLETED_WITH_GAPS" if cpg_with_gaps else "COMPLETED",
                "artifacts": {
                    "nodes": nodes_path.relative_to(root).as_posix(),
                    "edges": edges_path.relative_to(root).as_posix(),
                },
                "gaps": [{"reason": "one file timed out"}] if cpg_with_gaps else [],
            }
            summary_path = unit.unit_root / "alternate-cpg-summary.json"
            atomic_json(summary_path, summary)
            from appsec_review.interchange import producer_gap as _pgap
            cpg_gaps = (
                [_pgap(GapCode.PRODUCER_REPORTED_GAP, "one file timed out", scope_id="scope-0")]
                if cpg_with_gaps
                else []
            )
            return {
                "alternate_cpg": artifact_ref(root, summary_path),
                "nodes": artifact_ref(root, nodes_path),
                "edges": artifact_ref(root, edges_path),
                "gaps": cpg_gaps,
                "terminal_status": (
                    ProducerStatus.COMPLETED_WITH_GAPS.value if cpg_with_gaps else ProducerStatus.SUCCEEDED.value
                ),
            }

        cpg_job = Job(
            CODE_GRAPH_JOB,
            "code_graph_index",
            lambda _ctx: {},
            units=(Unit("acceptance.publish_handoff", cpg_unit),),
            datasets=tuple(d for d in CODE_GRAPH_DATASETS if d.output_kind == "alternate_cpg"),
            contract=JobContract(),
            strict_gaps=False,
        )
        cpg_outcome = runner.run(cpg_job, run_id=run_id, source_fingerprint=SNAPSHOT)
        cpg_sha = cpg_outcome["handoff_sha256"]

    upstreams = {GATE_JOB: gate_outcome["handoff_sha256"]}
    if cpg_sha is not None:
        upstreams[CODE_GRAPH_JOB] = cpg_sha
    return {
        "run_root": run_root,
        "run_id": run_id,
        "upstreams": upstreams,
        "gate_sha": gate_outcome["handoff_sha256"],
        "cpg_sha": cpg_sha,
    }



def _publish_result(run_root: Path, accepted_ho: Mapping[str, Any]) -> dict[str, Any]:
    ctrl = accepted_ho["outputs"]["acceptance.publish_handoff"]
    assert set(ctrl.keys()) == {"schema", "terminal_status", "item_count", "artifact", "gaps"}
    attempt_id = accepted_ho["attempt_id"]
    res_path = (
        run_root
        / "data"
        / "jobs"
        / JOB_ID
        / "attempts"
        / attempt_id
        / "steps"
        / "acceptance"
        / "tasks"
        / "publish_handoff"
        / "result.json"
    )
    return json.loads(res_path.read_text(encoding="utf-8"))


def test_end_to_end_detailed_finding_report_publishes_3a_3b_3c_svg_md_html_tex_pdf_and_claims_files(
    tmp_path: Path,
) -> None:
    config, runner = _runner_environment(tmp_path, include_backlog=True, render_pdf=True)
    ctx = _publish_gate_and_cpg(runner, config, with_cpg=True)
    run_root = ctx["run_root"]
    image_id = config.jobs[JOB_ID].settings["image_id"]

    seen_cmds: list[tuple[str, ...]] = []
    job = build_job(
        executor_factory=_fake_pdf_executor(seen_cmds, image_id=image_id),
        repository_root=ROOT,
    )
    outcome = runner.run(
        job,
        run_id=ctx["run_id"],
        upstream_handoffs=ctx["upstreams"],
    )
    assert outcome["status"]["status"] in ("SUCCEEDED", "COMPLETED")
    accepted = accepted_handoff(run_root, JOB_ID)
    assert accepted is not None
    payload = _publish_result(run_root, accepted.handoff)
    assert payload["schema"] == DETAILED_FINDING_REPORT_HANDOFF_SCHEMA
    assert payload["report_schema"] == DETAILED_FINDING_REPORT_SCHEMA
    assert payload["terminal_status"] == ProducerStatus.SUCCEEDED.value
    assert payload["gaps"] == []
    assert payload["item_count"] == 2
    assert payload["summary"]["publishable_defect_count"] == 1
    assert payload["summary"]["backlog_defect_count"] == 1
    assert payload["summary"]["total_defect_count"] == 2
    assert payload["summary"]["diagram_count"] == 6
    assert payload["summary"]["cpg_fanout_resolved_count"] == 1
    assert payload["summary"]["cpg_cfg_resolved_count"] == 1
    assert len(payload["diagram_files"]) == 6
    assert payload["pdf"]["state"] == "rendered"
    assert payload["pdf"]["file"] is not None

    report_doc = read_bound_json(run_root, payload["artifact"])
    assert report_doc["schema"] == DETAILED_FINDING_REPORT_SCHEMA
    assert report_doc["status"]["code_graph_status"] == "COMPLETED"
    assert len(report_doc["defects"]) == 1
    assert len(report_doc["backlog_defects"]) == 1

    d0 = report_doc["defects"][0]
    d1 = report_doc["backlog_defects"][0]
    assert d0["section"] == "publishable"
    assert d0["primary_location"]["path"] == "src/parser.c"
    assert d0["enclosing_symbol"] == "parser::parse_frame"
    assert d0["diagram_provenance"]["3a"] == "dossier_flow_diagram"
    assert d0["diagram_provenance"]["3b"] == "alternate_cpg_call_fanout"
    assert d0["diagram_provenance"]["3c"] == "alternate_cpg_cfg"

    assert d1["section"] == "backlog"
    assert d1["primary_location"]["path"] == "src/config_loader.py"
    assert d1["diagram_provenance"]["3a"] in ("dossier_flow_diagram", "dossier_invariant_fallback")
    assert d1["diagram_provenance"]["3b"] == "dossier_structural_fallback"
    assert d1["diagram_provenance"]["3c"] == "dossier_cfg_fallback"

    for diag_entry in payload["diagram_files"]:
        svg = read_bound(run_root, diag_entry["svg"]).decode("utf-8")
        mmd = read_bound(run_root, diag_entry["mermaid"]).decode("utf-8")
        dot = read_bound(run_root, diag_entry["dot"]).decode("utf-8")
        assert "<svg" in svg
        assert "flowchart" in mmd
        assert "digraph" in dot

    md_text = read_bound(run_root, payload["markdown"]).decode("utf-8")
    for kind in ("3a", "3b", "3c"):
        rel_svg = d0["diagrams"][kind]["relative_paths"]["svg"]
        assert f"]({rel_svg})" in md_text

    html_text = read_bound(run_root, payload["html"]).decode("utf-8")
    assert html_text.count("<svg") >= 6

    tex_text = read_bound(run_root, payload["pdf"]["latex"]).decode("utf-8")
    assert "\\begin{tikzpicture}" in tex_text

    pdf_raw = read_bound(run_root, payload["pdf"]["file"])
    assert pdf_raw.startswith(b"%PDF-")

    claims = runtime_claims({JOB_ID: ("load", "report", "acceptance")}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    tree = scan_run_tree(run_root, FileClaims(claims), max_files=10_000)
    unaccounted = [p for p in tree.unaccounted if p.startswith(f"data/jobs/{JOB_ID}")]
    assert unaccounted == []

    # Reuse check: identical inputs & settings reuse attempt_0001 without re-running xelatex.
    before_reuse_cmds = len(seen_cmds)
    assert sum(1 for c in seen_cmds if "run" in c) == 1
    reused_outcome = runner.run_or_reuse(job, run_id=ctx["run_id"], upstream_handoffs=ctx["upstreams"])
    assert reused_outcome.get("reused") is True
    assert len(seen_cmds) == before_reuse_cmds


def test_optional_cpg_absent_partial_unadmitted_dossier_and_pdf_failure_record_typed_gaps(
    tmp_path: Path,
) -> None:
    config, runner = _runner_environment(tmp_path, include_backlog=False, render_pdf=True)
    ctx = _publish_gate_and_cpg(
        runner,
        config,
        with_cpg=False,
        extra_confirmed_without_dossier=True,
    )
    run_root = ctx["run_root"]
    image_id = config.jobs[JOB_ID].settings["image_id"]

    seen_cmds: list[tuple[str, ...]] = []
    job = build_job(
        executor_factory=_fake_pdf_executor(seen_cmds, image_id=image_id, render_status=2, pdf=None),
        repository_root=ROOT,
    )
    outcome = runner.run(
        job,
        run_id=ctx["run_id"],
        upstream_handoffs={GATE_JOB: ctx["gate_sha"]},
    )
    assert outcome["status"]["status"] == "COMPLETED_WITH_GAPS"
    accepted = accepted_handoff(run_root, JOB_ID)
    assert accepted is not None
    payload = _publish_result(run_root, accepted.handoff)
    assert payload["terminal_status"] == ProducerStatus.COMPLETED_WITH_GAPS.value
    gap_codes = {g["code"] for g in payload["gaps"]}
    gap_scopes = {g["scope_id"] for g in payload["gaps"]}
    assert GapCode.INPUT_UNAVAILABLE.value in gap_codes
    assert GapCode.PRODUCER_FAILED.value in gap_codes
    assert {CODE_GRAPH_JOB, "dossier_binding", "detailed_pdf"} <= gap_scopes
    assert payload["pdf"]["state"] == "render_failed"
    assert payload["pdf"]["file"] is None

    report_doc = read_bound_json(run_root, payload["artifact"])
    assert len(report_doc["defects"]) == 2
    assert report_doc["backlog_defects"] == []
    sparse_defect = next(
        d for d in report_doc["defects"] if d["dossier"]["dossier_id"].startswith("dossier-00000000")
    )
    assert sparse_defect["diagram_provenance"]["3a"] == "dossier_invariant_fallback"
    assert sparse_defect["diagram_provenance"]["3b"] == "dossier_structural_fallback"
    assert sparse_defect["diagram_provenance"]["3c"] == "dossier_cfg_fallback"

    cfg2, runner2 = _runner_environment(tmp_path / "cpg_gaps", include_backlog=False, render_pdf=True)
    ctx2 = _publish_gate_and_cpg(runner2, cfg2, with_cpg=True, cpg_with_gaps=True)
    job_ok_pdf = build_job(
        executor_factory=_fake_pdf_executor([], image_id=image_id),
        repository_root=ROOT,
    )
    outcome2 = runner2.run(
        job_ok_pdf,
        run_id=ctx2["run_id"],
        upstream_handoffs=ctx2["upstreams"],
    )
    assert outcome2["status"]["status"] == "COMPLETED_WITH_GAPS"
    acc2 = accepted_handoff(ctx2["run_root"], JOB_ID)
    assert acc2 is not None
    payload2 = _publish_result(ctx2["run_root"], acc2.handoff)
    assert any(
        g["code"] == GapCode.PRODUCER_REPORTED_GAP.value and g["scope_id"] == CODE_GRAPH_JOB
        for g in payload2["gaps"]
    )


def test_disabled_dispatch_tamper_rejection_redaction_guard_reuse_and_exe_viewer_graphs(
    tmp_path: Path,
) -> None:
    dis_cfg, dis_runner = _runner_environment(tmp_path / "dis", enabled=False)
    dis_ctx = _publish_gate_and_cpg(dis_runner, dis_cfg, with_cpg=False)
    dis_job = build_job(repository_root=ROOT)
    with pytest.raises(ValueError, match="target-independent contract"):
        dis_runner.run(
            dis_job,
            run_id=dis_ctx["run_id"],
            source_fingerprint=SNAPSHOT,
            upstream_handoffs={GATE_JOB: dis_ctx["gate_sha"]},
        )

    with pytest.raises(ValueError, match="disabled"):
        dis_runner.run(
            dis_job,
            run_id=dis_ctx["run_id"],
            upstream_handoffs={GATE_JOB: dis_ctx["gate_sha"]},
        )

    t_cfg, t_runner = _runner_environment(tmp_path / "tamper", render_pdf=False)
    t_ctx = _publish_gate_and_cpg(t_runner, t_cfg, with_cpg=False)
    gate_acc = accepted_handoff(t_ctx["run_root"], GATE_JOB)
    assert gate_acc is not None
    gate_rel = gate_acc.handoff["outputs"]["acceptance.publish_handoff"]["artifact"]["path"]
    gate_file = t_ctx["run_root"] / gate_rel
    gate_file.write_text(gate_file.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    t_job = build_job(repository_root=ROOT)
    with pytest.raises(Exception):
        t_runner.run(
            t_job,
            run_id=t_ctx["run_id"],
            upstream_handoffs={GATE_JOB: t_ctx["gate_sha"]},
        )
    assert accepted_handoff(t_ctx["run_root"], JOB_ID) is None

    with pytest.raises(IntegrityError, match="marker"):
        assert_no_redaction_markers("leak <redacted:api_token> in diagram", artifact_name="3a.svg")

    fanout_payload = {
        "nodes": [
            {"id": "0x1000", "label": "recv_loop", "role": "caller", "address": "0x1000"},
            {"id": "0x2000", "label": "decode_pkt", "focal": True, "address": "0x2000"},
            {"id": "0x3000", "label": "strcpy@plt", "is_sink": True, "address": "0x3000"},
        ],
        "edges": [
            {"source": "0x1000", "target": "0x2000", "label": "bl"},
            {"source": "0x2000", "target": "0x3000", "label": "bl", "kind": "sink"},
        ],
    }
    cfg_payload = {
        "nodes": [
            {"id": "bb0", "label": "entry", "kind": "entry", "address": "0x2000"},
            {"id": "bb1", "label": "cmp w0, #0x40", "kind": "branch", "guard": "w0 <= 0x40"},
            {"id": "bb2", "label": "bl strcpy", "is_sink": True, "address": "0x2024"},
        ],
        "edges": [
            {"source": "bb0", "target": "bb1"},
            {"source": "bb1", "target": "bb2", "branch": "false"},
        ],
    }
    diag_fanout = flow_diagram_from_exe_viewer_json(fanout_payload, kind="fanout")
    diag_cfg = flow_diagram_from_exe_viewer_json(cfg_payload, kind="cfg")
    assert any(n.role == "sink" for n in diag_fanout.nodes)
    assert any(n.role == "guard" for n in diag_cfg.nodes)

    pkg = package(0, "confirmed")
    pid = pkg["finding_package_id"]
    dossier = _make_dossier(pkg, "2026-11-27-0099")
    fake_ref = {"path": "data/fake.json", "sha256": "b" * 64}
    report_doc, _diags = build_detailed_finding_report(
        {
            "run_id": "2026-11-27-0099",
            "status": "PASS",
            "review": {"status": "COMPLETE"},
            "packages": [{**pkg, "bucket": "publishable"}],
            "buckets": {"publishable": [pid], "verification_backlog": []},
            "attachments": {},
            "limitations": [],
        },
        {pid: (dossier, fake_ref)},
        gate_handoff=fake_ref,
        gate_document=fake_ref,
        configuration_profile={"name": "dev", "sha256": None},
        exe_viewer_graphs={pid: {"fanout": fanout_payload, "cfg": cfg_payload}},
    )
    assert len(report_doc["defects"]) == 1
    assert report_doc["defects"][0]["diagram_provenance"]["3b"] == "exe_viewer_fanout"
    assert report_doc["defects"][0]["diagram_provenance"]["3c"] == "exe_viewer_cfg"
