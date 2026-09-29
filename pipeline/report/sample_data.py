#!/usr/bin/env python3
"""Regenerate the derived blocks of the SAMPLE report data file (brief P).

    python3 pipeline/report/sample_data.py            # rewrite examples/hello-autotools.review.json
    python3 pipeline/report/sample_data.py --check    # exit 1 when the file is stale

``examples/hello-autotools.review.json`` stays SAMPLE DATA: the cover, findings and evidence register
are illustrative and hand-kept. Every block below is produced by the real code paths instead, so it
cannot drift from the pipeline (deterministic, offline, no model call):

* ``families`` / ``processes`` / ``scoring.family_weight`` -- one process per job in
  ``appsec-review-process/job-graph.json``, grouped by the graph's own ``lane`` field; kind and tools
  from the design-parity manifest. Statuses follow the fixed SAMPLE rule in ``SKIPPED`` and
  ``GAPS`` (everything else OK); skip receipts are the reason-code constants the workers emit.
* ``threat_workbench`` (section 3C) -- the canned cell replies in
  ``examples/hello-autotools.workbench-replies.json`` go through ``threat_model_core.build_model``,
  ``threat_workbench.join``, the core and overlay validators, ``synthesis_report.build_report`` (closed
  ``synthesis-report`` schema) and ``synthesis_report_presentation._threat_workbench``.
* ``attack_chains`` (3A) -- lane 14's composition and refutation workers over the canned composer and
  refuter replies of ``tests/test_attack_chain_report.py``, projected by ``attack_chain_report.build``.
* ``dependency_reachability`` (3B) -- ``dependency_reachability_report.build`` over a canned,
  schema-valid 06 summary with no SCA match (vendored cJSON has no purl or CPE).
* per finding: the lane-12 trail row from the pinned ``cvss4.py`` and the EPSS/KEV line from
  ``synthesis_report_presentation._exploit_text`` (no snapshot imported: "not assessed").
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROCESS = ROOT / "appsec-review-process"
EXAMPLE = HERE / "examples" / "hello-autotools.review.json"
REPLIES = HERE / "examples" / "hello-autotools.workbench-replies.json"
GRAPH = PROCESS / "job-graph.json"
MANIFEST = PROCESS / "design-parity-manifest.json"
COMPONENT = PROCESS / "tests" / "fixtures" / "component-characterization" / "hello-autotools.json"

for path in (PROCESS, PROCESS / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import analysis_feature_lifecycle  # noqa: E402
import codeql_sast  # noqa: E402
import cvss4  # noqa: E402
import epss_kev_snapshot  # noqa: E402
import poc_fix_worker  # noqa: E402
import test_evidence  # noqa: E402  (E09/E10 worker module, not a unit test)
import tool_instance_shapes  # noqa: E402

RUN_ID = "sample-hello-autotools"
SAMPLE_BYTES = b"SAMPLE hello-autotools target file: "   # target bytes are not in this repository

# ---- SAMPLE status rule (fixed, documented) --------------------------------------------------------
# hello-autotools is a C++ Autotools CLI with a Dockerfile, a vendored cJSON and no tests, no fuzz
# harness, no mobile markers and no OCI archive. Jobs whose applicability probe would find nothing
# publish SKIPPED with the worker's own reason code; the jobs in GAPS publish OK_WITH_GAPS with the
# stated (illustrative) coverage; every other job is OK.
SKIPPED = {
    **{f"02-codeql-{language}": codeql_sast.SKIP_REASON
       for language in ("csharp", "go", "java", "javascript", "python", "ruby", "rust")},
    "02-container-image-inventory": tool_instance_shapes.SKIP_REASON,
    "02-mobile-sast": tool_instance_shapes.SKIP_REASON,
    "02-test-execution": test_evidence.NO_TEST_PLAN,
    "13-fuzz-target-triage": analysis_feature_lifecycle.SKIPS["13-fuzz-target-triage"],
    "12b-poc-and-fix": poc_fix_worker.SKIP_REASON,   # no finding is Critical and REACHABLE (ADR-0020)
}
EPSS_KEV_GAP = "EPSS/KEV not assessed: no pinned offline snapshot has been imported"   # finding_enrichment.py
GAPS = {
    "02-sre-operations-topology": (0.7, "No runbooks or monitoring configuration in the target; topology "
                                   "inferred from the Dockerfile only."),
    "02-sbom-inventory": (0.5, "Syft found no package manifest; vendored cJSON 1.7.18 was added from the "
                          "accepted build-index vendored members without a purl or CPE (inferred component "
                          "kept as an explicit gap)."),
    "02-sca-vulnerability-match": (0.5, "Grype ran and matched nothing; OSV was SKIPPED_NA per tool because no "
                                   "component carries a purl. Vendored cJSON was not matched against any advisory."),
    "02-dependency-lifecycle": (0.5, "cJSON 1.7.18 is not in the pinned lifecycle reference table; its "
                                "lifecycle is reported unknown."),
    "02-test-result-ingest": (0.0, "No test plan and no test results: nothing to ingest (explicit gap)."),
    "02-test-coverage-ingest": (0.0, "No instrumented test run: coverage is missing (explicit gap)."),
    "10-synthesis-report": (0.9, EPSS_KEV_GAP + "; every exploit signal reads 'not assessed'."),
}
# Findings that are dependency matches (EPSS/KEV applies); the rest are code findings.
DEPENDENCY_FINDINGS = {"AR-005": []}   # vendored cJSON: no advisory identifier was matched


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_sha(value: Any) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


# ---- P1: families and processes from the job graph ------------------------------------------------
def lane_name(lane: str) -> str:
    number, _, rest = lane.partition("-")
    return f"Lane {number}: {rest.replace('-', ' ')}"


def processes(evidence: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))["jobs"]
    manifest = {row["id"]: row for row in json.loads(MANIFEST.read_text(encoding="utf-8"))["jobs"]}
    unknown = sorted((set(SKIPPED) | set(GAPS)) - set(graph))
    if unknown:
        raise SystemExit(f"sample status rule names jobs that are not in job-graph.json: {unknown}")
    lanes = sorted({job["lane"] for job in graph.values()})
    rows = []
    for lane in lanes:
        for job_id, job in graph.items():
            if job["lane"] != lane:
                continue
            spec = manifest[job_id]
            worker = (spec["execution"].get("worker") or "").removeprefix("appsec-review-process/")
            row = {"id": job_id, "family": lane, "kind": spec["execution"]["mode"],
                   "status": "OK", "tools": f"{spec['registry']['tooling_profile']} ({worker})"}
            if job_id in SKIPPED:
                row.update(status="SKIPPED_NA", receipt=SKIPPED[job_id])
            elif job_id in GAPS:
                row.update(status="OK_WITH_GAPS", coverage=GAPS[job_id][0], gap=GAPS[job_id][1])
            cited = [item["id"] for item in evidence if item["producer"] == job_id]
            if cited:
                row["evidence"] = cited
            rows.append(row)
    counts = {lane: sum(job["lane"] == lane for job in graph.values()) for lane in lanes}
    families = [{"id": lane, "name": lane_name(lane),
                 "note": f"{counts[lane]} job(s) whose job-graph.json lane is {lane}."} for lane in lanes]
    # every applicable process weighs the same: a family's weight is its job count
    return families, rows, counts


# ---- P2: section 3C from the real workbench join ---------------------------------------------------
TARGET_FILES = ("Dockerfile", "Makefile.am", "configure.ac", "src/greet.cpp", "src/jsonreport.cpp", "src/main.cpp",
                "vendor/cJSON-1.7.18/cJSON.c")


def _menu() -> dict[str, Any]:
    import threat_workbench as tw
    items = []
    for job, category, path in (("02-sbom-inventory", "dependency", "outputs/sbom.cdx.json"),
                                ("02-native-sast", "tool-leads", "native-sast.json")):
        body = f"SAMPLE {job} {path}".encode()
        items.append({"item_id": job, "category": category, "description": tw.MENU_DESCRIPTIONS[job][1],
                      "status": "AVAILABLE", "reason": None, "attempt_id": f"{job}-sample",
                      "files": [{"ref": f"{tw.ASSEMBLY_ROOT}:{path}", "path": path, "sha256": "sha256:" + _sha(body),
                                 "bytes": len(body), "pinned": True, "producer": job, "attempt_id": f"{job}-sample",
                                 "run_path": f"data/jobs/02-evidence-assembly/attempts/evidence-sample/{path}"}]})
    return {"schema": "appsec-review/supporting-evidence-menu/1.0", "run_id": RUN_ID, "stage": tw.JOB,
            "root_id": tw.ASSEMBLY_ROOT, "root": "sample", "source": "f02-intel-manifest", "note": "SAMPLE",
            "items": items}


def _core_inputs(component: dict[str, Any]) -> dict[str, Any]:
    """Same shape as tests/test_threat_workbench.py core_inputs; hashes are content-derived."""
    return {"run_id": RUN_ID, "source_snapshot_sha256": component["source_snapshot_sha256"],
            "component_attempt_id": "component-sample", "component_pointer_sha256": "sha256:" + _json_sha(["pointer", component]),
            "component_envelope_sha256": "sha256:" + _json_sha(["envelope", component]),
            "component_map_path": "data/jobs/01-component-characterization/attempts/component-sample/component-purpose-map.json",
            "component_map_sha256": _json_sha(component), "evidence_attempt_id": "evidence-sample",
            "evidence_manifest_sha256": "sha256:" + _json_sha(["manifest", component["evidence_manifest_lineage"]]),
            "evidence_path": "data/jobs/02-evidence-assembly/attempts/evidence-sample/evidence/index.json",
            "evidence_sha256": _json_sha(["evidence", component["evidence_manifest_lineage"]]),
            "component_map": component, "code": {}}


def workbench_model() -> tuple[dict[str, Any], dict[str, Any]]:
    """The integrated 03 model the real join builds from the canned replies, validated as 03 would."""
    import threat_model_core as tm
    import threat_workbench as tw
    from schema_validate import validate_document
    component = json.loads(COMPONENT.read_text(encoding="utf-8"))
    inputs = _core_inputs(component)
    base = tm.build_model(inputs, "attempt-sample")
    replies = {key: value for key, value in json.loads(REPLIES.read_text(encoding="utf-8")).items()
               if not key.startswith("_")}
    menu = _menu()
    traits = tw.detect_traits(menu, component, TARGET_FILES)
    selection = tw.select(traits)
    config = tw.settings()
    rows = []
    for item in selection:
        if not item["selected"]:
            continue
        cell = tw.CELLS[item["workcell_id"]]
        reply = replies[cell.workcell_id]
        rows.append({"workcell_id": cell.workcell_id, "wave": cell.wave, "selection": "selected",
                     "omission_reason": None, "instance_id": "sample-" + cell.workcell_id,
                     "persona_id": cell.persona_id, "prompt_hash": _sha(cell.template_id.encode()),
                     "model_identity_hash": _sha(b"SAMPLE: no model was called"), "terminal_status": "OK",
                     "cause": None, "output_sha256": _json_sha(reply), "started_at": "2026-09-29T00:00:00Z",
                     "finished_at": "2026-09-29T00:00:01Z"})
    index = tw._readable_index(menu, [{"path": path, "sha256": "sha256:" + _sha(SAMPLE_BYTES + path.encode())}
                                      for path in TARGET_FILES])
    record = {"schema": tw.RECORD_SCHEMA, "enabled": config["enabled"], "budget_class": config["budget_class"],
              "record_limit": config["record_limit"], "traits": traits, "selection": selection,
              "menu_root": menu["root_id"], "cells": rows, "pools": [], "readable_index": index,
              "wave_1_model_sha256": None}
    model = tw.join(base, record, replies)
    problems = (validate_document(model, "integrated-threat-model.schema.json") + tm.validate_model(model, inputs)
                + tw.validate_overlays(model))
    if problems:
        raise SystemExit(f"workbench replay does not validate: {problems[:3]}")
    return model, record


def synthesis_threat_model(model: dict[str, Any]) -> dict[str, Any]:
    """``report.json`` as 10-synthesis-report would publish it with this 03 output's workbench families.

    The ledger, L08 and OWASP inputs are the canned ones of tests/test_synthesis_report.py (as in
    tests/test_threat_workbench_report.py); build_report enforces the closed synthesis-report schema."""
    import synthesis_report as synthesis
    import test_synthesis_report as base
    inputs = base.SynthesisReportTests().inputs()
    inputs["documents"]["threat"].update({key: model[key] for key in
                                          ("data_classes", "privacy_threats", "deployment_zones", "attack_trees")})
    return synthesis.build_report(inputs)[0]


def threat_workbench(model: dict[str, Any]) -> dict[str, Any]:
    import synthesis_report_presentation as presentation
    return presentation._threat_workbench(synthesis_threat_model(model)["threat_model"])


# ---- P3: sections 3A and 3B through their report builders -----------------------------------------
CHAIN_TEXT = {"objective": "Run attacker-chosen code through the hello command line",
              "narrative": "argv[1] reaches the unbounded copy of {claim} into a fixed-size stack buffer."}


def attack_chains(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Lane 14 composition, refutation and report projection over the case-001 argv -> strcpy fixture
    (the canned entry fact keeps that fixture's path); the impact link is bound to AR-001's title."""
    import attack_chain_composition as composition
    import attack_chain_pool as chain_pool
    import attack_chain_refutation as refutation
    import attack_chain_refute as refute
    import attack_chain_report as chain_report
    import synthesis_report_presentation as presentation
    from tests.test_attack_chain_derive import CLAIM, two_link_chain
    from tests.test_attack_chain_report import ReportTests, report
    from tests.test_attack_chain_workers import LAUNCHED, RUN, composition_inputs, merge_for
    title = next(item["title"] for item in findings if item["id"] == "AR-001")
    harness = ReportTests("test_published_chain_is_ranked_labelled_and_never_a_finding")
    harness.setUp()
    try:   # the steps of ReportTests.publish with this chain's composer and refuter replies
        inputs = composition_inputs()
        chain = two_link_chain(objective=CHAIN_TEXT["objective"], narrative=CHAIN_TEXT["narrative"].format(claim=CLAIM))
        first, _second, _dispatch = harness.compose(inputs, harness.composer_merge(inputs, {"chains": [chain]}))
        chain_id = json.loads((composition.root(RUN) / "attempts" / first["attempt_id"] /
                               composition.RESULT).read_text())["chains"][0]["chain_id"]
        outcome, _ = refute.derive(refutation.prepare(RUN)["batches"][0],
                                   {"chains": [{"chain_id": chain_id, "disposition": "holds"}]}, refuter=None)
        merge = merge_for([("attack-chain-refuter", refute.candidates(outcome, "sha256:" + "b" * 64))])
        with mock.patch.object(chain_pool, "dispatch", return_value=(merge, LAUNCHED)):
            refutation.run(RUN, "dagster-3")
        section = chain_report.build(report(verified_findings=[{"claim_id": CLAIM, "title": title, "severity": "HIGH"}]),
                                     harness.run_root())
    finally:
        harness.tearDown()
    return presentation._attack_chains(section)


def dependency_summary() -> dict[str, Any]:
    from schema_validate import validate_document
    snapshot = "sha256:" + _sha(SAMPLE_BYTES)
    summary = {"schema": "appsec-review/dependency-reachability-summary/1", "run_id": RUN_ID,
               "job_id": "06-cve-reachability", "attempt_id": "cve-reachability-sample", "source_snapshot_sha256": snapshot,
               "counts": {"reachable": 0, "unreachable": 0, "conflict": 0, "unknown": 0},
               "engines": [{"job_id": "06-reachability-codeql", "engine": "codeql", "attempt_id": "codeql-sample",
                            "result_sha256": "sha256:" + _sha(b"SAMPLE 06-reachability-codeql"), "status": "OK"},
                           {"job_id": "06-reachability-ir", "engine": "ir", "attempt_id": "ir-sample",
                            "result_sha256": "sha256:" + _sha(b"SAMPLE 06-reachability-ir"), "status": "OK"}],
               "matches": [], "review": {"p1_match_ids": [], "conflict_match_ids": []},
               "coverage_gaps": [], "claim_ceiling": "EVIDENCE_LEADS_ONLY"}
    errors = validate_document(summary, "dependency-reachability-summary.schema.json")
    if errors:
        raise SystemExit(f"canned 06 summary is invalid: {errors[:3]}")
    return summary


def dependency_reachability() -> dict[str, Any]:
    import dependency_reachability_report as section
    import synthesis_report_presentation as presentation
    summary = dependency_summary()
    with tempfile.TemporaryDirectory() as folder:
        pointer = Path(folder) / "data" / "jobs" / section.JOB
        pointer.mkdir(parents=True)
        (pointer / "accepted.json").write_text(json.dumps({"status": "OK", "attempt_id": summary["attempt_id"]}))
        # the loader's envelope and hash checks need a real published attempt; the canned summary stands in
        with mock.patch.object(section.bounded_analysis_workers, "load_accepted",
                               return_value=(summary, {"artifact_sha256": "sha256:" + _json_sha(summary)})):
            value = section.build({"run_id": RUN_ID}, Path(folder))
    return presentation._dependency_reachability(value)


# ---- per-finding derived fields -------------------------------------------------------------------
def finding_fields(finding: dict[str, Any]) -> dict[str, Any]:
    import synthesis_report_presentation as presentation
    value = dict(finding)
    exploit = (epss_kev_snapshot.not_assessed(DEPENDENCY_FINDINGS[finding["id"]])
               if finding["id"] in DEPENDENCY_FINDINGS else None)
    value["exploit_signal"] = presentation._exploit_text(exploit, {"status": "not assessed"})
    trail = [row for row in finding["trail"] if row[0] != "12"]
    if finding.get("cvss"):
        score = cvss4.score(finding["cvss"])
        trail.append(["12", f"CVSS {score} {cvss4.severity(score)} (pinned cvss4.py)"])
    value["trail"] = trail
    return value


def build(data: dict[str, Any]) -> dict[str, Any]:
    data = copy.deepcopy(data)
    families, rows, weights = processes(data["evidence"])
    data["families"], data["processes"] = families, rows
    data["scoring"]["family_weight"] = weights
    graph_sha = _sha(GRAPH.read_bytes())
    data["report"]["pipeline_commit"] = f"sample; job-graph.json sha256:{graph_sha[:12]} ({len(rows)} jobs)"
    data["findings"] = [finding_fields(item) for item in data["findings"]]
    data["attack_chains"] = attack_chains(data["findings"])
    data["dependency_reachability"] = dependency_reachability()
    model, _record = workbench_model()
    data["threat_workbench"] = threat_workbench(model)
    return data


def render_text(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the sample file is stale")
    parser.add_argument("--path", default=str(EXAMPLE))
    args = parser.parse_args(argv)
    path = Path(args.path)
    current = path.read_text(encoding="utf-8")
    fresh = render_text(build(json.loads(current)))
    if args.check:
        if fresh != current:
            print(f"{path} is stale: run python3 pipeline/report/sample_data.py", file=sys.stderr)
            return 1
        print(f"{path} is current")
        return 0
    path.write_text(fresh, encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    raise SystemExit(main())
