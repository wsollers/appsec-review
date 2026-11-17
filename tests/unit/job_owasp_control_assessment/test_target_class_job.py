"""T-5008 Done-when (c), job level: a CLI-only target ends the OWASP job after applicability.

No batch, no OWASP_WORKER_STARTED event, no control_evidence fact; the only gaps are the fixture
catalogs' own, so with complete catalogs the handoff is SUCCEEDED.
"""
from __future__ import annotations

import json

from appsec_review.jobs.job_owasp_control_assessment import build_job
from appsec_review.observability import PipelineLog
from appsec_review.storage.shared import publication_scope
from tests.test_owasp_assessment_job import (
    ScriptedAssessment, _base_app_config, accepted_fixture, context_for, execute,
)


def test_cli_target_ends_after_applicability_with_a_not_applicable_ledger(tmp_path) -> None:
    fixture = accepted_fixture(tmp_path, facets="cli")
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport)
    assert transport.calls == []
    classifications = outputs["characterization.classify_components"]["classifications"]
    assert {item["component_id"]: item["target_classes"] for item in classifications} == {
        "component:0001": ["target:cli"], "component:0002": ["target:cli"]}
    matrix = outputs["applicability.build_matrix"]
    assert set(matrix["outcome_counts"]) == {"not_applicable"} and matrix["dispatchable_rows"] == 0
    ledger = matrix["ledger"]
    assert ledger["schema"] == "appsec-review/target-class-ledger/1"
    assert {entry["verdict"] for entry in ledger["entries"]} == {"not_applicable"}
    assert all(entry["citations"] for entry in ledger["entries"])
    assert outputs["batching.partition_work"]["batch_count"] == 0
    events, _truncated = PipelineLog(fixture.run_root).read()
    assert not any("OWASP_WORKER_STARTED" in json.dumps(record) for record in events)
    assert all(outputs[f"validation.cell_0{index}"]["assigned_batch_count"] == 0 for index in range(1, 5))
    handoff = outputs["publication.publish_handoff"]
    report = json.loads((fixture.run_root / handoff["artifact"]["path"]).read_text(encoding="utf-8"))
    catalog_gaps = set(outputs["standards_selection.ingest_catalogs"]["gaps"])
    assert set(report["gaps"]) == catalog_gaps, "the not-applicable ledger is a result, not a gap"
    assert handoff["terminal_status"] == ("COMPLETED_WITH_GAPS" if catalog_gaps else "SUCCEEDED")
    # D5: a typed coverage disposition travels with the status (outcomes.json recorded None before).
    assert outputs["join.deterministic_join"]["coverage_disposition"] == "complete"
    assert handoff["coverage_disposition"] == report["coverage_disposition"] == (
        "partial" if catalog_gaps else "complete")
    assert outputs["characterization.load_inputs"]["gaps"] == []
    assert outputs["characterization.load_inputs"]["terminal_status"] == "SUCCEEDED"
    assert report["coverage"]["applicable_rows"] == 0 and report["coverage"]["dispatched_rows"] == 0
    assert report["target_class_ledger"] == ledger
    joined = outputs["join.deterministic_join"]["joined"]["results"]
    assert joined and {row["applicability"] for row in joined} == {"not_applicable"}
    assert {row["control_status"] for row in joined} == {"not_assessed"}
    # Projection: a not_applicable row is a ledger entry, never a control_evidence fact.
    from appsec_review.indexing.products import control_evidence_candidate
    assert not any(control_evidence_candidate(row) for row in joined)
    assert control_evidence_candidate({**joined[0], "applicability": "applicable"})
    assert control_evidence_candidate({**joined[0], "applicability": "cannot_determine"})


def test_network_service_target_admits_only_the_transport_agnostic_asvs_chapters(tmp_path) -> None:
    """D3 (run 2026-11-16-0005): a non-HTTP listener is target:network-service beside target:cli.

    The fixture's svc handler is a Python network service with a SQL subject, so the one admitted control
    with a reviewed procedure (V1.2.4) is assessed; the other admitted rows have no procedure and the
    web-only chapters cite the class. The C component stays a plain CLI.
    """
    fixture = accepted_fixture(tmp_path, facets="network-service")
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport)
    classifications = outputs["characterization.classify_components"]["classifications"]
    svc = next(item for item in classifications if item["component_id"] == "component:0001")
    assert svc["target_classes"] == ["target:cli", "target:network-service"] and "network" in svc["roles"]
    assert svc["source_support"]["supported_files"] >= 1 and svc["target_class_unread"] is False
    matrix = outputs["applicability.build_matrix"]
    ledger = {(entry["component_id"], entry["family"]): entry for entry in matrix["ledger"]["entries"]}
    asvs = ledger[("component:0001", "ASVS")]
    assert asvs["verdict"] == "partially_applicable" and asvs["basis_class"] == "target:network-service"
    assert asvs["admitted_chapters"] == ["V1", "V2", "V5", "V7", "V16"] and asvs["citations"]
    assert ledger[("component:0001", "MASVS")]["verdict"] == "not_applicable"
    assert ledger[("component:0002", "ASVS")]["verdict"] == "not_applicable"
    svc_rows = [row for row in matrix["rows"] if row["component_id"] == "component:0001" and row["standard"] == "ASVS"]
    admitted = [row for row in svc_rows if row["control_id"].split(".")[0] in {"V1", "V2", "V5", "V7", "V16"}]
    web_only = [row for row in svc_rows if row not in admitted]
    assert web_only and {row["outcome"] for row in web_only} == {"not_applicable"}
    assert all("target:network-service admits ASVS only for the transport-agnostic chapters" in row["reason"]
               and "web-only" in row["reason"] for row in web_only)
    assert all(row["admitted_chapters"] == ["V1", "V2", "V5", "V7", "V16"] and row["basis_class"] == "target:network-service"
               for row in svc_rows)
    dispatched = [row for row in admitted if row["outcome"] in {"applicable", "conditional"}]
    assert [row["control_id"] for row in dispatched] == ["V1.2.4"]
    assert {row["outcome"] for row in admitted if row not in dispatched} == {"unsupported_missing_evidence"}
    assert all("no reviewed versioned proof procedure" in row["reason"] for row in admitted if row not in dispatched)
    assert outputs["batching.partition_work"]["batch_count"] == 1 and transport.calls
    assert outputs["join.deterministic_join"]["coverage_disposition"] == "partial"
    joined = outputs["join.deterministic_join"]["joined"]["results"]
    assert sum(row["applicability"] in {"applicable", "conditional"} for row in joined) == 1
    selection = outputs["standards_selection.select_profiles"]["selection"]
    assert all(item["reasons"] for item in selection["selections"])


CPP_SERVER = (
    "#include <cstdio>\n"
    "#include <cstdlib>\n"
    "#include <cstring>\n"
    "#include <sys/socket.h>\n"
    "\n"
    "struct Session {\n"
    "  char name[32];\n"
    "  char *scratch;\n"
    "};\n"
    "\n"
    "// Writes one line to the server log; the client supplies the line.\n"
    "void log_message(const char *fmt) {\n"
    "  printf(fmt);\n"
    "  putchar('\\n');\n"
    "}\n"
    "\n"
    "bool session_touch(Session *session, const char *arg) {\n"
    "  if (session == nullptr) {\n"
    "    return false;\n"
    "  }\n"
    "  if (arg != nullptr && strcmp(arg, \"reset\") == 0) {\n"
    "    free(session->scratch);\n"
    "    session->scratch[0] = '\\0';\n"
    "    session->scratch = (char *)malloc(64);\n"
    "  }\n"
    "  return true;\n"
    "}\n"
    "\n"
    "int handle_request(char *line, size_t len, int sock, Session *session) {\n"
    "  char cmd[640];\n"
    "  snprintf(cmd, sizeof(cmd), \"/usr/libexec/smoke/report %s\", line);\n"
    "  FILE *pipe = popen(cmd, \"r\");\n"
    "  if (pipe == nullptr) {\n"
    "    return 500;\n"
    "  }\n"
    "  log_message(line);\n"
    "  return pclose(pipe) == 0 ? 200 : 500;\n"
    "}\n"
    "\n"
    "int serve_once(int sock) {\n"
    "  static char line[1024];\n"
    "  ssize_t n = recv(sock, line, sizeof(line) - 1, 0);\n"
    "  if (n <= 0) {\n"
    "    return -1;\n"
    "  }\n"
    "  line[n] = '\\0';\n"
    "  Session session = {};\n"
    "  return handle_request(line, (size_t)n, sock, &session);\n"
    "}\n"
)
ADMITTED = {"V1", "V2", "V5", "V7", "V16"}


def _cpp_fixture(tmp_path):
    return accepted_fixture(tmp_path, facets="native-network-service",
                            extra_files={"native/src/server.cpp": ("C++", CPP_SERVER)})


def test_cpp_network_service_is_assessed_through_the_worker_pool(tmp_path) -> None:
    """T-5013: the C/C++ recognisers give the admitted chapters subjects, batches, packages and model calls.

    The native component is the raw-socket listener (target:cli + target:network-service) with C and C++
    sources; the svc component stays an HTTP route. Every admitted control with a C/C++ procedure and a
    recognised subject is dispatched; the others name their missing recogniser.
    """
    fixture = _cpp_fixture(tmp_path)
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport, asvs_level=2, max_batch_size=12)
    native = next(item for item in outputs["characterization.classify_components"]["classifications"]
                  if item["component_id"] == "component:0002")
    assert native["target_classes"] == ["target:cli", "target:network-service"]
    assert native["source_support"]["languages"] == ["c-cpp"] and native["source_support"]["evidence_count"] >= 3
    matrix = outputs["applicability.build_matrix"]
    rows = [row for row in matrix["rows"] if row["component_id"] == "component:0002" and row["standard"] == "ASVS"]
    admitted = [row for row in rows if row["control_id"].split(".")[0] in ADMITTED]
    dispatched = {row["control_id"] for row in admitted if row["outcome"] in {"applicable", "conditional"}}
    from appsec_review.owasp_workbench.c_procedures import C_CONTROL_FAMILIES
    assert dispatched == set(C_CONTROL_FAMILIES)
    unresolved = [row for row in admitted if row["control_id"] not in dispatched]
    assert unresolved and {row["outcome"] for row in unresolved} == {"unsupported_missing_evidence"}
    assert all("no C/C++ recogniser for this control" in row["reason"] for row in unresolved)
    assert all(row["outcome"] == "not_applicable" and "web-only" in row["reason"] for row in rows if row not in admitted)
    # Batches group by domain/persona; the four cells take them round-robin; packages carry bounded subjects.
    work = outputs["batching.partition_work"]["work"]
    assert outputs["batching.partition_work"]["batch_count"] >= 1
    native_batches = [batch for batch in work["batches"] if batch["component_ids"] == ["component:0002"]]
    assert native_batches and all(batch["assignment"]["persona"] for batch in native_batches)
    assert sum(outputs[f"validation.cell_0{index}"]["assigned_batch_count"] for index in range(1, 5)) == len(work["batches"])
    for position, batch in enumerate(work["batches"]):
        cell = outputs[f"validation.cell_0{position % 4 + 1}"]
        assert batch["batch_id"] in {result["batch_id"] for result in cell["batch_results"]}
    packages = outputs["batching.build_packages"]["packages"]
    settings = _base_app_config().job("job_owasp_control_assessment").settings
    supported_by_control: dict[str, int] = {}
    for batch in native_batches:
        for package in packages[batch["batch_id"]]:
            supported = [item for item in package["proof_obligations"] if item["supported"]]
            assert len(supported) <= settings["max_subjects_per_control"]
            supported_by_control[package["control"]["id"]] = len(supported)
            for item in supported:
                assert item["subject"]["language"] == "c-cpp" and item["subject"]["sites"]["recogniser"]
                assert item["procedure"]["language"] == "c-cpp"
    assert supported_by_control["V1.2.5"] >= 2 and supported_by_control["V7.4.1"] >= 1
    assert supported_by_control["V1.4.1"] >= 1 and supported_by_control["V16.4.1"] >= 1
    # The reviewer profile and the worker both ran, over C/C++ packages only for the native component.
    roles = {request.role for request in transport.calls}
    assert roles == {"control_assessor", "independent_reviewer"}
    assert all(request.model == settings["model"]["model"] for request in transport.calls if request.role == "control_assessor")
    joined = outputs["join.deterministic_join"]["joined"]["results"]
    assessed = [row for row in joined if row["component_id"] == "component:0002" and row["control_status"] == "not_satisfied"]
    # Run 2026-11-17-0003: every batch is now dispatched (split into request-sized parts), so the twelve-row
    # batch's rows reach the worker too. Their per-package evidence bound (half the input budget shared by
    # twelve packages) can leave a supported obligation without its record in the request; the honest double
    # answers cannot_verify for that obligation, so the row is adverse on its evidenced subject and unresolved
    # on the other, never silently independently_assessed.
    assert assessed and {row["verification_status"] for row in assessed} <= {"independently_assessed", "unresolved"}
    assert any(row["verification_status"] == "independently_assessed" for row in assessed)
    for row in assessed:
        if row["verification_status"] == "unresolved":
            assert any("package evidence bounded" in note for note in row["limitations"])
            assert any(item["final_outcome"] == "cannot_verify" for item in row["obligations"])
    assert all(row["evidence_used"] and row["obligations"] for row in assessed)
    assert all(row["worker_attempt_count"] >= 1 for row in joined if row["component_id"] == "component:0002"
               and any(item["obligation"].get("supported") for item in row["obligations"]))
    assert outputs["join.deterministic_join"]["joined"]["accounting"]["exactly_once"]


def test_failed_cell_leaves_cpp_rows_cannot_verify_with_a_gap(tmp_path) -> None:
    fixture = _cpp_fixture(tmp_path)
    transport = ScriptedAssessment()
    context = context_for(fixture, asvs_level=2, max_batch_size=12)
    with publication_scope(context):
        result = build_job(fail_cell="cell_01", infer=transport).execute(context)
    assert not result["failed_units"]
    outputs = result["outputs"]
    failed = outputs["validation.cell_01"]
    assert failed["failed_batch_count"] == failed["assigned_batch_count"] >= 1
    assert failed["terminal_status"] == "COMPLETED_WITH_GAPS"
    failed_rows = {item["row_id"] for batch in failed["batch_results"] for item in batch["results"]}
    joined = outputs["join.deterministic_join"]["joined"]["results"]
    for row in joined:
        if row["row_id"] in failed_rows:
            assert row["control_status"] == "cannot_verify" and row["coverage_completeness"] == "unresolved"
            assert any("validator worker failed" in gap for gap in row["gaps"]) and not row["lead_eligible"]
    assert any(row["row_id"] in failed_rows for row in joined)
    assert any(row["control_status"] == "not_satisfied" for row in joined), "sibling cells still assess"
    assert outputs["publication.publish_handoff"]["coverage_disposition"] == "partial"
