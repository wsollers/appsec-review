"""The four published documents (T-107): schema-valid, counted, byte-stable and renderable."""
from __future__ import annotations

import random
from typing import Any, Mapping

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.threat_model.contract import (
    DFD_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA, THREAT_MODEL_SCHEMA, InputLedgerRow, InputState, Interaction,
    LaneResult, Limits, Origin, UnknownKind, canonical,
)
from appsec_review.threat_model.assemble import assemble
from appsec_review.threat_model.documents import Documents, build_documents, plain
from appsec_review.threat_model.render import BANNER, node_id, render_markdown, render_mermaid
from appsec_review.threat_model.schemas import validate_document
from appsec_review.threat_model.threats import enumerate_threats
from appsec_review.threat_model.validate import validate_documents
from tests.test_threat_model_assembly import LIMITS, process, reference, site
from tests.threat_model_support import SHA_A

LEDGER = (
    InputLedgerRow("job_target_catalog", "build_units", InputState.READ, "c" * 64, "complete", 0, 3),
    InputLedgerRow("job_code_graph_index", "code_graph_facts", InputState.PARTIAL, "d" * 64, "partial", 2, 7),
    InputLedgerRow("job_target_catalog", "build_units", InputState.READ, "c" * 64, "complete", 0, 2),
    InputLedgerRow("job_artifact_indexing", "artifact_catalog", InputState.ABSENT),
)
LANE_GAPS = (
    producer_gap(GapCode.INPUT_UNAVAILABLE, "job_artifact_indexing/artifact_catalog has no accepted handoff",
                 unit_id="facts.structure", scope_id="job_artifact_indexing", retryable=True),
    producer_gap(GapCode.PRODUCER_REPORTED_GAP, "job_code_graph_index/code_graph_facts was accepted with 2 gaps",
                 unit_id="facts.interactions", scope_id="job_code_graph_index/code_graph_facts", retryable=True),
)
ARTIFACTS = {"dfd": {"path": "dfd.json", "sha256": SHA_A, "size_bytes": 10},
             "threat_model": {"path": "threat-model.json", "sha256": SHA_A, "size_bytes": 20}}


def origin() -> Origin:
    return Origin("run-1", "attempt-1", "snapshot-1", dict(reference().sha256s))


def facts() -> list[Any]:
    return [process("server", roots=("server/",)), process("client", unit="unit-b", roots=("client/",)),
            site(Interaction.NETWORK_RECEIVE, "server/net.c", 40), site(Interaction.NETWORK_LISTEN, "server/main.c", 5),
            site(Interaction.NETWORK_CONNECT, "client/http.c", 9), site(Interaction.DATASTORE_QUERY, "server/db.c", 7),
            site(Interaction.ARGUMENT_READ, "client/main.c", 1), site(Interaction.FILE_READ, "vendor/x.c", 1)]


def documents(seed: int | None = None, limits: Limits = LIMITS) -> Documents:
    """The documents of one fixed input; ``seed`` shuffles every input sequence."""
    ordered, ledger, gaps = facts(), list(LEDGER), list(LANE_GAPS)
    names = sorted(ARTIFACTS)
    if seed is not None:
        chooser = random.Random(seed)
        for sequence in (ordered, ledger, gaps, names):
            chooser.shuffle(sequence)
    half = len(ordered) // 2
    assembly = assemble((LaneResult(tuple(ordered[:half])), LaneResult(tuple(ordered[half:]))), reference(), limits)
    threats, threat_gaps = enumerate_threats(assembly, reference(), limits)
    threats = list(threats)
    if seed is not None:
        random.Random(seed).shuffle(threats)
    return build_documents(origin(), assembly, threats, ledger, [*gaps, *assembly.gaps, *threat_gaps],
                           artifacts={name: ARTIFACTS[name] for name in names},
                           supplied_documents=("doc:threat-model", "doc:dfd"))


def plains(built: Documents) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return plain(built.dfd), plain(built.threat_model), plain(built.evidence), plain(built.result)


def _cited(*published: Mapping[str, Any]) -> list[str]:
    found = []
    for document in published:
        for key, records in document.items():
            for item in records if isinstance(records, list) else ():
                if isinstance(item, dict):
                    found += [reference["ref"] for reference in item.get("evidence", ())]
                    found += [reference["ref"] for reference in item.get("mitigation", {}).get("evidence", ())]
    return found


def test_documents_validate_against_the_published_schemas() -> None:
    dfd, model, evidence, result = plains(documents())

    assert [item["schema"] for item in (dfd, model, evidence, result)] == [
        DFD_SCHEMA, THREAT_MODEL_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA]
    for document in (dfd, model, evidence, result):
        validate_document(document)
    validate_documents(dfd, model, evidence, result)
    assert dfd["origin"] == model["origin"] == evidence["origin"] == result["origin"]
    assert dfd["origin"]["target_supplied"] is False and dfd["origin"]["model"] is None
    assert model["assets"] == [] and model["supplied_documents"] == ["doc:dfd", "doc:threat-model"]
    assert result["artifacts"] == ARTIFACTS
    stores = [item["id"] for item in dfd["elements"] if item["kind"] == "data_store"]
    assert len(stores) == 1
    assert [(item["kind"], item["subject_ids"]) for item in model["unknowns"]] == [
        (UnknownKind.ASSET_SENSITIVITY_UNKNOWN.value, stores)]
    assert UnknownKind.FLOW_ENDPOINT_UNRESOLVED.value in {item["kind"] for item in dfd["unknowns"]}


def test_an_empty_model_still_publishes_valid_documents() -> None:
    assembly = assemble((), reference(), LIMITS)
    built = build_documents(origin(), assembly, (), (), ())
    dfd, model, evidence, result = plains(built)

    validate_documents(dfd, model, evidence, result)
    assert dfd["elements"] == [] and evidence["references"] == [] and result["artifacts"] == {}
    assert [item["kind"] for item in dfd["unknowns"]] == [UnknownKind.NO_ELEMENT_ESTABLISHED.value]
    assert result["counts"]["unknowns"] == 1 and result["counts"]["processes"] == 0


def test_evidence_document_lists_each_cited_reference_once() -> None:
    dfd, model, evidence, _ = plains(documents())

    listed = [item["ref"] for item in evidence["references"]]
    cited = _cited(dfd, model)
    assert listed == sorted(set(cited)) and len(listed) == len(set(listed))
    assert len(cited) > len(listed)  # references are shared between records and still listed once
    by_ref = {item["ref"]: item for item in evidence["references"]}
    for element in dfd["elements"]:
        for item in element["evidence"]:
            assert by_ref[item["ref"]] == item  # the full reference, not a label


def test_counts_match_the_documents() -> None:
    dfd, model, evidence, result = plains(documents(limits=Limits(max_threats=3)))

    kinds = [item["kind"] for item in dfd["elements"]]
    assert result["counts"] == {
        "processes": kinds.count("process"), "data_stores": kinds.count("data_store"),
        "external_entities": kinds.count("external_entity"), "flows": len(dfd["flows"]),
        "boundaries": len(dfd["boundaries"]), "entry_points": len(model["entry_points"]),
        "actors": len(model["actors"]), "assets": 0, "threats": len(model["threats"]),
        "unknowns": len(dfd["unknowns"]) + len(model["unknowns"]), "gaps": len(result["gaps"]),
        "evidence_references": len(evidence["references"]),
    }
    assert (result["counts"]["processes"], result["counts"]["data_stores"], result["counts"]["external_entities"],
            result["counts"]["flows"], result["counts"]["threats"], result["counts"]["gaps"]) == (2, 1, 3, 5, 3, 3)
    assert {gap["scope_id"] for gap in result["gaps"]} == {
        "job_artifact_indexing", "job_code_graph_index/code_graph_facts", "threats.max_threats"}


def test_ledger_has_one_sorted_row_per_input_with_summed_records() -> None:
    result = plain(documents().result)

    assert [(row["producer"], row["output_kind"], row["state"], row["records_read"]) for row in result["input_ledger"]] == [
        ("job_artifact_indexing", "artifact_catalog", "absent", 0),
        ("job_code_graph_index", "code_graph_facts", "partial", 7),
        ("job_target_catalog", "build_units", "read", 5)]
    assert result["input_ledger"][1]["upstream_gap_count"] == 2


def test_documents_are_byte_identical_for_shuffled_inputs() -> None:
    first = documents()
    expected = [canonical(item) for item in (first.dfd, first.threat_model, first.evidence, first.result)]
    for seed in range(5):
        other = documents(seed)
        assert [canonical(item) for item in (other.dfd, other.threat_model, other.evidence, other.result)] == expected


def test_documents_render_through_the_real_renderer() -> None:
    dfd, model, _, result = plains(documents())

    views, truncated = render_mermaid(dfd, LIMITS)
    assert truncated is False and list(views) == ["dfd.mmd"]
    process_id = next(item["id"] for item in dfd["elements"] if item["kind"] == "process")
    assert BANNER[0] in views["dfd.mmd"] and node_id(process_id) in views["dfd.mmd"]
    assert f"subgraph {node_id(dfd['boundaries'][0]['id'])}" in views["dfd.mmd"]
    markdown = render_markdown(dfd, model, result)
    assert BANNER[0] in markdown and process_id in markdown
    assert model["threats"][0]["id"] in markdown and dfd["unknowns"][0]["id"] in markdown
