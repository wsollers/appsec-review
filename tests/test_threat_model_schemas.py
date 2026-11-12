"""The closed JSON Schemas of the generated DFD and threat-model documents (T-107)."""
from __future__ import annotations

import copy
from dataclasses import fields, is_dataclass
from enum import StrEnum
import inspect
import json
from typing import Any, get_args, get_origin, get_type_hints

from jsonschema import Draft202012Validator
import pytest

from appsec_review.application_paths import application_asset
from appsec_review.interchange import GapCode, producer_gap
from appsec_review.threat_model import contract, schemas
from appsec_review.threat_model.contract import (
    Actor, Asset, Basis, Boundary, BoundaryKind, DFD_SCHEMA, EVIDENCE_SCHEMA, Element, ElementKind, EntryPoint,
    EvidenceRef, Flow, InputLedgerRow, InputState, Interaction, Mitigation, MitigationState, NameBasis, Origin,
    RESULT_SCHEMA, Stride, THREAT_MODEL_SCHEMA, Threat, ThreatState, Unknown, UnknownKind, canonical, cite,
    element_id, sorted_records, unknown,
)
from appsec_review.threat_model.view import truncated_gap
from tests.threat_model_support import SHA_A, SHA_B, record, span

SCHEMA_IDS = sorted(schemas.SCHEMA_FILES)
RECORDS = {name: item for name, item in vars(contract).items()
           if inspect.isclass(item) and is_dataclass(item) and item.__module__ == contract.__name__}
VOCABULARIES = {name: item for name, item in vars(contract).items()
                if inspect.isclass(item) and issubclass(item, StrEnum) and item is not StrEnum}
# The document shapes of the design (section 6): top-level array -> the record it holds.
DOCUMENT_ARRAYS = {
    DFD_SCHEMA: {"elements": Element, "flows": Flow, "boundaries": Boundary, "unknowns": Unknown},
    THREAT_MODEL_SCHEMA: {"assets": Asset, "actors": Actor, "entry_points": EntryPoint, "threats": Threat,
                          "unknowns": Unknown},
    EVIDENCE_SCHEMA: {"references": EvidenceRef},
    RESULT_SCHEMA: {"input_ledger": InputLedgerRow},
}
# The only objects that are not ``additionalProperties: false``, by design.
OPEN_OBJECTS = {
    DFD_SCHEMA: {"/$defs/Element/properties/attributes", "/$defs/Flow/properties/attributes"},
    THREAT_MODEL_SCHEMA: {"/$defs/Threat/properties/crosswalk", "/$defs/Threat/properties/related_controls/items"},
    EVIDENCE_SCHEMA: set(),
    RESULT_SCHEMA: {"/properties/counts", "/properties/artifacts"},
}


def _schema(schema_id: str) -> dict[str, Any]:
    return json.loads(schemas.schema_path(schema_id).read_text(encoding="utf-8"))


def _walk(node: Any, pointer: str = ""):
    if isinstance(node, dict):
        yield pointer, node
        for key, value in node.items():
            yield from _walk(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{pointer}/{index}")


def _classes(hint: Any) -> set[type]:
    found = {hint} if isinstance(hint, type) and not get_args(hint) else set()
    for argument in get_args(hint):
        found |= _classes(argument)
    return found


def _reachable(roots: list[type]) -> set[type]:
    seen: set[type] = set()
    queue = list(roots)
    while queue:
        item = queue.pop()
        if item in seen:
            continue
        seen.add(item)
        for hint in get_type_hints(item).values():
            queue.extend(found for found in _classes(hint) if found in RECORDS.values())
    return seen


def _ref(entity_id: str = "artifact:server", basis: Basis = Basis.DECLARED, *, line: int = 3) -> EvidenceRef:
    return cite(record("job_target_catalog", "build_units", "build_unit", entity_id, at=span("server/main.c", line)),
                basis, "test.rule")


def _origin(model: dict[str, str] | None = None) -> Origin:
    return Origin("run-1", "attempt_0001", "snapshot-1",
                  {"interaction_catalog_sha256": SHA_A, "threat_templates_sha256": SHA_B, "crosswalk_sha256": SHA_A},
                  model)


def _documents() -> dict[str, dict[str, Any]]:
    """One canonical example of each published document, built from real contract records."""
    declared, semantic = _ref(), _ref("graph:entry", Basis.VERIFIED_SEMANTIC, line=9)
    artifact = EvidenceRef(element_id("ev", ["sbom", SHA_B, None]), "run_artifact", "sbom", "artifact",
                           contract.Publication("job_dependency_intelligence", "sbom", None, None, SHA_B), None, SHA_B,
                           Basis.DECLARED, "test.artifact")
    process = Element(element_id("proc", ["unit", "server"]), ElementKind.PROCESS, "server", NameBasis.ARTIFACT_NAME,
                      Basis.DECLARED, (declared,), {"build_unit_id": "unit", "built": True, "ports": [8080]},
                      ("component-1",))
    peer = Element(element_id("ext", "remote-peer"), ElementKind.EXTERNAL_ENTITY, "remote peer", NameBasis.DERIVED,
                   Basis.DERIVED, (semantic,))
    store = Element(element_id("store", "db"), ElementKind.DATA_STORE, "db", NameBasis.DECLARED_NAME, Basis.DECLARED,
                    (artifact,))
    boundary_id = element_id("tb", ["network", process.id])
    receive = Flow(element_id("flow", "receive"), peer.id, process.id, Interaction.NETWORK_RECEIVE,
                   Basis.VERIFIED_SEMANTIC, (semantic, declared), (boundary_id,), None, {"callee": "recv"})
    query = Flow(element_id("flow", "query"), process.id, store.id, Interaction.DATASTORE_QUERY, Basis.OBSERVED_SYNTAX,
                 (declared,), (), "orders")
    boundary = Boundary(boundary_id, BoundaryKind.NETWORK, (process.id,), Basis.DERIVED, (semantic,))
    unknowns = [unknown(UnknownKind.PROTOCOL_UNKNOWN, "the protocol of the receive flow is not established",
                        subject_ids=(receive.id,), would_resolve=("job_deployment_inventory/deployment_inventory",)),
                unknown(UnknownKind.NO_ELEMENT_ESTABLISHED, "no element was established from the secrets input")]
    entry = EntryPoint(element_id("ep", ["network_receive", "handle"]), process.id, Interaction.NETWORK_RECEIVE,
                       "remote", "handle", Basis.VERIFIED_SEMANTIC, (semantic,))
    argument = EntryPoint(element_id("ep", ["argument_read", None]), process.id, Interaction.ARGUMENT_READ, None, None,
                          Basis.OBSERVED_SYNTAX, (declared,))
    actor = Actor(element_id("actor", peer.id), peer.id, ("remote_unauthenticated",), (semantic,))
    asset = Asset(element_id("asset", "db"), "orders store", (store.id,), Basis.DECLARED, (artifact,))
    candidate = Threat(
        element_id("threat", ["tampering", receive.id]), ThreatState.CANDIDATE, Stride.TAMPERING, "T-NET-001",
        "Tampering with received data", "Is received data validated before use?", (process.id, peer.id),
        (receive.id,), (boundary.id,), (semantic,), ("locate the validation of the received buffer",),
        Mitigation(MitigationState.EVIDENCE_FOUND, (declared,)), ({"family": "asvs", "id": "V5.1.3"},),
        {"cwe": ["CWE-20"], "attacker_positions": ["remote_unauthenticated"]})
    elaborated = Threat(
        element_id("threat", ["spoofing", peer.id]), ThreatState.ELABORATED, Stride.SPOOFING, None,
        "Spoofed peer", "Is the peer authenticated?", (peer.id,), (), (), (semantic,), (),
        Mitigation(MitigationState.NOT_EXAMINED))
    cited = {item.ref: item for item in (declared, semantic, artifact)}
    ledger = sorted([InputLedgerRow("job_target_catalog", "build_units", InputState.READ, SHA_A, "complete", 0, 3),
                     InputLedgerRow("job_deployment_inventory", "deployment_inventory", InputState.NOT_REGISTERED)],
                    key=lambda row: (row.producer, row.output_kind))
    gaps = [producer_gap(GapCode.INPUT_UNAVAILABLE, "job_deployment_inventory is not registered",
                         unit_id="facts.deployment", scope_id="job_deployment_inventory",
                         evidence_refs=({"path": "data/jobs/x/handoff.json", "sha256": SHA_B, "size_bytes": 12},)),
            dict(truncated_gap("graph.entry_point", 5, unit_id="facts.interactions")),
            producer_gap(GapCode.EMPTY_RESULT, "nothing was established")]
    documents = {
        DFD_SCHEMA: {"schema": DFD_SCHEMA, "origin": _origin(), "elements": sorted_records([process, peer, store]),
                     "flows": sorted_records([receive, query]), "boundaries": [boundary],
                     "unknowns": sorted_records(unknowns)},
        THREAT_MODEL_SCHEMA: {
            "schema": THREAT_MODEL_SCHEMA,
            "origin": _origin({"provider": "anthropic", "model": "model-1", "guidance_bundle_sha256": SHA_B}),
            "assets": [asset], "actors": [actor], "entry_points": sorted_records([entry, argument]),
            "threats": sorted_records([candidate, elaborated]), "supplied_documents": ["doc:threat-model.md"],
            "unknowns": sorted_records(unknowns)},
        EVIDENCE_SCHEMA: {"schema": EVIDENCE_SCHEMA, "origin": _origin(),
                          "references": sorted_records(cited.values())},
        RESULT_SCHEMA: {
            "schema": RESULT_SCHEMA, "origin": _origin(), "input_ledger": ledger,
            "counts": {"elements": 3, "flows": 2, "threats": 2, "unknowns": 2}, "gaps": gaps,
            "artifacts": {"dfd": {"path": "dfd.json", "sha256": SHA_A, "size_bytes": 2048},
                          "evidence": {"path": "evidence.json", "sha256": SHA_B, "size_bytes": 0}}},
    }
    return {schema_id: json.loads(canonical(document)) for schema_id, document in documents.items()}


def _at(document: Any, path: tuple[Any, ...]) -> Any:
    for part in path:
        document = document[part]
    return document


def _changed(schema_id: str, path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    document = copy.deepcopy(_documents()[schema_id])
    _at(document, path[:-1])[path[-1]] = value
    return document


@pytest.mark.parametrize("schema_id", SCHEMA_IDS, ids=[item.split("/")[1] for item in SCHEMA_IDS])
def test_schemas_are_closed_and_match_the_records(schema_id: str) -> None:
    schema = _schema(schema_id)
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema"] == {"const": schema_id}
    assert schema["properties"]["origin"] == {"$ref": "#/$defs/Origin"}
    assert sorted(schema["required"]) == sorted(schema["properties"]), "every document key is required"
    definitions = schema["$defs"]
    nodes = dict(_walk(schema))

    # Self-contained: every reference resolves inside the file, and every definition is used.
    references = {node["$ref"] for node in nodes.values() if "$ref" in node}
    assert references == {f"#/$defs/{name}" for name in definitions}

    # Closed: the only objects that admit unlisted keys are the ones the design leaves open.
    admits_more = {pointer for pointer, node in nodes.items()
                   if "object" in (node["type"] if isinstance(node.get("type"), list) else [node.get("type")])
                   and node.get("additionalProperties") is not False}
    assert admits_more == OPEN_OBJECTS[schema_id]
    for pointer in sorted(admits_more - {"/properties/artifacts"}):
        assert nodes[pointer]["description"].startswith("Open object by design"), pointer
    if schema_id == RESULT_SCHEMA:
        assert schema["properties"]["artifacts"]["additionalProperties"] == {"$ref": "#/$defs/artifactReference"}
        assert schema["properties"]["counts"]["additionalProperties"] == {"type": "integer", "minimum": 0}

    # The records: exactly the dataclasses the document's arrays reach, field for field.
    arrays = DOCUMENT_ARRAYS[schema_id]
    for name, kind in arrays.items():
        assert schema["properties"][name] == {"type": "array", "items": {"$ref": f"#/$defs/{kind.__name__}"}}
    expected = _reachable([Origin, *arrays.values()])
    assert {name for name in definitions if name in RECORDS} == {item.__name__ for item in expected}
    used_vocabularies: set[str] = set()
    for kind in sorted(expected, key=lambda item: item.__name__):
        body = definitions[kind.__name__]
        names = [item.name for item in fields(kind)]
        assert list(body["properties"]) == names, f"{kind.__name__} fields drifted from the contract"
        assert body["required"] == names and body["additionalProperties"] is False
        for name, hint in get_type_hints(kind).items():
            found, entry = _classes(hint), body["properties"][name]
            for vocabulary in found & set(VOCABULARIES.values()):
                assert entry == {"$ref": f"#/$defs/{vocabulary.__name__}"}
                used_vocabularies.add(vocabulary.__name__)
            for nested in found & set(RECORDS.values()):
                target = entry["items"] if get_origin(hint) is tuple else entry
                assert target == {"$ref": f"#/$defs/{nested.__name__}"}

    # The vocabularies: every enum keyword in the file is a contract vocabulary, value for value.
    assert {name for name in definitions if name in VOCABULARIES} == used_vocabularies
    enums = {pointer: node["enum"] for pointer, node in nodes.items() if isinstance(node.get("enum"), list)}
    for name in sorted(used_vocabularies):
        assert enums.pop(f"/$defs/{name}") == [item.value for item in VOCABULARIES[name]]
    if "EvidenceRef" in definitions:
        kinds, reference = enums.pop("/$defs/EvidenceRef/properties/kind"), _ref()
        values = {item.name: getattr(reference, item.name) for item in fields(EvidenceRef)}
        for kind in kinds:
            assert EvidenceRef(**{**values, "kind": kind}).kind == kind
        assert len(kinds) == len(set(kinds)) == 2  # the contract names two evidence kinds
    if "producerGap" in definitions:
        assert enums.pop("/$defs/producerGap/properties/code") == [item.value for item in GapCode]
    assert enums == {}, "an enum that no contract vocabulary accounts for"


def test_the_gap_record_mirrors_the_job_control_schema() -> None:
    control = json.loads(application_asset("docs/schemas/job-control.schema.json").read_text(encoding="utf-8"))["$defs"]
    ours, theirs = _schema(RESULT_SCHEMA)["$defs"], control["producerGap"]
    mirrored = ours["producerGap"]
    assert sorted(mirrored["properties"]) == sorted(theirs["properties"])
    assert sorted(mirrored["required"]) == sorted(theirs["required"])
    for name in ("schema", "code", "retryable"):
        assert mirrored["properties"][name] == theirs["properties"][name]
    assert mirrored["properties"]["evidence_refs"]["maxItems"] == theirs["properties"]["evidence_refs"]["maxItems"]
    assert mirrored["properties"]["unit_id"]["pattern"] == control["unitId"]["pattern"]
    assert sorted(ours["artifactReference"]["properties"]) == sorted(control["artifactReference"]["properties"])
    assert ours["sha256"]["pattern"] == control["sha256"]["pattern"]


@pytest.mark.parametrize("schema_id", SCHEMA_IDS, ids=[item.split("/")[1] for item in SCHEMA_IDS])
def test_a_canonical_example_of_each_document_validates(schema_id: str) -> None:
    document = _documents()[schema_id]
    assert document["schema"] == schema_id
    schemas.validate_document(document)
    for name, kind in DOCUMENT_ARRAYS[schema_id].items():
        assert document[name], f"the example exercises {kind.__name__}"
    assert schemas.schema_path(schema_id).name == schemas.SCHEMA_FILES[schema_id]
    assert schemas.validator(schema_id) is schemas.validator(schema_id), "each schema file is loaded once"


SURPLUS = "surplus_key"
REFUSED = {
    "extra-actor": (THREAT_MODEL_SCHEMA, ("actors", 0, SURPLUS), 1, "$.actors[0]"),
    "extra-artifact": (RESULT_SCHEMA, ("artifacts", "dfd", SURPLUS), 1, "$.artifacts.dfd"),
    "extra-asset": (THREAT_MODEL_SCHEMA, ("assets", 0, SURPLUS), 1, "$.assets[0]"),
    "extra-boundary": (DFD_SCHEMA, ("boundaries", 0, SURPLUS), 1, "$.boundaries[0]"),
    "extra-dfd": (DFD_SCHEMA, (SURPLUS,), 1, "$"),
    "extra-element": (DFD_SCHEMA, ("elements", 0, SURPLUS), 1, "$.elements[0]"),
    "extra-entry-point": (THREAT_MODEL_SCHEMA, ("entry_points", 0, SURPLUS), 1, "$.entry_points[0]"),
    "extra-evidence": (EVIDENCE_SCHEMA, (SURPLUS,), 1, "$"),
    "extra-flow": (DFD_SCHEMA, ("flows", 0, SURPLUS), 1, "$.flows[0]"),
    "extra-gap": (RESULT_SCHEMA, ("gaps", 0, SURPLUS), 1, "$.gaps[0]"),
    "extra-gap-reference": (RESULT_SCHEMA, ("gaps", 0, "evidence_refs", 0, SURPLUS), 1,
                            "$.gaps[0].evidence_refs[0]"),
    "extra-ledger-row": (RESULT_SCHEMA, ("input_ledger", 0, SURPLUS), 1, "$.input_ledger[0]"),
    "extra-mitigation": (THREAT_MODEL_SCHEMA, ("threats", 0, "mitigation", SURPLUS), 1, "$.threats[0].mitigation"),
    "extra-model": (THREAT_MODEL_SCHEMA, ("origin", "model", SURPLUS), 1, "$.origin.model"),
    "extra-origin": (EVIDENCE_SCHEMA, ("origin", SURPLUS), 1, "$.origin"),
    "extra-publication": (EVIDENCE_SCHEMA, ("references", 0, "publication", SURPLUS), 1,
                          "$.references[0].publication"),
    "extra-reference": (EVIDENCE_SCHEMA, ("references", 0, SURPLUS), 1, "$.references[0]"),
    "extra-reference-data": (DFD_SCHEMA, ("origin", "reference_data", SURPLUS), SHA_A, "$.origin.reference_data"),
    "extra-result": (RESULT_SCHEMA, (SURPLUS,), 1, "$"),
    "extra-threat": (THREAT_MODEL_SCHEMA, ("threats", 0, SURPLUS), 1, "$.threats[0]"),
    "extra-threat-model": (THREAT_MODEL_SCHEMA, (SURPLUS,), 1, "$"),
    "extra-unknown": (DFD_SCHEMA, ("unknowns", 0, SURPLUS), 1, "$.unknowns[0]"),
    "value-basis": (DFD_SCHEMA, ("elements", 0, "basis"), "guessed", "$.elements[0].basis"),
    "value-boundary-kind": (DFD_SCHEMA, ("boundaries", 0, "kind"), "moat", "$.boundaries[0].kind"),
    "value-element-kind": (DFD_SCHEMA, ("elements", 0, "kind"), "trust_boundary", "$.elements[0].kind"),
    "value-evidence-basis": (EVIDENCE_SCHEMA, ("references", 0, "basis"), "guessed", "$.references[0].basis"),
    "value-evidence-kind": (EVIDENCE_SCHEMA, ("references", 0, "kind"), "target_statement", "$.references[0].kind"),
    "value-gap-code": (RESULT_SCHEMA, ("gaps", 0, "code"), "clean", "$.gaps[0].code"),
    "value-input-state": (RESULT_SCHEMA, ("input_ledger", 0, "state"), "skipped", "$.input_ledger[0].state"),
    "value-interaction": (DFD_SCHEMA, ("flows", 0, "interaction"), "teleport", "$.flows[0].interaction"),
    "value-mitigation-state": (THREAT_MODEL_SCHEMA, ("threats", 0, "mitigation", "state"), "absent",
                               "$.threats[0].mitigation.state"),
    "value-name-basis": (DFD_SCHEMA, ("elements", 0, "name_basis"), "invented", "$.elements[0].name_basis"),
    "value-stride": (THREAT_MODEL_SCHEMA, ("threats", 0, "stride"), "lateral_movement", "$.threats[0].stride"),
    "value-threat-state": (THREAT_MODEL_SCHEMA, ("threats", 0, "state"), "confirmed", "$.threats[0].state"),
    "value-unknown-kind": (THREAT_MODEL_SCHEMA, ("unknowns", 0, "kind"), "unknown_unknown", "$.unknowns[0].kind"),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_an_extra_key_or_an_unknown_vocabulary_value_fails(case: str) -> None:
    schema_id, path, value, where = REFUSED[case]
    with pytest.raises(ValueError) as refusal:
        schemas.validate_document(_changed(schema_id, path, value))
    message = str(refusal.value)
    assert schema_id in message and f"at {where}: " in message, message
    assert (SURPLUS if path[-1] == SURPLUS else repr(value)) in message, message


EVIDENCED = {
    "actor": (THREAT_MODEL_SCHEMA, ("actors", 0)),
    "asset": (THREAT_MODEL_SCHEMA, ("assets", 0)),
    "boundary": (DFD_SCHEMA, ("boundaries", 0)),
    "element": (DFD_SCHEMA, ("elements", 0)),
    "entry-point": (THREAT_MODEL_SCHEMA, ("entry_points", 0)),
    "flow": (DFD_SCHEMA, ("flows", 0)),
    "threat": (THREAT_MODEL_SCHEMA, ("threats", 0)),
}


@pytest.mark.parametrize("case", sorted(EVIDENCED))
def test_an_element_flow_boundary_or_threat_with_empty_evidence_fails(case: str) -> None:
    schema_id, path = EVIDENCED[case]
    where = f"$.{path[0]}[{path[1]}]"
    with pytest.raises(ValueError, match=r"evidence: \[\] ") as refusal:
        schemas.validate_document(_changed(schema_id, (*path, "evidence"), []))
    assert f"at {where}.evidence:" in str(refusal.value)
    missing = copy.deepcopy(_documents()[schema_id])
    del _at(missing, path)["evidence"]
    with pytest.raises(ValueError, match="'evidence' is a required property"):
        schemas.validate_document(missing)
    stripped = _changed(schema_id, (*path, "evidence", 0), {"ref": _ref().ref})
    with pytest.raises(ValueError, match=r"evidence\[0\]"):
        schemas.validate_document(stripped)


def test_a_mitigation_or_candidate_that_contradicts_its_state_fails() -> None:
    threats = _documents()[THREAT_MODEL_SCHEMA]["threats"]
    found = next(index for index, item in enumerate(threats) if item["mitigation"]["state"] == "evidence_found")
    other = next(index for index, item in enumerate(threats) if item["mitigation"]["state"] == "not_examined")
    reference = threats[found]["mitigation"]["evidence"][0]
    for path, value in ((("threats", found, "mitigation", "evidence"), []),
                        (("threats", other, "mitigation", "evidence"), [reference]),
                        (("threats", found, "template_id"), None),
                        (("threats", found, "template_id"), "")):
        assert threats[found]["state"] == "candidate"
        with pytest.raises(ValueError, match=rf"threats\[{path[1]}\]"):
            schemas.validate_document(_changed(THREAT_MODEL_SCHEMA, path, value))


@pytest.mark.parametrize(("path", "value"), [
    (("elements", 0, "id"), "proc:0123"),
    (("elements", 0, "id"), "Proc:0123456789abcdef"),
    (("flows", 0, "source"), "server"),
    (("flows", 0, "evidence", 0, "ref"), "E12"),
    (("flows", 0, "evidence", 0, "publication", "sha256"), "A" * 64),
    (("flows", 0, "evidence", 0, "publication", "sha256"), "a" * 63),
    (("origin", "reference_data", "crosswalk_sha256"), "not-a-digest"),
    (("elements", 0, "name"), "  "),
], ids=["id-short", "id-upper", "id-plain", "ref-plain", "sha-upper", "sha-short", "sha-text", "name-blank"])
def test_identities_digests_and_names_are_pinned(path: tuple[Any, ...], value: str) -> None:
    with pytest.raises(ValueError, match="violates its schema"):
        schemas.validate_document(_changed(DFD_SCHEMA, path, value))


@pytest.mark.parametrize("schema_id", SCHEMA_IDS, ids=[item.split("/")[1] for item in SCHEMA_IDS])
def test_origin_cannot_be_target_supplied_or_authoritative(schema_id: str) -> None:
    origin = _documents()[schema_id]["origin"]
    assert (origin["kind"], origin["target_supplied"], origin["producer"], origin["authority"]) == (
        "generated", False, contract.JOB_ID, contract.AUTHORITY)
    for name, value in (("target_supplied", True), ("target_supplied", None), ("kind", "supplied"),
                        ("authority", "producer_evidence"), ("authority", "intent"),
                        ("producer", "job_target_catalog")):
        with pytest.raises(ValueError, match=rf"at \$\.origin\.{name}: "):
            schemas.validate_document(_changed(schema_id, ("origin", name), value))
    for name in ("kind", "target_supplied", "producer", "authority"):
        document = copy.deepcopy(_documents()[schema_id])
        del document["origin"][name]
        with pytest.raises(ValueError, match=rf"at \$\.origin: '{name}' is a required property"):
            schemas.validate_document(document)
    document = copy.deepcopy(_documents()[schema_id])
    del document["origin"]
    with pytest.raises(ValueError, match="'origin' is a required property"):
        schemas.validate_document(document)


def test_unknown_schema_id_is_refused() -> None:
    document = _documents()[DFD_SCHEMA]
    for schema_id in ("appsec-review/generated-dfd/2", contract.INTERACTION_CATALOG_SCHEMA, "", None, 1,
                      [DFD_SCHEMA]):
        with pytest.raises(ValueError, match="unknown threat-model document schema"):
            schemas.validate_document({**document, "schema": schema_id})
        with pytest.raises(ValueError, match="unknown threat-model document schema"):
            schemas.schema_path(schema_id)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown threat-model document schema"):
        schemas.validate_document({name: value for name, value in document.items() if name != "schema"})
    with pytest.raises(ValueError, match="must be a JSON object"):
        schemas.validate_document([document])  # type: ignore[arg-type]
    # A document is validated against the schema it names, never against the one a caller expected.
    with pytest.raises(ValueError, match=EVIDENCE_SCHEMA):
        schemas.validate_document({**document, "schema": EVIDENCE_SCHEMA})
