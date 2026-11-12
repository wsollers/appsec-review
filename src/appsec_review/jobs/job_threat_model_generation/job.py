"""job_threat_model_generation: a generated DFD and threat model from accepted evidence (T-107).

Design: docs/architecture/dfd-and-threat-model-generation.md sections 3, 4, 6, 7, 8 and 11. First
slice: deterministic only. There is no model step, no declarations lane, and no consumer reads the
output. The job reads accepted index shards through ``threat_model.index_view.IndexEvidenceView``
and nothing else: no checkout, no target tree, no other job's ``latest.json``.

Units hand records to later units only through attempt-owned canonical files under
``artifacts/threat-model/work/`` (read back with ``threat_model.codec`` after their digest is
checked against the reference in the producing unit's result) plus small JSON result values.

Gaps: every gap is a ``producer-gap/1`` record and is reported by the one unit that created it.
``publication.publish_handoff`` joins them into ``result.json`` and returns ``"gaps": []``. The
deployment inventory producer is not registered (T-108), which is one gap of ``load.accepted_inputs``
on every run, so the job always completes with gaps in this slice.

The job fails (a unit raises) only when the reference data is invalid or changed during the attempt,
an attempt-owned working file or an admitted input changed, or the documents violate their
contract. An absent optional input never fails it.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from typing import Any, Iterator, Mapping, Sequence

from appsec_review.config.loader import ThreatModelSettings, parse_threat_model_settings
from appsec_review.interchange import GapCode, producer_gap
from appsec_review.observability.spans import operation_span
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime.resources import Reservation, ResourceAdmission
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_bytes
from appsec_review.storage.shared import safe_path
from appsec_review.storage.validation import validation_scope
from appsec_review.threat_model import codec
from appsec_review.threat_model.assemble import Assembly, assemble
from appsec_review.threat_model.contract import (
    JOB_ID, RESULT_SCHEMA, InputLedgerRow, InputState, Origin, Threat, canonical,
)
from appsec_review.threat_model.documents import Documents, build_documents, plain
from appsec_review.threat_model.index_view import DECLARED_INPUTS, IndexEvidenceView
from appsec_review.threat_model.lanes import interactions as interaction_lane
from appsec_review.threat_model.lanes import structure as structure_lane
from appsec_review.threat_model.reference import Reference, load_reference
from appsec_review.threat_model.render import MARKDOWN_FILE, render_markdown, render_mermaid
from appsec_review.threat_model.threats import enumerate_threats
from appsec_review.threat_model.validate import resolve_citations, validate_documents
from appsec_review.threat_model.view import open_input, truncated_gap

from .datasets import ARTIFACT_DIRECTORY, CONTRACT, DATASETS

NAME = "threat_model_generation"
SCHEMA = RESULT_SCHEMA
LOAD, STRUCTURE, INTERACTIONS = "load.accepted_inputs", "facts.structure", "facts.interactions"
ASSEMBLY, THREATS, RESOLVE = "assembly.dfd", "threats.enumerate", "validation.resolve_citations"
RENDER, PUBLISH = "publication.render", "publication.publish_handoff"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "load": ("accepted_inputs",), "facts": ("structure", "interactions"), "assembly": ("dfd",),
    "threats": ("enumerate",), "validation": ("resolve_citations",), "publication": ("render", "publish_handoff"),
}
DEPLOYMENT_INPUT = ("job_deployment_inventory", "deployment_inventory")
DEPLOYMENT_GAP = "job_deployment_inventory/deployment_inventory producer is not registered (T-108)"
RENDER_BOUND = "publication.max_render_nodes"
LANE_INPUTS = frozenset((*structure_lane.INPUTS, interaction_lane.GRAPH_INPUT, interaction_lane.SYNTAX_INPUT,
                         interaction_lane.SIGNAL_INPUT))
# Declared inputs no lane of this slice opens; ``load.accepted_inputs`` records their ledger rows.
UNREAD_INPUTS = tuple(sorted(set(DECLARED_INPUTS) - LANE_INPUTS))
DOCUMENT_FILES = {"dfd": "dfd.json", "threat_model": "threat-model.json", "evidence": "evidence.json"}
RESULT_FILE = "result.json"
VIEW_DIRECTORY = "views"


class ThreatModelGenerationFailed(RuntimeError):
    """The job could not publish a valid generated model.

    Raised by the units: invalid or changed reference data, a working file of this attempt that is
    missing or whose bytes changed, a missing evidence target snapshot, documents that violate
    their contract, or views that do not re-render to the bytes ``publication.render`` wrote. An
    integrity failure of an admitted input keeps its own class (``UpstreamIntegrityError``).
    """


def _settings(context: Any) -> ThreatModelSettings:
    return parse_threat_model_settings(context.config.settings)


def _reference(unit: UnitContext, expected: Mapping[str, str] | None = None) -> Reference:
    try:
        reference = load_reference(unit.job.repository_root)
    except (OSError, ValueError) as error:
        raise ThreatModelGenerationFailed(f"threat-model reference data is invalid: {error}") from error
    if expected is not None and dict(reference.sha256s) != dict(expected):
        raise ThreatModelGenerationFailed("threat-model reference data changed during the attempt")
    return reference


def _view(unit: UnitContext) -> IndexEvidenceView:
    return IndexEvidenceView(unit.job.run_root, unit.job.upstream_handoffs)


def _write(unit: UnitContext, relative: str, payload: bytes) -> dict[str, Any]:
    path = unit.job.attempt_root / ARTIFACT_DIRECTORY / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(path, payload)
    return _identity(unit, relative, payload)


def _identity(unit: UnitContext, relative: str, payload: bytes) -> dict[str, Any]:
    path = unit.job.attempt_root / ARTIFACT_DIRECTORY / relative
    return {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload)}


def _read_bytes(unit: UnitContext, identity: Mapping[str, Any]) -> bytes:
    """The bytes of a working file of this attempt, checked against the producing unit's reference."""
    path = safe_path(unit.job.run_root, str(identity["path"]))
    if unit.job.attempt_root.resolve() not in path.resolve().parents or not path.is_file() or path.is_symlink():
        raise ThreatModelGenerationFailed(f"working file is not owned by this attempt: {identity['path']}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != identity["sha256"]:
        raise ThreatModelGenerationFailed(f"working file changed after it was written: {identity['path']}")
    return data


def _read(unit: UnitContext, unit_id: str) -> Any:
    try:
        return json.loads(_read_bytes(unit, unit.output(unit_id)["artifact"]))
    except ValueError as error:
        raise ThreatModelGenerationFailed(f"working file of {unit_id} is not valid JSON: {error}") from error


def _decoded(unit_id: str, read: Any, value: Any) -> Any:
    try:
        return read(value)
    except (ValueError, TypeError, KeyError) as error:
        raise ThreatModelGenerationFailed(f"working record of {unit_id} is invalid: {error}") from error


def _result(artifact: Mapping[str, Any], gaps: Sequence[Mapping[str, Any]], **payload: Any) -> dict[str, Any]:
    records = [dict(gap) for gap in gaps]
    return {"schema": SCHEMA, "artifact": dict(artifact), **payload, "gaps": records,
            "terminal_status": "COMPLETED_WITH_GAPS" if records else "SUCCEEDED"}


@contextmanager
def _reserved(unit: UnitContext, settings: ThreatModelSettings, action: str) -> Iterator[None]:
    """Hold the configured admission-ledger reservation while a lane reads index shards."""
    reservation = settings.reservation
    admission = ResourceAdmission(unit.job.metadata_root, unit.job.review_policy.resources)
    request = Reservation(reservation.cpu, reservation.memory_mb, reservation.io_slots)
    with admission.reserve(request, events=unit.job.events, action=action,
                           timeout_seconds=reservation.admission_timeout_seconds, unit_id=unit.unit_id) as lease_id, \
            operation_span(unit.job.events, action, unit_id=unit.unit_id, resource_lease_id=lease_id), \
            validation_scope(unit.job.run_root):
        yield


def _loaded(unit: UnitContext) -> tuple[Origin, tuple[InputLedgerRow, ...]]:
    value = _read(unit, LOAD)
    return (_decoded(LOAD, codec.origin_from_plain, value.get("origin")),
            tuple(_decoded(LOAD, codec.ledger_row_from_plain, row) for row in value.get("ledger", ())))


def _lane(unit: UnitContext, unit_id: str) -> Any:
    return _decoded(unit_id, codec.lane_result_from_plain, _read(unit, unit_id))


def _validated(unit: UnitContext) -> tuple[Assembly, tuple[Threat, ...]]:
    value = _read(unit, RESOLVE)
    return (_decoded(RESOLVE, codec.assembly_from_plain, value.get("assembly")),
            _decoded(RESOLVE, codec.threats_from_plain, value.get("threats")))


def _joined(unit: UnitContext, unit_ids: Sequence[str]) -> list[Mapping[str, Any]]:
    """The gap records the named units reported, each once (the unit that created a gap owns it)."""
    return [gap for unit_id in unit_ids for gap in unit.output(unit_id)["gaps"]]


def _documents(unit: UnitContext, gaps: Sequence[Mapping[str, Any]],
               artifacts: Mapping[str, Mapping[str, Any]] | None = None) -> Documents:
    origin, rows = _loaded(unit)
    ledger = [*rows, *_lane(unit, STRUCTURE).ledger, *_lane(unit, INTERACTIONS).ledger]
    assembly, threats = _validated(unit)
    return build_documents(origin, assembly, threats, ledger, gaps, artifacts=artifacts)


def _views(documents: Documents, settings: ThreatModelSettings) -> tuple[dict[str, bytes], bool]:
    """File name to bytes of every generated view, and whether the render bound was reached."""
    dfd = plain(documents.dfd)
    diagrams, truncated = render_mermaid(dfd, settings.limits)
    views = {name: text.encode("utf-8") for name, text in diagrams.items()}
    views[MARKDOWN_FILE] = render_markdown(dfd, plain(documents.threat_model), plain(documents.result)).encode("utf-8")
    return dict(sorted(views.items())), truncated


def build_job() -> Job:
    def validate_config(context, _result) -> None:
        steps = {step: tuple(context.config.step(step).tasks) for step in context.config.steps}
        if tuple(steps) != tuple(TOPOLOGY) or steps != dict(TOPOLOGY):
            raise ValueError("threat-model job topology does not match configuration")
        _settings(context)

    def load(unit: UnitContext) -> Mapping[str, Any]:
        reference = _reference(unit)
        if not unit.job.evidence_target_snapshot:
            raise ThreatModelGenerationFailed("the attempt has no evidence target snapshot")
        origin = Origin(unit.job.run_id, unit.job.attempt_id, unit.job.evidence_target_snapshot, reference.sha256s,
                        model=None)
        rows: list[InputLedgerRow] = []
        gaps: list[Mapping[str, Any]] = []
        view = _view(unit)
        with validation_scope(unit.job.run_root):
            for producer, output_kind in UNREAD_INPUTS:
                opened = open_input(view, producer, output_kind, unit_id=unit.unit_id)
                rows.append(opened.row)
                gaps.extend(opened.gaps)
        rows.append(InputLedgerRow(*DEPLOYMENT_INPUT, InputState.NOT_REGISTERED))
        gaps.append(producer_gap(GapCode.INPUT_UNAVAILABLE, DEPLOYMENT_GAP, unit_id=unit.unit_id,
                                 scope_id=DEPLOYMENT_INPUT[0]))
        artifact = _write(unit, "work/inputs.json", canonical({"origin": origin, "ledger": rows}))
        return _result(artifact, gaps, reference_data=dict(reference.sha256s),
                       counts={"declared_inputs": len(DECLARED_INPUTS) + 1, "ledger_rows": len(rows)})

    def facts(unit: UnitContext, name: str, run: Any) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        with _reserved(unit, settings, f"threat_model.facts_{name}"):
            result = run(_view(unit), settings)
        artifact = _write(unit, f"work/{name}.json", canonical(result))
        kinds = [fact.kind.value for fact in result.facts]
        return _result(artifact, result.gaps,
                       counts={"facts": len(kinds), **{kind: kinds.count(kind) for kind in sorted(set(kinds))},
                               "records_read": sum(row.records_read for row in result.ledger)})

    def structure(unit: UnitContext) -> Mapping[str, Any]:
        return facts(unit, "structure", lambda view, settings: structure_lane.structure(
            view, settings.limits, unit_id=unit.unit_id))

    def interactions(unit: UnitContext) -> Mapping[str, Any]:
        reference = _reference(unit, unit.output(LOAD)["reference_data"])
        return facts(unit, "interactions", lambda view, settings: interaction_lane.interactions(
            view, reference, settings.limits, unit_id=unit.unit_id))

    def assembly_dfd(unit: UnitContext) -> Mapping[str, Any]:
        reference = _reference(unit, unit.output(LOAD)["reference_data"])
        lanes = [_lane(unit, STRUCTURE), _lane(unit, INTERACTIONS)]
        assembly = assemble(lanes, reference, _settings(unit.job).limits, unit_id=unit.unit_id)
        artifact = _write(unit, "work/assembly.json", canonical(assembly))
        return _result(artifact, assembly.gaps, counts={
            "elements": len(assembly.elements), "flows": len(assembly.flows), "boundaries": len(assembly.boundaries),
            "entry_points": len(assembly.entry_points), "actors": len(assembly.actors),
            "unknowns": len(assembly.unknowns)})

    def threats_enumerate(unit: UnitContext) -> Mapping[str, Any]:
        reference = _reference(unit, unit.output(LOAD)["reference_data"])
        assembly = _decoded(ASSEMBLY, codec.assembly_from_plain, _read(unit, ASSEMBLY))
        threats, gaps = enumerate_threats(assembly, reference, _settings(unit.job).limits, unit_id=unit.unit_id)
        artifact = _write(unit, "work/threats.json", canonical({"threats": threats}))
        return _result(artifact, gaps, counts={"threats": len(threats)})

    def resolve(unit: UnitContext) -> Mapping[str, Any]:
        assembly = _decoded(ASSEMBLY, codec.assembly_from_plain, _read(unit, ASSEMBLY))
        threats = _decoded(THREATS, codec.threats_from_plain, _read(unit, THREATS).get("threats"))
        cited = len({item.ref for record in (*assembly.elements, *assembly.flows, *assembly.boundaries,
                                              *assembly.entry_points, *assembly.actors, *threats)
                     for item in record.evidence})
        view = _view(unit)
        with validation_scope(unit.job.run_root):
            kept, remaining, gaps = resolve_citations(assembly, threats, view.resolves, unit_id=unit.unit_id)
        artifact = _write(unit, "work/validated.json", canonical({"assembly": kept, "threats": remaining}))
        return _result(artifact, gaps, counts={
            "citations": cited, "demoted": len(gaps), "elements": len(kept.elements), "flows": len(kept.flows),
            "threats": len(remaining)})

    def render(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        earlier = _joined(unit, (LOAD, STRUCTURE, INTERACTIONS, ASSEMBLY, THREATS, RESOLVE))
        views, truncated = _views(_documents(unit, earlier), settings)
        gaps = [truncated_gap(RENDER_BOUND, settings.limits.max_render_nodes, unit_id=unit.unit_id)] if truncated else []
        if gaps:  # the Markdown view lists every gap, this one included
            views, _ = _views(_documents(unit, [*earlier, *gaps]), settings)
        written = {name: _write(unit, f"{VIEW_DIRECTORY}/{name}", data) for name, data in views.items()}
        return _result(written[MARKDOWN_FILE], gaps, views=written, counts={"views": len(written)})

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        gaps = _joined(unit, (LOAD, STRUCTURE, INTERACTIONS, ASSEMBLY, THREATS, RESOLVE, RENDER))
        rendered = {name: dict(identity) for name, identity in unit.output(RENDER)["views"].items()}
        first = _documents(unit, gaps)
        payloads = {"dfd": canonical(first.dfd), "threat_model": canonical(first.threat_model),
                    "evidence": canonical(first.evidence)}
        artifacts = {DOCUMENT_FILES[name]: _identity(unit, DOCUMENT_FILES[name], data)
                     for name, data in payloads.items()}
        artifacts.update({f"{VIEW_DIRECTORY}/{name}": identity for name, identity in rendered.items()})
        documents = _documents(unit, gaps, artifacts)
        try:
            validate_documents(plain(documents.dfd), plain(documents.threat_model), plain(documents.evidence),
                               plain(documents.result))
        except ValueError as error:
            raise ThreatModelGenerationFailed(str(error)) from error
        if (canonical(documents.dfd), canonical(documents.threat_model), canonical(documents.evidence)) != (
                payloads["dfd"], payloads["threat_model"], payloads["evidence"]):
            raise ThreatModelGenerationFailed("published documents are not a pure function of the working records")
        # The views are generated: re-render from what is about to be published and compare bytes.
        views, _ = _views(documents, settings)
        if set(views) != set(rendered) or any(_read_bytes(unit, rendered[name]) != data for name, data in views.items()):
            raise ThreatModelGenerationFailed("generated views differ from a fresh render of the published documents")
        for name, data in payloads.items():
            _write(unit, DOCUMENT_FILES[name], data)
        result = _write(unit, RESULT_FILE, canonical(documents.result))
        counts = dict(plain(documents.result)["counts"])
        unit.job.events.write("THREAT_MODEL_PUBLISHED", unit_id=unit.unit_id, counts=counts, gap_count=len(gaps),
                              artifact=result)
        # The joined gaps are payload of result.json; the units that created them declared them.
        return {"schema": SCHEMA, "artifact": result, "artifacts": {**artifacts, RESULT_FILE: result},
                "counts": counts, "joined_gap_count": len(gaps), "gaps": [], "terminal_status": "SUCCEEDED"}

    units = (
        Unit(LOAD, load),
        Unit(STRUCTURE, structure, (LOAD,)),
        Unit(INTERACTIONS, interactions, (LOAD,)),
        Unit(ASSEMBLY, assembly_dfd, (STRUCTURE, INTERACTIONS)),
        Unit(THREATS, threats_enumerate, (ASSEMBLY,)),
        Unit(RESOLVE, resolve, (THREATS,)),
        Unit(RENDER, render, (RESOLVE,)),
        Unit(PUBLISH, publish, (RENDER,)),
    )
    return Job(JOB_ID, NAME, UnitExecutor(units).execute, input_validators=(validate_config,),
               schema_identity=SCHEMA, units=units, datasets=DATASETS, contract=CONTRACT, strict_gaps=True)
