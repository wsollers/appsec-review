"""T-5000: hunt packages reference their unit's context once (``package-unit-context/1``, package schema v7).

The measured defect: every partition of a hunted unit embedded the unit-wide ``context``, ``scope.source_ids``
and ``retrieval.entity_ids``, so the byte cap split 25-lead chunks down to one to three leads. These tests
show that the partition size means what it says, that the reference is hash-pinned and verified, and that the
view, label table and cell request resolved through the reference keep the same citable identities while the
request shrinks.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.cells import run_cell
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.models import CellStatus, IntegrityError, Lane
from appsec_review.review.package_view import UNIT_CONTEXT_FILE, ViewLimits, build_view
from appsec_review.review.packages import (
    UNIT_CONTEXT_SCHEMA, PackageSettings, assemble_packages, publish_packages, resolve_package_document,
    verify_package_manifest,
)
from appsec_review.review.scope import accept_manifest
from appsec_review.storage.atomic import canonical_json
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.review.test_cells import FakeCore, ScriptedInfer, capability as cell_capability, final, spec as cell_spec, validate

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
UNIT_CONTEXT_SCHEMA_DOCUMENT = json.loads(
    (ROOT / "docs" / "schemas" / "review-package-unit-context.schema.json").read_text(encoding="utf-8"))
NATIVE_UNIT = "unit:component:0002:-:native-main:r0000"
LIMITS = ViewLimits(48 * 1024, 160, 6)
CAP = 64 * 1024


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("unitctx"))


@pytest.fixture(scope="module")
def assembly(fixture):
    return assemble_packages(accept_manifest(fixture.run_root))


def _with_synthetic_leads(collection, template_id: str, count: int):
    """``count`` more medium-severity leads in the template's file: hunted with the unit, never admitted to lane A."""
    template = next(lead for lead in collection.leads if lead.observation_id == template_id)
    extra = [replace(template, observation_id="asr:tool_observation:" + hashlib.sha256(f"t153-{number}".encode()).hexdigest(),
                     reported_severity="medium", duplicate_of=None, flow_ids=(), related=(), coverage_gaps=(),
                     advisory=None, control_assessment=None, start_line=3 + number % 5,
                     message=f"synthetic lead {number}")
             for number in range(count)]
    return replace(collection, leads=tuple(sorted((*collection.leads, *extra), key=lambda lead: lead.observation_id)))


def _native_hunts(assembly) -> list:
    hunts = [item for item in assembly.packages if item.kind == "hunt" and item.unit_key == NATIVE_UNIT]
    return sorted(hunts, key=lambda item: item.document()["partition"]["number"])


def _unit_context(assembly, unit_key: str = NATIVE_UNIT):
    [found] = [item for item in assembly.unit_contexts if item.unit_key == unit_key]
    return found


# (a) ---------------------------------------------------------------------------------------------- partitions


def test_sixty_five_leads_with_partition_size_25_yield_exactly_three_hunt_packages(fixture, tmp_path: Path) -> None:
    scope = accept_manifest(fixture.run_root)
    collection = _with_synthetic_leads(collect_leads(scope), fixture.ids["sast_critical"], 60)
    settings = PackageSettings(hunt_menu_partition_size=25)
    assembly = assemble_packages(scope, settings, collection=collection)
    hunts = _native_hunts(assembly)
    assert len(hunts) == 3 == -(-65 // 25)
    assert [item.document()["partition"] for item in hunts] == [{"number": number, "count": 3} for number in range(3)]
    assert sum(len(item.lead_ids) for item in hunts) == 65 and all(len(item.body) <= CAP for item in hunts)
    assert [len(item.lead_ids) for item in hunts] == [25, 25, 15]
    assert assembly.manifest["audit"]["lane_b"]["status"] == "passed"
    # Lane A never saw the synthetic medium leads: they are hunted, not admitted.
    assert not any(set(item.lead_ids) - {fixture.ids[key] for key in fixture.ids}
                   for item in assembly.packages if item.kind == "finding_lead")

    unit_context = _unit_context(assembly)
    jsonschema.validate(unit_context.document, UNIT_CONTEXT_SCHEMA_DOCUMENT)
    assert unit_context.document["unit_key"] == NATIVE_UNIT and unit_context.body == canonical_json(unit_context.document)
    references = {json.dumps(item.document()["unit_context"], sort_keys=True) for item in hunts}
    assert len(references) == 1, "every partition references the same unit context"
    reference = hunts[0].document()["unit_context"]
    assert reference == {"schema": UNIT_CONTEXT_SCHEMA, "path": f"unit-context/{unit_context.sha256}.json",
                         "sha256": hashlib.sha256(unit_context.body).hexdigest(), "size_bytes": len(unit_context.body),
                         "counts": {"context_entries": len(unit_context.document["context"]),
                                    "source_ids": len(unit_context.document["scope"]["source_ids"]),
                                    "entity_ids": len(unit_context.document["entity_ids"])}}
    assert reference["counts"]["context_entries"] >= 1 and reference["counts"]["source_ids"] >= 1
    unit_entities = set(unit_context.document["entity_ids"])
    assert set(unit_context.document["scope"]["source_ids"]) <= unit_entities
    assert {entry["id"] for entry in unit_context.document["context"]} <= unit_entities
    for package in hunts:
        body = package.document()
        jsonschema.validate(body, PACKAGE_SCHEMA)
        assert body["context"] == [] and "source_ids" not in body["scope"]
        assert not set(body["retrieval"]["entity_ids"]) & unit_entities, "the body holds only partition identities"
        assert set(package.lead_ids) <= set(body["retrieval"]["entity_ids"])
        resolved = package.resolved()
        assert resolved["scope"]["source_ids"] == unit_context.document["scope"]["source_ids"]
        assert resolved["context"] == unit_context.document["context"]
        assert resolved["retrieval"]["entity_ids"] == sorted({*body["retrieval"]["entity_ids"], *unit_entities})
        assert resolved["unit_context"] == reference
    # Lead-lane bodies are unchanged: per-lead context stays embedded, no reference.
    for package in (item for item in assembly.packages if item.kind == "finding_lead"):
        body = package.document()
        assert body["unit_context"] is None and isinstance(body["scope"]["source_ids"], list) and package.unit_context is None
        assert package.resolved() == body

    manifest = assembly.manifest
    [entry] = [item for item in manifest["unit_contexts"] if item["unit_key"] == NATIVE_UNIT]
    assert entry == {"unit_key": NATIVE_UNIT, "schema": UNIT_CONTEXT_SCHEMA, "path": reference["path"],
                     "sha256": unit_context.sha256, "bytes": len(unit_context.body), "counts": reference["counts"]}
    assert {item["unit_key"] for item in manifest["unit_contexts"]} == {item.unit_key for item in assembly.unit_contexts} \
        == {row["unit_key"] for row in manifest["units"] if row["hunted"]}
    assert all(item["unit_context_sha256"] == unit_context.sha256
               for item in manifest["packages"] if item["unit_key"] == NATIVE_UNIT)
    assert all(item["unit_context_sha256"] is None for item in manifest["packages"] if item["kind"] == "finding_lead")

    # The cap now applies to the partition's own body: a cap the inline form could not have met still
    # yields three partitions, and the published tree verifies.
    largest = max(len(item.body) for item in assembly.packages)
    cap = largest + 256
    assert cap < max(len(item.body) for item in hunts) + len(unit_context.body), "premise: inline form exceeds the cap"
    capped = assemble_packages(scope, replace(settings, max_package_bytes=cap), collection=collection)
    assert [len(item.lead_ids) for item in _native_hunts(capped)] == [25, 25, 15]
    assert _unit_context(capped).sha256 == unit_context.sha256, "the unit context does not depend on the cap"

    manifest_path = publish_packages(assembly, tmp_path / "assembly")
    assert (tmp_path / "assembly" / reference["path"]).read_bytes() == unit_context.body
    verify_package_manifest(manifest_path)
    for package in hunts:
        path = tmp_path / "assembly" / "packages" / f"{package.package_id}.json"
        assert resolve_package_document(path) == package.resolved()
    again = assemble_packages(scope, settings, collection=collection)
    assert [item.body for item in again.packages] == [item.body for item in assembly.packages]
    assert again.manifest_bytes == assembly.manifest_bytes


# (b) ---------------------------------------------------------------------------------------------- verification


def test_verify_refuses_a_package_whose_unit_context_hash_does_not_match(assembly, tmp_path: Path) -> None:
    out = tmp_path / "assembly"
    manifest_path = publish_packages(assembly, out)
    assert verify_package_manifest(manifest_path)["unit_contexts"]
    unit_context = _unit_context(assembly)
    hunt = _native_hunts(assembly)[0]
    package_path = out / "packages" / f"{hunt.package_id}.json"
    path = out / unit_context.path
    original = path.read_bytes()

    tampered = json.loads(original)
    tampered["context"].append({"id": "asr:component:" + "0" * 64, "kind": "component", "role": "component"})
    path.write_bytes(canonical_json(tampered))
    with pytest.raises(IntegrityError, match="unit context does not match its reference"):
        verify_package_manifest(manifest_path)
    with pytest.raises(IntegrityError, match="unit context does not match its reference"):
        resolve_package_document(package_path)

    # A manifest rewritten to list the tampered bytes still fails the package's own pin.
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    moved = out / "unit-context" / f"{new_sha}.json"
    path.rename(moved)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("content_sha256")
    entry = next(item for item in manifest["unit_contexts"] if item["sha256"] == unit_context.sha256)
    entry.update(sha256=new_sha, bytes=moved.stat().st_size, path=f"unit-context/{new_sha}.json")
    entry["counts"]["context_entries"] += 1
    manifest["content_sha256"] = sha256_hex(manifest)
    manifest_path.write_bytes(canonical_json(manifest))
    with pytest.raises(IntegrityError, match="unlisted unit context|reference does not match the manifest"):
        verify_package_manifest(manifest_path)

    # Restored bytes verify again; a package that names an unlisted document is refused.
    moved.rename(path)
    path.write_bytes(original)
    manifest["unit_contexts"] = [item for item in manifest["unit_contexts"] if item["sha256"] != new_sha]
    manifest.pop("content_sha256")
    manifest["content_sha256"] = sha256_hex(manifest)
    manifest_path.write_bytes(canonical_json(manifest))
    with pytest.raises(IntegrityError, match="unlisted unit context|does not match the manifest"):
        verify_package_manifest(manifest_path)


# (c) ---------------------------------------------------------------------------------------------- view and labels


@pytest.fixture(scope="module")
def views(fixture, assembly):
    core = RetrievalCore(fixture.runs_dir, fixture.run_id)
    hunt = _native_hunts(assembly)[0]
    resolved = hunt.resolved()
    inline = {**resolved, "unit_context": None}          # the pre-v7 shape: the same material, embedded
    return hunt, resolved, build_view(resolved, core, LIMITS), build_view(inline, core, LIMITS)


def test_view_resolved_through_the_reference_keeps_the_citable_identities(views) -> None:
    hunt, resolved, referenced, inline = views
    assert referenced.packaged_refs == inline.packaged_refs
    assert set(hunt.lead_ids) <= referenced.packaged_refs
    assert set(resolved["retrieval"]["entity_ids"]) <= referenced.packaged_refs
    assert referenced.lead_refs == inline.lead_refs
    # The T and O rows become one hash-referenced file; every row's identity stays citable.
    inline_rows = {row["ref"] for row in (*inline.document["tags"], *inline.document["other_context"])}
    assert inline_rows, "the inline form shows unit context rows"
    assert referenced.document["tags"] == [] and referenced.document["other_context"] == []
    assert {row["ref"] for row in referenced.files[UNIT_CONTEXT_FILE]} == inline_rows
    assert referenced.document["unit_context"] == {
        "schema": UNIT_CONTEXT_SCHEMA, "sha256": resolved["unit_context"]["sha256"],
        "size_bytes": resolved["unit_context"]["size_bytes"], "counts": resolved["unit_context"]["counts"],
        "file": UNIT_CONTEXT_FILE}
    assert referenced.document["files"][UNIT_CONTEXT_FILE]["count"] == len(inline_rows)
    page = referenced.file_page(UNIT_CONTEXT_FILE, 0, 3)
    assert page["count"] == len(inline_rows) and page["rows"] == list(referenced.files[UNIT_CONTEXT_FILE][:3])
    assert inline.document["unit_context"] is None and UNIT_CONTEXT_FILE not in inline.document["files"]
    # Labels agree outside the T/O rows; the label table resolves every unit identity cited raw.
    assert {label: ref for label, ref in inline.labels.items() if label[0] not in "TO"} == referenced.labels
    table = referenced.table(hunt.lead_ids)
    for ref in sorted(inline_rows)[:5]:
        assert table.resolve(ref) == ref and table.label_for(ref) is None
    assert table.resolve("asr:component:" + "0" * 64) is None
    # The unit's identities reach the model through the file and the tools, not through the view document.
    rendered = json.dumps(referenced.document)
    assert not any(ref in rendered for ref in inline_rows) and '"entity_ids": [' not in rendered


# (d) ---------------------------------------------------------------------------------------------- cell request


def test_cell_request_for_a_hunt_package_is_smaller_and_still_validates(views, tmp_path: Path) -> None:
    hunt, _resolved, referenced, inline = views
    lead = hunt.lead_ids[0]

    def request_size(view, name: str) -> int:
        infer = ScriptedInfer(final(lead))
        cap = cell_capability(entities=tuple(sorted(view.packaged_refs)), tools=("find", "read_excerpt", "expand"))
        spec = cell_spec(lane=Lane.HUNT, task_input={"view": view.document}, evidence_set=tuple(sorted(view.packaged_refs)))
        outcome = run_cell(replace(spec, view=view), infer=infer, core=FakeCore(), capability=cap,
                           receipts_root=tmp_path / name, validate_final=validate)
        assert outcome.record.status is CellStatus.SUCCEEDED
        [request] = infer.requests
        assert request.task_input["input"]["view"]["rule"] == "appsec-review/package-view/6"
        return len(canonical_json(asdict(request)))

    smaller, larger = request_size(referenced, "referenced"), request_size(inline, "inline")
    assert smaller < larger
    assert larger - smaller >= 0.5 * len(canonical_json(inline.files.get(UNIT_CONTEXT_FILE, ()) or
                                                         [*inline.document["tags"], *inline.document["other_context"]]))
