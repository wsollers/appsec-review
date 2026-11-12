"""The threat-model reference data (T-107): closed shapes, complete vocabularies, no target names."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Callable

import pytest

from appsec_review.graph.contract import ATTACKER_REACHABLE_SOURCES, SinkClass, SourceClass
from appsec_review.jobs.job_review_prioritization import rules, scoring
from appsec_review.observability.findings.contracts import AttackerPosition
from appsec_review.threat_model import contract
from appsec_review.threat_model.contract import BoundaryKind, Interaction, Origin, Stride
from appsec_review.threat_model.reference import (
    CROSSWALK_FILE, INTERACTION_CATALOG_FILE, REFERENCE_DIRECTORY, SHA256_KEYS, THREAT_TEMPLATES_FILE, BoundaryRule,
    Reference, Template, load_reference, load_reference_from,
)

ROOT = Path(__file__).resolve().parents[1]
FILES = (INTERACTION_CATALOG_FILE, THREAT_TEMPLATES_FILE, CROSSWALK_FILE)
TARGET_WORDS = ("appsec-multi-vuln", "civ", "ddnet", "freeciv", "multivuln", "northwinds")
ASSERTING_PHRASES = ("critical", "high risk", "is vulnerable", "severity")
OWASP_CATALOGS = {  # crosswalk key -> (pinned catalog file, record id -> chapter, group or entry id)
    "api_top10_2023": ("api-top10-2023.json", lambda value: value),
    "asvs": ("asvs-5.0.0.json", lambda value: value.split(".")[0]),
    "masvs": ("masvs-2.1.0.json", lambda value: value.rsplit("-", 1)[0]),
    "top10_2025": ("top10-2025.json", lambda value: value),
}


def _reference() -> Reference:
    return load_reference(ROOT)


def _document(name: str) -> dict:
    return json.loads((ROOT / REFERENCE_DIRECTORY / name).read_text(encoding="utf-8"))


def _copy(tmp_path: Path) -> Path:
    directory = tmp_path / "reference"
    directory.mkdir()
    for name in FILES:
        shutil.copyfile(ROOT / REFERENCE_DIRECTORY / name, directory / name)
    return directory


def test_reference_files_validate_and_hash_deterministically() -> None:
    first, again = _reference(), _reference()
    assert first == again
    assert set(first.sha256s) == set(SHA256_KEYS) == {"interaction_catalog_sha256", "threat_templates_sha256",
                                                      "crosswalk_sha256"}
    for key, name in SHA256_KEYS.items():
        assert first.sha256s[key] == hashlib.sha256((ROOT / REFERENCE_DIRECTORY / name).read_bytes()).hexdigest()
    origin = Origin("run", "attempt", "snapshot", first.sha256s)
    assert dict(origin.reference_data) == dict(first.sha256s)
    assert _document(INTERACTION_CATALOG_FILE)["schema"] == contract.INTERACTION_CATALOG_SCHEMA
    assert _document(THREAT_TEMPLATES_FILE)["schema"] == contract.THREAT_TEMPLATES_SCHEMA
    assert _document(CROSSWALK_FILE)["schema"] == contract.CROSSWALK_SCHEMA
    assert set(first.versions) == set(FILES) and all(value >= 1 for value in first.versions.values())


def test_a_modified_copy_loads_and_changes_only_its_own_digest(tmp_path: Path) -> None:
    directory = _copy(tmp_path)
    assert load_reference_from(directory) == _reference()
    with (directory / CROSSWALK_FILE).open("ab") as handle:
        handle.write(b"\n")
    changed, original = load_reference_from(directory).sha256s, _reference().sha256s
    assert changed["crosswalk_sha256"] != original["crosswalk_sha256"]
    assert changed["interaction_catalog_sha256"] == original["interaction_catalog_sha256"]
    assert changed["threat_templates_sha256"] == original["threat_templates_sha256"]


def _set(path: tuple[Any, ...], value: Any) -> Callable[[dict], None]:
    def mutate(document: dict) -> None:
        node: Any = document
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return mutate


def _drop(path: tuple[Any, ...]) -> Callable[[dict], None]:
    def mutate(document: dict) -> None:
        node: Any = document
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    return mutate


def _repeat(key: str) -> Callable[[dict], None]:
    def mutate(document: dict) -> None:
        document[key].append(dict(document[key][0]))
    return mutate


C, T, X = INTERACTION_CATALOG_FILE, THREAT_TEMPLATES_FILE, CROSSWALK_FILE
REJECTED: dict[str, tuple[str, Callable[[dict], None], str]] = {
    "catalog-boundary-kind": (C, _set(("boundary_for", "file_read", "boundary_kind"), "moat"), "boundary_kind"),
    "catalog-callee-key": (C, _set(("callees", 0, "note"), "x"), r"callees\[0\]"),
    "catalog-callee-language": (C, _set(("callees", 0, "languages"), ["cobol"]), "languages"),
    "catalog-callee-repeat": (C, _repeat("callees"), "repeats the callee"),
    "catalog-dependency-category": (C, _set(("dependency_categories", 0, "category"), "graphics"), "category"),
    "catalog-direction": (C, _set(("boundary_for", "file_read", "direction"), "sideways"), "direction"),
    "catalog-entity-key": (C, _set(("boundary_for", "file_read", "external_entity", "role"), "x"), "external_entity"),
    "catalog-interaction-missing": (C, _drop(("boundary_for", "local_ipc")), "boundary_for"),
    "catalog-schema": (C, _set(("schema",), "appsec-review/interaction-catalog/2"), "schema"),
    "catalog-signal-interaction": (C, _set(("prioritization_signals", 0, "interaction"), "teleport"), "interaction"),
    "catalog-sink-class-missing": (C, _drop(("graph_sink_classes", "sql_query")), "graph_sink_classes"),
    "catalog-sink-class-unknown": (C, _set(("graph_sink_classes", "laser"), None), "graph_sink_classes"),
    "catalog-source-interaction": (C, _set(("graph_source_classes", "remote"), "teleport"), "graph_source_classes.remote"),
    "catalog-top-key": (C, _set(("extra",), 1), "unknown keys"),
    "catalog-version": (C, _set(("version",), "1"), "version"),
    "crosswalk-both": (X, _set(("unmapped", "asvs"), ["V2", "V3"]), "unmapped.asvs"),
    "crosswalk-cwe-form": (X, _set(("templates", "code-load-origin", "cwe_families"), ["memory safety"]), "cwe_families"),
    "crosswalk-id-form": (X, _set(("templates", "code-load-origin", "asvs"), ["V1.2.3"]), "asvs"),
    "crosswalk-position": (X, _set(("templates", "code-load-origin", "attacker_positions"), ["orbital"]),
                           "attacker_positions"),
    "crosswalk-row-key": (X, _set(("templates", "code-load-origin", "note"), []), "code-load-origin"),
    "crosswalk-row-missing": (X, _drop(("templates", "code-load-origin")), "without a crosswalk row"),
    "crosswalk-template": (X, _set(("templates", "no-such-template"), {}), "unknown template ids"),
    "crosswalk-top-key": (X, _set(("extra",), 1), "unknown keys"),
    "templates-boundary": (T, _set(("templates", 0, "applies_to", "boundary_kind"), "deployment_exposure"), "applies_to"),
    "templates-evidence-kind": (T, _set(("templates", 0, "mitigation_evidence"), ["hearsay"]), "mitigation_evidence"),
    "templates-id-form": (T, _set(("templates", 0, "template_id"), "Not_Kebab"), "template_id"),
    "templates-id-repeat": (T, _repeat("templates"), "repeats the template"),
    "templates-no-obligation": (T, _set(("templates", 0, "obligations"), []), "obligations"),
    "templates-row-key": (T, _set(("templates", 0, "severity"), "low"), r"templates\[0\]"),
    "templates-stride": (T, _set(("templates", 0, "stride"), "sabotage"), "stride"),
    "templates-unlisted": (T, _set(("untemplated",), []), "untemplated"),
    "templates-untemplated-has": (T, _set(("untemplated",), ["datastore_query", "file_write", "file_read"]),
                                  "untemplated"),
}


@pytest.mark.parametrize("case", sorted(REJECTED))
def test_unknown_key_or_unknown_vocabulary_value_is_rejected(case: str, tmp_path: Path) -> None:
    name, mutate, field = REJECTED[case]
    directory = _copy(tmp_path)
    document = json.loads((directory / name).read_text(encoding="utf-8"))
    mutate(document)
    (directory / name).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=field) as raised:
        load_reference_from(directory)
    assert str(raised.value).startswith(f"{name}: "), "the error names the file"


def test_a_duplicate_json_key_or_a_missing_file_is_rejected(tmp_path: Path) -> None:
    directory = _copy(tmp_path)
    text = (directory / CROSSWALK_FILE).read_text(encoding="utf-8")
    (directory / CROSSWALK_FILE).write_text(text.replace('"version": 1,', '"version": 1, "version": 1,', 1),
                                            encoding="utf-8")
    with pytest.raises(ValueError, match="threat-crosswalk.json: file: .*duplicate key"):
        load_reference_from(directory)
    (directory / CROSSWALK_FILE).unlink()
    with pytest.raises(ValueError, match="threat-crosswalk.json: file: cannot be read"):
        load_reference_from(directory)


def test_every_interaction_has_at_least_one_template_or_is_listed_as_untemplated() -> None:
    reference = _reference()
    templated = {item.interaction for item in reference.templates}
    assert templated.isdisjoint(reference.untemplated)
    assert templated | set(reference.untemplated) == set(Interaction)
    for interaction in Interaction:
        rule = reference.boundary_for(interaction)
        if rule is None:
            assert interaction in reference.untemplated, "a template needs a boundary crossing"
            continue
        assert isinstance(rule, BoundaryRule) and isinstance(rule.boundary_kind, BoundaryKind)
        assert rule.direction in {"inbound", "outbound"} and rule.external_key and rule.external_name
        found = reference.templates_for(interaction, rule.boundary_kind, rule.direction)
        assert found, f"{interaction.value} crosses a boundary and has no template"
        assert [item.template_id for item in found] == sorted(item.template_id for item in found)
        assert all(isinstance(item, Template) and isinstance(item.stride, Stride) for item in found)
        other = "outbound" if rule.direction == "inbound" else "inbound"
        assert reference.templates_for(interaction, rule.boundary_kind, other) == ()
    assert sum(len(reference.templates_for(item, rule.boundary_kind, rule.direction))
               for item in Interaction if (rule := reference.boundary_for(item)) is not None) == len(reference.templates)
    assert 25 <= len(reference.templates) <= 40


def test_every_graph_source_and_sink_class_is_mapped() -> None:
    reference, document = _reference(), _document(INTERACTION_CATALOG_FILE)
    assert set(document["graph_source_classes"]) == {item.value for item in SourceClass}
    assert set(document["graph_sink_classes"]) == {item.value for item in SinkClass}
    for source in SourceClass:
        mapped = reference.interaction_for_source_class(source)
        assert mapped is None or isinstance(mapped, Interaction)
        assert mapped == reference.interaction_for_source_class(source.value)
    for source in sorted(ATTACKER_REACHABLE_SOURCES):
        interaction = reference.interaction_for_source_class(source)
        assert interaction is not None, f"attacker-reachable source class {source.value} has no interaction"
        rule = reference.boundary_for(interaction)
        assert rule is not None and rule.direction == "inbound", "attacker-reachable input crosses a boundary inward"
    assert reference.interaction_for_source_class(SourceClass.INTERNAL) is None
    assert reference.interaction_for_sink_class(SinkClass.MEMORY_WRITE) is None
    assert reference.interaction_for_sink_class(SinkClass.SQL_QUERY) is Interaction.DATASTORE_QUERY
    assert reference.interaction_for_sink_class(SinkClass.COMMAND_EXECUTION) is Interaction.PROCESS_SPAWN
    assert reference.interaction_for_sink_class("no_such_class") is None


def test_every_pinned_owasp_chapter_is_mapped_or_explicitly_unmapped() -> None:
    reference = _reference()
    assert set(reference.unmapped) == set(OWASP_CATALOGS)
    for key in sorted(OWASP_CATALOGS):
        name, chapter = OWASP_CATALOGS[key]
        records = json.loads((ROOT / "data/reference/owasp/catalogs" / name).read_text(encoding="utf-8"))["records"]
        pinned = sorted({chapter(record["id"]) for record in records})
        mapped = {item for row in reference.crosswalk.values() for item in row[key]}
        unmapped = set(reference.unmapped[key])
        assert mapped.isdisjoint(unmapped), key
        assert sorted(mapped | unmapped) == pinned, f"{key}: the crosswalk and the pinned catalog disagree"
        assert mapped, f"{key}: no template maps to this catalog"


def test_crosswalk_rows_use_the_upstream_vocabularies() -> None:
    reference = _reference()
    assert set(reference.crosswalk) == {item.template_id for item in reference.templates}
    catalog = json.loads((ROOT / "rules/codeql-graph-export/catalog.json").read_text(encoding="utf-8"))
    graph_families = {sink["cwe_family"] for language in catalog["languages"].values() for sink in language["sinks"]}
    positions = {item.value for item in AttackerPosition}
    for template in reference.templates:
        row = reference.crosswalk_for(template.template_id)
        assert set(row["cwe_families"]) <= graph_families, template.template_id
        assert row["attacker_positions"] and set(row["attacker_positions"]) <= positions
    used = {item for row in reference.crosswalk.values() for item in row["attacker_positions"]}
    assert used == positions, "every attacker position is a candidate for some crossing"
    with pytest.raises(KeyError):
        reference.crosswalk_for("no-such-template")


def test_reference_data_names_no_target() -> None:
    for name in FILES:
        text = (ROOT / REFERENCE_DIRECTORY / name).read_text(encoding="utf-8").lower()
        for word in TARGET_WORDS:
            assert word not in text, f"{name} names {word}"


def test_template_ids_are_unique_and_questions_assert_no_weakness() -> None:
    reference, rows = _reference(), _document(THREAT_TEMPLATES_FILE)["templates"]
    ids = [row["template_id"] for row in rows]
    assert len(ids) == len(set(ids)) == len(reference.templates)
    assert [item.template_id for item in reference.templates] == sorted(ids)
    for template in reference.templates:
        text = " ".join((template.title, template.question, *template.obligations)).lower()
        for phrase in ASSERTING_PHRASES:
            assert phrase not in text, f"{template.template_id} says {phrase!r}"
        assert template.question.endswith("?"), f"{template.template_id} is a question"
        assert template.obligations and template.mitigation_evidence
        assert dict(template.applies_to) == {"interaction": template.interaction.value,
                                             "boundary_kind": template.boundary_kind.value,
                                             "direction": template.direction}


def test_prioritization_signal_keys_are_values_the_upstream_job_emits() -> None:
    reference, document = _reference(), _document(INTERACTION_CATALOG_FILE)
    emitted = ({(rule.category, rule.surface) for rule in rules.CALL_RULES}
               | {(category, surface) for group in rules.ANNOTATIONS.values() for _, category, surface in group})
    for row in document["prioritization_signals"]:
        assert row["category"] in scoring.SIGNAL_FEATURES
        assert (row["category"], row["surface"]) in emitted, row
        assert reference.interaction_for_signal(row["category"], row["surface"]) == row["interaction"]
    assert reference.interaction_for_signal("ingress", "route_handler") is Interaction.NETWORK_RECEIVE
    assert reference.interaction_for_signal("state_mutation", "fs_write") is Interaction.FILE_WRITE
    assert reference.interaction_for_signal("privilege_shift", "impersonation") is Interaction.PRIVILEGE_CHANGE
    assert reference.interaction_for_signal("ingress", "untrusted_input") is None, "one surface, many interactions"
    assert reference.interaction_for_signal("validator", "validation") is None
    assert reference.interaction_for_signal("ingress") is None


def test_callee_names_are_sorted_exact_and_agree_with_the_graph_catalog() -> None:
    reference = _reference()
    names = reference.callee_names()
    assert list(names) == sorted(set(names)) and 36 <= len(names) <= 120
    for name, expected in (("accept", Interaction.NETWORK_LISTEN), ("recv", Interaction.NETWORK_RECEIVE),
                           ("getaddrinfo", Interaction.NETWORK_CONNECT), ("dlopen", Interaction.CODE_LOAD),
                           ("luaL_loadfile", Interaction.CODE_LOAD), ("getenv", Interaction.ENVIRONMENT_READ),
                           ("setuid", Interaction.PRIVILEGE_CHANGE), ("execve", Interaction.PROCESS_SPAWN),
                           ("fwrite", Interaction.FILE_WRITE), ("fread", Interaction.FILE_READ)):
        assert reference.interaction_for_callee(name) is expected
        assert "c" in reference.languages_for_callee(name)
    assert reference.interaction_for_callee("Recv") is None and reference.languages_for_callee("Recv") == ()
    assert {reference.interaction_for_callee(name) for name in names} == set(Interaction)
    cpp = json.loads((ROOT / "rules/codeql-graph-export/catalog.json").read_text(encoding="utf-8"))["languages"]["cpp"]
    for kind, key, lookup in (("sources", "source_class", reference.interaction_for_source_class),
                              ("sinks", "sink_class", reference.interaction_for_sink_class)):
        for entry in cpp[kind]:
            api = entry["match"].get("api")
            if api in names and lookup(entry[key]) is not None:
                assert reference.interaction_for_callee(api) is lookup(entry[key]), f"{api} disagrees with the graph"


def test_dependency_names_resolve_to_the_closed_categories() -> None:
    reference = _reference()
    expected = {"sqlite3": "database", "libpq": "database", "OpenSSL": "tls", "libssl-dev": "tls", "zlib": "compression",
                "z": "compression", "liblua5.4": "scripting", "lua": "scripting", "libcurl4": "http_client",
                "curl": "http_client", "protobuf-c": "serialization", "com.google.code.gson:gson": "serialization",
                "axios": "http_client", "zebra": None, "luac-wrapper": None, "": None}
    for name in sorted(expected):
        assert reference.dependency_category(name) == expected[name], name
    assert {row["category"] for row in _document(INTERACTION_CATALOG_FILE)["dependency_categories"]} == {
        "compression", "database", "http_client", "scripting", "serialization", "tls"}
