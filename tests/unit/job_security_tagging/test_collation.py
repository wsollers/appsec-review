"""The collation pass (T-5008): facet tags per first-party file and component from accepted facts.

Only accepted-index and source I/O is faked (``CannedIndexes``); rule parsing, tag validation,
derivation, identities and the job handler are real.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath

import pytest

from appsec_review.config.collation import CollationSettings, parse_collation_settings
from appsec_review.jobs.job_security_tagging import job
from appsec_review.jobs.job_security_tagging.collation import COLLATION_SCHEMA, collect_facets
from appsec_review.jobs.job_security_tagging.producers import Row
from appsec_review.jobs.job_security_tagging.taxonomy import (
    COLLATION_NAMESPACES, TaxonomyError, assignment, parse_capability_rules,
)
from appsec_review.retrieval import EntityKind, LogicalIdentity
from appsec_review.review.dispositions import SourceDispositions

from .helpers import ROOT, SNAPSHOT, CannedIndexes, scope, shard, taxonomy, unit_context

HTTP_LOGIN = """from flask import Flask, request, session
import jwt

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    if not verify_password(body["user"], body["password"]):
        return "", 401
    session["user"] = body["user"]
    return "", 204
"""
CLI_MAIN = """#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  int n = argc > 1 ? atoi(argv[1]) : 0;
  printf("%d\\n", n);
  return 0;
}
"""
VENDORED = "#include <sys/socket.h>\nint pull(int s, char *b) { return recv(s, b, 8, 0); }\n"
LIMIT = 100


def source_row(path: str, text: str, language: str | None) -> tuple[Row, bytes]:
    data = text.encode("utf-8")
    sha = hashlib.sha256(data).hexdigest()
    identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": path, "sha256": sha}).value
    location = {"path": path, "file_sha256": sha, "start_byte": 0, "end_byte": len(data), "start_line": 1,
                "end_line": max(1, text.count("\n")), "start_column": 1, "end_column": 1, "target_snapshot": SNAPSHOT,
                "mapping_method": "fixture-exact", "confidence": 1.0}
    payload = {"language": language, "size_bytes": len(data), "path": path}
    return Row(identity, "source_file", path, PurePosixPath(path).name, payload, location), data


def canned(*files: tuple[str, str, str | None], graph: bool = False, build_rows: list[Row] = ()) -> CannedIndexes:
    rows, data = [], {}
    for path, text, language in files:
        row, raw = source_row(path, text, language)
        rows.append(row)
        data[path] = raw
    groups = [(shard("source", "default"), rows)]
    if graph:
        groups.append((shard(), []))
    if build_rows:
        groups.append((shard("build", "default", "d"), list(build_rows)))
    return CannedIndexes(groups=groups, data=data)


def settings(**overrides) -> CollationSettings:
    return CollationSettings(source_dispositions=SourceDispositions(vendored=("**/third_party/**",)), **overrides)


def by_tag(records):
    result: dict[str, list[dict]] = {}
    for record in records:
        result.setdefault(record["tag"], []).append(record)
    return result


def file_tags(records, path: str) -> set[str]:
    return {record["tag"] for record in records if record["subject"].get("path") == path}


def component_tags(records) -> set[str]:
    return {record["tag"] for record in records if record["subject"]["kind"] == "component"}


# (a) ------------------------------------------------------------------------------------------- Done-when (a)


def test_http_login_route_gets_auth_exposure_trust_mechanism_and_state_facets() -> None:
    vocabulary, rules, _ = taxonomy()
    records, gaps, document = collect_facets(canned(("app/login.py", HTTP_LOGIN, "Python")), scope(), vocabulary,
                                             rules, settings(), [], LIMIT)
    tags = file_tags(records, "app/login.py")
    assert {"role:auth", "exposure:client-facing", "trust:user-tainted", "mechanism:http", "state:session",
            "role:session", "mechanism:networked-listener", "asset:credentials", "asset:session-tokens",
            "role:input-parsing", "state:stateful"} <= tags
    index = by_tag(records)
    for tag in ("role:auth", "mechanism:http", "state:session", "trust:user-tainted"):
        record = next(item for item in index[tag] if item["subject"]["kind"] == "source_file")
        assert record["basis"] in {"declared", "derived"} and record["namespace"] == tag.split(":")[0]
        if record["basis"] == "declared":
            span = record["evidence"][0]["span"]
            assert span["start_line"] == span["end_line"] >= 1 and record["evidence"][0]["rule"].startswith("lex-")
            assert record["evidence"][0]["location"]["start_line"] == span["start_line"]
        else:
            assert record["derived_from"] and record["crosswalk_rule"].startswith("collation:")
    # The route handler line, not the whole file, is the evidence span of the HTTP mechanism.
    http = next(item for item in index["mechanism:http"] if item["basis"] == "declared")
    assert http["evidence"][0]["span"] == {"start_line": 7, "end_line": 7}
    # Exposure is derived from the listener and cites the mechanism assignments it rests on.
    exposure = index["exposure:client-facing"][0]
    assert exposure["basis"] == "derived" and set(exposure["derived_from"]) <= {item["assignment_id"] for item in records}
    assert component_tags(records) >= {"target:web-api", "role:auth", "mechanism:http"}
    assert "target:cli" not in component_tags(records)
    assert document["schema"] == COLLATION_SCHEMA and document["components"][0]["target_classes"] == ["target:web-api"]
    assert not any(gap.startswith("collation:target_class_unresolved") for gap in gaps)


def test_cli_main_reading_argv_is_operator_only_and_user_tainted() -> None:
    vocabulary, rules, _ = taxonomy()
    records, gaps, document = collect_facets(canned(("tools/main.c", CLI_MAIN, "C")), scope(), vocabulary, rules,
                                             settings(), [], LIMIT)
    assert file_tags(records, "tools/main.c") == {"mechanism:cli", "trust:user-tainted", "exposure:operator-only",
                                                   "role:input-parsing"}
    # Two assignments carry the tag (the operator-channel derivation and the component roll-up); their
    # order follows assignment ids that hash the rules file, so select the derivation by rule.
    operator = next(item for item in by_tag(records)["exposure:operator-only"]
                    if item["producer"]["rule_id"] == "exposure-from-operator-channel")
    assert operator["basis"] == "derived" and operator["confidence"] == "medium"
    assert operator["evidence"][0]["rests_on_absence"] is True
    assert "mechanism:http" in operator["evidence"][0]["condition"]["none_of"]
    assert component_tags(records) >= {"target:cli", "mechanism:cli"}
    assert document["components"][0]["target_classes"] == ["target:cli"]


# (b) -------------------------------------------------------------------------------------- scope, gaps, determinism


def test_vendored_files_are_counted_not_tagged_and_missing_sources_are_named_gaps() -> None:
    vocabulary, rules, _ = taxonomy()
    indexes = canned(("tools/main.c", CLI_MAIN, "C"), ("third_party/net/pull.c", VENDORED, "C"))
    records, gaps, document = collect_facets(indexes, scope(), vocabulary, rules, settings(), [], LIMIT)
    assert not file_tags(records, "third_party/net/pull.c")
    assert document["skipped_dispositions"] == {"vendored": 1}
    assert [item["path"] for item in document["files"]] == ["tools/main.c"]
    assert {gap.split(":")[1] for gap in gaps} >= {"no_graph_facts", "no_build_facts", "no_documents"}
    assert document["sources"] == {"build": "unavailable", "documents": "unavailable", "graph": "unavailable"}
    # A vendored file's bytes are never read.
    assert [read["path"] for read in indexes.source_reads] == ["tools/main.c"]
    # The facets the lexical rules prove are still assigned without a graph.
    assert "mechanism:cli" in file_tags(records, "tools/main.c")


def test_graph_presence_clears_the_graph_gap_and_capability_inputs_derive_facets() -> None:
    vocabulary, rules, _ = taxonomy()
    indexes = canned(("svc/api.py", "import os\nport = os.getenv('PORT')\n", "Python"), graph=True)
    subject = scope().subjects("source_file", indexes.groups[0][1][0].identity, "svc/api.py")[0]
    route = assignment(vocabulary=vocabulary, tag="func:net:http-route", basis="declared", subject=subject,
                       producer={"name": "capability-rules", "rule_id": "pkg-http-route", "version": "x"},
                       evidence=[{"ref": "obs:1"}])
    records, gaps, _ = collect_facets(indexes, scope(), vocabulary, rules, settings(), [route], LIMIT)
    assert not any(gap.startswith("collation:no_graph_facts") for gap in gaps)
    http = next(item for item in records if item["tag"] == "mechanism:http" and item["subject"]["kind"] == "source_file")
    assert http["basis"] == "derived" and http["derived_from"] == [route["assignment_id"]]
    assert http["crosswalk_rule"] == "collation:facet-http-route"
    assert {"exposure:client-facing", "trust:user-tainted", "role:config"} <= file_tags(records, "svc/api.py")
    assert "target:web-api" in component_tags(records)


def test_same_inputs_in_any_order_give_byte_identical_output() -> None:
    vocabulary, rules, _ = taxonomy()
    files = [("app/login.py", HTTP_LOGIN, "Python"), ("tools/main.c", CLI_MAIN, "C"), ("CMakeLists.txt", "project(x)\n", None)]
    first = collect_facets(canned(*files), scope(), vocabulary, rules, settings(), [], LIMIT)
    second = collect_facets(canned(*reversed(files)), scope(), vocabulary, rules, settings(), [], LIMIT)
    assert json.dumps(first[2], sort_keys=True) == json.dumps(second[2], sort_keys=True)
    assert first[0] == second[0] and first[1] == second[1]
    assert file_tags(first[0], "CMakeLists.txt") == {"role:build-glue", "exposure:build-time"}
    # A component with both a web route and a CLI is a web API; the cli rule yields to the http condition.
    assert first[2]["components"][0]["target_classes"] == ["target:web-api"]


def test_oversized_and_unreadable_files_are_gaps_and_the_file_cap_is_named() -> None:
    vocabulary, rules, _ = taxonomy()
    indexes = canned(("a/big.c", CLI_MAIN, "C"), ("b/small.c", CLI_MAIN, "C"))
    records, gaps, document = collect_facets(indexes, scope(), vocabulary, rules,
                                             settings(max_source_bytes_per_file=len(CLI_MAIN) - 1), [], LIMIT)
    assert not records or not any(record["namespace"] == "mechanism" for record in records)
    assert sum(gap.startswith("collation:source_unread:") for gap in gaps) == 2
    assert any(gap.startswith("collation:target_class_unresolved") for gap in gaps)
    capped = collect_facets(indexes, scope(), vocabulary, rules, settings(max_files_per_component=1), [], LIMIT)
    assert len(capped[2]["files"]) == 1 and any(gap.startswith("collation:file_bound: b/small.c") for gap in capped[1])
    broken = CannedIndexes(groups=[(shard("source", "default"), [source_row("c/x.c", CLI_MAIN, "C")[0]])],
                           data=ValueError("target source changed after indexing"))
    _, gaps, _ = collect_facets(broken, scope(), vocabulary, rules, settings(), [], LIMIT)
    assert any(gap.startswith("collation:source_unread:c/x.c: target source changed") for gap in gaps)


def test_library_class_rests_on_build_points_or_recorded_absence() -> None:
    vocabulary, rules, _ = taxonomy()
    build = Row("build:1", "build_action", "cmake", "cmake", {"build_points": [
        {"kind": "static_library", "name": "libx", "sources": ["lib/x.c"]}]}, None)
    records, gaps, document = collect_facets(canned(("lib/x.c", "int x(void) { return 1; }\n", "C"), build_rows=[build]),
                                             scope(), vocabulary, rules, settings(), [], LIMIT)
    # No facet on the only file: there is nothing to derive a class from, so the class is unresolved, not guessed.
    assert any(gap.startswith("collation:target_class_unresolved") for gap in gaps)
    assert document["components"][0]["build_point_kinds"] == ["static_library"]
    records, gaps, document = collect_facets(
        canned(("lib/x.c", "#include <openssl/evp.h>\nint x(void) { return 1; }\n", "C"), build_rows=[build]),
        scope(), vocabulary, rules, settings(), [], LIMIT)
    library = by_tag(records)["target:library"][0]
    assert library["confidence"] == "high" and library["evidence"][0]["rests_on_absence"] is False
    assert document["components"][0]["target_classes"] == ["target:library"]
    assert "role:crypto" in component_tags(records)


# (c) ---------------------------------------------------------------------------------- pinned rules and settings


def rule_document():
    return json.loads((ROOT / "data/reference/taxonomy/capability-rules.json").read_text())


@pytest.mark.parametrize("case", ["unknown-key", "bad-regex", "lexical-weakness", "lexical-control", "tag-emit-capability",
                                  "tag-input-facet", "target-emit-facet", "facet-emit-target", "duplicate-id",
                                  "missing-rationale", "bad-kind", "bad-language", "unknown-term"])
def test_pinned_collation_rules_reject_invalid_or_widening_rules(case: str) -> None:
    vocabulary, _, _ = taxonomy()
    document = rule_document()
    collation = document["collation"]
    lexical, tag_rule, target, facet = (collation["lexical_rules"][0], collation["tag_rules"][0],
                                        collation["target_rules"][0], collation["facet_rules"][0])
    if case == "unknown-key":
        collation["symbol_rules"] = []
    elif case == "bad-regex":
        lexical["patterns"] = ["(unclosed"]
    elif case == "lexical-weakness":
        lexical["emit"] = ["cwe:89"]
    elif case == "lexical-control":
        lexical["emit"] = ["asvs5:v1"]
    elif case == "tag-emit-capability":
        tag_rule["emit"] = ["func:net:grpc"]
    elif case == "tag-input-facet":
        tag_rule["inputs"] = ["role:auth"]
    elif case == "target-emit-facet":
        target["emit"] = ["role:auth"]
    elif case == "facet-emit-target":
        facet["emit"] = ["target:cli"]
    elif case == "duplicate-id":
        collation["facet_rules"].append(deepcopy(facet))
    elif case == "missing-rationale":
        lexical.pop("rationale")
    elif case == "bad-kind":
        lexical["kind"] = "regex"
    elif case == "bad-language":
        lexical["languages"] = ["python"]
    else:
        facet["any_of"] = ["mechanism:telepathy"]
    with pytest.raises(TaxonomyError):
        parse_capability_rules(document, "0" * 64, vocabulary)


def test_pinned_rules_parse_and_every_facet_namespace_is_closed() -> None:
    vocabulary, rules, _ = taxonomy()
    assert rules.collation is not None and len(rules.collation.lexical_rules) > 40
    assert set(rules.collation.patterns) == {rule["id"] for rule in rules.collation.lexical_rules}
    for namespace in COLLATION_NAMESPACES:
        assert vocabulary.namespaces[namespace].family == "code_facts" and vocabulary.namespaces[namespace].terms
    with pytest.raises(TaxonomyError):
        vocabulary.validate_tag("target:cli", "declared")       # a class is only ever derived
    with pytest.raises(TaxonomyError):
        vocabulary.validate_tag("exposure:public", "declared")  # not a value
    assert vocabulary.validate_tag("state:session", "derived").name == "state"


def test_collation_settings_inherit_or_match_the_review_dispositions() -> None:
    inherited = {"vendored": ["**/third_party/**"], "test": ["**/tests/**"]}
    typed = parse_collation_settings({"max_source_bytes_per_file": 4096}, inherited_dispositions=inherited)
    assert typed.source_dispositions.classify("x/third_party/a.c") == "vendored"
    assert typed.max_source_bytes_per_file == 4096 and typed.model_pass.enabled is False
    same = parse_collation_settings({"source_dispositions": inherited}, inherited_dispositions=inherited)
    assert same.source_dispositions == typed.source_dispositions
    with pytest.raises(ValueError, match="must equal"):
        parse_collation_settings({"source_dispositions": {"vendored": ["**/ext/**"]}}, inherited_dispositions=inherited)
    with pytest.raises(ValueError, match="unknown settings"):
        parse_collation_settings({"model": {}})
    with pytest.raises(ValueError, match="enabled model profile"):
        parse_collation_settings({"model_pass": {"enabled": True}})
    assert parse_collation_settings(None).source_dispositions.classify("third_party/a.c") == "first_party"


def test_central_configuration_resolves_the_dispositions_into_the_tagging_job() -> None:
    from appsec_review.config import load_config
    config = load_config(ROOT / "appsec-review.toml")
    tagging = config.job("job_security_tagging")
    review = config.job("job_inference_security_review")
    assert tuple(tagging.steps) == tuple(job.TOPOLOGY) and "collation" in tagging.steps
    assert tagging.typed_settings.source_dispositions == review.typed_settings.source_dispositions
    assert tagging.settings["collation"]["source_dispositions"]["vendored"] == list(
        review.typed_settings.source_dispositions.vendored)
    assert tagging.settings["collation"]["model_pass"]["enabled"] is False


# (d) ---------------------------------------------------------------------------------------------- the job unit


def handler(name):
    return next(unit.handler for unit in job.build_job().units if unit.unit_id == name)


def test_collate_facets_handler_publishes_facets_summary_and_gaps(tmp_path, monkeypatch) -> None:
    indexes = canned(("app/login.py", HTTP_LOGIN, "Python"), ("third_party/net/pull.c", VENDORED, "C"))
    monkeypatch.setattr(job, "_indexes", lambda unit: indexes)
    monkeypatch.setattr(job, "_scope", lambda unit: scope())
    monkeypatch.setattr(job, "_collation_settings", lambda value: settings())
    loaded = handler("taxonomy.load_taxonomy")(unit_context(tmp_path, "taxonomy.load_taxonomy"))
    source_unit = unit_context(tmp_path, "collection.source_facts", {"taxonomy.load_taxonomy": loaded})
    source_result = handler("collection.source_facts")(source_unit)
    empty = {"artifact": job._write(source_unit, "empty.json", {"schema": "appsec-review/tag-assignment-set/1",
                                                                 "collector": "fixture", "assignments": [], "gaps": []})}
    unit = unit_context(tmp_path, job.COLLATION, {
        "taxonomy.load_taxonomy": loaded, "collection.source_facts": source_result,
        "collection.observation_facts": empty, "collection.coverage_gaps": empty})
    result = handler(job.COLLATION)(unit)
    facets = job._read(unit, result["artifact"])
    tags = {record["tag"] for record in facets["assignments"]}
    assert {"role:auth", "mechanism:http", "exposure:client-facing", "target:web-api"} <= tags
    assert facets["collector"] == "facet-facts"
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any(gap.startswith("collation:no_graph_facts") for gap in result["gaps"])
    assert result["first_party_files"] == 1 and result["skipped_dispositions"] == {"vendored": 1}
    assert result["target_classes"] == {"component:app": ["target:web-api"]}
    summary = job._read(unit, result["collation"])
    assert summary["schema"] == COLLATION_SCHEMA and summary["files"][0]["path"] == "app/login.py"
    assert summary["settings"]["source_dispositions"]["vendored"] == ["**/third_party/**"]
    # The lang tag the source collector declared is an input of the lexical rules, not an output of collation.
    assert "lang:python" not in tags and all(record["namespace"] in COLLATION_NAMESPACES for record in facets["assignments"])
