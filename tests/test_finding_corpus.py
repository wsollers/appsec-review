"""Fix-pair corpora, their scoring keys and the private-holdout usage ledger (T-067).

Every advisory, project and revision here is synthetic.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import tomllib

import pytest

from appsec_review.acceptance.scoring import load_scoring_key
from appsec_review.observability.findings import corpus as k

PRE, POST = "1" * 40, "2" * 40


def pair(pair_id="CVE-0000-0001", **changes):
    value = {"id": pair_id, "project": "synthetic-engine", "advisory": "CVE-0000-0001", "license": "MIT",
             "source": "https://example.invalid/advisories/0001", "pre_revision": PRE, "post_revision": POST,
             "path": "src/net/parse.c", "line": 40, "end_line": 44, "scope_start": 30, "scope_end": 60,
             "cwe": "CWE-787", "severity": "high", "attacker_position": "client_to_server",
             "weakness_class": "bitstream length"}
    value.update(changes)
    return {name: item for name, item in value.items() if item is not None}


def toml_text(pairs, header=None, extra=""):
    def table(name, row):
        return "\n".join([name, *(f"{field} = {json.dumps(item)}" for field, item in row.items())])
    corpus = {"name": "synthetic-fix-pairs", "holdout": False} if header is None else header
    return "\n\n".join([table("[corpus]", corpus), *(table("[[pair]]", row) for row in pairs)]) + "\n" + extra


def load(tmp_path, pairs=None, header=None, extra=""):
    path = tmp_path / "corpus.toml"
    path.write_text(toml_text([pair()] if pairs is None else pairs, header, extra), encoding="utf-8", newline="\n")
    return k.load_fix_pairs(path)


def holdout(tmp_path, **changes):
    return load(tmp_path, [pair(**changes)], {"name": "private-holdout", "holdout": True})


# ------------------------------------------------------------------------------------- loading

def test_load_normalizes_a_pair_and_freezes_it(tmp_path):
    corpus = load(tmp_path, [pair(path="./src//net/parse.c", cwe="787")],
                  {"name": "synthetic-fix-pairs", "holdout": False, "description": "two revisions of one defect"})
    assert (corpus.name, corpus.holdout, corpus.description) == ("synthetic-fix-pairs", False,
                                                                 "two revisions of one defect")
    item, = corpus.pairs
    assert item == k.FixPair(
        id="CVE-0000-0001", project="synthetic-engine", advisory="CVE-0000-0001", license="MIT",
        source="https://example.invalid/advisories/0001", pre_revision=PRE, post_revision=POST,
        path="src/net/parse.c", line=40, end_line=44, scope_start=30, scope_end=60, cwe="CWE-787", severity="high",
        attacker_position="client_to_server", weakness_class="bitstream length")
    assert item.scope == (30, 60)
    with pytest.raises(FrozenInstanceError):
        item.line = 1
    with pytest.raises(FrozenInstanceError):
        corpus.holdout = True


def test_optional_fields_default_to_not_established(tmp_path):
    item, = load(tmp_path, [pair(end_line=None, scope_start=None, scope_end=None, severity=None,
                                 attacker_position=None, weakness_class=None)]).pairs
    assert (item.line, item.end_line, item.scope_start, item.scope_end) == (40, 40, None, None)
    assert item.severity is item.attacker_position is item.weakness_class is None
    assert item.scope == (40, 40)


def test_corpus_digest_covers_normalized_content_not_file_order(tmp_path):
    first, second = pair("pair-a"), pair("pair-b", path="src/net/other.c")
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    (tmp_path / "z").mkdir()
    forward = load(tmp_path / "x", [first, second])
    backward = load(tmp_path / "y", [second, {**first, "cwe": 787, "path": "src/net/./parse.c"}])
    changed = load(tmp_path / "z", [first, {**second, "line": 41}])
    assert forward.sha256 == backward.sha256 and len(forward.sha256) == 64
    assert [item.id for item in backward.pairs] == ["pair-a", "pair-b"]
    assert changed.sha256 != forward.sha256
    assert load(tmp_path / "x", [first, second], {"name": "synthetic-fix-pairs", "holdout": True}).sha256 \
        != forward.sha256


@pytest.mark.parametrize("changes, message", [
    ({"advisory": ""}, "advisory must be a non-empty"),
    ({"attacker_position": "remote"}, "attacker_position is one of"),
    ({"cwe": "CWE-0"}, "unrecognised cwe"),
    ({"cwe": "overflow"}, "unrecognised cwe"),
    ({"end_line": 39}, "end_line precedes line"),
    ({"id": "bad#id"}, "pair id"),
    ({"id": "x" * 129}, "pair id"),
    ({"license": "  "}, "license must be a non-empty"),
    ({"line": 0}, "line must be a positive integer"),
    ({"line": True}, "line must be a positive integer"),
    ({"path": "/etc/passwd"}, "not target-relative"),
    ({"path": "src/../../x.c"}, "escapes the target"),
    ({"post_revision": PRE}, "same revision"),
    ({"post_revision": "2" * 39}, "post_revision must be 40"),
    ({"pre_revision": "A" * 40}, "pre_revision must be 40"),
    ({"project": "two\nlines"}, "project must be a non-empty"),
    ({"scope_end": 43}, "does not contain its lines"),
    ({"scope_end": None}, "go together"),
    ({"scope_start": 41}, "does not contain its lines"),
    ({"severity": "severe"}, "severity is one of"),
    ({"source": ""}, "source must be a non-empty"),
    ({"reviewer_note": "x"}, "unknown keys \\['reviewer_note'\\]"),
    ({"license": None}, "missing keys \\['license'\\]"),
    ({"cwe": None}, "missing keys \\['cwe'\\]"),
], ids=["advisory-empty", "attacker", "cwe-zero", "cwe-text", "end-before-line", "id-hash", "id-long",
        "license-blank", "line-zero", "line-bool", "path-absolute", "path-escape", "same-revision", "post-short",
        "pre-upper", "project-newline", "scope-end-short", "scope-half", "scope-start-late", "severity", "source-empty",
        "unknown-key", "no-license", "no-cwe"])
def test_an_inconsistent_pair_is_refused(tmp_path, changes, message):
    with pytest.raises(ValueError, match=message):
        load(tmp_path, [pair(**changes)])


@pytest.mark.parametrize("header, extra, message", [
    ({"name": "c"}, "", "holdout must be true or false"),
    ({"name": "c", "holdout": "no"}, "", "holdout must be true or false"),
    ({"holdout": False}, "", "name must be a non-empty"),
    ({"name": "c", "holdout": False, "owner": "x"}, "", "unknown \\[corpus\\] keys: owner"),
    ({"name": "c", "holdout": False}, "\n[defect]\nid = 1\n", "unknown top-level keys: defect"),
], ids=["no-holdout", "holdout-text", "no-name", "corpus-key", "top-level-key"])
def test_an_invalid_corpus_header_is_refused(tmp_path, header, extra, message):
    with pytest.raises(ValueError, match=message):
        load(tmp_path, header=header, extra=extra)


def test_empty_duplicate_and_malformed_corpora_are_refused(tmp_path):
    with pytest.raises(ValueError, match="lists no fix pairs"):
        load(tmp_path, [])
    with pytest.raises(ValueError, match="repeats the pair id CVE-0000-0001"):
        load(tmp_path, [pair(), pair(path="src/other.c")])
    path = tmp_path / "broken.toml"
    path.write_text("[corpus\n", encoding="utf-8")
    with pytest.raises(ValueError):
        k.load_fix_pairs(path)
    path.write_text('pair = "x"\n[corpus]\nname = "c"\nholdout = false\n', encoding="utf-8")
    with pytest.raises(ValueError, match="array of tables"):
        k.load_fix_pairs(path)
    path.write_text('corpus = "x"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="must be a table"):
        k.load_fix_pairs(path)


def test_pair_bound_is_exactly_2000(tmp_path):
    pairs = [pair(f"pair-{index:04d}") for index in range(k.MAX_PAIRS)]
    assert len(load(tmp_path, pairs).pairs) == 2000
    with pytest.raises(ValueError, match="at most 2000 pairs"):
        load(tmp_path, [*pairs, pair("pair-extra")])


# ---------------------------------------------------------------------------------- expansion

def test_expand_yields_a_defect_before_the_fix_and_a_control_after_it(tmp_path):
    corpus = load(tmp_path, [pair("pair-b", severity=None, scope_start=None, scope_end=None), pair("pair-a")])
    expanded = k.expand(corpus)
    assert [row["id"] for row in expanded["defects"]] == ["pair-a#pre", "pair-b#pre"]
    assert [row["id"] for row in expanded["controls"]] == ["pair-a#post", "pair-b#post"]
    assert expanded["defects"][0] == {
        "id": "pair-a#pre", "pair_id": "pair-a", "project": "synthetic-engine", "advisory": "CVE-0000-0001",
        "revision": PRE, "path": "src/net/parse.c", "line": 40, "end_line": 44, "scope": [30, 60], "cwe": "CWE-787",
        "severity": "high", "attacker_position": "client_to_server", "weakness_class": "bitstream length"}
    assert expanded["controls"][0] == {**expanded["defects"][0], "id": "pair-a#post", "revision": POST}
    assert expanded["defects"][1]["severity"] is None and expanded["defects"][1]["scope"] == [40, 44]
    assert expanded["expected_recheck"] == {"pair-a#post": "fixed", "pair-a#pre": "still_present",
                                            "pair-b#post": "fixed", "pair-b#pre": "still_present"}
    assert list(expanded["expected_recheck"]) == sorted(expanded["expected_recheck"])
    assert (expanded["corpus"], expanded["corpus_sha256"], expanded["holdout"]) == (corpus.name, corpus.sha256, False)
    assert k.expand(corpus) == expanded


# ----------------------------------------------------------------------------------- key file

@pytest.mark.parametrize("role, kind", [("post", "control"), ("pre", "defect")], ids=str)
def test_written_key_round_trips_through_the_existing_scorer_loader(tmp_path, role, kind):
    corpus = load(tmp_path, [pair("pair-a", project='quoted "engine" \\ ünïcode'),
                             pair("pair-b", path="src/net/other.c", end_line=None, scope_start=None, scope_end=None,
                                  severity=None)])
    destination = tmp_path / "keys" / "expectations.toml"
    destination.parent.mkdir()
    assert k.write_scoring_key(corpus, role, destination) == destination
    assert b"\r" not in destination.read_bytes()
    key = load_scoring_key(destination)
    assert [entry.id for entry in key.entries] == [f"pair-a#{role}", f"pair-b#{role}"]
    assert all(entry.kind.value == kind and entry.pair is None for entry in key.entries)
    assert (len(key.defects), len(key.controls)) == ((2, 0) if role == "pre" else (0, 2))
    first, second = key.entries
    assert (first.path, first.cwe, first.lines, first.scope) == ("src/net/parse.c", "CWE-787", (40, 41, 42, 43, 44),
                                                                 (30, 60))
    assert (second.path, second.lines, second.scope) == ("src/net/other.c", (40,), (40, 40))
    assert first.summary == f'quoted "engine" \\ ünïcode CVE-0000-0001 at {PRE if role == "pre" else POST}'
    document = tomllib.loads(destination.read_text(encoding="utf-8"))
    assert document["corpus"] == {"name": f"synthetic-fix-pairs:{role}", "fix_pair_corpus_sha256": corpus.sha256,
                                  "revision_role": role, "holdout": False}
    rows = document[kind]
    assert all("pair" not in row for row in rows)
    assert [row.get("severity") for row in rows] == (["high", None] if role == "pre" else [None, None])


def test_key_can_be_restricted_to_one_project(tmp_path):
    corpus = load(tmp_path, [pair("pair-a"), pair("pair-b", project="synthetic-game")])
    with pytest.raises(ValueError, match="scopes of pair-a and pair-b overlap"):
        k.write_scoring_key(corpus, "pre", tmp_path / "all.toml")
    assert not (tmp_path / "all.toml").exists()
    k.write_scoring_key(corpus, "pre", tmp_path / "game.toml", project="synthetic-game")
    assert [entry.id for entry in load_scoring_key(tmp_path / "game.toml").entries] == ["pair-b#pre"]
    with pytest.raises(ValueError, match="no pair of project 'absent'"):
        k.write_scoring_key(corpus, "pre", tmp_path / "absent.toml", project="absent")


def test_adjacent_scopes_in_one_file_may_share_a_key(tmp_path):
    corpus = load(tmp_path, [pair("pair-a"), pair("pair-b", line=61, end_line=61, scope_start=61, scope_end=70)])
    k.write_scoring_key(corpus, "post", tmp_path / "key.toml")
    assert len(load_scoring_key(tmp_path / "key.toml").controls) == 2


def test_keys_stay_outside_targets_and_never_overwrite(tmp_path):
    corpus = load(tmp_path)
    inside = tmp_path / "targets" / "game"
    inside.mkdir(parents=True)
    with pytest.raises(ValueError, match="keys stay outside targets"):
        k.write_scoring_key(corpus, "pre", inside / "expectations.toml")
    assert list(inside.iterdir()) == []
    with pytest.raises(ValueError, match="keys stay outside targets"):
        k.write_scoring_key(corpus, "pre", tmp_path / "Targets" / "expectations.toml")
    destination = tmp_path / "expectations.toml"
    destination.write_text("existing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        k.write_scoring_key(corpus, "pre", destination)
    assert destination.read_text(encoding="utf-8") == "existing\n"
    with pytest.raises(ValueError, match="revision_role is one of"):
        k.write_scoring_key(corpus, "both", tmp_path / "other.toml")
    with pytest.raises(ValueError, match="does not exist"):
        k.write_scoring_key(corpus, "pre", tmp_path / "missing" / "expectations.toml")


# ------------------------------------------------------------------------------ holdout ledger

def test_holdout_use_is_recorded_once_in_an_append_only_ledger(tmp_path):
    corpus = holdout(tmp_path)
    ledger = tmp_path / "ledger.json"
    assert k.holdout_uses(ledger) == []
    first = {"purpose": "evaluation", "run_id": "run-1", "used_on": "2026-11-11"}
    second = {"purpose": "evaluation", "run_id": "run-2", "used_on": "2026-11-10"}
    document = k.record_holdout_use(ledger, corpus, purpose="evaluation", run_id="run-1", used_on="2026-11-11")
    assert document == {"schema": "appsec-review/holdout-usage/1", "corpus_sha256": corpus.sha256, "uses": [first]}
    assert json.loads(ledger.read_text(encoding="utf-8")) == document
    k.record_holdout_use(ledger, corpus, purpose="evaluation", run_id="run-2", used_on="2026-11-10")
    before = ledger.read_bytes()
    again = k.record_holdout_use(ledger, corpus, purpose="evaluation", run_id="run-1", used_on="2026-11-11")
    assert again["uses"] == [first, second] and ledger.read_bytes() == before
    assert k.holdout_uses(ledger) == [first, second]                      # recording order, never re-sorted
    assert sorted(item.name for item in tmp_path.iterdir()) == ["corpus.toml", "ledger.json"]
    assert before.endswith(b"\n") and b"\r" not in before


@pytest.mark.parametrize("purpose", ["", "Evaluation", "guidance", "tuning"], ids=["empty", "case", "guidance",
                                                                                 "tuning"])
def test_a_holdout_is_never_used_for_tuning(tmp_path, purpose):
    ledger = tmp_path / "ledger.json"
    with pytest.raises(ValueError, match="^a holdout corpus is never used for tuning$"):
        k.record_holdout_use(ledger, holdout(tmp_path), purpose=purpose, run_id="run-1", used_on="2026-11-11")
    assert not ledger.exists()


def test_only_a_holdout_corpus_has_a_ledger(tmp_path):
    with pytest.raises(ValueError, match="only a holdout corpus"):
        k.record_holdout_use(tmp_path / "ledger.json", load(tmp_path), purpose="evaluation", run_id="run-1",
                             used_on="2026-11-11")
    assert not (tmp_path / "ledger.json").exists()


@pytest.mark.parametrize("run_id, used_on, message", [
    ("", "2026-11-11", "run_id must be a non-empty"),
    ("run-1", "11/11/2026", "ISO date"),
    ("run-1", "2026-02-30", "not a calendar date"),
    ("run-1", "2026-11-11T00:00:00", "ISO date"),
    ("run-1", 20261111, "ISO date"),
], ids=["run-id", "slashes", "no-such-day", "timestamp", "number"])
def test_a_use_needs_a_run_and_an_iso_date(tmp_path, run_id, used_on, message):
    with pytest.raises(ValueError, match=message):
        k.record_holdout_use(tmp_path / "ledger.json", holdout(tmp_path), purpose="evaluation", run_id=run_id,
                             used_on=used_on)


def test_a_ledger_belongs_to_one_corpus(tmp_path):
    ledger = tmp_path / "ledger.json"
    k.record_holdout_use(ledger, holdout(tmp_path), purpose="evaluation", run_id="run-1", used_on="2026-11-11")
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="ledger of a different corpus"):
        k.record_holdout_use(ledger, holdout(tmp_path, line=41), purpose="evaluation", run_id="run-2",
                             used_on="2026-11-11")
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("document, message", [
    ([], "not a appsec-review/holdout-usage/1 ledger"),
    ({"schema": "other/1", "corpus_sha256": "a" * 64, "uses": []}, "not a appsec-review/holdout-usage/1 ledger"),
    ({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": "a" * 64, "uses": [], "note": 1}, "not a appsec-review"),
    ({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": "abc", "uses": []}, "corpus_sha256 or uses are invalid"),
    ({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": "a" * 64, "uses": {}}, "corpus_sha256 or uses are invalid"),
    ({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": "a" * 64,
      "uses": [{"purpose": "tuning", "run_id": "r", "used_on": "2026-11-11"}]}, "never used for tuning"),
    ({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": "a" * 64,
      "uses": [{"purpose": "evaluation", "run_id": "r"}]}, "exactly purpose, run_id and used_on"),
    ({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": "a" * 64,
      "uses": [{"purpose": "evaluation", "run_id": "r", "used_on": "2026-11-11"}] * 2}, "recorded twice"),
], ids=["list", "schema", "extra-key", "sha", "uses-type", "tuning-use", "use-keys", "duplicate-use"])
def test_an_invalid_ledger_is_refused(tmp_path, document, message):
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        k.holdout_uses(ledger)


def test_ledger_bound_is_exactly_10000_uses(tmp_path):
    corpus = holdout(tmp_path)
    ledger = tmp_path / "ledger.json"
    uses = [{"purpose": "evaluation", "run_id": f"run-{index}", "used_on": "2026-11-11"}
            for index in range(k.MAX_HOLDOUT_USES - 1)]
    ledger.write_text(json.dumps({"schema": k.HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": corpus.sha256, "uses": uses}),
                      encoding="utf-8")
    k.record_holdout_use(ledger, corpus, purpose="evaluation", run_id="run-last", used_on="2026-11-11")
    assert len(k.holdout_uses(ledger)) == 10_000
    with pytest.raises(ValueError, match="at most 10000 uses"):
        k.record_holdout_use(ledger, corpus, purpose="evaluation", run_id="run-over", used_on="2026-11-11")
    k.record_holdout_use(ledger, corpus, purpose="evaluation", run_id="run-last", used_on="2026-11-11")  # idempotent
    assert len(k.holdout_uses(ledger)) == 10_000
    full = json.loads(ledger.read_text(encoding="utf-8"))
    full["uses"].append({"purpose": "evaluation", "run_id": "run-over", "used_on": "2026-11-11"})
    ledger.write_text(json.dumps(full), encoding="utf-8")
    with pytest.raises(ValueError, match="at most 10000 uses"):
        k.holdout_uses(ledger)
