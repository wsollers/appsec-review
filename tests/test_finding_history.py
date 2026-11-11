"""The per-target finding history store: derived, content-addressed, verified on every read."""
from __future__ import annotations

import copy
import hashlib
import json
import re

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import history as h
from appsec_review.observability.findings import lifecycle as lc
from appsec_review.observability.findings.identity import fingerprint
from appsec_review.storage import canonical_json

CODE = "void f(char *p) {\n  char b[8];\n  strcpy(b, p); // copy\n}\n"
PATH = "src/net/parse.c"
H1, H2 = "1" * 64, "2" * 64


def located(path=PATH, line=10, function="parse_packet", code=CODE):
    return [{"path": path, "start_line": line, "end_line": line + 2, "function": function, "code": code}]


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "lead", "locations": located()}
    value.update(changes)
    return value


def other(finding_id="F2"):
    return finding(finding_id, weakness_cwe="CWE-78",
                   locations=located(path="src/cmd/run.c", function="run_command", code="system(cmd);"))


def snapshot(findings=(), **changes):
    arguments = dict(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def place(directory, document, name=None):
    """Write a store file directly (no fsync), named by its digest unless ``name`` is given."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name or c.digest(document)}.json"
    path.write_bytes(canonical_json(document))
    return path


def fixed_lifecycle():
    """run-1 -> run-2 in which F1 persists and F2 was re-checked as fixed."""
    before = snapshot([finding(), other()], reviewed_units={PATH: H1, "src/cmd/run.c": H1})
    after = snapshot([finding()], run_id="run-2", reviewed_units={PATH: H1, "src/cmd/run.c": H2})
    classified = lc.classify(before, after)
    return before, after, classified, lc.apply_rechecks(classified, {"F2": {"outcome": "fixed"}})


# ----------------------------------------------------------------------------------- publish

def test_publish_snapshot_is_content_addressed_and_idempotent(tmp_path):
    document = snapshot([finding()])
    kept = copy.deepcopy(document)
    first = h.publish_snapshot(tmp_path, document)
    path = tmp_path / "game" / "snapshots" / f"{c.digest(document)}.json"
    assert first == {"status": "published", "sha256": c.digest(document), "path": str(path)}
    assert path.read_bytes() == canonical_json(document)
    assert h.publish_snapshot(tmp_path, document) == {**first, "status": "duplicate"}
    assert document == kept and [item.name for item in path.parent.iterdir()] == [path.name]


def test_publish_snapshot_refuses_other_bytes_at_its_content_address(tmp_path):
    document = snapshot([finding()])
    target = tmp_path / "game" / "snapshots"
    target.mkdir(parents=True)
    (target / f"{c.digest(document)}.json").write_bytes(canonical_json(document).rstrip(b"\n"))
    with pytest.raises(ValueError):
        h.publish_snapshot(tmp_path, document)


def test_a_run_and_stage_holds_one_snapshot_per_target(tmp_path):
    h.publish_snapshot(tmp_path, snapshot([finding()]))
    with pytest.raises(ValueError, match="different snapshot of this run and stage"):
        h.publish_snapshot(tmp_path, snapshot([other()]))
    assert h.publish_snapshot(tmp_path, snapshot([other()], stage="verified"))["status"] == "published"
    assert h.publish_snapshot(tmp_path, snapshot([other()], run_id="run-2"))["status"] == "published"
    assert h.publish_snapshot(tmp_path, snapshot([other()], target_id="engine"))["status"] == "published"
    assert len(h.load_history(tmp_path, "game")["snapshots"]) == 3


def test_publish_snapshot_refuses_a_document_that_is_not_a_snapshot(tmp_path):
    with pytest.raises(ValueError):
        h.publish_snapshot(tmp_path, {**snapshot([finding()]), "extra": 1})
    assert not (tmp_path / "game").exists()


def test_publish_lifecycle_is_content_addressed_and_keeps_both_documents_of_a_run_pair(tmp_path):
    _, _, classified, rechecked = fixed_lifecycle()
    kept = copy.deepcopy(classified)
    first = h.publish_lifecycle(tmp_path, "game", classified)
    path = tmp_path / "game" / "lifecycles" / f"{c.digest(classified)}.json"
    assert first == {"status": "published", "sha256": c.digest(classified), "path": str(path)}
    assert h.publish_lifecycle(tmp_path, "game", classified)["status"] == "duplicate"
    assert h.publish_lifecycle(tmp_path, "game", rechecked)["status"] == "published"
    assert classified == kept and len(h.load_history(tmp_path, "game")["lifecycles"]) == 2


def test_publish_lifecycle_refuses_another_target_an_invalid_document_and_a_collision(tmp_path):
    _, _, classified, _ = fixed_lifecycle()
    with pytest.raises(ValueError):
        h.publish_lifecycle(tmp_path, "engine", classified)
    with pytest.raises(ValueError):
        h.publish_lifecycle(tmp_path, "game", {**classified, "stage": "final"})
    assert not tmp_path.joinpath("game").exists() and not tmp_path.joinpath("engine").exists()
    directory = tmp_path / "game" / "lifecycles"
    directory.mkdir(parents=True)
    (directory / f"{c.digest(classified)}.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError):
        h.publish_lifecycle(tmp_path, "game", classified)


# ------------------------------------------------------------------------------ path custody

@pytest.mark.parametrize("target_id", ["", "-a", ".a", "..", "A", "a b", "a..b", "a/b", "a\\b", "a\n", "x" * 65,
                                       None, 7], ids=repr)
def test_target_ids_outside_the_closed_pattern_are_refused(tmp_path, target_id):
    with pytest.raises(ValueError):
        h.load_history(tmp_path, target_id)
    with pytest.raises(ValueError):
        h.read_snapshot(tmp_path, target_id, "0" * 64)
    with pytest.raises(ValueError):
        h.publish_lifecycle(tmp_path, target_id, fixed_lifecycle()[2])
    if isinstance(target_id, str) and target_id and "\n" not in target_id:
        with pytest.raises(ValueError):
            h.publish_snapshot(tmp_path, snapshot(target_id=target_id))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("target_id", ["a", "0", "a.b_c-1", "x" * 64], ids=["letter", "digit", "mixed", "max-64"])
def test_target_ids_inside_the_closed_pattern_are_accepted(tmp_path, target_id):
    published = h.publish_snapshot(tmp_path, snapshot(target_id=target_id))
    assert h.load_history(tmp_path, target_id)["snapshots"][0]["sha256"] == published["sha256"]


@pytest.mark.parametrize("level", ["root", "target", "snapshots"])
def test_symlinked_store_directories_are_refused(tmp_path, level):
    real = tmp_path / "real"
    document = snapshot([finding()])
    h.publish_snapshot(real, document)
    store = tmp_path / "store"
    if level == "root":
        store.symlink_to(real, target_is_directory=True)
    elif level == "target":
        store.mkdir()
        (store / "game").symlink_to(real / "game", target_is_directory=True)
    else:
        (store / "game").mkdir(parents=True)
        (store / "game" / "snapshots").symlink_to(real / "game" / "snapshots", target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        h.load_history(store, "game")
    with pytest.raises(ValueError, match="symbolic link"):
        h.publish_snapshot(store, snapshot([other()], run_id="run-2"))
    with pytest.raises(ValueError, match="symbolic link"):
        h.read_snapshot(store, "game", c.digest(document))
    assert len(list((real / "game" / "snapshots").iterdir())) == 1


def test_a_symlinked_lifecycle_directory_and_symlinked_entries_are_refused(tmp_path):
    _, _, classified, _ = fixed_lifecycle()
    document = snapshot([finding()])
    outside = place(tmp_path / "outside", document)
    (tmp_path / "store" / "game" / "snapshots").mkdir(parents=True)
    (tmp_path / "store" / "game" / "snapshots" / outside.name).symlink_to(outside)
    with pytest.raises(ValueError, match=re.escape(outside.name)):
        h.load_history(tmp_path / "store", "game")
    with pytest.raises(ValueError):
        h.read_snapshot(tmp_path / "store", "game", c.digest(document))
    with pytest.raises(ValueError):
        h.publish_snapshot(tmp_path / "store", document)
    (tmp_path / "second" / "game").mkdir(parents=True)
    (tmp_path / "second" / "game" / "lifecycles").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        h.publish_lifecycle(tmp_path / "second", "game", classified)


def test_a_file_where_a_store_directory_belongs_is_refused(tmp_path):
    (tmp_path / "game").write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        h.load_history(tmp_path, "game")


# -------------------------------------------------------------------------------------- load

def test_an_absent_target_is_an_empty_history_not_an_error(tmp_path):
    empty = {"schema": c.HISTORY_SCHEMA, "target_id": "game", "snapshots": [], "lifecycles": []}
    assert h.load_history(tmp_path / "missing", "game") == empty
    h.publish_snapshot(tmp_path, snapshot(target_id="engine"))
    assert h.load_history(tmp_path, "game") == empty
    assert h.previously_fixed(empty) == frozenset() and h.ages(empty) == {}
    assert h.latest_prior(empty, stage="published", before_run_id="run-9") is None


def test_load_history_lists_verified_snapshots_and_lifecycles_in_a_stable_order(tmp_path):
    before, after, classified, rechecked = fixed_lifecycle()
    third = snapshot([finding()], run_id="run-3", source_revision="b" * 40)
    verified = snapshot([other()], run_id="run-0", stage="verified")
    later = lc.classify(after, third)
    for document in (third, verified, after, before):
        h.publish_snapshot(tmp_path, document)
    for document in (later, rechecked, classified):
        h.publish_lifecycle(tmp_path, "game", document)
    history = h.load_history(tmp_path, "game")
    assert list(history) == ["schema", "target_id", "snapshots", "lifecycles"]
    assert (history["schema"], history["target_id"]) == ("appsec-review/finding-history/1", "game")
    assert [(row["stage"], row["run_id"]) for row in history["snapshots"]] == [
        ("published", "run-1"), ("published", "run-2"), ("published", "run-3"), ("verified", "run-0")]
    exact = sorted(item["fingerprint"]["exact"] for item in before["findings"])
    assert history["snapshots"][0] == {"sha256": c.digest(before), "run_id": "run-1", "stage": "published",
                                       "source_revision": "a" * 40, "finding_count": 2, "fingerprints": exact}
    assert history["snapshots"][2]["source_revision"] == "b" * 40
    assert [(doc["prior_run_id"], doc["current_run_id"]) for doc in history["lifecycles"]] == [
        ("run-1", "run-2"), ("run-1", "run-2"), ("run-2", "run-3")]
    pair = sorted([classified, rechecked], key=c.digest)
    assert history["lifecycles"] == [*pair, later]
    assert history == h.load_history(tmp_path, "game")
    json.dumps(history)


def _rewrite(path, document):
    path.write_bytes(canonical_json({**document, "source_revision": "c" * 40}))


def _rename(path, document):
    path.rename(path.with_name("0" * 64 + ".json"))


def _not_json(path, document):
    path.write_bytes(b"not json\n")


def _not_canonical(path, document):
    path.write_bytes(json.dumps(document, indent=2).encode())


def _stray(path, document):
    path.with_name("notes.txt").write_bytes(b"x")


def _directory_entry(path, document):
    path.with_name("1" * 64 + ".json").mkdir()


def _foreign_schema(path, document):
    foreign = {**document, "schema": "appsec-review/finding-snapshot/0"}
    path.unlink()
    place(path.parent, foreign)


def _foreign_target(path, document):
    foreign = snapshot([finding()], target_id="engine")
    path.unlink()
    place(path.parent, foreign)


def _array(path, document):
    path.unlink()
    place(path.parent, [1, 2])


TAMPERS = [_array, _directory_entry, _foreign_schema, _foreign_target, _not_canonical, _not_json, _rename, _rewrite,
           _stray]


@pytest.mark.parametrize("tamper", TAMPERS, ids=[item.__name__.strip("_") for item in TAMPERS])
def test_a_tampered_snapshot_store_is_an_error_naming_the_file(tmp_path, tamper):
    good = snapshot([other()], run_id="run-0")
    document = snapshot([finding()])
    h.publish_snapshot(tmp_path, good)
    path = tmp_path / "game" / "snapshots" / f"{c.digest(document)}.json"
    h.publish_snapshot(tmp_path, document)
    path.chmod(0o600)
    tamper(path, document)
    with pytest.raises(ValueError, match=re.escape(str(tmp_path / "game" / "snapshots"))):
        h.load_history(tmp_path, "game")
    with pytest.raises(ValueError):
        h.publish_snapshot(tmp_path, snapshot([finding()], run_id="run-5"))


def test_a_non_canonical_entry_named_by_the_hash_of_its_own_bytes_is_refused(tmp_path):
    raw = json.dumps(snapshot([finding()]), indent=2).encode()
    directory = tmp_path / "game" / "snapshots"
    directory.mkdir(parents=True)
    (directory / f"{hashlib.sha256(raw).hexdigest()}.json").write_bytes(raw)
    with pytest.raises(ValueError, match="content address"):
        h.load_history(tmp_path, "game")


@pytest.mark.parametrize("tamper", ["rewrite", "foreign-target", "not-a-lifecycle"])
def test_a_tampered_lifecycle_store_is_an_error_naming_the_file(tmp_path, tamper):
    _, _, classified, _ = fixed_lifecycle()
    path = tmp_path / "game" / "lifecycles" / f"{c.digest(classified)}.json"
    h.publish_lifecycle(tmp_path, "game", classified)
    path.chmod(0o600)
    if tamper == "rewrite":
        path.write_bytes(canonical_json({**classified, "current_run_id": "run-7"}))
    else:
        path.unlink()
        place(path.parent, {**classified, "target_id": "engine"} if tamper == "foreign-target" else {"prior": []})
    with pytest.raises(ValueError, match=re.escape(str(path.parent))):
        h.load_history(tmp_path, "game")


def test_the_snapshot_store_is_bounded_at_512(tmp_path):
    directory = tmp_path / "game" / "snapshots"
    documents = [snapshot(run_id=f"run-{index:04d}") for index in range(h.MAX_SNAPSHOTS + 1)]
    for document in documents[:h.MAX_SNAPSHOTS]:
        place(directory, document)
    assert h.MAX_SNAPSHOTS == 512 and len(h.load_history(tmp_path, "game")["snapshots"]) == 512
    assert h.publish_snapshot(tmp_path, documents[0])["status"] == "duplicate"
    with pytest.raises(ValueError, match="bounded number of snapshots"):
        h.publish_snapshot(tmp_path, documents[-1])
    place(directory, documents[-1])
    with pytest.raises(ValueError, match="more than 512 snapshots"):
        h.load_history(tmp_path, "game")
    with pytest.raises(ValueError):
        h.publish_snapshot(tmp_path, documents[0])


def test_the_lifecycle_store_is_bounded_at_1024(tmp_path):
    base = fixed_lifecycle()[2]
    directory = tmp_path / "game" / "lifecycles"
    documents = [{**base, "current_run_id": f"run-{index:04d}"} for index in range(2, h.MAX_LIFECYCLES + 3)]
    for document in documents[:h.MAX_LIFECYCLES - 1]:
        place(directory, document)
    assert h.publish_lifecycle(tmp_path, "game", documents[h.MAX_LIFECYCLES - 1])["status"] == "published"
    assert h.MAX_LIFECYCLES == 1024 and len(h.load_history(tmp_path, "game")["lifecycles"]) == 1024
    assert h.publish_lifecycle(tmp_path, "game", documents[0])["status"] == "duplicate"
    with pytest.raises(ValueError, match="bounded number of lifecycles"):
        h.publish_lifecycle(tmp_path, "game", documents[-1])
    place(directory, documents[-1])
    with pytest.raises(ValueError, match="more than 1024 lifecycles"):
        h.load_history(tmp_path, "game")


# ----------------------------------------------------------------------------------- queries

def test_read_snapshot_returns_the_verified_document(tmp_path):
    document = snapshot([finding()])
    published = h.publish_snapshot(tmp_path, document)
    assert h.read_snapshot(tmp_path, "game", published["sha256"]) == document
    for sha256 in ("0" * 64, "abc", "../x", None):
        with pytest.raises(ValueError):
            h.read_snapshot(tmp_path, "game", sha256)
    place(tmp_path / "engine" / "snapshots", document)
    with pytest.raises(ValueError, match="another target"):
        h.read_snapshot(tmp_path, "engine", published["sha256"])
    path = tmp_path / "game" / "snapshots" / f"{published['sha256']}.json"
    path.chmod(0o600)
    path.write_bytes(canonical_json({**document, "gaps": ["edited"]}))
    with pytest.raises(ValueError, match="content address"):
        h.read_snapshot(tmp_path, "game", published["sha256"])


def test_previously_fixed_holds_only_rows_a_stored_lifecycle_records_as_fixed(tmp_path):
    before, _, classified, rechecked = fixed_lifecycle()
    h.publish_lifecycle(tmp_path, "game", classified)
    assert h.previously_fixed(h.load_history(tmp_path, "game")) == frozenset()
    h.publish_lifecycle(tmp_path, "game", rechecked)
    fixed_key = next(item["fingerprint"]["exact"] for item in before["findings"] if item["finding_id"] == "F2")
    assert h.previously_fixed(h.load_history(tmp_path, "game")) == frozenset({fixed_key})


def test_a_finding_fixed_in_history_regresses_when_it_returns(tmp_path):
    before, after, _, rechecked = fixed_lifecycle()
    h.publish_lifecycle(tmp_path, "game", rechecked)
    returned = snapshot([finding(), other("N1")], run_id="run-3")
    fixed = h.previously_fixed(h.load_history(tmp_path, "game"))
    regressed = lc.classify(after, returned, previously_fixed=fixed)
    states = {row["finding_id"]: row["state"] for row in regressed["current"]}
    assert states == {"F1": "persisting", "N1": "regressed"}


def test_ages_count_the_stored_snapshots_of_a_stage_that_hold_each_fingerprint(tmp_path):
    first, second = snapshot([finding(), other()]), snapshot([finding()], run_id="run-2")
    for document in (first, second, snapshot([other()], run_id="run-2", stage="verified")):
        h.publish_snapshot(tmp_path, document)
    history = h.load_history(tmp_path, "game")
    kept = copy.deepcopy(history)
    one, two = (item["fingerprint"]["exact"] for item in first["findings"])
    assert h.ages(history) == {one: 2, two: 1} == h.ages(history, stage="published")
    assert h.ages(history, "verified") == {two: 1} and h.ages(history, "candidate") == {}
    assert list(h.ages(history)) == sorted(h.ages(history)) and history == kept
    with pytest.raises(ValueError):
        h.ages(history, "final")


def test_latest_prior_is_the_greatest_earlier_run_of_the_stage(tmp_path):
    documents = {run_id: snapshot(run_id=run_id) for run_id in ("run-1", "run-2", "run-4")}
    verified = snapshot(run_id="run-3", stage="verified")
    for document in (*documents.values(), verified):
        h.publish_snapshot(tmp_path, document)
    history = h.load_history(tmp_path, "game")
    assert h.latest_prior(history, stage="published", before_run_id="run-4") == c.digest(documents["run-2"])
    assert h.latest_prior(history, stage="published", before_run_id="run-9") == c.digest(documents["run-4"])
    assert h.latest_prior(history, stage="published", before_run_id="run-2") == c.digest(documents["run-1"])
    assert h.latest_prior(history, stage="published", before_run_id="run-1") is None
    assert h.latest_prior(history, stage="verified", before_run_id="run-4") == c.digest(verified)
    assert h.latest_prior(history, stage="candidate", before_run_id="run-4") is None
    prior = h.read_snapshot(tmp_path, "game", h.latest_prior(history, stage="published", before_run_id="run-4"))
    assert prior["run_id"] == "run-2"


@pytest.mark.parametrize("arguments", [{"stage": "final", "before_run_id": "run-2"},
                                       {"stage": "published", "before_run_id": ""},
                                       {"stage": "published", "before_run_id": 2}], ids=["stage", "empty", "number"])
def test_latest_prior_refuses_an_open_stage_or_an_invalid_run_id(arguments):
    history = {"schema": c.HISTORY_SCHEMA, "target_id": "game", "snapshots": [], "lifecycles": []}
    with pytest.raises(ValueError):
        h.latest_prior(history, **arguments)


@pytest.mark.parametrize("history", [None, {}, {"schema": "other/1", "snapshots": [], "lifecycles": []},
                                     {"schema": c.HISTORY_SCHEMA, "snapshots": []}],
                         ids=["none", "empty", "foreign-schema", "no-lifecycles"])
def test_queries_refuse_a_document_that_is_not_a_history(history):
    with pytest.raises(ValueError):
        h.previously_fixed(history)
    with pytest.raises(ValueError):
        h.ages(history)
    with pytest.raises(ValueError):
        h.latest_prior(history, stage="published", before_run_id="run-2")
