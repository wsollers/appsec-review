from __future__ import annotations

from dataclasses import replace
import io
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_source_history_analysis import changelog, discovery, git, github, job, lines, signals, sources, symbols
from .support import HEAD, PARENT, SOURCE, STAMP, artifact, context, document, header, node, nodes
from .test_changelog import LIMITS, lane
from .test_github import API, PATH, client, settings
from .test_handlers import baseline, invoke
from .test_sources import metadata


def test_changelog_dates_line_decoding_and_detection_bounds():
    assert changelog._stated_date("31 Feb 2024") is None
    assert changelog._split_lines(b"\r\nx\r\n", 2) == (["", "x"], 0, 0)
    assert changelog.detect(["prose"] * changelog.DETECTION_LINES + ["## 2024-01-01"]) is None
    assert changelog._rename_target("a/{old => new}/x") == "a/new/x"
    assert changelog._rename_target("old => new") == "new"
    assert changelog._rename_target("a/{nochange}/x => b") == "b"
    binder = changelog.PathBinder(["a.py"])
    assert binder.bind("a.py") == binder.bind("a.py") == ("exact", "a.py")


@pytest.mark.parametrize("data,expected", [
    (b"preface\ncommit " + HEAD.encode() + b"\nM\ta.py\n", ("git-log", 1, 1)),
    (b"preface\nr1 | a | 2024-01-01 | 1 line\nChanged paths:\nwrong row\n\nmessage\n",
     ("svn-log", 1, 2)),
    (b"preface\n2024-01-01 Author\n  * a.py: fixed\n", ("gnu-changelog", 1, 1)),
    (b"  orphan\n2024-01-01 Author\n  * a.py: fixed\n", ("gnu-changelog", 1, 1)),
    (b"## 2024-01-01\ncommit " + HEAD.encode() + b"\n", (None, 0, 1)),
    (b"commit " + HEAD.encode() + b"\nDate: 2024-01-01\n", ("git-log", 1, 0)),
], ids=["git-preface", "svn-preface", "gnu-preface", "gnu-orphan", "markdown-foreign", "git-no-message"])
def test_changelog_format_edge_rows(data, expected):
    result = changelog.parse(data, LIMITS, signals.classify_text)
    assert (result["format"], result["counts"]["entry_count"], result["counts"]["unparsed_lines"]) == expected


def test_changelog_skips_overlong_svn_paths_and_blank_header_separator():
    data = b"r1 | a | 2024-01-01 | 1 line\nChanged paths:\n" + b"x" * 100 + b"\n\nbody\n"
    result = changelog.parse(data, replace(LIMITS, max_line_bytes=64), signals.classify_text)
    assert result["entries"][0]["paths"] == []
    assert changelog.file_gaps("NEWS", result) == [
        {"gap": "changelog_line_too_long", "path": "NEWS", "count": 1, "unit": "lines"}]
    result = changelog.parse(b"r1 | a | 2024-01-01 | 1 line\nmessage", LIMITS, signals.classify_text)
    assert result["entries"][0]["id"] == "r1" and result["status"] == "parsed"


def test_changelog_no_target_and_disabled_multi_source_outcomes(tmp_path):
    unit, handler = lane(tmp_path / "none", {"a.py": b"x"})
    assert handler(replace(unit, job=replace(unit.job, target_root=None))) == {
        "terminal_status": "SKIPPED_NA", "reason": "no_target", "gaps": []}
    for enabled, expected in ((True, "SKIPPED_NA"), (False, "SKIPPED_POLICY")):
        unit, handler = lane(tmp_path / str(enabled), {"one/a.py": b"x", "two/b.py": b"y"},
                             sources={"one": "one", "two": "two"}, bounds={"enabled": enabled})
        result = handler(unit)
        assert result["terminal_status"] == expected and result["gaps"] == []
        assert {value["terminal_status"] for value in result["by_source"].values()} == {expected}


def test_git_blank_tokens_eof_buffer_and_large_final_message(monkeypatch):
    monkeypatch.setattr(git, "CHUNK_BYTES", 8)
    assert git.parse_log(b"\0\n\0" + header())[0]["commit"] == HEAD
    buffer = git._Buffer(io.BytesIO(b""))
    assert not buffer.fill() and not buffer.fill()
    body = b"x\0y" * 100
    result = git.parse_messages_stream(io.BytesIO(HEAD.encode() + b"\0" + body + b"\0"), [HEAD], max_message_bytes=2)
    assert result == ({HEAD: b"x\0"}, ["commit_message_bound_reached"], [HEAD])


def test_source_metadata_unreadable_is_a_stable_gap_identity(tmp_path, monkeypatch):
    directory = metadata(tmp_path)
    assert sources._resolve_ref(directory, "refs/heads/missing", "sha1") is None
    (directory / "packed-refs").write_text(f"{HEAD} refs/heads/other\n")
    assert sources._resolve_ref(directory, "refs/heads/missing", "sha1") is None
    (directory / "HEAD").unlink()
    (directory / "HEAD").symlink_to(directory / "refs/heads/main")
    before = sources.history_identity(tmp_path)
    assert before == sources.history_identity(tmp_path) and len(before) == 64
    (tmp_path / "missing").mkdir()
    assert discovery.origin_url(tmp_path / "missing") == ""


def test_discovery_manifest_identity_and_target_mismatch_are_scoped(tmp_path):
    target = tmp_path / "target"
    metadata(target / "a")
    for identity, path in (({"kind": "other"}, "target/a"), ({"kind": "git", "commit": HEAD}, "elsewhere")):
        manifest = {"identity": identity, "target_path": path}
        file = tmp_path / "manifest.json"
        file.write_text(json.dumps(manifest))
        acquisition = {"schema": "appsec-review/target-system-acquisition/1", "components": {
            "a": {"manifest": "manifest.json", "manifest_sha256": job.file_sha256(file)}},
            "identity": {"a": {"identity": {"kind": "git", "commit": HEAD}}}}
        result = discovery.discover_sources(target=target, repository=tmp_path, acquisition=acquisition,
                                           components=[], api_base="https://api.github.com")
        assert result[0]["source_id"] == "a"
        assert result[0]["git"]["decision"] == "GAP" and result[0]["git"]["reason"] == "acquisition_source_unavailable:ValueError"


def test_discovery_missing_acquired_git_and_unreadable_metadata(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    manifest = {"schema": "appsec-review/target-acquisition/1", "target_id": "t",
                "identity": {"kind": "git", "commit": HEAD}}
    result = discovery.discover_sources(target=target, repository=tmp_path, acquisition=manifest,
                                       components=[], api_base=API)[0]
    assert (result["source_id"], result["git"]["reason"]) == ("t", "acquired_git_history_unavailable:no_git_metadata")
    monkeypatch.setattr(discovery, "_safe_root", lambda *args: (_ for _ in ()).throw(OSError("fixture")))
    result = discovery.discover_sources(target=target, repository=tmp_path, acquisition=manifest,
                                       components=[], api_base=API)[0]
    assert (result["source_id"], result["git"]["reason"]) == ("t", "source_metadata_unreadable:OSError")
    monkeypatch.setattr(discovery, "MAX_SOURCES", 1)
    with pytest.raises(ValueError, match="source count is invalid"):
        discovery.discover_sources(target=target, repository=tmp_path, acquisition={
            "schema": "appsec-review/target-system-acquisition/1", "components": {"a": {}},
            "spec": {"components": {"b": {}}}}, components=[], api_base=API)


def test_github_incomplete_associations_keep_later_commits_and_link_scope():
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {"link": f'<{API}{PATH}?per_page=2&page=9>; rel="next"'}, []),
        f"/repos/acme/repo/commits/{PARENT}/pulls?per_page=2&page=1": (200, {}, []),
    }
    result = github.enrich(client(responses)[0], HEAD, [HEAD, PARENT])
    assert result["facts"][HEAD]["gap"] == "github_pagination_malformed"
    assert result["facts"][HEAD]["evidence"]["pulls"]["path"] == PATH
    assert result["facts"][PARENT]["direct_push"] is True
    instance, _ = client((200, {}, {}), max_requests=1)
    instance.requests = 1
    result = github.enrich(instance, HEAD, [HEAD])
    assert result["gaps"] == ["github_request_budget_exhausted"] and result["missing_commit_count"] == 1


def test_github_pull_detail_transport_failure_and_cached_pull_selection():
    pull = {"number": 7, "merged_at": "x", "user": {"login": "author"}, "head": {"sha": "not-an-object"}}
    responses = {
        f"/repos/acme/repo/commits/{HEAD}": (200, {}, {"sha": HEAD}),
        PATH + "?per_page=2&page=1": (200, {}, [pull]),
        f"/repos/acme/repo/commits/{PARENT}/pulls?per_page=2&page=1": (200, {}, [pull]),
        "/repos/acme/repo/pulls/7": OSError("offline"),
        "/repos/acme/repo/pulls/7/reviews?per_page=2&page=1": (200, {}, []),
    }
    instance, seen = client(responses)
    result = github.enrich(instance, HEAD, [HEAD, PARENT])
    assert result["facts"][HEAD]["self_merged"] is None
    assert result["facts"][HEAD]["review_bypass"] is True
    assert result["facts"][HEAD]["evidence"]["pull_detail"]["status"] == 0
    assert sum(path == "/repos/acme/repo/pulls/7" for path, _, _ in seen) == 1
    assert result["facts"][PARENT]["pull_request"] == 7


def test_classification_promotes_security_fix_and_skips_unowned_component():
    result = signals.classify(
        [{"change_id": HEAD, "files": []}], {HEAD: b"security CWE-79"}, {}, known_commits=[],
        fix_labels=[], security_labels=[], formatting_tolerance=0.1)
    assert result[HEAD]["fix"] == result[HEAD]["security_fix"] == "heuristic"
    from .support import change
    from .test_algorithms import RULES
    values = signals.compute_signals([change()], {}, {}, eligible={"a.py": {"line_count": 1}},
                                     roots=[], anchor_time=STAMP, window_months=6, half_life_days=90,
                                     minor_author_share=0.1, fix_interval_days=30, filters=RULES)
    assert values["components"] == {} and values["files"]["a.py"]["component_id"] is None
    assert values["files"]["a.py"]["churn_lines"] == 2
    assert values["files"]["a.py"]["fix_change_count"] == values["files"]["a.py"]["repeat_fix_count"] == 0


def test_partial_fix_history_preserves_known_events():
    history = lines.FileLines([
        {"commit": HEAD, "hunks": [[1, 1, 1, 1]], "binary": False},
        {"commit": PARENT, "hunks": [[1, 1, 1, 1]], "binary": False}], 1)
    changes = [{"change_id": commit, "effective_time": time, "fix": True}
               for commit, time in ((HEAD, 2), (PARENT, 1), ("c" * 40, 0))]
    result = lines.fix_on_fix(changes, lines=history, lines_reason=None, symbols=None,
                              symbols_reason=None, interval_days=30)
    assert result["status"] == "partial" and result["count"] == 1
    assert result["events"][0]["earlier_change"] == PARENT
    assert {item["earlier_change"] for item in result["undetermined"]} == {"c" * 40}
    assert lines.parse_file_history(b"\n") == []


def test_symbol_name_declarators_parent_fields_and_unnamed_root():
    record = [node((), "module"), node((0,), "function_definition"),
              node((0, 0), "function_declarator", field="declarator"),
              node((0, 0, 0), "identifier", 4, 5, field="declarator")]
    tree = symbols._Tree(record)
    assert symbols._name(tree, SOURCE, (0,)) == "f"
    assert symbols._name(tree, SOURCE, ()) is None and symbols._name(tree, SOURCE, None) is None
    tree = symbols._Tree([node((), "assignment"), node((0,), "identifier", 4, 5, field="left"),
                          node((1,), "lambda_expression")])
    assert symbols._name(tree, SOURCE, (1,)) == "f"
    tree = symbols._Tree([node((), "function_definition"), node((0,), "identifier", 0, 0, field="name")])
    assert symbols._name(tree, SOURCE, ()) is None


def test_symbol_else_if_parentheses_boolean_runs_and_alternative_body():
    tree = symbols._Tree([
        node((), "module"), node((0,), "if_statement"),
        node((0, 0), "if_statement", field="alternative"), node((0, 0, 0), "statement", field="alternative"),
        node((0, 1), "else_clause"), node((0, 1, 0), "if_statement"),
        node((1,), "binary_expression"), node((1, 0), "&&", named=False),
        node((1, 1), "parenthesized_expression"), node((1, 1, 0), "binary_expression"),
        node((1, 1, 0, 0), "&&", named=False)])
    result = symbols._measure(tree, (), symbols.RULES["C"])
    assert result["decisions"] == 5 and result["cognitive"] == 5
    assert result["gaps"] == [] and result["nested"] == []


def test_ruby_lambda_wrapper_is_not_a_nested_function():
    tree = symbols._Tree([node((), "module"), node((0,), "lambda"), node((0, 0), "block"),
                          node((1,), "block")])
    assert symbols._is_function(tree, (0,), symbols.RULES["Ruby"])
    assert not symbols._is_function(tree, (0, 0), symbols.RULES["Ruby"])
    assert symbols._is_function(tree, (1,), symbols.RULES["Ruby"])


def test_fix_and_symbol_handlers_without_lines_or_symbols(tmp_path):
    unit = baseline(context(tmp_path, "analyze.fix_on_fix"))
    unit.outputs["analyze.line_history"] = {}
    unit.outputs["analyze.symbol_spans"] = {}
    result = invoke(unit)
    value = document(unit, result)["files"]["a.py"]
    assert value["status"] == "unavailable" and value["count"] is None
    assert value["undetermined"][0]["reason"] == "line_history_unavailable"
    assert result["gaps"] == ["fix_on_fix_undetermined"]
    result = invoke(replace(unit, unit_id="analyze.symbol_signals"))
    assert result["symbol_count"] == 0 and document(unit, result)["symbols"] == {}
    metrics = document(unit, unit.outputs["analyze.compute_signals"])
    for change in metrics["files"]["a.py"]["changes"]:
        change["fix"] = False
    unit.outputs["analyze.compute_signals"]["artifact"] = artifact(unit, "no-fixes.json", metrics)
    result = invoke(unit)
    assert result["event_count"] == 0 and document(unit, result)["files"] == {}


def test_retain_detects_post_storage_identity_change(tmp_path, monkeypatch):
    source = tmp_path / "input"
    source.write_bytes(b"x")
    monkeypatch.setattr(job, "_artifact", lambda *args: {"sha256": "wrong", "size_bytes": 1})
    with pytest.raises(ValueError, match="retained git output changed"):
        job._retain(tmp_path, source, tmp_path / "retained", 1)


def test_gnu_path_budget_markdown_nonpaths_and_empty_internal_parsers():
    parsed = changelog.parse(b"2024-01-01 Author\n  * a.py, b.py: fixed\n",
                             replace(LIMITS, max_paths_per_entry=1), signals.classify_text)
    assert parsed["entries"][0]["paths"] == [("a.py", ())]
    assert changelog.file_gaps("NEWS", parsed) == [{
        "gap": "changelog_entry_paths_truncated", "path": "NEWS", "count": 1, "unit": "entries"}]
    markdown = changelog.parse(b"## 2024-01-01\n- mention `symbol` and `bad path` plus `a.py`\n", LIMITS,
                               signals.classify_text)
    assert markdown["entries"][0]["paths"] == [("a.py", ())]
    for parser in (changelog._parse_git, changelog._parse_gnu):
        assert list(parser([], {}, signals.classify_text, LIMITS)) == []


def test_origin_ignores_non_url_lines_and_discovery_ignores_nonrepo_roots(tmp_path):
    root = tmp_path / "target"
    metadata(root, config='[remote "upstream"]\nurl=x\n[remote "origin"]\n# comment\nfetch=+refs/*\nurl=https://github.com/a/b\n')
    assert discovery.origin_url(root) == "https://github.com/a/b"
    assert discovery.discover_sources(target=tmp_path, repository=tmp_path, acquisition=None,
                                     components=[], api_base=API)[0]["root"] == "target"
    (tmp_path / "empty").mkdir()
    value = discovery.discover_sources(target=tmp_path / "empty", repository=tmp_path, acquisition=None,
                                      components=[], api_base=API)
    assert value[0]["root"] == "." and value[0]["git"]["reason"] == "no_git_metadata"


def test_metadata_union_bound_counts_root_before_filtering(tmp_path, monkeypatch):
    metadata(tmp_path / "a")
    metadata(tmp_path / "b")
    monkeypatch.setattr(sources, "MAX_DISCOVERY_ENTRIES", 2)
    with pytest.raises(ValueError, match="history_metadata_discovery_bound_reached"):
        sources.metadata_roots(tmp_path, ("a", "b"))


def test_bounded_changelog_read_hashes_bytes_after_retention_limit(tmp_path, monkeypatch):
    path = tmp_path / "ChangeLog"
    path.write_bytes(b"abcdef")
    monkeypatch.setattr(job, "CHUNK_BYTES", 2)
    assert job._read_bounded(tmp_path, {"path": "ChangeLog", "sha256": job.file_sha256(path)}, 2) == (b"ab", 6)
    original = job.file_sha256(path)
    path.write_bytes(b"abcdeg")
    with pytest.raises(job.ChangelogIntegrityError, match="accepted target bytes changed: ChangeLog"):
        job._read_bounded(tmp_path, {"path": "ChangeLog", "sha256": original}, 2)


def test_fix_without_hunks_and_with_a_binary_snapshot_prefix():
    history = lines.FileLines([
        {"commit": "c" * 40, "hunks": [], "binary": True},
        {"commit": HEAD, "hunks": [], "binary": False},
        {"commit": PARENT, "hunks": [], "binary": False}], 1)
    result = lines.fix_on_fix(
        [{"change_id": HEAD, "effective_time": 1, "fix": True},
         {"change_id": PARENT, "effective_time": 0, "fix": True}],
        lines=history, lines_reason=None, symbols=[], symbols_reason=None, interval_days=30)
    assert result["count"] == 0 and result["status"] == "complete" and result["candidate_pair_count"] == 1
    assert history.snapshot_regions(HEAD) is None


def test_unknown_revert_target_does_not_create_reverse_classification():
    result = signals.classify([{"change_id": HEAD, "files": []}], {
        HEAD: b"This reverts commit " + PARENT.encode()}, {}, known_commits=[PARENT],
        fix_labels=[], security_labels=[], formatting_tolerance=0.1)
    assert result[HEAD]["reverts"] == PARENT and PARENT not in result


def test_symbol_declarator_depth_and_same_line_nested_ownership():
    records = [node((), "module"), node((0,), "function_definition")]
    for depth in range(1, 18):
        records.append(node((0,) * (depth + 1), "function_declarator", field="declarator"))
    assert symbols._name(symbols._Tree(records), SOURCE, (0,)) is None
    records = [node((), "module"), node((0,), "function_definition", end_row=0),
               node((0, 0), "lambda_expression", end_row=0)]
    value = symbols.extract({"nodes": records}, SOURCE, "C", "a.c")
    assert len(value["symbols"]) == 2 and value["symbols"][0]["own_lines"] == [(1, 1)]
