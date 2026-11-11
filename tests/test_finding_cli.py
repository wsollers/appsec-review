"""The finding-metrics operator command line, end to end over the real modules.

The only fake is the run read boundary (``run_adapter.load_run``): reading a real accepted run is
the integration test's job.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.observability.findings import cli, run_adapter
from appsec_review.observability.findings.contracts import METRICS_SCHEMA
from appsec_review.observability.findings.run_adapter import RunDocuments

FIXTURES = Path(__file__).parent / "fixtures" / "finding_metrics" / "crash"
KEY = """
[[defect]]
id = "d1"
cwe = "CWE-416"
path = "net/parse.c"
line = 11
scope_start = 1
scope_end = 40
severity = "critical"

[[control]]
id = "c1"
path = "net/safe.c"
line = 11
scope_start = 1
scope_end = 40
"""


def package(finding_id, claim_id, *, severity="high", state="confirmed"):
    return {"finding_package_id": finding_id, "claim_id": claim_id, "lane": "lead", "state": state,
            "ship_block": {"status": "ship_blocking", "technical_severity": severity,
                           "verifier_model_distinct": True},
            "judge_verdict": None, "verification_review_id": "v1", "direct_evidence": ["r1"],
            "missing_predicates": []}


def documents(rows):
    """``rows``: (finding_id, path, cwe, code) tuples of one fake accepted run."""
    report = {"findings": [package(finding_id, f"claim-{finding_id}") for finding_id, *_ in rows],
              "verification_backlog": [], "withheld": []}
    claims = [{"claim_id": f"claim-{finding_id}", "weakness_cwe": cwe, "security_predicate": "memory_corruption",
               "preconditions": ["network_reachable"], "state": "confirmed", "duplicate_of": None}
              for finding_id, _path, cwe, _code in rows]
    located = {finding_id: {"locations": [{"path": path, "start_line": 10, "end_line": 12, "function": None,
                                           "code": code}], "citations": {"total": 1, "unresolved": 0}}
               for finding_id, path, _cwe, code in rows}
    return RunDocuments(report=report, projection={"claims": claims}, located=located, observations=[],
                        identities={"configuration_sha256": "a" * 64, "guidance_sha256": "b" * 64,
                                    "model_sha256": "c" * 64})


RUN_ONE = [("F1", "net/parse.c", "CWE-416", "use(buffer);"), ("F2", "net/old.c", "CWE-121", "strcpy(b, p);")]
RUN_TWO = [("F1", "net/parse.c", "CWE-416", "use(buffer);"), ("F3", "net/new.c", "CWE-190", "n = a * b;")]


@pytest.fixture
def runs(monkeypatch):
    table = {"run-1": documents(RUN_ONE), "run-2": documents(RUN_TWO)}

    def load(run_root):
        if Path(run_root).name not in table:
            raise RuntimeError("current accepted job_final_report_publication is unavailable")
        return table[Path(run_root).name]

    monkeypatch.setattr(run_adapter, "load_run", load)
    return table


def units(tmp_path, name, reviewed):
    path = tmp_path / name
    path.write_text(json.dumps({"schema": cli.UNITS_SCHEMA, "reviewed": reviewed, "unreviewed": {}}), encoding="utf-8")
    return path


def publish(tmp_path, run_id, revision, reviewed):
    return cli.main(["snapshot", "--run", str(tmp_path / "runs" / run_id), "--target-id", "game",
                     "--source-revision", revision, "--history", str(tmp_path / "history"),
                     "--units", str(units(tmp_path, f"{run_id}-units.json", reviewed))])


def both_runs(tmp_path):
    assert publish(tmp_path, "run-1", "1" * 40, {"net/parse.c": "a" * 64, "net/old.c": "b" * 64}) == 0
    assert publish(tmp_path, "run-2", "2" * 40,
                   {"net/parse.c": "a" * 64, "net/old.c": "c" * 64, "net/new.c": "d" * 64}) == 0


def scorecard(tmp_path, *extra):
    return cli.main(["scorecard", "--history", str(tmp_path / "history"), "--target-id", "game",
                     "--run-id", "run-2", *extra])


def test_snapshot_publishes_once_and_reports_its_gaps(tmp_path, runs, capsys):
    arguments = ["snapshot", "--run", str(tmp_path / "runs" / "run-1"), "--target-id", "game",
                 "--source-revision", "1" * 40, "--history", str(tmp_path / "history")]
    assert cli.main(arguments) == 0
    first = json.loads(capsys.readouterr().out)
    assert (first["status"], first["run_id"], first["findings"]) == ("published", "run-1", 2)
    assert first["gaps"] == ["reviewed_units_not_supplied"] and first["slice_rules_sha256"] is None
    assert Path(first["path"]).is_file()
    assert cli.main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "duplicate"


def test_snapshot_applies_slice_rules_and_records_their_identity(tmp_path, runs, capsys):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"schema": "appsec-review/finding-slice-rules/1",
                                 "ownership": {"engine": ["net/old.c"], "default": "first_party"}}), encoding="utf-8")
    assert cli.main(["snapshot", "--run", str(tmp_path / "runs" / "run-1"), "--target-id", "game",
                     "--source-revision", "1" * 40, "--history", str(tmp_path / "history"),
                     "--slice-rules", str(rules)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert len(receipt["slice_rules_sha256"]) == 64
    stored = json.loads(Path(receipt["path"]).read_text(encoding="utf-8"))
    assert {item["finding_id"]: item["ownership"] for item in stored["findings"]} == {
        "F1": "first_party", "F2": "engine"}


def test_scorecard_compares_with_the_latest_prior_run_by_default(tmp_path, runs, capsys):
    both_runs(tmp_path)
    capsys.readouterr()
    assert scorecard(tmp_path) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("finding scorecard run=run-2 target=game ")
    # F1 persists; F2's file changed and it is gone: a fix candidate, never a fix; F3 is new.
    assert "   since run-1: new=1 regressed=0 persisting=1 fixed=0 still_present=0" in lines
    assert "   not progress: fix_candidate=1 not_redetected=0 not_covered=0" in lines
    assert "   units reviewed: 3/3 (1.000)" in lines


def test_scorecard_can_skip_or_name_the_prior_run(tmp_path, runs, capsys):
    both_runs(tmp_path)
    capsys.readouterr()
    assert scorecard(tmp_path, "--prior-run-id", "none") == 0
    assert "   since prior run: n/a (no_prior_run)" in capsys.readouterr().out.splitlines()
    assert scorecard(tmp_path, "--prior-run-id", "run-1", "--json") == 0
    document = json.loads(capsys.readouterr().out)
    assert document["schema"] == METRICS_SCHEMA and document["lifecycle"]["prior_run_id"] == "run-1"
    assert scorecard(tmp_path, "--prior-run-id", "run-0") == 2
    assert "no published snapshot of prior run" in capsys.readouterr().err


def test_scorecard_with_a_key_and_developer_outcomes_writes_the_canonical_document(tmp_path, runs, capsys):
    both_runs(tmp_path)
    key = tmp_path / "key.toml"
    key.write_text(KEY, encoding="utf-8")
    stored = json.loads(next((tmp_path / "history" / "game" / "snapshots").glob("*.json")).read_text(encoding="utf-8"))
    outcomes = tmp_path / "outcomes.json"
    outcomes.write_text(json.dumps({"schema": "appsec-review/developer-outcomes/1", "target_id": "game", "outcomes": [
        {"fingerprint": stored["findings"][0]["fingerprint"]["exact"], "disposition": "fixed",
         "opened_on": "2026-11-01", "decided_on": "2026-11-05", "expires_on": None}]}), encoding="utf-8")
    output = tmp_path / "scorecard.json"
    capsys.readouterr()
    assert scorecard(tmp_path, "--key", str(key), "--outcomes", str(outcomes), "--as-of", "2026-11-11",
                     "--output", str(output)) == 0
    text = capsys.readouterr().out
    assert "   this run on the key: recall 1/1 (1.000" in text
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["correctness"]["defects_found"] == ["d1"] and document["correctness"]["controls_reported"] == []
    assert document["outcomes"]["available"] is True and document["labels"]["available"] is True
    assert scorecard(tmp_path, "--outcomes", str(outcomes)) == 2          # the clock is never read
    assert "--as-of" in capsys.readouterr().err


def test_crash_ingest_then_scorecard_corroborates_a_finding_and_lists_a_missed_bucket(tmp_path, runs, capsys):
    runs["run-2"] = documents([("F1", "net/parse.c", "CWE-416", "use(buffer);")])
    assert publish(tmp_path, "run-2", "2" * 40, {"net/parse.c": "a" * 64, "net/session.c": "b" * 64,
                                                 "game/score.c": "c" * 64, "game/math.c": "d" * 64}) == 0
    capsys.readouterr()
    assert cli.main(["crash-ingest", "--source", f"sanitizer_report={FIXTURES / 'sanitizer_wellformed.log'}",
                     "--strip-root", "/home/builder/src/", "--output", str(tmp_path / "crash")]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "published" and receipt["counts"]["parsed"] == 1 and receipt["counts"]["buckets"] == 3
    evidence_text = Path(receipt["path"]).read_text(encoding="utf-8")
    assert "/home/builder" not in evidence_text, "the build-machine prefix is never stored"
    assert scorecard(tmp_path, "--prior-run-id", "none", "--crash-evidence", receipt["path"], "--json") == 0
    document = json.loads(capsys.readouterr().out)
    crash = document["crash"]
    assert crash["available"] is True and crash["corroborated_findings"] == 1
    assert crash["corroborated_share_of_actionable"]["value"] == 1.0
    assert crash["by_binding_tier"]["symbol_matched"] == 3
    # The use-after-free is on a finding; the data race and the overflow are not memory-safety faults.
    assert crash["memory_safety_buckets_without_finding"] == 0
    assert document["labels"]["counts"]


def test_crash_ingest_reads_a_directory_and_records_failures_without_file_names(tmp_path, capsys):
    source = tmp_path / "export"
    source.mkdir()
    (source / "player-alice-crash.log").write_bytes((FIXTURES / "sanitizer_wellformed.log").read_bytes())
    (source / "broken.log").write_bytes((FIXTURES / "malformed.json").read_bytes())
    assert cli.main(["crash-ingest", "--source", f"stackwalk_json={source}", "--output", str(tmp_path / "out")]) == 0
    out = capsys.readouterr().out
    assert "alice" not in out and json.loads(out)["counts"]["files"] == 2
    assert "alice" not in Path(json.loads(out)["path"]).read_text(encoding="utf-8")


def test_audit_sample_is_reproducible_and_never_overwritten(tmp_path, capsys):
    leads = tmp_path / "leads.json"
    leads.write_text(json.dumps([{"lead_id": f"L{index}", "disposition": "dismissed_by_adjudication"}
                                 for index in range(10)]), encoding="utf-8")
    arguments = ["audit-sample", "--leads", str(leads), "--seed", "2026-11", "--size", "4"]
    assert cli.main([*arguments, "--output", str(tmp_path / "one.json")]) == 0
    first = json.loads(capsys.readouterr().out)
    assert cli.main([*arguments, "--output", str(tmp_path / "two.json")]) == 0
    assert json.loads(capsys.readouterr().out) == first and first == {
        "eligible": 10, "sampled": 4, "sample_sha256": first["sample_sha256"]}
    assert (tmp_path / "one.json").read_bytes() == (tmp_path / "two.json").read_bytes()
    assert cli.main([*arguments, "--output", str(tmp_path / "one.json")]) == 2
    assert "never overwritten" in capsys.readouterr().err


def test_an_unverifiable_run_is_named_and_nothing_is_published(tmp_path, runs, capsys):
    assert cli.main(["snapshot", "--run", str(tmp_path / "runs" / "run-9"), "--target-id", "game",
                     "--source-revision", "1" * 40, "--history", str(tmp_path / "history")]) == 2
    assert "RuntimeError" in capsys.readouterr().err
    assert not (tmp_path / "history").exists()


@pytest.mark.parametrize("arguments, message", [
    (["scorecard", "--history", "{h}", "--target-id", "game", "--run-id", "run-7"], "holds 0 published snapshots"),
    (["snapshot", "--run", "{r}", "--target-id", "Not Safe", "--source-revision", "1", "--history", "{h}"],
     "target_id"),
    (["crash-ingest", "--source", "sanitizer_report", "--output", "{h}"], "ADAPTER=PATH"),
    (["snapshot", "--run", "{r}", "--target-id", "game", "--source-revision", "1", "--history", "{h}",
      "--units", "{u}"], "reviewed-units/1"),
], ids=["unknown-run", "unsafe-target", "bad-source", "bad-units"])
def test_unusable_inputs_exit_two_with_a_named_reason(tmp_path, runs, capsys, arguments, message):
    bad_units = tmp_path / "units.json"
    bad_units.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    filled = [item.format(h=tmp_path / "history", r=tmp_path / "runs" / "run-1", u=bad_units) for item in arguments]
    assert cli.main(filled) == 2
    assert message in capsys.readouterr().err
