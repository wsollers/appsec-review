"""The per-defect funnel (``appsec_review.acceptance.funnel``) on small synthetic run trees.

Each defect of the synthetic key is built to stop for one reason, so the stage vocabulary and the
``stopped_because`` codes are pinned. A separate fixture carries the shapes of a real run (trimmed).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

from appsec_review.acceptance import funnel
from appsec_review.acceptance.answer_key import Defect

INFERENCE = "data/jobs/job_inference_security_review"
ATTEMPT = f"{INFERENCE}/attempts/attempt_0001"
FIXTURE = Path(__file__).parent / "data" / "funnel_real_shape.json"


class Tree:
    """Builds a minimal run directory of the shapes the evaluator reads."""

    def __init__(self, root: Path, run_id: str = "run-1") -> None:
        self.root = root / run_id
        self.catalog: set[str] = set()
        self.observations: list[tuple[str, str, str, int, int]] = []
        self.events: list[dict] = []
        self.queue: dict[str, list[str]] = {"lead": [], "hunt": []}
        self.report: dict[str, list[dict]] = {"findings": [], "verification_backlog": [], "withheld": []}
        self.projection: list[dict] = []
        self.write_json("data/jobs/job_inference_security_review/latest.json",
                        {"handoff_path": f"{ATTEMPT}/handoff.json"})

    def write_json(self, relative: str, value: object) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    def observe(self, name: str, path: str, line: int, producer: str = "codeql", end: int | None = None) -> str:
        identity = f"asr:tool_observation:{name}"
        self.observations.append((identity, producer, path, line, end or line))
        self.catalog.add(path)
        return identity

    def package(self, package_id: str, observation: str, lane: str = "lead", queued: bool = True,
                review_only: bool = False) -> None:
        document = {"package_id": package_id, "lane": lane, "kind": "finding_lead" if lane == "lead" else "hunt",
                    "lead_menu": [{"observation_id": observation}]}
        if review_only:
            self.write_json(f"data/review-packages/set/{package_id}.json", {k: v for k, v in document.items() if k != "lane"})
            return
        self.write_json(f"{ATTEMPT}/steps/packages/tasks/assemble_lead_packages/assembly/packages/{package_id}.json", document)
        if queued:
            self.queue[lane].append(package_id)

    def cell(self, cell_id: str, package_id: str, status: str, *, role: str = "red_team_analyst",
             claim_id: str | None = None, gap_class: str | None = None, retrievals: tuple[dict, ...] = (),
             result: dict | None = None, lane: str = "lead") -> None:
        self.events.append({"kind": "cell_terminal", "event_id": f"event-{cell_id}", "subject_id": cell_id, "body": {"cell": {
            "cell_id": cell_id, "lane": lane, "package_id": package_id, "role": role, "task": "t", "claim_id": claim_id,
            "status": status, "attempts": 1, "gap_ids": []}}})
        self.write_json(f"{INFERENCE}/cells/{cell_id}/attempt-1.json", {
            "attempt": 1, "cell_id": cell_id, "status": status, "gap_class": gap_class, "result": result,
            "counts": {"queries": len(retrievals)}, "turns": [{"turn": 1, "retrievals": list(retrievals)}]})

    def claim(self, claim_id: str, observation: str, state: str, package_id: str = "p") -> None:
        claim = {"claim_id": claim_id, "state": "proposed", "package_id": package_id, "lane": "lead",
                 "affected_entities": [observation]}
        self.events.append({"kind": "claim_proposed", "event_id": f"event-{claim_id}", "subject_id": claim_id,
                            "body": {"claim": claim, "round": 0}})
        if state != "proposed":
            self.events.append({"kind": "state_transition", "event_id": f"event-t-{claim_id}", "subject_id": claim_id,
                                "body": {"from_state": "proposed", "to_state": state, "round": 1}})

    def publish(self, bucket: str, claim_id: str, ship: str) -> None:
        self.report[bucket].append({"claim_id": claim_id, "ship_block": {"status": ship}})

    def recording(self, name: str, cell_id: str, *, repair: bool = False, parsed: bool = True, role: str = "red_team_analyst") -> None:
        self.write_json(f"data/inference-recordings/job_inference_security_review/{name}.json", {
            "request": {"cell_id": cell_id, "role": role, "repair_errors": ["bad"] if repair else []},
            "result": {"proposal": {"action": "final"}} if parsed else None})

    def build(self) -> Path:
        index = self.root / "data" / "indices" / "observations" / "shard.sqlite"
        index.parent.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(index)
        database.execute("CREATE TABLE entities(identity TEXT PRIMARY KEY, kind TEXT, name TEXT, payload_json TEXT)")
        database.execute("CREATE TABLE locations(entity_id TEXT PRIMARY KEY, path TEXT, start_line INT, end_line INT)")
        for identity, producer, path, start, end in self.observations:
            database.execute("INSERT INTO entities VALUES (?, 'tool_observation', 'rule', ?)",
                             (identity, json.dumps({"scanner": producer})))
            database.execute("INSERT INTO locations VALUES (?, ?, ?, ?)", (identity, f"<target>/{path}", start, end))
        database.commit()
        database.close()
        source = self.root / "data" / "indices" / "source" / "shard.sqlite"
        source.parent.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(source)
        database.execute("CREATE TABLE entities(identity TEXT PRIMARY KEY, kind TEXT, name TEXT, payload_json TEXT)")
        database.execute("CREATE TABLE locations(entity_id TEXT PRIMARY KEY, path TEXT, start_line INT, end_line INT)")
        for number, path in enumerate(sorted(self.catalog)):
            database.execute("INSERT INTO entities VALUES (?, 'source_file', ?, '{}')", (f"asr:source_file:{number}", path))
            database.execute("INSERT INTO locations VALUES (?, ?, 1, 1)", (f"asr:source_file:{number}", path))
        database.commit()
        database.close()
        for lane, ids in self.queue.items():
            self.write_json(f"{ATTEMPT}/lanes/{lane}.json", {"lane": lane, "package_ids": ids})
        ledger = self.root / ATTEMPT / "steps" / "lead_review" / "tasks" / "teams" / "ledger.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in self.events), encoding="utf-8")
        if self.projection:
            self.write_json(f"{ATTEMPT}/steps/publication/tasks/publish_claim_ledger/projection.json",
                            {"claims": self.projection})
        if any(self.report.values()):
            self.write_json("data/jobs/job_final_report_publication/attempts/attempt_0001/steps/report/tasks/assemble/"
                            "final-report.json", self.report)
        return self.root


def defect(name: str, path: str, line: int = 10, end: int | None = None) -> Defect:
    return Defect(name, "CWE-1", path, line, "", (), end)


EXECUTED = {"status": "executed", "tool": "search", "result_count": 3}
DENIED = {"status": "denied", "tool": "query_code_graph", "denial_code": "schema_violation"}


def synthetic(tmp_path: Path) -> tuple[Path, list[Defect]]:
    tree = Tree(tmp_path)
    keys = []

    def add(name: str, line: int = 10, *, observe: bool = True, catalog: bool = True) -> str | None:
        keys.append(defect(name, f"src/{name}.cpp", line))
        if catalog:
            tree.catalog.add(f"src/{name}.cpp")
        return tree.observe(name, f"src/{name}.cpp", line) if observe else None

    add("not_in_catalog", catalog=False, observe=False)
    add("no_observation", observe=False)
    add("no_lead")
    tree.package("review-only", add("review_cap"), review_only=True)
    tree.package("hunt-unqueued", add("hunt_cap"), lane="hunt", queued=False)
    tree.package("p-notlaunched", add("not_launched"))
    tree.cell("c-nl", "p-notlaunched", "not_launched")
    tree.package("p-invalid", add("invalid"))
    tree.cell("c-inv", "p-invalid", "invalid", gap_class="schema_error")
    tree.package("p-timeout", add("timeout"))
    tree.cell("c-to", "p-timeout", "timed_out", gap_class="budget_gap")
    tree.package("p-denied", add("denied"))
    tree.cell("c-den", "p-denied", "invalid", gap_class="schema_error", retrievals=(DENIED, DENIED))
    tree.package("p-noclaim", add("no_claim"))
    tree.cell("c-nc", "p-noclaim", "succeeded", retrievals=(EXECUTED, DENIED), result={"claims": []})
    tree.package("p-blue", add("blue"))
    observation = tree.observations[-1][0]
    tree.cell("c-blue-red", "p-blue", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-blue", observation, "contradicted", "p-blue")
    tree.cell("c-blue-b", "p-blue", "succeeded", role="blue_team_refuter", claim_id="claim-blue",
              result={"disposition": "contradicts"})
    tree.cell("c-blue-v", "p-blue", "succeeded", role="independent_verifier", claim_id="claim-blue",
              result={"proposed_disposition": "contradicted"})
    tree.package("p-judge", add("judge_blue"))
    observation = tree.observations[-1][0]
    tree.cell("c-j-red", "p-judge", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-judge", observation, "contradicted", "p-judge")
    tree.cell("c-j-b", "p-judge", "succeeded", role="blue_team_refuter", claim_id="claim-judge",
              result={"disposition": "contradicts"})
    tree.cell("c-j-v", "p-judge", "succeeded", role="independent_verifier", claim_id="claim-judge",
              result={"proposed_disposition": "insufficient_evidence"})
    tree.events.append({"kind": "judge_verdict", "event_id": "event-jv", "subject_id": "claim-judge",
                        "body": {"claim_id": "claim-judge", "verdict": "blue_correct"}})
    tree.package("p-insuff", add("insufficient"))
    observation = tree.observations[-1][0]
    tree.cell("c-i-red", "p-insuff", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-insuff", observation, "insufficient_evidence", "p-insuff")
    tree.cell("c-i-b", "p-insuff", "succeeded", role="blue_team_refuter", claim_id="claim-insuff",
              result={"disposition": "qualifies"})
    tree.cell("c-i-v", "p-insuff", "succeeded", role="independent_verifier", claim_id="claim-insuff",
              result={"proposed_disposition": "insufficient_evidence"})
    tree.package("p-backlog", add("backlog"))
    observation = tree.observations[-1][0]
    tree.cell("c-b-red", "p-backlog", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-backlog", observation, "supported", "p-backlog")
    tree.cell("c-b-b", "p-backlog", "succeeded", role="blue_team_refuter", claim_id="claim-backlog",
              result={"disposition": "qualifies"})
    tree.cell("c-b-v", "p-backlog", "succeeded", role="independent_verifier", claim_id="claim-backlog",
              result={"proposed_disposition": "supported"})
    tree.publish("verification_backlog", "claim-backlog", "not_ship_blocking")
    tree.package("p-pub", add("published"))
    observation = tree.observations[-1][0]
    tree.cell("c-p-red", "p-pub", "succeeded", retrievals=(EXECUTED, EXECUTED))
    tree.claim("claim-pub", observation, "confirmed", "p-pub")
    tree.claim("claim-pub-weak", observation, "contradicted", "p-pub")
    tree.cell("c-p-b", "p-pub", "succeeded", role="blue_team_refuter", claim_id="claim-pub",
              result={"disposition": "supports"})
    tree.cell("c-p-v", "p-pub", "succeeded", role="independent_verifier", claim_id="claim-pub",
              result={"proposed_disposition": "confirmed"})
    tree.events.append({"kind": "judge_verdict", "event_id": "event-jp", "subject_id": "claim-pub",
                        "body": {"claim_id": "claim-pub", "verdict": "red_correct"}})
    tree.publish("findings", "claim-pub", "ship_blocking")
    tree.package("p-noreport", add("unreported"))
    observation = tree.observations[-1][0]
    tree.cell("c-u-red", "p-noreport", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-unreported", observation, "confirmed", "p-noreport")
    tree.cell("c-u-b", "p-noreport", "succeeded", role="blue_team_refuter", claim_id="claim-unreported",
              result={"disposition": "supports"})
    tree.cell("c-u-v", "p-noreport", "succeeded", role="independent_verifier", claim_id="claim-unreported",
              result={"proposed_disposition": "confirmed"})
    return tree.build(), keys


EXPECTED = {
    "not_in_catalog": ("none", "file_not_in_catalog"),
    "no_observation": ("available", "no_tool_observation_at_location"),
    "no_lead": ("observed", "no_lead_at_location"),
    "review_cap": ("observed", "package_not_selected_cap"),
    "hunt_cap": ("observed", "package_not_selected_hunt_cap"),
    "not_launched": ("selected", "red_not_launched"),
    "invalid": ("reviewed", "red_cells_invalid:schema_error"),
    "timeout": ("reviewed", "red_cells_timed_out:budget_gap"),
    "denied": ("reviewed", "retrieval_all_denied:schema_violation"),
    "no_claim": ("retrieved", "red_no_claim"),
    "blue": ("adjudicated", "claim_contradicted_by_blue"),
    "judge_blue": ("adjudicated", "judge_sided_with_blue"),
    "insufficient": ("adjudicated", "verifier_insufficient_evidence"),
    "backlog": ("published", "claim_supported_not_confirmed"),
    "published": ("published", "published_confirmed"),
    "unreported": ("adjudicated", "not_in_final_report"),
}


def by_id(report: funnel.FunnelReport) -> dict[str, funnel.DefectFunnel]:
    return {item.defect_id: item for item in report.defects}


def test_each_defect_stops_for_its_own_reason(tmp_path: Path) -> None:
    root, keys = synthetic(tmp_path)
    report = by_id(funnel.evaluate_funnel(root, keys))

    assert {name: (item.stage, item.stopped_because) for name, item in report.items()} == EXPECTED
    assert [item.defect_id for item in funnel.evaluate_funnel(root, keys).defects] == [key.id for key in keys]
    for item in report.values():
        assert item.stopped_because.split(":")[0] in funnel.STOPPED_CODES
        assert [stage.stage for stage in item.stages] == list(funnel.STAGES)


def test_the_reasons_carry_the_evidence_they_rest_on(tmp_path: Path) -> None:
    root, keys = synthetic(tmp_path)
    report = by_id(funnel.evaluate_funnel(root, keys))

    assert report["invalid"].reviewed == {"cells": 1, "by_status": {"invalid": 1}, "dominant_gap_class": "schema_error"}
    assert report["denied"].retrieval == {"executed": 0, "denied": 2, "rows": 0, "tools": {},
                                          "denials_by_code": {"schema_violation": 2}}
    assert report["no_claim"].retrieval["rows"] == 3 and report["no_claim"].retrieval["denied"] == 1
    assert report["no_claim"].retrieval["tools"] == {"search": 1}
    assert report["no_observation"].producers_seen == [] and report["no_lead"].producers_seen == ["codeql"]

    blue = report["blue"]
    assert blue.verdicts == {"blue": ["contradicts"], "judge": None, "verifier": ["contradicted"]}
    assert blue.claims[0]["claim_id"] == "claim-blue" and blue.claims[0]["state"] == "contradicted"
    # A judge exists elsewhere in this run, so its absence for this claim is reported, not skipped.
    assert {stage.stage: stage.status for stage in blue.stages}["judged"] == funnel.NOT_REACHED


def test_a_run_without_a_judge_marks_that_stage_not_applicable_and_does_not_stop(tmp_path: Path) -> None:
    tree = Tree(tmp_path, "older")
    observation = tree.observe("o", "src/a.cpp", 5)
    tree.package("p", observation)
    tree.cell("red", "p", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-1", observation, "confirmed", "p")
    tree.cell("b", "p", "succeeded", role="blue_team_refuter", claim_id="claim-1", result={"disposition": "supports"})
    tree.cell("v", "p", "succeeded", role="independent_verifier", claim_id="claim-1",
              result={"proposed_disposition": "confirmed"})
    tree.publish("findings", "claim-1", "ship_blocking")
    item = funnel.evaluate_funnel(tree.build(), [defect("d", "src/a.cpp", 5)]).defects[0]

    statuses = {stage.stage: stage.status for stage in item.stages}
    assert statuses["judged"] == funnel.NOT_APPLICABLE
    assert item.stage == "published" and item.stopped_because == "published_confirmed" and item.ship_decision == "ship_blocking"
    assert item.verdicts["judge"] is None


def test_a_judge_verdict_is_recorded_and_a_disagreement_with_a_published_claim_is_noted(tmp_path: Path) -> None:
    tree = Tree(tmp_path, "judged")
    observation = tree.observe("o", "src/a.cpp", 5)
    tree.package("p", observation)
    tree.cell("red", "p", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-1", observation, "confirmed", "p")
    tree.cell("b", "p", "succeeded", role="blue_team_refuter", claim_id="claim-1", result={"disposition": "contradicts"})
    tree.cell("v", "p", "succeeded", role="independent_verifier", claim_id="claim-1",
              result={"proposed_disposition": "confirmed"})
    tree.events.append({"kind": "judge_verdict", "event_id": "j", "subject_id": "claim-1",
                        "body": {"claim_id": "claim-1", "verdict": "blue_correct"}})
    tree.publish("findings", "claim-1", "ship_blocking_pending_distinct_verification")
    item = funnel.evaluate_funnel(tree.build(), [defect("d", "src/a.cpp", 5)]).defects[0]

    assert item.stopped_because == "published_confirmed" and item.verdicts["judge"] == ["blue_correct"]
    assert item.ship_decision == "ship_blocking_pending_distinct_verification"
    assert item.notes == ["the judge sided with blue on a published claim"]


def test_blue_cells_that_exist_but_never_ran_for_the_claim_stop_the_chain(tmp_path: Path) -> None:
    tree = Tree(tmp_path, "partial")
    first = tree.observe("o1", "src/a.cpp", 5)
    second = tree.observe("o2", "src/b.cpp", 5)
    tree.package("p1", first)
    tree.package("p2", second)
    tree.cell("red1", "p1", "succeeded", retrievals=(EXECUTED,))
    tree.cell("red2", "p2", "succeeded", retrievals=(EXECUTED,))
    tree.claim("c1", first, "proposed", "p1")
    tree.claim("c2", second, "proposed", "p2")
    tree.cell("b2", "p2", "invalid", role="blue_team_refuter", claim_id="c2", gap_class="schema_error")
    items = by_id(funnel.evaluate_funnel(tree.build(), [defect("one", "src/a.cpp", 5), defect("two", "src/b.cpp", 5)]))

    assert (items["one"].stage, items["one"].stopped_because) == ("proposed", "blue_not_run")
    assert (items["two"].stage, items["two"].stopped_because) == ("proposed", "blue_cells_not_succeeded")


def test_a_projection_state_wins_over_the_event_stream(tmp_path: Path) -> None:
    tree = Tree(tmp_path, "projected")
    observation = tree.observe("o", "src/a.cpp", 5)
    tree.package("p", observation)
    tree.cell("red", "p", "succeeded", retrievals=(EXECUTED,))
    tree.claim("claim-1", observation, "proposed", "p")
    tree.projection = [{"claim_id": "claim-1", "state": "not_reachable", "affected_entities": [observation]}]
    item = funnel.evaluate_funnel(tree.build(), [defect("d", "src/a.cpp", 5)]).defects[0]
    assert item.claims[0]["state"] == "not_reachable" and item.stage == "adjudicated"
    assert item.stopped_because == "claim_not_reachable"


def test_a_missing_or_empty_run_never_raises_and_names_what_is_absent(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    (empty / "data").mkdir(parents=True)
    report = funnel.evaluate_funnel(empty, [defect("d", "src/a.cpp", 5)])
    assert report.defects[0].stage == "available" and report.defects[0].stopped_because == "no_tool_observation_at_location"
    assert report.run["inference_review_present"] is False

    tree = Tree(tmp_path, "no-inference")
    tree.observe("o", "src/a.cpp", 5)
    root = tree.build()
    shutil.rmtree(root / INFERENCE)
    absent = funnel.evaluate_funnel(root, [defect("d", "src/a.cpp", 5)]).defects[0]
    assert absent.stopped_because == "inference_review_absent" and absent.stage == "observed"


def test_the_aggregate_counts_stages_reasons_and_model_quality(tmp_path: Path) -> None:
    root, keys = synthetic(tmp_path)
    tree_recordings = Tree(tmp_path, "unused")  # a second helper only to write recording documents
    tree_recordings.root = root
    tree_recordings.recording("r1", "c-inv")
    tree_recordings.recording("r2", "c-inv", repair=True, parsed=False)
    tree_recordings.recording("r3", "c-to", parsed=False)
    tree_recordings.recording("r4", "c-to", repair=True)
    tree_recordings.recording("r5", "c-den")
    aggregate = funnel.evaluate_funnel(root, keys).aggregate

    assert aggregate["defects"] == len(keys)
    assert aggregate["conversion"]["available"]["reached"] == len(keys) - 1
    assert aggregate["conversion"]["observed"]["reached"] == len(keys) - 2
    assert aggregate["conversion"]["published"]["reached"] == 2
    assert aggregate["conversion"]["judged"]["not_applicable"] == 0
    assert aggregate["by_furthest_stage"]["published"] == 2 and aggregate["by_furthest_stage"]["none"] == 1
    assert aggregate["by_stopped_because"]["published_confirmed"] == 1
    quality = aggregate["model_quality"]
    assert quality["recordings"]["calls"] == 5 and quality["recordings"]["first_attempt_calls"] == 3
    assert quality["recordings"]["first_attempt_parsed"] == 2 and quality["recordings"]["first_attempt_parse_rate"] == 0.6667
    assert quality["recordings"]["repair_calls"] == 2 and quality["recordings"]["failed_calls"] == 2
    assert quality["cells"]["calls_per_cell"] == {"cells_with_calls": 3, "min": 1, "max": 2, "mean": 1.67}
    assert quality["retrieval"]["denials_by_code"] == {"schema_violation": 3}
    assert quality["retrieval"]["executed"] == 8 and quality["retrieval"]["rows"] == 24
    assert quality["claims"]["by_state"]["contradicted"] == 3
    assert quality["cells"]["by_status"]["not_launched"] == 1


def test_output_is_deterministic_and_the_run_directory_is_untouched(tmp_path: Path) -> None:
    root, keys = synthetic(tmp_path)

    def snapshot() -> dict[str, str]:
        return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(root.rglob("*")) if path.is_file()}

    before = snapshot()
    first = json.dumps(funnel.evaluate_funnel(root, keys).as_dict(), sort_keys=True)
    second = json.dumps(funnel.evaluate_funnel(root, list(keys)).as_dict(), sort_keys=True)
    assert first == second and snapshot() == before
    lines = funnel.render_lines(funnel.evaluate_funnel(root, keys))
    assert lines == funnel.render_lines(funnel.evaluate_funnel(root, keys))
    assert lines[0].startswith("funnel run=run-1 defects=16") and len(lines) == 1 + len(keys) + 4


def test_the_command_line_prints_the_table_and_the_json(tmp_path: Path, capsys) -> None:
    root, keys = synthetic(tmp_path)
    key = tmp_path / "expectations.toml"
    key.write_text("".join(f'[[defect]]\nid = "{d.id}"\ncwe = "CWE-1"\npath = "{d.path}"\nline = {d.line}\n'
                           for d in keys), encoding="utf-8")
    assert funnel.main(["--run", str(root), "--expectations", str(key)]) == 0
    table = capsys.readouterr().out
    assert "published_confirmed" in table and "funnel stages available=15" in table
    assert funnel.main(["--run", str(root), "--expectations", str(key), "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert [item["id"] for item in document["defects"]] == [d.id for d in keys]
    assert funnel.main(["--run", str(tmp_path / "missing"), "--expectations", str(key)]) == 2


def materialize(fixture: dict, destination: Path) -> Path:
    for relative, content in fixture["files"].items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, list) and content[:1] == ["JSONL"]:
            path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in content[1:]), encoding="utf-8")
        else:
            path.write_text(json.dumps(content), encoding="utf-8")
    for name, rows in (("observations", fixture["observations"]), ("source", [])):
        index = destination / "data" / "indices" / name / "shard.sqlite"
        index.parent.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(index)
        database.execute("CREATE TABLE entities(identity TEXT PRIMARY KEY, kind TEXT, name TEXT, payload_json TEXT)")
        database.execute("CREATE TABLE locations(entity_id TEXT PRIMARY KEY, path TEXT, start_line INT, end_line INT)")
        for number, path in enumerate(fixture["catalog"] if name == "source" else ()):
            database.execute("INSERT INTO entities VALUES (?, 'source_file', ?, '{}')", (f"asr:source_file:{number}", path))
            database.execute("INSERT INTO locations VALUES (?, ?, 1, 1)", (f"asr:source_file:{number}", path))
        for identity, kind, producer, path, start, end in rows:
            database.execute("INSERT OR IGNORE INTO entities VALUES (?, ?, 'rule', ?)", (identity, kind, json.dumps({"scanner": producer})))
            database.execute("INSERT OR IGNORE INTO locations VALUES (?, ?, ?, ?)", (identity, path, start, end))
        database.commit()
        database.close()
    return destination


def test_the_shapes_of_a_real_run_are_followed(tmp_path: Path) -> None:
    """A trimmed copy of run 2026-10-21-0007: red cells that hit their token cap after real retrievals."""

    assert FIXTURE.stat().st_size < 100_000
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    root = materialize(fixture, tmp_path / "2026-10-21-0007")
    items = by_id(funnel.evaluate_funnel(root, [
        defect("integer-overflow-frame-size", "src/frame.cpp", 9, 10), defect("hardcoded-api-key", "src/config.cpp", 6)]))

    frame = items["integer-overflow-frame-size"]
    assert frame.stage == "retrieved" and frame.stopped_because == "red_cells_timed_out:budget_gap"
    assert frame.retrieval["rows"] > 0 and frame.retrieval["denied"] > 0 and frame.reviewed["cells"] == 3
    assert frame.producers_seen and len(frame.packages) == 3
    key = items["hardcoded-api-key"]
    assert key.stage == "observed" and key.stopped_because == "no_lead_at_location" and key.producers_seen
