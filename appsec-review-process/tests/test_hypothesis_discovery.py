"""07-hypothesis-discovery: hunter derive, shard planning, post-pool resolution and ledger intake.

The fake replies below are shaped like what a hunter model actually sends: bookkeeping omitted or
echoed (ids, hashes, severity), aliases (``file``/``line``/``lines``), absolute and traversal paths,
lines past the end of a file, duplicates of tool leads and exact duplicates. No live model call.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import claim_ledger as ledger
import claude_cli_invoker as cli
import execution_state
import hypothesis_discovery as hunt
import hypothesis_hunt_derive as derive
import persona_dispatch
from claude_cli_invoker import InvokerOutputError
from review_control_loops import deterministic_merge
from schema_validate import validate_document

REPLAY_RUNS = ROOT.parent.parent / "appsec-review" / "appsec-review-process" / "runs"
REPLAY_RUN = "20260928T034921Z-be3585"
REPLAY_TARGET = ROOT.parent.parent / "appsec-review" / "fixtures" / "targets" / "appsec-multi-vuln"
MAIN_CPP = b'#include <cstring>\n#include <iostream>\n\nint main(int argc, char** argv) {\n    char buffer[16];\n' \
           b'    const char* value = argc > 1 ? argv[1] : "sample";\n    std::strcpy(buffer, value);\n' \
           b'    std::cout << buffer << \'\\n\';\n    return 0;\n}\n'
EVAL_JS = b'const value = process.argv[2] || "1 + 1";\nconsole.log(eval(value));\n'


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def item(root: str, path: str, data: bytes) -> SimpleNamespace:
    return SimpleNamespace(root=root, path=path, sha256=sha(data), data=data, role="evidence")


def brief(mode="general", shard="g01-general", **limits) -> dict:
    return {"schema": derive.BRIEF_SCHEMA_ID, "run_id": "r", "shard_id": shard, "mode": mode,
            "persona_id": derive.MODES[mode], "component_ids": ["cpp"], "pinned_files": [], "unpinned_files": [],
            "unpinned_total": 0, "lead_menu": [], "lead_menu_total": 0, "p3_leads_in_files": 0,
            "limits": {"max_hypotheses": 20, "max_line_span": 80, **limits}, "rules": list(hunt.RULES)}


def inputs_for(value: dict) -> tuple:
    data = hunt.brief_bytes(value)
    return (item(derive.BRIEF_ROOT_ID, value["shard_id"] + ".json", data),
            item(derive.TARGET_ROOT_ID, "projects/cpp/case-001/main.cpp", MAIN_CPP),
            item("evidence-menu", "supporting-evidence-menu.json", b"{}\n"))


def records(document: dict) -> list[dict]:
    return [json.loads(row["assertion"]) for row in document["candidates"]]


STRCPY = {"file": "./projects/cpp/case-001/main.cpp", "lines": "5-7", "class": "stack buffer overflow",
          "cwe": "CWE-121: Stack-based Buffer Overflow", "mechanism": "argv[1] is copied with strcpy into a "
          "16-byte stack buffer without a length check.", "preconditions": "attacker controls argv[1]",
          "evidence": [{"path": "projects/cpp/case-001/main.cpp", "line": 7}, "supporting-evidence:02-ir-facts/x.json",
                       "evidence-menu:supporting-evidence-menu.json"],
          "confidence": "High", "hypothesis_id": "hyp-model-made-this-up", "sha256": "sha256:" + "0" * 64,
          "severity": "high"}


class DeriveTests(unittest.TestCase):
    def run_derive(self, reply, value=None):
        value = value or brief()
        inputs = inputs_for(value)
        return derive.derive(value, reply, inputs, brief_sha256=inputs[0].sha256)

    def test_realistic_reply_without_bookkeeping_is_resolved_against_pinned_bytes(self):
        reply = {"candidates": {"findings": [
            STRCPY,
            {"path": "/home/hunter/checkout/projects/cpp/case-001/main.cpp", "start_line": 7,
             "vulnerability_class": "unbounded copy", "mechanism": "same copy, absolute path form",
             "attacker_preconditions": ["argv"], "evidence": [], "confidence": "medium", "cwe": 120},
            {"path": "projects/cpp/case-001/main.cpp", "start_line": 40, "vulnerability_class": "phantom",
             "mechanism": "a line that does not exist", "attacker_preconditions": ["x"], "evidence": [],
             "confidence": "low"},
            {"path": "../../etc/passwd", "start_line": 1, "vulnerability_class": "escape",
             "mechanism": "outside the checkout", "attacker_preconditions": ["x"], "evidence": [], "confidence": "low"},
            {"path": "projects/javascript/case-010/index.js", "start_line": 2, "vulnerability_class": "code injection",
             "mechanism": "eval of argv found through evidence_read", "attacker_preconditions": ["argv[2]"],
             "evidence": ["projects/javascript/case-010/index.js:2"], "confidence": "medium", "cwe": "CWE-95"},
        ]}}
        document, notes = self.run_derive(reply)
        self.assertEqual(validate_document(document, derive.CANDIDATES_SCHEMA), [])
        by_class = {row["vulnerability_class"]: row for row in records(document)}
        strcpy = by_class["stack buffer overflow"]
        self.assertEqual((strcpy["kind"], strcpy["path"], strcpy["start_line"], strcpy["end_line"], strcpy["cwe"]),
                         ("hypothesis", "projects/cpp/case-001/main.cpp", 5, 7, "CWE-121"))
        self.assertEqual(strcpy["file_sha256"], sha(MAIN_CPP))
        self.assertEqual(strcpy["location_check"], "pinned")
        self.assertEqual(strcpy["hunter"], {"mode": "general", "persona_id": "general-red-team-hunter",
                                            "shard_id": "g01-general"})
        kinds = [(row["kind"], row["path"]) for row in strcpy["evidence"]]
        self.assertEqual(kinds[0], ("target-range", "projects/cpp/case-001/main.cpp"))
        self.assertIn(("pinned-input", "supporting-evidence-menu.json"), kinds)
        self.assertIn(("unresolved", None), kinds)      # a menu file this call did not pin
        self.assertEqual(by_class["unbounded copy"]["path"], "projects/cpp/case-001/main.cpp")  # suffix-mapped
        self.assertEqual(by_class["unbounded copy"]["cwe"], "CWE-120")
        self.assertEqual((by_class["phantom"]["kind"], by_class["phantom"]["location_check"]), ("dropped", "rejected"))
        self.assertIn("past the end of the file (10 lines)", by_class["phantom"]["drop_reason"])
        self.assertEqual(by_class["escape"]["kind"], "dropped")
        deferred = by_class["code injection"]
        self.assertEqual((deferred["kind"], deferred["location_check"], deferred["file_sha256"]),
                         ("hypothesis", "deferred", None))
        self.assertEqual(deferred["evidence"][0]["kind"], "target-deferred")
        self.assertTrue(any("severity" in note for note in notes))
        for row in document["candidates"]:   # the model's made-up id and hash never survive
            self.assertNotIn("model-made-this-up", row["assertion"]); self.assertNotIn("0" * 64, row["assertion"])

    def test_duplicates_and_the_per_instance_limit(self):
        row = dict(STRCPY)
        reply = {"hypotheses": [row, dict(row), {**row, "lines": "7", "class": "second"},
                                {**row, "lines": "7", "class": "third"}]}
        document, notes = self.run_derive(reply, brief(max_hypotheses=2))
        rows = records(document)
        self.assertEqual(len(rows), 3)                      # the exact duplicate collapsed
        self.assertTrue(any("identical duplicate" in note for note in notes))
        third = next(row for row in rows if row["vulnerability_class"] == "third")
        self.assertEqual(third["kind"], "dropped"); self.assertIn("per-instance limit of 2", third["drop_reason"])

    def test_wide_ranges_are_dropped_and_empty_answers_are_valid(self):
        document, _ = self.run_derive({"hypotheses": [{**STRCPY, "lines": "1-200"}]}, brief(max_line_span=10))
        self.assertEqual(records(document)[0]["kind"], "dropped")
        document, _ = self.run_derive({"hypotheses": [], "coverage_notes": "checked copies"})
        self.assertEqual(document, {"candidates": []})

    def test_echoed_drop_reason_is_ignored_and_python_decides_it(self):
        document, _ = self.run_derive({"hypotheses": [{**STRCPY, "drop_reason": "model says so"}]})
        row = records(document)[0]
        self.assertEqual((row["kind"], row["drop_reason"]), ("hypothesis", None))

    def test_malformed_replies_go_back_for_repair(self):
        for reply in ("no json here", {"hypotheses": "none"},
                      {"hypotheses": [{"path": "a.c", "start_line": 1}]},
                      {"hypotheses": [{**STRCPY, "confidence": "certain"}]}):
            with self.subTest(reply=str(reply)[:40]), self.assertRaises(InvokerOutputError):
                self.run_derive(reply)


class HunterInvokerTests(unittest.TestCase):
    def test_persona_schema_and_hunt_block_are_rendered_and_candidates_derived(self):
        value = brief()
        contract = json.loads((ROOT / "registry/output-contracts/hypothesis-hunt-candidates.json").read_text())
        package = SimpleNamespace(composition={"output_contract": contract}, prompt=b"OUTER", inputs=inputs_for(value),
            request={"model": {"family": "claude-sonnet-5"}, "run_id": "r", "job_id": hunt.JOB, "attempt_id": "a" * 32,
                     "budget": {"input_unit_limit": 10 ** 9}},
            request_sha256="sha256:" + "4" * 64, allowed_claim_classes=("candidate_only",))
        replies = [json.dumps({"candidates": {"hypotheses": "oops"}}),      # repaired once
                   "```json\n" + json.dumps({"candidates": {"hypotheses": [STRCPY]}}) + "\n```"]
        prompts, written = [], {}

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            prompts.append(prompt)
            return {"timed_out": False, "final_result": {"result": replies.pop(0)}}

        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(cli.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(cli.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 1}}), \
                mock.patch.object(cli.pi, "write_invoker_output", side_effect=lambda package, root, **kw: written.update(kw)):
            hunt.HunterInvoker(effort="high", budget_usd=2.0, dispatch_fn=dispatch_fn).invoke(
                package, output_root=Path(out), cancel=threading.Event())
            published = json.loads((Path(out) / "candidates.json").read_text())
        self.assertIn(derive.PERSONA_SCHEMA, prompts[0])
        self.assertIn("Trusted hunt runtime", prompts[0]); self.assertIn("a menu, not a limit", prompts[0])
        self.assertEqual(len(prompts), 2)
        self.assertEqual(validate_document(published, derive.CANDIDATES_SCHEMA), [])
        self.assertEqual(written["claims"][0]["citations"][0]["path"], "projects/cpp/case-001/main.cpp")
        self.assertEqual(written["claims"][0]["citations"][0]["locator"], "L5-L7")


COMPONENTS = [{"component_id": "cpp", "path_patterns": ["projects/cpp/**"], "aliases": []},
              {"component_id": "js", "path_patterns": ["projects/javascript/**"], "aliases": []},
              {"component_id": "docs", "path_patterns": ["docs/**"], "aliases": []}]


def lead(path, line, tier_rule=("clang-static-analyzer", "security.insecureAPI.strcpy", "unsafe-copy"),
         producer="02-native-sast", ref="n1"):
    tool, rule, category = tier_rule
    row = {"kind": "code", "lead_ref": ref, "tool_id": tool, "rule_id": rule, "category": category, "path": path,
           "start_line": line, "end_line": line, "source_sha256": None}
    return producer, row


class PlanningTests(unittest.TestCase):
    def test_shards_follow_components_leads_and_pin_budget(self):
        files = [{"path": "projects/cpp/case-001/main.cpp", "sha256": sha(MAIN_CPP), "bytes": 300, "lines": 10, "readable": None},
                 {"path": "projects/cpp/big.cpp", "sha256": sha(b"b"), "bytes": 900, "lines": 5, "readable": None},
                 {"path": "projects/javascript/case-010/index.js", "sha256": sha(EVAL_JS), "bytes": 80, "lines": 2, "readable": None},
                 {"path": "docs/a.png", "sha256": sha(b"p"), "bytes": 10, "lines": 1, "readable": "binary"},
                 {"path": "README.md", "sha256": sha(b"r"), "bytes": 50, "lines": 3, "readable": None}]
        leads = hunt.flat_leads([{"producer_job_id": "02-native-sast",
                                  "leads": [lead("projects/cpp/case-001/main.cpp", 7)[1],
                                            lead("projects/cpp/big.cpp", 2, ("cppcheck", "variableScope", "style"))[1]]}])
        briefs = hunt.plan_shards(files, COMPONENTS, leads, shard_groups=3, modes_per_group=1, pin_bytes_max=1000,
                                  lead_menu_max=10, max_hypotheses=5, max_line_span=40)
        self.assertEqual([b["shard_id"] for b in briefs], ["g01-general", "g02-known-list", "g03-general"])
        first = briefs[0]
        self.assertEqual(first["component_ids"], ["cpp"])        # most P1 leads first
        self.assertEqual([row["path"] for row in first["pinned_files"]], ["projects/cpp/case-001/main.cpp"])
        self.assertEqual(first["unpinned_files"][0]["path"], "projects/cpp/big.cpp")   # over the pin budget
        self.assertEqual((first["lead_menu_total"], first["p3_leads_in_files"]), (1, 1))
        self.assertEqual(sorted(c for b in briefs for c in b["component_ids"]), ["component-unmapped", "cpp", "js"])
        both = hunt.plan_shards(files, COMPONENTS, leads, shard_groups=1, modes_per_group=2, pin_bytes_max=10 ** 6,
                                lead_menu_max=10, max_hypotheses=5, max_line_span=40)
        self.assertEqual([b["mode"] for b in both], ["general", "known-list"])
        self.assertEqual(hunt.plan_shards([], COMPONENTS, [], shard_groups=3, modes_per_group=1, pin_bytes_max=1,
                                          lead_menu_max=1, max_hypotheses=1, max_line_span=1), [])

    def test_walk_target_skips_git_symlinks_and_marks_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / ".git").mkdir(); (base / ".git" / "config").write_text("x")
            (base / "a.c").write_bytes(MAIN_CPP); (base / "b.bin").write_bytes(b"\x00\x01")
            (base / "link.c").symlink_to(base / "a.c")
            rows = hunt.walk_target(base, file_bytes_max=10 ** 6)
        self.assertEqual([(row["path"], row["readable"]) for row in rows], [("a.c", None), ("b.bin", "binary")])


class PrepareTests(unittest.TestCase):
    def test_prepared_spec_passes_c01_planning_with_brief_first_and_target_files_pinned(self):
        model = {"provider": "anthropic", "family": "claude-sonnet-5", "model_id": "claude-sonnet-5-20260927",
                 "snapshot": "claude-sonnet-5-20260927"}
        source = "sha256:" + "a" * 64
        component_map = {"source_snapshot_sha256": source, "functional_components": COMPONENTS}
        binding = {"job_id": "01-component-characterization", "attempt_id": "component-1"}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            target = base / "target"
            (target / "projects/cpp/case-001").mkdir(parents=True)
            (target / "projects/cpp/case-001/main.cpp").write_bytes(MAIN_CPP)
            (target / "projects/javascript/case-010").mkdir(parents=True)
            (target / "projects/javascript/case-010/index.js").write_bytes(EVAL_JS)
            pointer = base / "runs" / "r" / "data" / "jobs" / "01-component-characterization" / "accepted.json"
            pointer.parent.mkdir(parents=True)
            pointer.write_text(json.dumps({"accepted_at": "2026-09-28T16:09:29.866024+00:00"}))
            leads = [lead_source([lead("projects/cpp/case-001/main.cpp", 7)[1]])]
            with mock.patch.object(execution_state, "RUNS", base / "runs"), \
                    mock.patch.object(hunt.bounded_analysis_workers, "load_accepted", return_value=(component_map, binding)), \
                    mock.patch.object(hunt, "_target", return_value=(target, source)), \
                    mock.patch.object(hunt.claim_ledger, "lead_sources", return_value=(leads, [])), \
                    mock.patch.object(hunt.model_versions, "model_identity_for", return_value=model):
                value = hunt.prepare("r")
                self.assertEqual(value, json.loads(json.dumps(value)))          # fingerprintable
                self.assertEqual([b["shard_id"] for b in value["briefs"]], ["g01-general", "g02-known-list"])
                attempt = base / "attempt"; attempt.mkdir()
                context = hunt._context(value, attempt)
                plan = hunt.pool_specification.plan_expansion(value["spec"], context=context)
        self.assertEqual(len(plan.instances), 2)
        known = next(i for i in plan.instances if i.request.request["readable_inputs"][0]["path"] == "g02-known-list.json")
        readable = known.request.request["readable_inputs"]
        self.assertEqual(readable[0]["root"], derive.BRIEF_ROOT_ID)
        self.assertIn(("hunt-guides", "known-issue-catalog.md"), [(r["root"], r["path"]) for r in readable])
        self.assertIn(derive.TARGET_ROOT_ID, {r["root"] for r in readable})
        self.assertEqual(known.request.request["persona"]["persona_id"], "known-list-red-team-hunter")
        self.assertEqual(value["spec"]["pool_budget"]["max_instances"], 2)


class RunLifecycleTests(unittest.TestCase):
    def test_run_publishes_a_validated_result_and_reuses_it(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            target = base / "target"
            (target / "projects/cpp/case-001").mkdir(parents=True)
            (target / "projects/cpp/case-001/main.cpp").write_bytes(MAIN_CPP)
            merge = canned_merge({"g01-general": ("general", {"hypotheses": [STRCPY]})},
                                 {"projects/cpp/case-001/main.cpp": MAIN_CPP})
            value = {**result_inputs([brief()], []), "target_root": str(target), "component_binding": {"x": 1},
                     "pool_briefs": [brief()], "evidence_menu": {}, "accepted_at": "2026-09-28T16:09:29Z",
                     "spec": {"schema": "test-spec"}, "applicability": "APPLICABLE", "lead_coverage": [],
                     "code": hunt._code_hashes()}
            launched = hunt.pool_launcher.LaunchedPool(pool_root=base / "unused", pool_directory="pool-1",
                expansion_sha256="sha256:" + "6" * 64, terminal_manifest_sha256="sha256:" + "7" * 64,
                outcome="COMPLETE", instance_count=1)

            def context(_inputs, attempt):
                (attempt / "pools").mkdir(); (attempt / "rendezvous").mkdir()
                return SimpleNamespace(pool_parent=attempt / "pools")

            job_root = base / "jobs" / hunt.JOB
            with mock.patch.object(hunt, "root", return_value=job_root), \
                    mock.patch.object(hunt, "prepare", return_value=value), \
                    mock.patch.object(hunt, "_context", side_effect=context), \
                    mock.patch.object(hunt, "_budget_usd", return_value=2.0), \
                    mock.patch.object(hunt.pool_specification, "spec_sha256", return_value="sha256:" + "8" * 64), \
                    mock.patch.object(hunt.pool_launcher, "launch", return_value=launched) as launch, \
                    mock.patch.object(hunt.pool_rendezvous, "load_verified_manifest", return_value=object()), \
                    mock.patch.object(hunt.deterministic_pool_merge, "merge_verified_manifest", return_value=merge):
                first = hunt.run("r", "dagster-1")
                second = hunt.run("r", "dagster-2")
            attempt = job_root / "attempts" / first["attempt_id"]
            result = json.loads((attempt / hunt.RESULT).read_text())
            status = json.loads((attempt / "status.json").read_text())
            import report_input_assembly   # a hunter citation re-verifies like a tool-lead citation
            row = report_input_assembly._verify_citation(base / "jobs", (hunt.JOB, first["attempt_id"], hunt.RESULT,
                "sha256:" + execution_state.file_hash(attempt / hunt.RESULT)))
            self.assertEqual(row["artifact_path"], hunt.RESULT)
        self.assertEqual(first["status"], "OK_WITH_GAPS")      # the canned merge lost worker w9
        self.assertEqual(second["attempt_id"], first["attempt_id"]); self.assertEqual(launch.call_count, 1)
        self.assertEqual(len(result["hypotheses"]), 1); self.assertEqual(status["hypotheses"], 1)


def canned_merge(replies_by_shard: dict, pinned: dict[str, bytes]) -> dict:
    """Run the real derive per fake worker and the real deterministic merge (no pool, no model)."""
    expected, results = [], []
    for index, (shard, (mode, reply)) in enumerate(sorted(replies_by_shard.items())):
        value = brief(mode, shard)
        data = hunt.brief_bytes(value)
        inputs = (item(derive.BRIEF_ROOT_ID, shard + ".json", data),
                  *[item(derive.TARGET_ROOT_ID, path, raw) for path, raw in sorted(pinned.items())])
        document, _ = derive.derive(value, reply, inputs, brief_sha256=inputs[0].sha256)
        worker = f"w{index}"
        expected.append({"worker_id": worker, "producer_id": derive.MODES[mode], "run_id": "r"})
        results.append({"worker_id": worker, "producer_id": derive.MODES[mode], "run_id": "r", "status": "OK",
                        "candidates": document["candidates"]})
    expected.append({"worker_id": "w9", "producer_id": "general-red-team-hunter", "run_id": "r"})   # never returned
    return deterministic_merge("r", expected, results)


def result_inputs(briefs, leads, components=COMPONENTS, run_id="r", source="sha256:" + "a" * 64):
    return {"run_id": run_id, "source_generation": source, "component_generation": "component-1",
            "briefs": briefs, "leads": leads, "components": components}


class BuildResultTests(unittest.TestCase):
    def test_resolution_dedup_overlap_and_gaps(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "projects/cpp/case-001").mkdir(parents=True)
            (base / "projects/cpp/case-001/main.cpp").write_bytes(MAIN_CPP)
            (base / "projects/javascript/case-010").mkdir(parents=True)
            (base / "projects/javascript/case-010/index.js").write_bytes(EVAL_JS)
            (base / "projects/cpp/case-001/other.cpp").write_bytes(MAIN_CPP * 10)
            stale = MAIN_CPP.replace(b"16", b"64")
            merge = canned_merge({
                "g01-general": ("general", {"hypotheses": [STRCPY, {
                    "path": "projects/javascript/case-010/index.js", "start_line": 2, "vulnerability_class": "code injection",
                    "cwe": "CWE-95", "mechanism": "eval(argv[2])", "attacker_preconditions": ["controls argv[2]"],
                    "evidence": [], "confidence": "medium"}, {
                    "path": "projects/go/missing.go", "start_line": 3, "vulnerability_class": "ghost",
                    "mechanism": "file does not exist", "attacker_preconditions": ["x"], "evidence": [],
                    "confidence": "low"}]}),
                "g02-known-list": ("known-list", {"hypotheses": [{**STRCPY, "confidence": "medium",
                    "mechanism": "catalog: unsafe copy", "preconditions": ["local user runs the binary"]}]}),
                "g03-general": ("general", {"hypotheses": [{**STRCPY, "file": "projects/cpp/case-001/other.cpp",
                                                             "lines": "99"}]}),
            }, {"projects/cpp/case-001/main.cpp": MAIN_CPP, "projects/cpp/case-001/other.cpp": stale * 10})
            leads = hunt.flat_leads([{"producer_job_id": "02-native-sast",
                                      "leads": [lead("projects/cpp/case-001/main.cpp", 7)[1]]}])
            briefs = [brief("general", "g01-general"), brief("known-list", "g02-known-list")]
            result = hunt.build_result(result_inputs(briefs, leads), merge, hunt.checkout_reader(base))
        self.assertEqual(validate_document(result, hunt.RESULT_SCHEMA), [])
        rows = {row["path"]: row for row in result["hypotheses"]}
        strcpy = rows["projects/cpp/case-001/main.cpp"]
        self.assertEqual(len(strcpy["hunters"]), 2)                 # two hunters, one hypothesis
        self.assertEqual(strcpy["confidence"], "high"); self.assertEqual(strcpy["tier"], "P1")
        self.assertIn("local user runs the binary", strcpy["attacker_preconditions"])
        self.assertEqual([(o["tool_id"], o["start_line"]) for o in strcpy["lead_overlap"]], [("clang-static-analyzer", 7)])
        js = rows["projects/javascript/case-010/index.js"]           # deferred in the call, resolved here
        self.assertEqual(js["file_sha256"], sha(EVAL_JS)); self.assertEqual(js["component_ids"], ["js"])
        kinds = sorted(gap["kind"] for gap in result["gaps"])
        self.assertEqual(kinds, ["file-changed", "not-in-checkout", "worker-missing"])
        self.assertEqual(result["hypotheses"][0]["path"], "projects/cpp/case-001/main.cpp")   # P1 high first
        self.assertIn("| P1 |", hunt.summary(result))


def hunter_source(result: dict, generation=("sha256:" + "a" * 64, "component-1")) -> dict:
    return {"contract_id": ledger.HUNTER_CONTRACT, "producer_job_id": ledger.HUNTER_JOB,
            "producer_attempt_id": "hunt-1", "artifact_path": "jobs/07-hypothesis-discovery/attempts/hunt-1/"
            "hypothesis-discovery.json", "artifact_sha256": "sha256:" + "b" * 64,
            "accepted_pointer_sha256": "sha256:" + "c" * 64, "source_generation": generation[0],
            "component_generation": generation[1], "artifact": result}


def lead_source(leads, generation=("sha256:" + "a" * 64, "component-1")) -> dict:
    return {"contract_id": "native-sast", "producer_job_id": "02-native-sast", "producer_attempt_id": "n-1",
            "artifact_path": "jobs/02-native-sast/attempts/n-1/native-sast.json", "lead_artifact": "native-sast.json",
            "artifact_sha256": "sha256:" + "d" * 64, "accepted_pointer_sha256": "sha256:" + "e" * 64,
            "source_generation": generation[0], "component_generation": generation[1],
            "tool_snapshot_sha256": None, "leads": leads}


class LedgerIntakeTests(unittest.TestCase):
    def test_hunter_is_the_fourth_candidate_source_and_corroborates_tool_leads(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "projects/cpp/case-001").mkdir(parents=True)
            (base / "projects/cpp/case-001/main.cpp").write_bytes(MAIN_CPP)
            (base / "projects/javascript/case-010").mkdir(parents=True)
            (base / "projects/javascript/case-010/index.js").write_bytes(EVAL_JS)
            merge = canned_merge({"g01-general": ("general", {"hypotheses": [STRCPY, {
                "path": "projects/javascript/case-010/index.js", "start_line": 2, "vulnerability_class": "code injection",
                "cwe": "CWE-95", "mechanism": "eval of a verified finding source", "attacker_preconditions": ["argv[2]"],
                "evidence": [], "confidence": "low"}]})}, {"projects/cpp/case-001/main.cpp": MAIN_CPP})
            raw = [lead("projects/cpp/case-001/main.cpp", 7)[1]]
            result = hunt.build_result(result_inputs([brief()], hunt.flat_leads([lead_source(raw)])), merge,
                                       hunt.checkout_reader(base))
        inputs = {"sources": [lead_source(raw), hunter_source(result)], "lead_components": COMPONENTS}
        candidates = ledger._candidates(inputs)
        leads = [c for c in candidates if c["route_id"].startswith(ledger.LEAD_ROUTE_PREFIX)]
        hunters = [c for c in candidates if c["route_id"].startswith(ledger.HUNTER_ROUTE_PREFIX)]
        self.assertEqual(len(leads), 1); self.assertEqual(len(hunters), 1)      # strcpy attached, not duplicated
        self.assertIn("Corroborated by 1 code-reading hypothesis(es) [CWE-121 stack buffer overflow]", leads[0]["hypothesis"])
        self.assertEqual(leads[0]["confidence"], "medium")
        self.assertEqual({c["producer_job_id"] for c in leads[0]["citations"]}, {"02-native-sast", ledger.HUNTER_JOB})
        hunter_citation = next(c for c in leads[0]["citations"] if c["producer_job_id"] == ledger.HUNTER_JOB)
        self.assertEqual((hunter_citation["artifact_path"], hunter_citation["producer_attempt_id"]),
                         ("hypothesis-discovery.json", "hunt-1"))       # attempt-relative, like tool leads
        eval_claim = hunters[0]
        self.assertTrue(eval_claim["route_id"].startswith("hunter:P2:"))
        self.assertTrue(eval_claim["hypothesis"].startswith("Code-reading hypothesis (P2, CWE-95 code injection)"))
        self.assertNotIn("verified finding", eval_claim["hypothesis"])      # model words kept out of ledger text
        self.assertEqual(eval_claim["component_ids"], ["js"])
        value = ledger.build_ledger("r", "attempt-1", candidates)
        self.assertEqual(ledger.validate_ledger(value), [])
        routing = ledger.work_routing(value)
        self.assertEqual(sorted((row["source_kind"], row["review_priority"]) for row in routing["routes"]),
                         [("hunter", "P2"), ("tool-lead", "P1")])
        self.assertIn("hunter", ledger._summary(value, {"lead_coverage": []}) + "hunter")

    def test_stale_hunter_output_is_refused(self):
        result = {"schema": "x"}
        with self.assertRaises(execution_state.Blocked):
            ledger.hunter_candidates(hunter_source(result))


@unittest.skipUnless((REPLAY_RUNS / REPLAY_RUN / "data" / "jobs" / "02-source-sast" / "accepted.json").is_file()
                     and REPLAY_TARGET.is_dir(), "multi-vuln replay run be3585 is not present")
class ReplayBe3585Tests(unittest.TestCase):
    def test_python_side_replay_with_canned_hypotheses(self):
        """Read-only: real accepted leads, component map and threat model of be3585, the real checkout,
        canned hunter replies through the real derive, merge, result build and ledger."""
        with mock.patch.object(execution_state, "RUNS", REPLAY_RUNS):
            base_inputs = ledger.current_inputs(REPLAY_RUN)
            threat = base_inputs["sources"][0]
            source, component = threat["source_generation"], threat["component_generation"]
            lead_sources, _coverage = ledger.lead_sources(REPLAY_RUN, source, component)
            component_map = json.loads((REPLAY_RUNS / REPLAY_RUN / "data/jobs/01-component-characterization/attempts"
                                        / component / "component-purpose-map.json").read_text())
        components = ledger.lead_components(component_map)
        leads = hunt.flat_leads(lead_sources)
        files = hunt.walk_target(REPLAY_TARGET, file_bytes_max=512 * 1024)
        briefs = hunt.plan_shards(files, components, leads, shard_groups=3, modes_per_group=1,
                                  pin_bytes_max=8 * 1024 * 1024, lead_menu_max=200, max_hypotheses=20, max_line_span=80)
        self.assertEqual(len(briefs), 3)
        cpp = next(b for b in briefs if "cpp-sample-cases" in b["component_ids"])
        self.assertTrue(any(row["path"] == "projects/cpp/case-001/main.cpp" and row["start_line"] == 7
                            for row in cpp["lead_menu"]))
        pinned = {path: (REPLAY_TARGET / path).read_bytes() for path in
                  ("projects/cpp/case-001/main.cpp", "projects/php/case-018/index.php")}
        merge = canned_merge({
            "g01-general": ("general", {"hypotheses": [
                {"path": "projects/cpp/case-001/main.cpp", "start_line": 7, "vulnerability_class": "stack buffer overflow",
                 "cwe": "CWE-121", "mechanism": "strcpy of argv[1] into char buffer[16]",
                 "attacker_preconditions": ["controls argv[1]"], "evidence": ["projects/cpp/case-001/main.cpp:5-7"],
                 "confidence": "high"},
                {"path": "projects/cpp/case-001/nope.cpp", "start_line": 1, "vulnerability_class": "ghost",
                 "mechanism": "hallucinated file", "attacker_preconditions": ["x"], "evidence": [], "confidence": "low"}]}),
            "g02-known-list": ("known-list", {"hypotheses": [
                {"file": "projects/php/case-018/index.php", "lines": "2-3", "class": "local file inclusion",
                 "cwe": "CWE-98", "mechanism": "$_GET['page'] concatenated into include",
                 "attacker_preconditions": ["HTTP request with page parameter"], "evidence": [], "confidence": "medium"},
                {"path": "projects/javascript/case-010/index.js", "start_line": 2, "vulnerability_class": "code injection",
                 "cwe": "CWE-95", "mechanism": "eval of argv[2]", "attacker_preconditions": ["controls argv[2]"],
                 "evidence": [], "confidence": "medium"}]})}, pinned)
        inputs = {"run_id": REPLAY_RUN, "source_generation": source, "component_generation": component,
                  "briefs": briefs, "leads": leads, "components": components}
        result = hunt.build_result(inputs, merge, hunt.checkout_reader(REPLAY_TARGET))
        self.assertEqual(len(result["hypotheses"]), 3)
        self.assertEqual({gap["kind"] for gap in result["gaps"]}, {"not-in-checkout", "worker-missing"})
        strcpy = next(row for row in result["hypotheses"] if row["path"].endswith("case-001/main.cpp"))
        self.assertEqual({o["producer_job_id"] for o in strcpy["lead_overlap"]}, {"02-source-sast", "02-native-sast"})
        replay = dict(base_inputs, sources=base_inputs["sources"] + [hunter_source(result, (source, component))])
        candidates = ledger._candidates(replay)
        value = ledger.build_ledger(REPLAY_RUN, "replay", candidates)
        self.assertEqual(ledger.validate_ledger(value), [])
        lead_claim = next(c for c in candidates if "projects/cpp/case-001/main.cpp:7 " in c["hypothesis"])
        self.assertIn(ledger.HUNTER_JOB, {c["producer_job_id"] for c in lead_claim["citations"]})
        php = next(c for c in candidates if "projects/php/case-018/index.php:3 " in c["hypothesis"])
        self.assertIn("Corroborated", php["hypothesis"])                   # P2 lead at line 3 corroborated
        hunter_claims = [c for c in candidates if c["route_id"].startswith(ledger.HUNTER_ROUTE_PREFIX)]
        self.assertEqual(len(hunter_claims), 1)                            # the eval nobody flagged
        self.assertIn("projects/javascript/case-010/index.js:2", hunter_claims[0]["hypothesis"])
        self.assertEqual(len(value["claim_states"]), 60 + 90 + 1)


if __name__ == "__main__":
    unittest.main()
