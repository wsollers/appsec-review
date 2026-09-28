"""Call-graph reachability arbiter (ADR-0020): REACHABLE witness, UNREACHABLE proof, UNKNOWN escapes."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reachability as r

SHA = "sha256:" + "a" * 64


def method(full, name, path, start, end):
    return {"kind": "symbol", "label": "METHOD", "full_name": full, "name": name, "source_path": path,
            "start_line": start, "end_line": end, "source_sha256": SHA}


def call(caller, callee, name, path, line, code=""):
    return {"kind": "call", "label": "CALL", "caller": caller, "full_name": callee, "name": name,
            "source_path": path, "start_line": line, "code": code}


def graph(extra=(), gaps=()):
    records = [
        method("main:int(int,char**)", "main", "app/main.c", 1, 10),
        method("parse:void(char*)", "parse", "app/parse.c", 1, 20),
        method("copy:void(char*)", "copy", "app/parse.c", 22, 30),
        method("dead:void()", "dead", "app/dead.c", 1, 5),
        call("main:int(int,char**)", "parse:void(char*)", "parse", "app/main.c", 5, "parse(argv[1])"),
        call("parse:void(char*)", "<unresolvedNamespace>.copy:<unresolvedSignature>(1)", "copy", "app/parse.c", 12),
        call("copy:void(char*)", "<unresolvedNamespace>.strcpy:<unresolvedSignature>(2)", "strcpy", "app/parse.c", 25,
             "strcpy(buf, s)"),
        call("dead:void()", "<unresolvedNamespace>.memcpy:<unresolvedSignature>(3)", "memcpy", "app/dead.c", 3),
        *extra]
    return r.CallGraph.from_records(records, gaps)


class ReachabilityTests(unittest.TestCase):
    def test_reachable_has_ordered_witness_from_main(self):
        result = r.assess_location(graph(), "app/parse.c", 25)
        self.assertEqual(result["state"], r.REACHABLE)
        self.assertEqual([step["function"] for step in result["witness"]],
                         ["main", "parse", "copy", "(finding location)"])
        self.assertEqual(result["witness"][0]["calls_next_at"], "app/main.c:5")
        self.assertEqual(result["witness"][1]["resolution"], "unique-name")
        self.assertEqual((result["witness"][-1]["file"], result["witness"][-1]["line"]), ("app/parse.c", 25))

    def test_unreachable_requires_complete_graph_without_escapes(self):
        result = r.assess_location(graph(), "app/dead.c", 3)
        self.assertEqual(result["state"], r.UNREACHABLE)
        self.assertEqual(result["witness"], [])

    def test_dynamic_dispatch_gap_bound_and_missing_location_are_unknown(self):
        pointer = call("parse:void(char*)", "<operator>.pointerCall", "<operator>.pointerCall", "app/parse.c", 13)
        self.assertEqual(r.assess_location(graph([pointer]), "app/dead.c", 3)["state"], r.UNKNOWN)
        gapped = graph(gaps=[{"reason": "no-source-location", "count": 3}])
        self.assertIn("coverage gaps", r.assess_location(gapped, "app/dead.c", 3)["reason"])
        self.assertEqual(r.assess_location(gapped, "app/parse.c", 25)["state"], r.REACHABLE)
        benign = graph(gaps=[{"reason": "duplicate", "count": 9}])
        self.assertEqual(r.assess_location(benign, "app/dead.c", 3)["state"], r.UNREACHABLE)
        self.assertEqual(r.assess_location(graph(), "app/other.c", 3)["state"], r.UNKNOWN)
        bounded = r.analyze(graph(), "copy:void(char*)", ["main:int(int,char**)"], max_depth=1)
        self.assertEqual(bounded["state"], r.UNKNOWN)
        no_main = r.CallGraph.from_records([method("f:void()", "f", "a.c", 1, 3)])
        self.assertIn("no entry point", r.assess_location(no_main, "a.c", 2)["reason"])

    def test_exported_symbol_entry_point_and_ambiguous_names(self):
        self.assertEqual(r.assess_location(graph(), "app/dead.c", 3, ["dead"])["state"], r.REACHABLE)
        twin = [method("helper:void()", "helper", "x/a.c", 1, 3), method("helper:int()", "helper", "y/b.c", 1, 3),
                call("dead:void()", "<unresolvedNamespace>.helper:<unresolvedSignature>(0)", "helper", "app/dead.c", 4)]
        g = graph(twin)
        self.assertEqual(g.escapes["dead:void()"][0]["reason"], "ambiguous-name")

    def test_cve_evidence_links_vulnerable_function_to_app_path(self):
        sca = {"matches": [
            {"match_id": "VM-000001", "advisory_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2025-0001"]},
            {"match_id": "VM-000002", "advisory_id": "CVE-2025-0002", "aliases": ["CVE-2025-0002"]},
            {"match_id": "VM-000003", "advisory_id": "CVE-2025-0003", "aliases": ["CVE-2025-0003"]}]}
        result = r.cve_evidence(sca, {"CVE-2025-0001": ["strcpy"], "CVE-2025-0002": ["memcpy"]}, graph())
        rows = {row["match_ref"]: row for row in result["assessments"]}
        self.assertEqual(rows["VM-000001"]["classification"], "reachable")
        self.assertTrue(all(item["kind"] == "call" and item["sha256"] == SHA for item in rows["VM-000001"]["evidence"]))
        self.assertEqual(result["witnesses"]["VM-000001"]["witness"][-1]["function"], "strcpy")
        self.assertEqual(rows["VM-000002"]["classification"], "unreachable")
        self.assertNotIn("VM-000003", rows)
        self.assertEqual(result["witnesses"]["VM-000003"]["state"], r.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
