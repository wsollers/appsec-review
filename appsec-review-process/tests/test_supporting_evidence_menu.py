from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state
from publish_job_output import ACCEPTED_SCHEMA
import supporting_evidence_menu as menu_module

RUN = "menu-run"


def publish(jobs: Path, job: str, files: dict[str, bytes], *, status: str = "OK", whole: bool = False,
            attempt_id: str = "a1", run: str = RUN) -> Path:
    base = jobs / job / "whole" if whole else jobs / job
    attempt = base / "attempts" / attempt_id
    attempt.mkdir(parents=True)
    artifacts = []
    for relative, raw in files.items():
        path = attempt / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        artifacts.append({"path": relative, "sha256": execution_state.file_hash(path)})
    execution_state.atomic_json(attempt / "result.json", {"artifacts": artifacts})
    hashes = {item["path"]: item["sha256"] for item in artifacts}
    execution_state.atomic_json(base / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": status,
        "run_id": run, "job": job, "attempt_id": attempt_id, "fingerprint": "sha256:" + "0" * 64,
        "envelope_path": "result.json", "envelope_sha256": execution_state.file_hash(attempt / "result.json"),
        "hashes": hashes, "accepted_at": "2026-09-28T00:00:00+00:00"})
    execution_state.atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": "x"})
    return attempt


CLAIMS = [
    {"claim_id": "claim-b", "citations": [{"producer_job_id": "02-native-sast",
        "locator_json": json.dumps({"path": "src/a.c", "start_line": 7})}]},
    {"claim_id": "claim-a", "citations": [{"producer_job_id": "03-threat-model-dfd-stride", "locator_json": None}]},
    {"claim_id": "claim-c", "citations": [{"producer_job_id": "02-secrets-inventory",
        "locator_json": json.dumps({"lead_ref": "SI-000001"})}]},
]


class SupportingEvidenceMenuTests(unittest.TestCase):
    def fixture(self, directory: str) -> Path:
        jobs = Path(directory) / RUN / "data" / "jobs"
        publish(jobs, "02-ir-facts", {"ir-facts.json": json.dumps({"facts": [1, 2, 3], "debug_locations": [1]}).encode(),
                                      "ir-facts-summary.md": b"# x\n"})
        publish(jobs, "02-code-property-graph", {"code-property-graph.json": b"{}",
                                                 "code-property-graph.records.jsonl": b"{}\n{}\n"})
        publish(jobs, "02-native-build", {"native-build.json": b'{"units": [1]}',
            "outputs/u1/compile_commands.json": b"[]", "outputs/u1/binaries/app": b"\x7fELF"})
        publish(jobs, "02-mobile-sast", {"outputs/mobile-sast.json": b"{}"}, status="SKIPPED", whole=True)
        publish(jobs, "02-secrets-inventory", {"outputs/secrets-inventory.redacted.json": b'{"entries": []}'}, whole=True)
        return jobs

    def test_menu_is_deterministic_and_marks_skipped_and_absent(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(execution_state, "RUNS", Path(directory)):
            self.fixture(directory)
            first = menu_module.build(RUN, "07-red-team-adversarial", CLAIMS)
            second = menu_module.build(RUN, "07-red-team-adversarial", list(reversed(CLAIMS)))
        self.assertEqual(menu_module.menu_bytes(first), menu_module.menu_bytes(second))
        items = {item["item_id"]: item for item in first["items"]}
        self.assertEqual(len(items), len(menu_module.MENU))
        self.assertEqual((items["02-mobile-sast"]["status"], items["02-mobile-sast"]["reason"]),
                         ("NOT_AVAILABLE", "accepted status SKIPPED"))
        self.assertEqual(items["02-build-index"]["reason"], "no accepted publication in this run")
        facts = items["02-ir-facts"]["files"]
        self.assertEqual([entry["path"] for entry in facts], ["02-ir-facts/accepted/ir-facts.json"])
        self.assertEqual(facts[0]["records"], {"debug_locations": 1, "facts": 3})
        self.assertEqual(items["02-code-property-graph"]["files"][1]["records"], {"lines": 2})
        native = [entry["path"] for entry in items["02-native-build"]["files"]]
        self.assertEqual(native, ["02-native-build/accepted/native-build.json",
                                  "02-native-build/accepted/outputs/u1/compile_commands.json"])  # no binaries
        self.assertEqual(items["02-secrets-inventory"]["files"][0]["path"],
                         "02-secrets-inventory/whole/accepted/outputs/secrets-inventory.redacted.json")
        self.assertEqual(first["profiles"]["code"][:3], ["02-ir-facts", "02-code-property-graph", "02-native-build"])
        self.assertEqual([(row["claim_id"], row["profile"], row["locations"]) for row in first["claims"]],
                         [("claim-a", "architecture", []), ("claim-b", "code", ["src/a.c:7"]),
                          ("claim-c", "secret", [])])

    def test_every_pinned_pointer_is_a_readable_input_under_a_declared_root(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(execution_state, "RUNS", Path(directory)):
            jobs = self.fixture(directory)
            menu = menu_module.build(RUN, "08-blue-team-refutation", CLAIMS)
            written = menu_module.write(Path(directory) / "menu", menu)
            roots = menu_module.readable_roots(RUN, menu, written)
            rows = menu_module.readable_inputs(menu)
            self.assertEqual(rows[0]["path"], menu_module.MENU_FILE)
            self.assertEqual(rows[0]["sha256"], "sha256:" + execution_state.file_hash(written / menu_module.MENU_FILE))
            self.assertEqual(roots[menu_module.ROOT_ID], jobs.absolute())
            pinned = {(entry["path"], entry["sha256"]) for item in menu["items"] for entry in item["files"]
                      if entry["pinned"]}
            self.assertEqual({(row["path"], row["sha256"]) for row in rows[1:]}, pinned)
            for row in rows:
                real = execution_state.resolve_accepted_alias(roots[row["root"]], row["path"])
                path = roots[row["root"]].joinpath(*real.split("/"))
                self.assertEqual("sha256:" + execution_state.file_hash(path), row["sha256"])
                self.assertEqual(path.stat().st_size, row["bytes"])

    def test_pin_budget_and_tampering_keep_unreadable_files_out(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(execution_state, "RUNS", Path(directory)):
            jobs = self.fixture(directory)
            (jobs / "02-ir-facts" / "attempts" / "a1" / "ir-facts.json").write_text("{}")
            with mock.patch.object(menu_module, "FILE_PIN_MAX", 3):
                menu = menu_module.build(RUN, "07-red-team-adversarial", [])
        items = {item["item_id"]: item for item in menu["items"]}
        self.assertEqual(items["02-ir-facts"]["status"], "NOT_AVAILABLE")
        self.assertIn("does not match its accepted hash", items["02-ir-facts"]["reason"])
        cpg = items["02-code-property-graph"]["files"]
        self.assertEqual([entry["pinned"] for entry in cpg], [True, False])  # 2 bytes pinned, 6 bytes listed only
        self.assertNotIn(cpg[1]["path"], {row["path"] for row in menu_module.readable_inputs(menu)})

    def test_run_without_jobs_lists_everything_unavailable(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(execution_state, "RUNS", Path(directory)):
            (Path(directory) / RUN).mkdir()
            menu = menu_module.build(RUN, "07-red-team-adversarial", [])
            roots = menu_module.readable_roots(RUN, menu, Path(directory))
        self.assertTrue(all(item["status"] == "NOT_AVAILABLE" for item in menu["items"]))
        self.assertEqual(len(menu_module.readable_inputs(menu)), 1)
        self.assertEqual(set(roots), {menu_module.MENU_ROOT_ID})


def _persona_cache_key(jobs: Path, menu: dict) -> str:
    """The key an invocation over this menu gets: inputs read as persona_invocation reads them (alias
    resolved through the accepted pointer), prompt rendered by the invoker's own input renderer."""
    from types import SimpleNamespace
    import claude_cli_invoker as cli
    inputs = [SimpleNamespace(root=menu_module.MENU_ROOT_ID, path=menu_module.MENU_FILE,
                              data=menu_module.menu_bytes(menu))]
    for row in menu_module.readable_inputs(menu)[1:]:
        real = execution_state.resolve_accepted_alias(jobs, row["path"])
        data = jobs.joinpath(*real.split("/")).read_bytes()
        assert "sha256:" + __import__("hashlib").sha256(data).hexdigest() == row["sha256"]
        inputs.append(SimpleNamespace(root=row["root"], path=row["path"], data=data))
    package = SimpleNamespace(request={"job_id": "07-red-team-adversarial", "persona": {}}, inputs=tuple(inputs))
    return cli.persona_cache_key(package, cli._render_readable_inputs(package.inputs), "model", "low")


class AttemptFreeAliasTests(unittest.TestCase):
    """A producer that re-runs and publishes the same bytes under a new attempt id must not change the
    menu bytes or the persona cache key (before the alias both held ``<owner>/attempts/<id>/``)."""

    def observe(self, jobs: Path, attempt_id: str, raw: bytes) -> tuple[bytes, str, dict]:
        publish(jobs, "02-ir-facts", {"ir-facts.json": raw}, attempt_id=attempt_id)
        menu = menu_module.build(RUN, "07-red-team-adversarial", [])
        return menu_module.menu_bytes(menu), _persona_cache_key(jobs, menu), menu

    def test_identical_reattempt_keeps_menu_bytes_and_cache_key_and_changed_bytes_change_both(self):
        with tempfile.TemporaryDirectory() as directory,                 mock.patch.object(execution_state, "RUNS", Path(directory)):
            jobs = Path(directory) / RUN / "data" / "jobs"
            first = self.observe(jobs, "a1", b'{"facts": [1]}')
            second = self.observe(jobs, "a2", b'{"facts": [1]}')
            changed = self.observe(jobs, "a3", b'{"facts": [2]}')
            lineage = menu_module.lineage(RUN, changed[2])
        self.assertEqual(first[:2], second[:2])
        self.assertNotIn(b"a1", first[0].replace(b"sha256", b""))
        self.assertNotIn(b"attempt", first[0])
        self.assertNotEqual(second[0], changed[0])
        self.assertNotEqual(second[1], changed[1])
        self.assertEqual(lineage["02-ir-facts/accepted/ir-facts.json"],
                         {"producer": "02-ir-facts", "attempt_id": "a3", "path": "02-ir-facts/attempts/a3/ir-facts.json"})

    def test_alias_resolves_only_through_the_accepted_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "jobs"
            publish(jobs, "02-ir-facts", {"ir-facts.json": b"{}", "other.json": b"{}"}, attempt_id="a1")
            publish(jobs, "02-ir-facts", {"ir-facts.json": b"{}"}, attempt_id="a2")
            resolve = execution_state.resolve_accepted_alias
            self.assertEqual(resolve(jobs, "02-ir-facts/accepted/ir-facts.json"), "02-ir-facts/attempts/a2/ir-facts.json")
            self.assertEqual(resolve(jobs, "02-ir-facts/attempts/a1/ir-facts.json"),
                             "02-ir-facts/attempts/a1/ir-facts.json")   # a literal path is left alone
            with self.assertRaises(ValueError):   # in an old attempt, not in the accepted publication
                resolve(jobs, "02-ir-facts/accepted/other.json")
            self.assertEqual(resolve(jobs, "no-such-job/accepted/x.json"), "no-such-job/accepted/x.json")


if __name__ == "__main__":
    unittest.main()


class UpstreamOnlyMenuTests(unittest.TestCase):
    """Run 20261001T064759Z-4a8586: 03's fingerprinted menu listed the 02-codeql-<lang> lanes, which run in
    parallel with 03; one was accepted after 03 and the claim ledger refused 03's pointer."""

    def test_menu_lists_only_jobs_upstream_of_the_stage(self):
        import supporting_evidence_menu as sem
        with tempfile.TemporaryDirectory() as root:
            for stage in ("03-threat-model-dfd-stride", "07-hypothesis-discovery"):
                ids = {item["item_id"] for item in sem.build("run-1", stage, [], Path(root) / "jobs")["items"]}
                upstream = sem.upstream_jobs(stage)
                self.assertTrue(ids <= upstream, sorted(ids - upstream))
                # The 02-codeql-<lang> lanes are listed only because they are now upstream (through
                # 02-evidence-index-derived), so they are terminal before the stage fingerprints its menu.
                self.assertTrue(all(job in upstream for job in ids if job.startswith("02-codeql-")))
                self.assertIn("02-codeql-cpp", sem.upstream_jobs("02-evidence-index-derived"))
                self.assertNotIn(stage, ids)
            self.assertIn("01-component-characterization",
                          {item["item_id"] for item in sem.build("run-1", "03-threat-model-dfd-stride", [],
                                                                  Path(root) / "jobs")["items"]})

    def test_non_graph_stage_is_not_filtered(self):
        import supporting_evidence_menu as sem
        self.assertIsNone(sem.upstream_jobs("not-a-graph-job"))
