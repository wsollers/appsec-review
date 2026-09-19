"""Behavioral tests for run-owned OpenSSF Scorecard published-result ingestion."""
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import execution_state as state
import ossf_scorecard as scorecard
import phase1
import test_phase1 as fixtures
from schema_validate import validate_document


COMMIT = "a" * 40
PAYLOAD = {
    "date": "2026-09-19T00:00:00Z",
    "repo": {"name": "github.com/ossf/scorecard", "commit": COMMIT},
    "scorecard": {"version": "5.5.0", "commit": "b" * 40},
    "score": 9.2,
    "checks": [{"name": "Code-Review", "score": 10, "reason": "fixture", "details": []}],
}


class Response:
    def __init__(self, payload=PAYLOAD, url=None, status=200):
        self.raw = json.dumps(payload).encode()
        self.status = status
        self.url = url or scorecard.API_BASE + "/github.com/ossf/scorecard"
        self.headers = {"Content-Type": "application/json", "ETag": '"fixture"',
                        "Content-Length": str(len(self.raw))}

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, limit=-1): return self.raw[:limit]
    def getcode(self): return self.status
    def geturl(self): return self.url


class ScorecardTests(unittest.TestCase):
    setUp = fixtures.Phase1Tests.setUp
    tearDown = fixtures.Phase1Tests.tearDown
    new_run = fixtures.Phase1Tests.new_run

    def authorize(self):
        phase1.stage(self.run_id, self.target, "fixture", "Behavior qualification",
                     ["Linux", "Windows"], permissions=["read-source", scorecard.NETWORK_PERMISSION])

    def stage(self, projects=None):
        self.authorize()
        path = state.run_path(self.run_id) / "inputs" / scorecard.INPUT_NAME
        state.atomic_json(path, {"schema": "appsec-review/ossf-scorecard-projects/1",
                                 "projects": projects or [{"repository": "github.com/ossf/scorecard"}]})
        return path

    def test_input_validation_and_registry_composition(self):
        parsed = scorecard.parse_projects({"schema": "appsec-review/ossf-scorecard-projects/1",
                                           "projects": [{"repository": "github.com/ossf/scorecard",
                                                         "commit": COMMIT.upper()}]})
        self.assertEqual(parsed[0]["commit"], COMMIT)
        self.assertEqual(scorecard.template()["composition"]["output_contract_id"],
                         "ossf-scorecard-results")
        for value in ("https://github.com/ossf/scorecard", "github.com/ossf/scorecard/extra"):
            with self.assertRaises(ValueError):
                scorecard.parse_projects({"schema": "appsec-review/ossf-scorecard-projects/1",
                                          "projects": [{"repository": value}]})

    def test_bounded_fetch_preserves_raw_hash_and_not_published_gap(self):
        output = self.root / "output"
        calls = [Response(), urllib.error.HTTPError("fixture", 404, "missing", {}, io.BytesIO())]
        def opener(request, timeout):
            value = calls.pop(0)
            if isinstance(value, Exception): raise value
            value.url = request.full_url
            return value
        result = scorecard.fetch_projects(
            [{"repository": "github.com/ossf/scorecard"},
             {"repository": "github.com/example/missing"}], output, opener=opener)
        self.assertEqual((result["published_count"], result["not_published_count"]), (1, 1))
        published = result["projects"][0]
        self.assertEqual(published["raw_sha256"], state.file_hash(output / published["raw_path"]))
        self.assertEqual(result["projects"][1]["status"], "not-published")
        self.assertEqual(validate_document(result, "ossf-scorecard-results.schema.json"), [])

    def test_network_permission_and_redirect_fail_closed(self):
        path = state.run_path(self.run_id) / "inputs" / scorecard.INPUT_NAME
        state.atomic_json(path, {"schema": "appsec-review/ossf-scorecard-projects/1",
                                 "projects": [{"repository": "github.com/ossf/scorecard"}]})
        with self.assertRaisesRegex(state.Blocked, scorecard.NETWORK_PERMISSION):
            scorecard.current_inputs(self.run_id)
        with self.assertRaisesRegex(ValueError, "redirect"):
            scorecard.fetch_projects([{"repository": "github.com/ossf/scorecard"}],
                                     self.root / "redirect",
                                     opener=lambda request, timeout: Response(url="https://example.test/redirect"))

    def test_skip_without_input_is_accepted_and_reused(self):
        first = scorecard.run(self.run_id, "dagster-a")
        self.assertEqual(first["status"], "SKIPPED")
        self.assertEqual(first["reason"], "not-requested-no-scorecard-projects")
        self.assertEqual(first, scorecard.run(self.run_id, "dagster-b"))
        scorecard.validate(self.run_id, first)

    def test_attempt_reuse_force_tamper_and_failed_newer_attempt(self):
        self.stage()
        def successful(spec, **kwargs):
            projects, _ = scorecard.load_input(Path(spec.argv[-2]))
            response = Response()
            scorecard.fetch_projects(projects, Path(spec.argv[-1]),
                                     opener=lambda request, timeout: response)
            state.atomic_bytes(spec.log_dir / "stdout.log", b"fetched\n")
            state.atomic_bytes(spec.log_dir / "stderr.log", b"")
            return {"exit_code": 0, "error": None, "argv": list(spec.argv)}
        with patch.object(scorecard, "execute_child", side_effect=successful):
            first = scorecard.run(self.run_id, "dagster-a")
            self.assertEqual(first, scorecard.run(self.run_id, "dagster-b"))
            forced = scorecard.run(self.run_id, "dagster-c", force=True)
        attempt = scorecard.validate(self.run_id, forced)
        legacy_pointer = {"status": forced["status"], "attempt_id": forced["attempt_id"],
                          "hashes": state.tree_hashes(attempt)}
        self.assertEqual(scorecard.validate(self.run_id, legacy_pointer), attempt)
        with (attempt / "outputs" / "scorecard-results.json").open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaises(state.Blocked): scorecard.validate(self.run_id, forced)
        with patch.object(scorecard, "execute_child",
                          return_value={"exit_code": 9, "error": "fixture"}):
            with self.assertRaises(state.Blocked): scorecard.run(self.run_id, "dagster-d", force=True)
        self.assertEqual(state.read_json(scorecard.root(self.run_id) / "accepted.json")["status"],
                         "FAILED")


if __name__ == "__main__": unittest.main()
