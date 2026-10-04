"""Every graph job's output contract that declares a claim class has the matching trusted policy.

A contract with a ``claim_class`` and no entry in ``validate_job_output.CLAIM_CLASS_POLICIES`` is
refused at publication ("no trusted claim-class policy"); hello-autotools re-run 2026-10-04 failed
02-lsp-xref and 04-owasp-participation that way. Checking every contract file catches it before a run.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import validate_job_output  # noqa: E402


class ClaimClassPolicyCoverage(unittest.TestCase):
    def test_every_declared_claim_class_has_its_trusted_policy(self):
        graph = json.loads((ROOT / "pipeline" / "job-graph.json").read_text(encoding="utf-8"))["jobs"]
        published = {job["contract"] for job in graph.values()}   # cell reply contracts validate elsewhere
        checked = 0
        for path in sorted((ROOT / "pipeline" / "output-contracts").glob("*.json")):
            if path.stem not in published:
                continue
            contract = json.loads(path.read_text(encoding="utf-8"))
            declaration = contract.get("claim_class")
            if declaration is None:
                continue
            checked += 1
            with self.subTest(contract=contract.get("contract_id")):
                policy = validate_job_output.CLAIM_CLASS_POLICIES.get(contract.get("contract_id"))
                self.assertIsNotNone(policy, f"{path.name}: no trusted claim-class policy")
                self.assertEqual(declaration.get("claim_class_id"), policy["claim_class_id"])
                self.assertEqual(set(declaration.get("allowed_assertions") or []), policy["allowed_assertions"])
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
