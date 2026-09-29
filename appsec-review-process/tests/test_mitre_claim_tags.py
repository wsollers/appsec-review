"""O3 (ADR-0026): optional ATT&CK/CAPEC labels on the 07 claim path, validated or withheld with a gap."""
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import attack_reference
import claim_lifecycle_core as core
import claim_review_derive
import claim_review_lifecycle
import mitre_feed
from schema_validate import validate_document
from test_claim_lifecycle_core import binding, fixture
from test_mitre_feed import SPECS, FakeDownloader, attack_bundle, capec_bundle


class ClaimTagTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"
        self.env = mock.patch.dict(os.environ, {"APPSEC_MITRE_FEED_ROOT": str(self.root)})
        self.env.start()
        attack_reference._LOADED.clear()

    def tearDown(self):
        self.env.stop()
        attack_reference._LOADED.clear()
        self.temporary.cleanup()

    def publish(self, at):
        mitre_feed.sync(self.root, "r", clock=lambda: at, specs=SPECS, sources=tuple(SPECS),
                        fetch_file=FakeDownloader({"enterprise-attack": attack_bundle(), "capec": capec_bundle()}))

    def decisions(self, attack=("T1190", "T9999", "T1066"), capec=("CAPEC-66",)):
        red = copy.deepcopy(fixture("red-decisions.json"))
        red["decisions"][0]["attack_refs"] = list(attack)
        red["decisions"][0]["capec_refs"] = list(capec)
        return red

    def chain(self, red_decisions, mitre_binding=None):
        red = core.red_team(fixture("claim-ledger.json"), binding("claim-ledger-routing", "claim-decision-ledger.json"),
                            red_decisions, mitre_binding)
        blue = core.blue_team(red, binding("07-red-team-adversarial", "red-team-adversarial.json"),
                              fixture("blue-decisions.json"))
        verification = core.verify(blue, binding("08-blue-team-refutation", "blue-team-refutation.json"),
                                   fixture("verification-decisions.json"))
        scoring = core.score(verification, binding("09-independent-verification", "independent-verification.json"),
                             fixture("scoring-decisions.json"))
        return red, blue, verification, scoring

    def test_valid_tags_are_kept_invalid_dropped_with_gaps_and_carried_forward(self):
        self.publish(datetime.now(timezone.utc))
        bound = attack_reference.binding()
        self.assertEqual(bound["status"], "OK")
        one = self.chain(self.decisions(), bound)
        self.assertEqual(one, self.chain(self.decisions(), bound))            # deterministic re-validation
        red, blue, verification, scoring = one
        labels = red["hypotheses"][0]["mitre_refs"]
        self.assertEqual((labels["attack_refs"], labels["capec_refs"]), (["T1190"], ["CAPEC-66"]))
        self.assertEqual({(gap["code"], gap["ref"]) for gap in labels["gaps"]},
                         {("MITRE_REF_UNKNOWN_ID", "T9999"), ("MITRE_REF_DEPRECATED", "T1066")})
        self.assertEqual(labels["reference"]["attack_versions"], {"enterprise-attack": "19.2"})
        for record in (blue["reviews"][0], verification["verifications"][0], scoring["priorities"][0]):
            self.assertEqual(record["mitre_refs"], labels)
        self.assertNotIn("mitre_refs", red["hypotheses"][1])
        schemas = ("07-red-team-adversarial.schema.json", "08-blue-team-refutation.schema.json",
                   "09-independent-verification.schema.json", "scoring-prioritization.schema.json")
        for document, schema in zip(one, schemas):
            self.assertEqual(validate_document(document, schema), [], schema)
        # a label never changes the claim's review outcome
        plain = self.chain(fixture("red-decisions.json"))
        self.assertEqual(scoring["priorities"][0]["severity"], plain[3]["priorities"][0]["severity"])

    def test_stale_snapshot_withholds_every_tag_and_never_blocks(self):
        self.publish(datetime.now(timezone.utc) - timedelta(days=15))
        bound = attack_reference.binding()
        self.assertEqual(bound, {"status": "MITRE_REFERENCE_STALE"})
        red = self.chain(self.decisions(), bound)[0]
        labels = red["hypotheses"][0]["mitre_refs"]
        self.assertEqual((labels["attack_refs"], labels["capec_refs"], labels["reference"]), ([], [], None))
        self.assertEqual(labels["gaps"][0]["code"], "MITRE_REFERENCE_STALE")
        self.assertEqual(validate_document(red, "07-red-team-adversarial.schema.json"), [])

    def test_missing_snapshot_withholds(self):
        bound = attack_reference.binding()
        self.assertEqual(bound, {"status": "MITRE_REFERENCE_MISSING"})
        labels = self.chain(self.decisions(), bound)[0]["hypotheses"][0]["mitre_refs"]
        self.assertEqual((labels["attack_refs"], labels["gaps"][0]["code"]), ([], "MITRE_REFERENCE_MISSING"))

    def test_untagged_decisions_do_not_touch_the_feed(self):
        with mock.patch.object(attack_reference, "load", side_effect=AssertionError("loaded")), \
             mock.patch.object(attack_reference, "bound", side_effect=AssertionError("bound")):
            red = self.chain(fixture("red-decisions.json"))[0]
        self.assertTrue(all("mitre_refs" not in row for row in red["hypotheses"]))

    def test_decision_contract_accepts_the_optional_fields(self):
        required, optional = claim_review_derive.PERSONA_FIELDS["07-red-team-adversarial"]
        self.assertTrue({"attack_refs", "capec_refs"} <= optional)
        self.assertTrue({"attack_refs", "capec_refs"} <= claim_review_lifecycle.OPTIONAL_DECISION_KEYS["07-red-team-adversarial"])
        self.assertFalse({"attack_refs", "capec_refs"} & claim_review_lifecycle.OPTIONAL_DECISION_KEYS["08-blue-team-refutation"])
        decision = {**self.decisions()["decisions"][0]}
        self.assertEqual(validate_document({"stage": "07-red-team-adversarial", "decision": decision},
                                           "claim-review-decision.schema.json"), [])
        bad = self.decisions()
        bad["decisions"][0]["attack_refs"] = "T1190"                    # a string, not a list
        with self.assertRaises(core.Blocked):
            self.chain(bad)


if __name__ == "__main__":
    unittest.main()
