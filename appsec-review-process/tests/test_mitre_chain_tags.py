"""O3 (ADR-0026): optional ATT&CK labels on lane-14 chain links, rendered in the attack-chain section only."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_chain_derive as derive
import attack_chain_report as chain_report
import attack_reference
import execution_state
import mitre_feed
import synthesis_report_presentation as presentation
from schema_validate import validate_document
from tests.test_attack_chain_derive import run, two_link_chain
from tests.test_attack_chain_report import report
from tests.test_attack_chain_workers import LAUNCHED, RUN, Harness, composition_inputs, merge_for
import attack_chain_composition as composition
import attack_chain_pool as chain_pool
import attack_chain_refutation as refutation
import attack_chain_refute as refute
from tests.test_mitre_feed import SPECS, FakeDownloader, attack_bundle, capec_bundle


def tagged_chain(entry=("T1190", "T9999", "T1059"), impact=("T1059.004",)):
    chain = two_link_chain()
    chain["links"][0]["attack_refs"] = list(entry)
    chain["links"][1]["attack_refs"] = list(impact)
    return chain


class FeedRoot:
    def start_feed(self):
        self.feed_folder = tempfile.TemporaryDirectory()
        self.feed = Path(self.feed_folder.name) / "data" / "feeds" / "mitre"
        self.env = mock.patch.dict(os.environ, {"APPSEC_MITRE_FEED_ROOT": str(self.feed)})
        self.env.start()
        attack_reference._LOADED.clear()

    def stop_feed(self):
        self.env.stop()
        attack_reference._LOADED.clear()
        self.feed_folder.cleanup()

    def publish(self, at=None):
        at = at or datetime.now(timezone.utc)
        mitre_feed.sync(self.feed, "r", clock=lambda: at, specs=SPECS, sources=tuple(SPECS),
                        fetch_file=FakeDownloader({"enterprise-attack": attack_bundle(), "capec": capec_bundle()}))


class ChainLabelTests(FeedRoot, unittest.TestCase):
    def setUp(self):
        self.start_feed()

    def tearDown(self):
        self.stop_feed()

    def test_link_labels_are_validated_against_the_stage_tactics(self):
        self.publish()
        document, notes = run({"chains": [tagged_chain()]})
        chain = document["chains"][0]
        self.assertEqual(validate_document(chain, derive.RECORD_SCHEMA), [])
        self.assertEqual(chain["links"][0]["attack_refs"], ["T1190"])
        self.assertEqual(chain["links"][1]["attack_refs"], [])       # an execution technique on an impact link
        text = "\n".join(notes)
        self.assertIn("T9999 withheld (MITRE_REF_UNKNOWN_ID)", text)
        self.assertIn("T1059 withheld (MITRE_REF_TACTIC_MISMATCH)", text)
        self.assertEqual(chain["mitre_reference"]["attack_versions"], {"enterprise-attack": "19.2"})
        plain, _ = run({"chains": [two_link_chain()]})
        # labels never change the chain's identity, states or edges
        for key in ("chain_id", "state", "weakest", "edges", "causal_claim_ids"):
            self.assertEqual(chain[key], plain["chains"][0][key], key)
        self.assertNotIn("mitre_reference", plain["chains"][0])
        self.assertTrue(all("attack_refs" not in link for link in plain["chains"][0]["links"]))

    def test_stale_or_missing_snapshot_withholds_link_labels(self):
        document, notes = run({"chains": [tagged_chain()]})
        self.assertEqual([link["attack_refs"] for link in document["chains"][0]["links"]], [[], []])
        self.assertIn("MITRE_REFERENCE_MISSING", "\n".join(notes))
        self.publish(datetime.now(timezone.utc) - timedelta(days=15))
        attack_reference._LOADED.clear()
        document, notes = run({"chains": [tagged_chain()]})
        self.assertEqual([link["attack_refs"] for link in document["chains"][0]["links"]], [[], []])
        self.assertIn("MITRE_REFERENCE_STALE", "\n".join(notes))
        self.assertNotIn("mitre_reference", document["chains"][0])
        self.assertEqual(validate_document(document["chains"][0], derive.RECORD_SCHEMA), [])

    def test_unlabelled_reply_never_loads_the_feed(self):
        with mock.patch.object(attack_reference, "load", side_effect=AssertionError("loaded")):
            run({"chains": [two_link_chain()]})

    def test_model_cannot_supply_the_reference_identity(self):
        self.publish()
        chain = tagged_chain()
        chain["mitre_reference"] = {"attack_versions": {"enterprise-attack": "99"}}
        document, _ = run({"chains": [chain]})
        self.assertEqual(document["chains"][0]["mitre_reference"]["attack_versions"], {"enterprise-attack": "19.2"})


class ChainReportLabelTests(FeedRoot, Harness):
    def setUp(self):
        super().setUp()
        self.start_feed()
        self.publish()

    def tearDown(self):
        self.stop_feed()
        super().tearDown()

    def publish_chain(self):
        inputs = composition_inputs()
        first, _second, _dispatch = self.compose(inputs, self.composer_merge(inputs, {"chains": [tagged_chain()]}))
        chain_id = json.loads((composition.root(RUN) / "attempts" / first["attempt_id"] /
                               composition.RESULT).read_text())["chains"][0]["chain_id"]
        batch = refutation.prepare(RUN)["batches"][0]
        outcome, _ = refute.derive(batch, {"chains": [{"chain_id": chain_id, "disposition": "holds"}]}, refuter=None)
        merge = merge_for([("attack-chain-refuter", refute.candidates(outcome, "sha256:" + "b" * 64))])
        with mock.patch.object(chain_pool, "dispatch", return_value=(merge, LAUNCHED)):
            return refutation.run(RUN, "dagster-3")

    def test_report_section_carries_link_labels_and_versions(self):
        self.publish_chain()
        section = chain_report.build(report(), execution_state.run_path(RUN))
        chain = section["chains"][0]
        self.assertEqual(chain["links"][0]["attack_refs"], ["T1190"])
        self.assertNotIn("attack_refs", chain["links"][1])
        self.assertEqual(chain["attack_versions"], {"enterprise-attack": "19.2"})
        self.assertEqual(chain["state"], "supported")
        projected = presentation._attack_chains(section)
        self.assertEqual(projected["chains"][0]["links"][0]["attack_refs"], ["T1190"])
        self.render(projected)

    def render(self, projected):
        if not (importlib.util.find_spec("cvss") and importlib.util.find_spec("jinja2")):
            self.skipTest("the report renderer needs cvss and jinja2 (images/audit-report)")
        path = ROOT.parent / "pipeline" / "report" / "render.py"
        spec = importlib.util.spec_from_file_location("appsec_review_report_renderer_mitre_test", path)
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        data = json.loads((ROOT.parent / "pipeline" / "report" / "examples" / "hello-autotools.review.json").read_text())
        with tempfile.TemporaryDirectory() as out:
            document = copy.deepcopy(data)
            document["attack_chains"] = projected
            source = Path(out) / "review.json"
            source.write_text(json.dumps(document))
            renderer.render(source, Path(out) / "presentation")
            html = (Path(out) / "presentation" / "report.html").read_text()
            tex = (Path(out) / "presentation" / "report.tex").read_text()
        self.assertIn("ATT&amp;CK T1190", html)
        self.assertIn("enterprise-attack v19.2; labels only, never evidence", html)
        self.assertIn("ATT\\&CK T1190", tex)
        self.assertEqual(html.count("ATT&amp;CK T"), 1)             # nowhere outside the chain section


if __name__ == "__main__":
    unittest.main()
