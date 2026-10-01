import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import attack_reference
import mitre_feed
import tunables
from dependency_snapshot_registry import SnapshotBlocked, SnapshotInvalid, SnapshotStale


def technique(identifier, name, tactics, deprecated=False, revoked=False):
    return {"type": "attack-pattern", "id": "attack-pattern--" + identifier, "name": name, "revoked": revoked,
            "x_mitre_deprecated": deprecated, "x_mitre_platforms": ["Linux", "Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics],
            "external_references": [{"source_name": "mitre-attack", "external_id": identifier,
                                      "url": "https://attack.mitre.org/techniques/" + identifier.replace(".", "/")}]}


def attack_bundle(version="19.2", extra=()):
    objects = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": version},
        {"type": "marking-definition", "id": "marking-definition--1",
         "definition": {"statement": "Copyright 2015-2026, The MITRE Corporation."}},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Initial Access", "x_mitre_shortname": "initial-access",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001",
                                  "url": "https://attack.mitre.org/tactics/TA0001"}]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--2", "name": "Execution", "x_mitre_shortname": "execution",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002",
                                  "url": "https://attack.mitre.org/tactics/TA0002"}]},
        technique("T1190", "Exploit Public-Facing Application", ["initial-access"]),
        technique("T1059", "Command and Scripting Interpreter", ["execution"]),
        technique("T1059.004", "Unix Shell", ["execution"]),
        technique("T1066", "Indicator Removal from Tools", ["stealth"], revoked=True),
        technique("T1086", "PowerShell", ["execution"], deprecated=True),
        *extra]
    return json.dumps({"type": "bundle", "id": "bundle--a", "objects": objects}).encode()


def capec_bundle(version="3.9"):
    def pattern(number, name, status="Stable", cwe=(), attack=()):
        refs = [{"source_name": "capec", "external_id": f"CAPEC-{number}",
                 "url": f"https://capec.mitre.org/data/definitions/{number}.html"}]
        refs += [{"source_name": "cwe", "external_id": c} for c in cwe]
        refs += [{"source_name": "ATTACK", "external_id": a} for a in attack]
        return {"type": "attack-pattern", "id": f"attack-pattern--c{number}", "name": name, "x_capec_status": status,
                "x_capec_version": version, "external_references": refs}
    objects = [pattern(66, "SQL Injection", "Draft", cwe=["CWE-89", "CWE-1286"]),
               pattern(13, "Subverting Environment Variable Values", attack=["T1574.006"]),
               pattern(7, "Old pattern", "Deprecated")]
    return json.dumps({"type": "bundle", "id": "bundle--c", "objects": objects}).encode()


SPECS = {
    "enterprise-attack": {"kind": "attack", "url": "https://example.test/enterprise-attack-19.2.json",
                          "upstream_version": "19.2", "licence": "MITRE ATT&CK Terms of Use", "sha256": None},
    "capec": {"kind": "capec", "url": "https://example.test/stix-capec.json", "upstream_version": "3.9",
              "licence": "MITRE CAPEC Terms of Use", "sha256": None},
}
T0 = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)


class FakeDownloader:
    def __init__(self, payloads):
        self.payloads, self.calls = payloads, []

    def __call__(self, url, destination, etag=None, **_):
        name = "capec" if "capec" in url else "enterprise-attack"
        self.calls.append((name, etag))
        value = self.payloads[name]
        if isinstance(value, Exception):
            raise value
        if etag and etag == "etag-" + name and value == "same":
            return {"not_modified": True, "size": 0, "etag": etag}
        Path(destination).write_bytes(value)
        return {"not_modified": False, "size": len(value), "etag": "etag-" + name}


class MitreFeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"
        self.payloads = {"enterprise-attack": attack_bundle(), "capec": capec_bundle()}

    def tearDown(self):
        self.temporary.cleanup()

    def sync(self, at=T0, specs=SPECS, **overrides):
        return mitre_feed.sync(self.root, "run-1", clock=lambda: at, specs=specs,
                               sources=tuple(specs), fetch_file=FakeDownloader({**self.payloads, **overrides}))

    def manifest(self, pointer):
        return json.loads((self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text())

    def test_pins_are_release_tags_and_default_is_enterprise_plus_capec(self):
        for name, spec in mitre_feed.SOURCES.items():
            self.assertNotIn("/master/", spec["url"], name)
            self.assertNotIn("latest", spec["url"], name)
            if spec["kind"] != "cwe":        # CWE is pinned by version; its byte pin is OPEN (brief O2, TODO)
                self.assertRegex(spec["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("/v19.2/enterprise-attack/enterprise-attack-19.2.json", mitre_feed.SOURCES["enterprise-attack"]["url"])
        self.assertIn("ATT%26CK-v19.2/capec/2.1/stix-capec.json", mitre_feed.SOURCES["capec"]["url"])
        self.assertEqual(mitre_feed.DEFAULT_SOURCES, ("enterprise-attack", "capec", "cwe"))
        with unittest.mock.patch.dict(os.environ, {"APPSEC_MITRE_SOURCES": "enterprise-attack,ics-attack"}):
            self.assertEqual(mitre_feed.configured_sources(), ("enterprise-attack", "ics-attack"))
        with unittest.mock.patch.dict(os.environ, {"APPSEC_MITRE_SOURCES": "enterprise-attack,latest"}):
            with self.assertRaises(ValueError):
                mitre_feed.configured_sources()

    def test_feed_root_default_and_override(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("APPSEC_MITRE_FEED_ROOT", None)
            self.assertEqual(mitre_feed.feed_root().parts[-3:], ("data", "feeds", "mitre"))
        with unittest.mock.patch.dict(os.environ, {"APPSEC_MITRE_FEED_ROOT": str(self.root)}):
            self.assertEqual(mitre_feed.feed_root(), self.root)

    def test_publish_layout_manifest_notice_reference_and_verify(self):
        pointer = self.sync()
        snap = self.root / "snapshots" / pointer["snapshot_id"]
        for name in SPECS:
            self.assertTrue((snap / "sources" / f"{name}.json").is_file())
        self.assertEqual((snap / "sources" / "capec.json").read_bytes(), self.payloads["capec"])
        notice = (snap / "NOTICE.txt").read_text()
        self.assertIn("The MITRE Corporation", notice)
        self.assertIn("royalty-free license", notice)
        manifest = self.manifest(pointer)
        entry = manifest["sources"]["enterprise-attack"]
        self.assertEqual((entry["upstream_version"], entry["record_count"], entry["status"]), ("19.2", 5, "OK"))
        self.assertEqual(entry["source_url"], SPECS["enterprise-attack"]["url"])
        self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(entry["fetched_at"], "2026-09-29T00:00:00Z")
        self.assertEqual(entry["licence"], "MITRE ATT&CK Terms of Use")
        self.assertEqual(manifest["reference"]["counts"], {"techniques": 5, "tactics": 2, "capec_patterns": 3})
        self.assertEqual(manifest["gaps"], [])
        self.assertIn("Copyright 2015-2026, The MITRE Corporation.", manifest["markings"])
        self.assertFalse((snap / "incoming").exists())
        self.assertEqual(mitre_feed.verify(self.root)["upstream_versions"], {"capec": "3.9", "enterprise-attack": "19.2"})

    def test_reference_is_deterministic(self):
        first = self.sync()
        data = (self.root / "snapshots" / first["snapshot_id"] / "reference.json").read_bytes()
        again = attack_reference.reference_bytes(attack_reference.derive(
            {"capec": ("capec", self.payloads["capec"]), "enterprise-attack": ("attack", self.payloads["enterprise-attack"])}))
        self.assertEqual(data, again)
        reference = json.loads(data)
        self.assertEqual([row["id"] for row in reference["attack"]["techniques"]],
                         ["T1059", "T1059.004", "T1066", "T1086", "T1190"])
        self.assertEqual(reference["capec"]["patterns"][2]["related_cwe"], ["CWE-89", "CWE-1286"])
        self.assertEqual(reference["capec"]["patterns"][1]["related_attack"], ["T1574.006"])

    def test_bad_source_is_a_recorded_gap_and_does_not_break_publication(self):
        for label, payload in (("notjson", b"{not json"), ("notbundle", b'{"type": "x"}'),
                               ("wrongversion", capec_bundle(version="3.8")), ("network", OSError("boom"))):
            with self.subTest(label=label):
                self.tearDown(); self.setUp()
                pointer = self.sync(capec=payload)
                self.assertEqual(pointer["gaps"], ["capec"])
                self.assertFalse((self.root / "snapshots" / pointer["snapshot_id"] / "sources" / "capec.json").exists())
                self.assertEqual(mitre_feed.verify(self.root)["gaps"], ["capec"])
                reference = json.loads((self.root / "snapshots" / pointer["snapshot_id"] / "reference.json").read_text())
                self.assertIsNone(reference["capec"])

    def test_pinned_sha_mismatch_is_rejected(self):
        specs = {**SPECS, "capec": {**SPECS["capec"], "sha256": "0" * 64}}
        pointer = self.sync(specs=specs)
        self.assertEqual(pointer["gaps"], ["capec"])
        self.assertIn("pinned sha256", self.manifest(pointer)["sources"]["capec"]["error"])

    def test_failed_source_keeps_last_good_bundle_with_original_age(self):
        first = self.sync()
        second = self.sync(T0 + timedelta(hours=2), capec=OSError("down"))
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        manifest = self.manifest(second)
        entry = manifest["sources"]["capec"]
        self.assertEqual(entry["status"], "CARRIED_FORWARD")
        self.assertEqual(entry["fetched_at"], "2026-09-29T00:00:00Z")
        self.assertIn("down", entry["carried_reason"])
        self.assertEqual(manifest["data_timestamp"], "2026-09-29T00:00:00Z")
        self.assertEqual(manifest["gaps"], [])
        self.assertEqual(manifest["sources"]["enterprise-attack"]["fetched_at"], "2026-09-29T02:00:00Z")
        self.assertEqual(manifest["reference"]["counts"]["capec_patterns"], 3)
        mitre_feed.verify(self.root)
        # the carried original fetched_at is what the ceiling measures
        with self.assertRaises(SnapshotStale):
            mitre_feed.resolve(self.root, now=T0 + timedelta(days=14, seconds=1))

    def test_pin_change_never_carries_the_old_release(self):
        self.sync()
        specs = {**SPECS, "capec": {**SPECS["capec"], "url": "https://example.test/v2/stix-capec.json"}}
        pointer = self.sync(T0 + timedelta(hours=1), specs=specs, capec=OSError("down"))
        self.assertEqual(pointer["gaps"], ["capec"])

    def test_total_failure_leaves_prior_pointer_untouched(self):
        self.sync()
        before = (self.root / "current.json").read_bytes()
        broken = {name: OSError("down") for name in SPECS}
        second = self.sync(T0 + timedelta(hours=2), **broken)       # every source carries forward
        self.assertEqual(second["gaps"], [])
        self.assertNotEqual(before, (self.root / "current.json").read_bytes())
        fresh = Path(self.temporary.name) / "fresh" / "feeds" / "mitre"
        with self.assertRaises(RuntimeError):
            mitre_feed.sync(fresh, "r", clock=lambda: T0, specs=SPECS, sources=tuple(SPECS),
                            fetch_file=FakeDownloader(broken))
        self.assertFalse((fresh / "current.json").exists())
        self.assertEqual(list((fresh / "staging").iterdir()), [])

    def test_reference_derivation_failure_leaves_pointer(self):
        self.sync()
        before = (self.root / "current.json").read_bytes()
        with unittest.mock.patch.object(attack_reference, "derive", side_effect=ValueError("boom")):
            with self.assertRaises(ValueError):
                self.sync(T0 + timedelta(hours=1))
        self.assertEqual(before, (self.root / "current.json").read_bytes())

    def test_not_modified_reuses_prior_bytes_and_refreshes_age(self):
        self.sync()
        downloader = FakeDownloader({name: "same" for name in SPECS})
        pointer = mitre_feed.sync(self.root, "r", clock=lambda: T0 + timedelta(hours=2), specs=SPECS,
                                  sources=tuple(SPECS), fetch_file=downloader)
        self.assertTrue(all(etag == "etag-" + name for name, etag in downloader.calls))
        manifest = self.manifest(pointer)
        self.assertEqual(manifest["data_timestamp"], "2026-09-29T02:00:00Z")
        self.assertEqual(manifest["sources"]["capec"]["status"], "OK")
        mitre_feed.verify(self.root)

    def test_prune_keeps_configured_number_and_current(self):
        for hours in range(5):
            mitre_feed.sync(self.root, "r", clock=lambda h=hours: T0 + timedelta(hours=h), specs=SPECS,
                            sources=tuple(SPECS), fetch_file=FakeDownloader(self.payloads), keep=2)
        self.assertEqual(len(list((self.root / "snapshots").iterdir())), 2)
        mitre_feed.verify(self.root)

    def test_requires_coordinator_and_safe_root(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DAGSTER_RUN_ID", None)
            with self.assertRaises(Exception):
                mitre_feed.sync(self.root, None, specs=SPECS, sources=tuple(SPECS), fetch_file=FakeDownloader(self.payloads))
        with self.assertRaises(ValueError):
            mitre_feed.sync("/", "r", specs=SPECS, sources=tuple(SPECS), fetch_file=FakeDownloader(self.payloads))

    def test_verify_and_resolve_detect_tamper(self):
        pointer = self.sync()
        for target in ("sources/enterprise-attack.json", "reference.json"):
            with self.subTest(target=target):
                self.tearDown(); self.setUp()
                pointer = self.sync()
                path = self.root / "snapshots" / pointer["snapshot_id"] / target
                os.unlink(path)          # break any hardlink sharing before altering bytes
                path.write_bytes(b"tampered")
                with self.assertRaises(SnapshotInvalid):
                    mitre_feed.verify(self.root)
                with self.assertRaises(SnapshotInvalid):
                    mitre_feed.resolve(self.root, now=T0)


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self, **overrides):
        payloads = {"enterprise-attack": attack_bundle(), "capec": capec_bundle(), **overrides}
        return mitre_feed.sync(self.root, "r", clock=lambda: T0, specs=SPECS, sources=tuple(SPECS),
                               fetch_file=FakeDownloader(payloads))

    def test_one_tunable_ceiling_defaults_to_fourteen_days(self):
        self.assertEqual(tunables.shared("reference_snapshot_max_age_seconds"), 1209600)
        self.assertEqual(mitre_feed.default_max_age_seconds(), 1209600)
        import osv_snapshot
        self.assertEqual(osv_snapshot.DEFAULT_MAX_AGE, timedelta(seconds=1209600))

    def test_within_limit_exact_limit_and_over_limit(self):
        self.publish()
        identity = mitre_feed.resolve(self.root, now=T0 + timedelta(days=13))
        self.assertEqual((identity["max_age_seconds"], identity["age_seconds"]), (1209600, 13 * 86400))
        self.assertTrue(Path(identity["reference_path"]).is_file())
        mitre_feed.resolve(self.root, now=T0 + timedelta(days=14))
        with self.assertRaises(SnapshotStale):
            mitre_feed.resolve(self.root, now=T0 + timedelta(days=14, seconds=1))
        with self.assertRaises(SnapshotInvalid):
            mitre_feed.resolve(self.root, now=T0 - timedelta(seconds=1))
        with self.assertRaises(ValueError):
            mitre_feed.resolve(self.root, now=datetime(2026, 1, 1))

    def test_missing_root_and_pointer_are_blocked(self):
        with self.assertRaises(SnapshotBlocked):
            mitre_feed.resolve(self.root, now=T0)
        self.root.mkdir(parents=True)
        with self.assertRaises(SnapshotBlocked):
            mitre_feed.resolve(self.root, now=T0)

    def test_cli_resolve_reports_the_gap_code(self):
        self.publish()
        with unittest.mock.patch("builtins.print") as printed:
            code = mitre_feed.main(["resolve", "--root", str(self.root), "--now", "2026-10-29T00:00:00Z"])
        self.assertEqual(code, 3)
        self.assertIn("MITRE_REFERENCE_STALE", printed.call_args[0][0])


class ValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference = attack_reference.derive({"enterprise-attack": ("attack", attack_bundle()),
                                             "capec": ("capec", capec_bundle())})
        cls.ref = attack_reference.Reference(reference, {"reference_sha256": "0" * 64})

    def test_validate_technique(self):
        ref = self.ref
        self.assertEqual(ref.validate_technique("T1190"), attack_reference.OK)
        self.assertEqual(ref.validate_technique(" t1059.004 "), attack_reference.OK)
        self.assertEqual(ref.validate_technique("T9999"), attack_reference.UNKNOWN_ID)
        self.assertEqual(ref.validate_technique("T1190; rm -rf /"), attack_reference.UNKNOWN_ID)
        self.assertEqual(ref.validate_technique(None), attack_reference.UNKNOWN_ID)
        self.assertEqual(ref.validate_technique("T1066"), attack_reference.DEPRECATED)      # revoked
        self.assertEqual(ref.validate_technique("T1086"), attack_reference.DEPRECATED)      # deprecated
        for tactic in ("execution", "TA0002", "Execution"):
            self.assertEqual(ref.validate_technique("T1059.004", tactic), attack_reference.OK, tactic)
        self.assertEqual(ref.validate_technique("T1059.004", "initial-access"), attack_reference.TACTIC_MISMATCH)
        self.assertEqual(ref.validate_technique("T1059.004", "TA9999"), attack_reference.TACTIC_MISMATCH)

    def test_validate_capec(self):
        self.assertEqual(self.ref.validate_capec("CAPEC-66"), attack_reference.OK)
        self.assertEqual(self.ref.validate_capec("66"), attack_reference.OK)
        self.assertEqual(self.ref.validate_capec("CAPEC-7"), attack_reference.DEPRECATED)
        self.assertEqual(self.ref.validate_capec("CAPEC-99999"), attack_reference.UNKNOWN_ID)
        self.assertEqual(self.ref.validate_capec("T1190"), attack_reference.UNKNOWN_ID)

    def test_screen_keeps_only_ok_ids_and_records_every_drop(self):
        result = attack_reference.screen(["T1190", "t1190", "T9999", "T1066", "<script>"], ["66", "CAPEC-7"],
                                         reference=self.ref)
        self.assertEqual(result["attack_refs"], ["T1190"])
        self.assertEqual(result["capec_refs"], ["CAPEC-66"])
        self.assertEqual(result["reference"]["reference_sha256"], "0" * 64)
        codes = [(gap["code"], gap["ref"]) for gap in result["gaps"]]
        self.assertIn(("MITRE_REF_UNKNOWN_ID", "T9999"), codes)
        self.assertIn(("MITRE_REF_DEPRECATED", "T1066"), codes)
        self.assertIn(("MITRE_REF_DEPRECATED", "CAPEC-7"), codes)
        self.assertNotIn("<script>", json.dumps(result))       # a malformed tag is described, never echoed

    def test_screen_with_no_tags_is_empty_and_does_not_load(self):
        with unittest.mock.patch.object(attack_reference, "load", side_effect=AssertionError("loaded")):
            self.assertEqual(attack_reference.screen([], None),
                             {"attack_refs": [], "capec_refs": [], "reference": None, "gaps": []})

    def test_screen_bounds_the_number_of_refs(self):
        result = attack_reference.screen(["T1190"] * (attack_reference.REFS_MAX + 2), [], reference=self.ref)
        self.assertEqual(result["attack_refs"], ["T1190"])
        self.assertEqual(sum(gap["code"] == "MITRE_REF_OVER_LIMIT" for gap in result["gaps"]), 2)


class StalenessGateTests(unittest.TestCase):
    """A stale or missing snapshot withholds every tag as a recorded gap; nothing unvalidated passes."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"
        attack_reference._LOADED.clear()

    def tearDown(self):
        self.temporary.cleanup()

    def test_missing_snapshot_withholds(self):
        result = attack_reference.screen(["T1190"], ["CAPEC-66"], root=self.root, now=T0)
        self.assertEqual((result["attack_refs"], result["capec_refs"], result["reference"]), ([], [], None))
        self.assertEqual(result["gaps"][0]["code"], "MITRE_REFERENCE_MISSING")
        self.assertEqual(result["gaps"][0]["withheld"], ["CAPEC-66", "T1190"])

    def test_stale_snapshot_withholds_and_fresh_accepts(self):
        mitre_feed.sync(self.root, "r", clock=lambda: T0, specs=SPECS, sources=tuple(SPECS),
                        fetch_file=FakeDownloader({"enterprise-attack": attack_bundle(), "capec": capec_bundle()}))
        fresh = attack_reference.screen(["T1190"], [], root=self.root, now=T0 + timedelta(days=1))
        self.assertEqual(fresh["attack_refs"], ["T1190"])
        stale = attack_reference.screen(["T1190"], [], root=self.root, now=T0 + timedelta(days=15))
        self.assertEqual(stale["attack_refs"], [])
        self.assertEqual(stale["gaps"][0]["code"], "MITRE_REFERENCE_STALE")

    def test_invalid_snapshot_withholds(self):
        pointer = mitre_feed.sync(self.root, "r", clock=lambda: T0, specs=SPECS, sources=tuple(SPECS),
                                  fetch_file=FakeDownloader({"enterprise-attack": attack_bundle(), "capec": capec_bundle()}))
        (self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").write_text("{}")
        result = attack_reference.screen(["T1190"], [], root=self.root, now=T0)
        self.assertEqual((result["attack_refs"], result["gaps"][0]["code"]), ([], "MITRE_REFERENCE_INVALID"))

    def test_source_gap_withholds_that_kind_only(self):
        mitre_feed.sync(self.root, "r", clock=lambda: T0, specs=SPECS, sources=tuple(SPECS),
                        fetch_file=FakeDownloader({"enterprise-attack": attack_bundle(), "capec": OSError("x")}))
        result = attack_reference.screen(["T1190"], ["CAPEC-66"], root=self.root, now=T0)
        self.assertEqual((result["attack_refs"], result["capec_refs"]), (["T1190"], []))
        self.assertEqual(result["gaps"][0]["code"], "MITRE_REFERENCE_MISSING")



class MitreDagsterTests(unittest.TestCase):
    """The third independent op of nvd_reference_sync (a failure in one op never stops the others)."""

    def setUp(self):
        try:
            import dagster  # noqa: F401
        except ImportError:
            self.skipTest("dagster is not installed")
        sys.path.insert(0, os.environ.get("APPSEC_DEFINITIONS_DIR",
                                          str(Path(__file__).resolve().parents[2] / "orchestrator" / "dagster")))
        import definitions
        self.definitions = definitions
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"

    def tearDown(self):
        self.temporary.cleanup()

    def test_job_has_three_independent_ops_and_the_op_publishes(self):
        import dagster
        job = self.definitions.nvd_reference_sync
        self.assertEqual({n.name for n in job.nodes}, {"nvd_sync_work", "osv_sync_work", "mitre_sync_work", "cve_bin_tool_db_work"})
        self.assertEqual(job.tags["mitre_feed_id"], "mitre")
        self.assertEqual(sum(1 for _ in job.graph.dependency_structure.input_to_upstream_outputs_for_node("mitre_sync_work")), 0)
        payloads = {"enterprise-attack": attack_bundle(), "capec": OSError("down")}
        fake = lambda coordinator_id: mitre_feed.sync(self.root, coordinator_id, specs=SPECS, sources=tuple(SPECS),
                                                      fetch_file=FakeDownloader(payloads))
        with unittest.mock.patch.object(self.definitions, "sync_mitre", fake):
            snapshot_id = self.definitions.mitre_sync_work(dagster.build_op_context())
        self.assertTrue(snapshot_id.startswith("sha256-"))
        self.assertEqual(mitre_feed.verify(self.root)["gaps"], ["capec"])


if __name__ == "__main__":
    unittest.main()
