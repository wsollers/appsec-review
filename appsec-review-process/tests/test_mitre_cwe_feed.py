"""Brief O1b: the full MITRE CWE catalog through the MITRE feed, curated fallback with a recorded gap."""
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import attack_reference
import claim_lifecycle_core
import finding_enrichment
import cwe_catalog
import mitre_feed
from test_mitre_feed import SPECS as ATTACK_SPECS, attack_bundle, capec_bundle

T0 = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)
CEILING = 1209600
OUTSIDE = "CWE-1004"          # a real CWE id that is not in the committed curated subset
RETIRED = "CWE-71"            # deprecated upstream: flagged in the table, never accepted
CWE_SPEC = {"kind": "cwe", "url": "https://example.test/cwec_v4.19.xml.zip", "upstream_version": "4.19",
            "licence": "MITRE CWE Terms of Use", "sha256": None}
SPECS = {**ATTACK_SPECS, "cwe": CWE_SPEC}


def cwe_zip(version="4.19", drop=(), deprecate=()):
    committed = json.loads((cwe_catalog.CWE_DIR / cwe_catalog.CATALOG).read_text())["entries"]
    rows = [(row["cwe_id"][4:], row["name"]) for row in committed if row["cwe_id"] not in drop]
    rows += [("1004", "Sensitive Cookie Without 'HttpOnly' Flag"), ("71", "DEPRECATED: Apple '.DS_Store'")]
    rows += [(str(5000 + n), f"Synthetic weakness {n}") for n in range(20)]
    weaknesses = "".join(
        f'<Weakness ID="{number}" Name="{name.replace(chr(39), "&apos;")}" Abstraction="Base" '
        f'Status="{"Deprecated" if number == "71" or "CWE-" + number in deprecate else "Stable"}"/>'
        for number, name in rows)
    xml = (f'<?xml version="1.0" encoding="UTF-8"?><Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" '
           f'Name="CWE" Version="{version}" Date="2026-01-21"><Weaknesses>{weaknesses}</Weaknesses>'
           f'</Weakness_Catalog>').encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"cwec_v{version}.xml", xml)
    return buffer.getvalue()


class Downloader:
    def __init__(self, payloads):
        self.payloads = payloads

    def __call__(self, url, destination, etag=None, **_):
        name = "cwe" if "cwec" in url else "capec" if "capec" in url else "enterprise-attack"
        value = self.payloads[name]
        if isinstance(value, Exception):
            raise value
        Path(destination).write_bytes(value)
        return {"not_modified": False, "size": len(value), "etag": None}


class CweFeedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"
        self.payloads = {"enterprise-attack": attack_bundle(), "capec": capec_bundle(), "cwe": cwe_zip()}

    def tearDown(self):
        self.temporary.cleanup()

    def sync(self, at=T0, **overrides):
        return mitre_feed.sync(self.root, "run-1", clock=lambda: at, specs=SPECS, sources=tuple(SPECS),
                               fetch_file=Downloader({**self.payloads, **overrides}))

    def catalog(self, at=T0 + timedelta(hours=1)):
        with unittest.mock.patch.object(mitre_feed, "default_max_age_seconds", return_value=CEILING):
            return cwe_catalog.Catalog(feed_root=self.root, now=at)

    def manifest(self, pointer):
        return json.loads((self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text())

    def test_sync_publishes_cwe_source_and_derived_table(self):
        pointer = self.sync()
        self.assertEqual(pointer["gaps"], [])
        manifest = self.manifest(pointer)
        entry = manifest["sources"]["cwe"]
        self.assertEqual((entry["status"], entry["upstream_version"], entry["licence"]),
                         ("OK", "4.19", "MITRE CWE Terms of Use"))
        self.assertEqual(entry["fetched_at"], "2026-09-29T00:00:00Z")
        directory = self.root / "snapshots" / pointer["snapshot_id"]
        self.assertTrue((directory / "sources" / "cwe.xml.zip").is_file())
        table = json.loads((directory / "cwe-catalog.json").read_text())
        self.assertEqual((table["schema"], table["version"], table["as_of"]),
                         ("appsec-review/cwe-catalog/1.0", "CWE List 4.19", "2026-01-21"))
        rows = {row["cwe_id"]: row for row in table["entries"]}
        self.assertTrue(rows[RETIRED]["deprecated"])                 # flagged, not dropped
        self.assertEqual(rows[OUTSIDE]["abstraction"], "Base")
        self.assertEqual(manifest["cwe_catalog"]["counts"], {"weaknesses": len(rows) - 1, "deprecated": 1})
        self.assertIn("CWE Terms of Use", (directory / "NOTICE.txt").read_text())
        self.assertEqual(mitre_feed.verify(self.root)["cwe_catalog"]["deprecated"], 1)
        # The ATT&CK/CAPEC reference is unaffected by the third source.
        self.assertEqual(manifest["reference"]["counts"]["capec_patterns"], 3)

    def test_full_catalog_accepts_an_id_outside_the_curated_subset(self):
        pointer = self.sync()
        catalog = self.catalog()
        self.assertIsNone(catalog.gap)
        self.assertEqual(catalog.source, pointer["snapshot_id"])
        self.assertEqual(catalog.validate("1004"), OUTSIDE)
        self.assertEqual(catalog.identity["catalog_source"], "mitre-feed")
        self.assertEqual(catalog.provenance()["catalog"], pointer["snapshot_id"])
        with self.assertRaisesRegex(cwe_catalog.CWEError, "deprecated"):
            catalog.validate(RETIRED)
        with self.assertRaisesRegex(cwe_catalog.CWEError, "not in the pinned CWE catalog"):
            catalog.validate("CWE-99999")
        # The committed rule map still resolves against the full catalog.
        self.assertEqual(catalog.rules, cwe_catalog.Catalog(cwe_catalog.CWE_DIR).rules)

    def test_stale_snapshot_falls_back_to_curated_with_gap(self):
        self.sync()
        catalog = self.catalog(T0 + timedelta(seconds=CEILING + 1))
        self.assertEqual(catalog.gap["code"], "CWE_REFERENCE_STALE")
        self.assertEqual(catalog.source, "committed-curated")
        self.assertEqual(catalog.provenance()["gap"]["used"], "committed-curated")
        self.assertIn("CWE_REFERENCE_STALE", catalog.gap_line())
        self.assertEqual(catalog.validate("CWE-89"), "CWE-89")
        with self.assertRaises(cwe_catalog.CWEError):
            catalog.validate(OUTSIDE)
        with self.assertRaises(cwe_catalog.CWEError):
            catalog.validate("CWE-99999")
        committed = cwe_catalog.Catalog(cwe_catalog.CWE_DIR).identity
        self.assertEqual(catalog.identity["catalog_sha256"], committed["catalog_sha256"])

    def test_bad_zip_falls_back_and_keeps_attack(self):
        pointer = self.sync(cwe=b"this is not a zip")
        self.assertEqual(pointer["gaps"], ["cwe"])
        self.assertIsNone(self.manifest(pointer)["cwe_catalog"])
        catalog = self.catalog()
        self.assertEqual((catalog.gap["code"], catalog.source), ("CWE_REFERENCE_MISSING", "committed-curated"))
        with self.assertRaises(cwe_catalog.CWEError):
            catalog.validate(OUTSIDE)
        reference, gap = attack_reference.load(self.root, now=T0 + timedelta(hours=1), max_age_seconds=CEILING)
        self.assertIsNone(gap)
        self.assertEqual(reference.validate_technique("T1190"), attack_reference.OK)

    def test_catalog_without_enough_weaknesses_is_rejected(self):
        tiny = io.BytesIO()
        with zipfile.ZipFile(tiny, "w") as archive:
            archive.writestr("cwec_v4.19.xml", b'<Weakness_Catalog Version="4.19"><Weakness ID="79" Name="XSS"/>'
                                               b'</Weakness_Catalog>')
        self.assertEqual(self.sync(cwe=tiny.getvalue())["gaps"], ["cwe"])
        self.assertEqual(self.sync(T0 + timedelta(hours=1), cwe=cwe_zip(version="4.18"))["gaps"], ["cwe"])

    def test_carry_forward_keeps_original_fetched_at_and_ages_per_kind(self):
        self.sync()
        later = T0 + timedelta(days=10)
        pointer = self.sync(later, cwe=OSError("cwe.mitre.org down"))
        entry = self.manifest(pointer)["sources"]["cwe"]
        self.assertEqual((entry["status"], entry["fetched_at"]), ("CARRIED_FORWARD", "2026-09-29T00:00:00Z"))
        at = T0 + timedelta(days=15)                  # CWE is past the ceiling; ATT&CK/CAPEC are 5 days old
        self.assertEqual(self.catalog(at).gap["code"], "CWE_REFERENCE_STALE")
        reference, gap = attack_reference.load(self.root, now=at, max_age_seconds=CEILING)
        self.assertIsNone(gap)
        self.assertEqual(reference.validate_capec("CAPEC-66"), attack_reference.OK)

    def test_missing_feed_and_explicit_directory(self):
        catalog = self.catalog()
        self.assertEqual((catalog.gap["code"], catalog.source), ("CWE_REFERENCE_MISSING", "committed-curated"))
        self.sync()
        explicit = cwe_catalog.Catalog(cwe_catalog.CWE_DIR)          # committed files only, no feed, no gap
        self.assertIsNone(explicit.gap)
        self.assertNotIn("catalog_source", explicit.identity)
        with self.assertRaises(cwe_catalog.CWEError):
            explicit.validate(OUTSIDE)

    def test_tampered_table_and_rule_map_mismatch_fall_back_invalid(self):
        pointer = self.sync()
        table = self.root / "snapshots" / pointer["snapshot_id"] / "cwe-catalog.json"
        table.write_text(table.read_text().replace("Synthetic weakness 1", "Tampered"))
        self.assertEqual(self.catalog().gap["code"], "CWE_REFERENCE_INVALID")
        rule_ids = {value for row in json.loads((cwe_catalog.CWE_DIR / cwe_catalog.RULE_MAP).read_text())["rules"]
                    for value in row["cwe_ids"]}
        self.sync(T0 + timedelta(hours=1), cwe=cwe_zip(deprecate={sorted(rule_ids)[0]}))
        catalog = self.catalog(T0 + timedelta(hours=2))
        self.assertEqual((catalog.gap["code"], catalog.source), ("CWE_REFERENCE_INVALID", "committed-curated"))
        self.assertIn("rule map", catalog.gap["detail"])

    def test_resolve_kinds_blocks_when_kind_absent(self):
        self.sync(cwe=b"bad")
        with self.assertRaises(mitre_feed.SnapshotBlocked):
            mitre_feed.resolve(self.root, now=T0, max_age_seconds=CEILING, kinds=("cwe",))
        self.assertIsNone(mitre_feed.resolve(self.root, now=T0, max_age_seconds=CEILING)["cwe_catalog_path"])

    def test_claim_path_records_catalog_used(self):
        self.sync()
        catalog = self.catalog()
        with unittest.mock.patch.object(claim_lifecycle_core, "_CATALOG", [catalog]):
            judged = claim_lifecycle_core._cwe_judgment(
                "07-red-team-adversarial", {"cwe": {"cwe_id": "1004", "rationale": "cookie lacks HttpOnly"}})
        self.assertEqual((judged["cwe_id"], judged["catalog"]), (OUTSIDE, catalog.source))

    def test_report_drops_judgment_the_fallback_catalog_does_not_know(self):
        stale = self.catalog()                            # no feed: committed curated catalog in force
        ctx = type("Ctx", (), {"catalog": stale})()
        finding = {"cwe_judgments": [
            {"stage": "07-red-team-adversarial", "cwe_id": OUTSIDE, "cwe_name": "x", "rationale": "r", "catalog": "s"},
            {"stage": "09-independent-verification", "cwe_id": "CWE-89", "cwe_name": "x", "rationale": "r"}]}
        result = finding_enrichment._cwe(ctx, finding, [])
        self.assertEqual(result["primary"], "CWE-89")
        self.assertTrue(any(OUTSIDE in gap and "dropped" in gap for gap in result["gaps"]))

    def test_intake_parser_unchanged(self):
        xml = cwe_catalog.xml_from_zip(cwe_zip())
        rows = cwe_catalog._parse_xml(xml)
        self.assertNotIn(RETIRED, {row["cwe_id"] for row in rows})
        self.assertEqual(set(rows[0]), {"cwe_id", "name"})


if __name__ == "__main__":
    unittest.main()
