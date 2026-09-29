"""CWE through the MITRE feed (brief O2, ADR-0026 addendum): publish, resolve, fall back, validate."""
from __future__ import annotations

import io
import json
import os
from datetime import timedelta
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cwe_catalog
import mitre_feed
from dependency_snapshot_registry import SnapshotBlocked, SnapshotInvalid, SnapshotStale
from test_mitre_feed import SPECS as ATTACK_SPECS, T0, attack_bundle, capec_bundle

CURATED = json.loads((cwe_catalog.CWE_DIR / cwe_catalog.CATALOG).read_text())["entries"]
CWE_SPEC = {"kind": "cwe", "url": "https://example.test/cwec_v4.20.xml.zip", "upstream_version": "4.20",
            "licence": "MITRE CWE Terms of Use", "sha256": None}
SPECS = {**ATTACK_SPECS, "cwe": CWE_SPEC}
OUTSIDE = "CWE-1321"          # real MITRE weakness, not in the curated 96-entry subset
DEPRECATED = "CWE-71"


def cwe_xml(version="4.20", extra="", doctype=""):
    rows = [(row["cwe_id"][4:], row["name"], "Base", "Stable") for row in CURATED]
    rows += [(str(9000 + n), f"Synthetic weakness {n}", "Variant", "Draft") for n in range(20)]
    rows += [("1321", "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
              "Variant", "Incomplete")]
    weaknesses = "".join(f'<Weakness ID="{i}" Name="{n.replace(chr(39), "&apos;")}" Abstraction="{a}" '
                         f'Structure="Simple" Status="{s}"><Description>d</Description></Weakness>'
                         for i, n, a, s in rows)
    weaknesses += ('<Weakness ID="71" Name="DEPRECATED: Apple .DS_Store" Abstraction="Variant" Structure="Simple" '
                   'Status="Deprecated"><Description>d</Description></Weakness>')
    return (f'<?xml version="1.0" encoding="UTF-8"?>{doctype}<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" '
            f'Name="CWE" Version="{version}" Date="2026-06-30"><Weaknesses>{weaknesses}{extra}</Weaknesses>'
            f'<Categories><Category ID="19" Name="Data Processing Errors" Status="Obsolete"/></Categories>'
            f'</Weakness_Catalog>').encode()


def cwe_zip(xml=None, member="cwec_v4.20.xml"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, xml if xml is not None else cwe_xml())
    return buffer.getvalue()


class Fake:
    def __init__(self, payloads):
        self.payloads = payloads

    def __call__(self, url, destination, etag=None, **_):
        name = "cwe" if "cwec" in url else "capec" if "capec" in url else "enterprise-attack"
        value = self.payloads[name]
        if isinstance(value, Exception):
            raise value
        Path(destination).write_bytes(value)
        return {"not_modified": False, "size": len(value), "etag": None}


class Base(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "data" / "feeds" / "mitre"
        self.payloads = {"enterprise-attack": attack_bundle(), "capec": capec_bundle(), "cwe": cwe_zip()}

    def tearDown(self):
        self.temporary.cleanup()

    def sync(self, at=T0, specs=SPECS, **overrides):
        return mitre_feed.sync(self.root, "run-1", clock=lambda: at, specs=specs, sources=tuple(specs),
                               fetch_file=Fake({**self.payloads, **overrides}))

    def manifest(self, pointer):
        return json.loads((self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").read_text())


class ParseTests(unittest.TestCase):
    def test_snapshot_table_has_the_curated_shape_and_flags_deprecated(self):
        table = cwe_catalog.derive_snapshot_catalog(cwe_zip(), "4.20")
        self.assertEqual((table["schema"], table["version"], table["as_of"]),
                         ("appsec-review/cwe-catalog/1.0", "CWE List 4.20", "2026-06-30"))
        rows = {row["cwe_id"]: row for row in table["entries"]}
        self.assertEqual(rows[OUTSIDE]["status"], "Incomplete")
        self.assertEqual(rows[OUTSIDE]["abstraction"], "Variant")
        self.assertTrue(rows[DEPRECATED]["deprecated"])            # flagged, not dropped
        self.assertFalse(rows["CWE-120"]["deprecated"])
        self.assertNotIn("CWE-19", rows)                          # categories are not weaknesses
        self.assertEqual([row["cwe_id"] for row in table["entries"]],
                         sorted(rows, key=lambda value: int(value[4:])))
        self.assertEqual(cwe_catalog.table_bytes(table),
                         cwe_catalog.table_bytes(cwe_catalog.derive_snapshot_catalog(cwe_zip(), "4.20")))

    def test_intake_parser_default_is_unchanged(self):
        rows = cwe_catalog._parse_xml(cwe_xml())
        self.assertNotIn(DEPRECATED, {row["cwe_id"] for row in rows})
        self.assertEqual(set(rows[0]), {"cwe_id", "name"})

    def test_bad_archives_are_refused(self):
        for label, data, version in (("not-a-zip", b"PK nope", "4.20"),
                                     ("wrong-version", cwe_zip(cwe_xml(version="4.19")), "4.20"),
                                     ("two-members", None, "4.20"),
                                     ("dtd", cwe_zip(cwe_xml(doctype='<!DOCTYPE x [<!ENTITY a "b">]>')), "4.20"),
                                     ("bad-xml", cwe_zip(b"<Weakness_Catalog"), "4.20"),
                                     ("too-small", cwe_zip(cwe_xml().replace(b"<Weakness ", b"<Other ")), "4.20")):
            if data is None:
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    archive.writestr("cwec_v4.20.xml", cwe_xml()); archive.writestr("extra.xml", b"<x/>")
                data = buffer.getvalue()
            with self.subTest(label=label), self.assertRaises(cwe_catalog.CWEError):
                cwe_catalog.derive_snapshot_catalog(data, version)


class PublishTests(Base):
    def test_cwe_is_a_third_source_in_the_same_snapshot(self):
        pointer = self.sync()
        snap = self.root / "snapshots" / pointer["snapshot_id"]
        self.assertEqual((snap / "sources" / "cwe.xml.zip").read_bytes(), self.payloads["cwe"])
        manifest = self.manifest(pointer)
        entry = manifest["sources"]["cwe"]
        self.assertEqual((entry["status"], entry["upstream_version"], entry["licence"], entry["fetched_at"]),
                         ("OK", "4.20", "MITRE CWE Terms of Use", "2026-09-29T00:00:00Z"))
        self.assertEqual(entry["source_url"], CWE_SPEC["url"])
        self.assertEqual(entry["record_count"], len(CURATED) + 22)
        self.assertEqual(manifest["cwe_catalog"]["counts"], {"weaknesses": len(CURATED) + 22, "deprecated": 1})
        self.assertIn("CWE Terms of Use", (snap / "NOTICE.txt").read_text())
        self.assertIn("royalty-free license to use CWE", (snap / "NOTICE.txt").read_text())
        self.assertEqual(mitre_feed.verify(self.root)["cwe_catalog"]["weaknesses"], len(CURATED) + 22)
        identity = mitre_feed.resolve_cwe(self.root, now=T0 + timedelta(days=1))
        self.assertEqual((identity["snapshot_id"], identity["upstream_version"]), (pointer["snapshot_id"], "4.20"))
        # ATT&CK/CAPEC read side is unchanged by the third source
        mitre = mitre_feed.resolve(self.root, now=T0)
        self.assertEqual(mitre["upstream_versions"], {"capec": "3.9", "enterprise-attack": "19.2"})
        self.assertEqual(mitre["gaps"], [])

    def test_table_is_stable_across_resyncs_of_the_same_pin(self):
        one = self.manifest(self.sync())["cwe_catalog"]["sha256"]
        two = self.manifest(self.sync(T0 + timedelta(hours=2)))["cwe_catalog"]["sha256"]
        self.assertEqual(one, two)

    def test_attack_capec_only_manifest_has_no_cwe_key(self):
        pointer = self.sync(specs=ATTACK_SPECS)
        self.assertNotIn("cwe_catalog", self.manifest(pointer))
        with self.assertRaises(SnapshotBlocked):
            mitre_feed.resolve_cwe(self.root, now=T0)

    def test_default_sources_include_cwe_pinned_by_version(self):
        spec = mitre_feed.SOURCES["cwe"]
        self.assertIn("cwe", mitre_feed.DEFAULT_SOURCES)
        self.assertRegex(spec["url"], r"^https://cwe\.mitre\.org/data/xml/cwec_v\d+\.\d+\.xml\.zip$")
        self.assertNotIn("latest", spec["url"])
        self.assertIn("cwec_v" + spec["upstream_version"] + ".xml.zip", spec["url"])

    def test_carry_forward_keeps_the_original_fetched_at(self):
        self.sync()
        second = self.sync(T0 + timedelta(days=10), cwe=OSError("cwe.mitre.org down"))
        entry = self.manifest(second)["sources"]["cwe"]
        self.assertEqual((entry["status"], entry["fetched_at"]), ("CARRIED_FORWARD", "2026-09-29T00:00:00Z"))
        mitre_feed.verify(self.root)
        mitre_feed.resolve_cwe(self.root, now=T0 + timedelta(days=14))
        with self.assertRaises(SnapshotStale):
            mitre_feed.resolve_cwe(self.root, now=T0 + timedelta(days=14, seconds=1))
        # the stale CWE source does not age ATT&CK/CAPEC, which were refreshed on day 10
        mitre_feed.resolve(self.root, now=T0 + timedelta(days=15))

    def test_bad_zip_is_a_source_gap_and_attack_still_publishes(self):
        pointer = self.sync(cwe=b"not a zip")
        manifest = self.manifest(pointer)
        self.assertEqual((pointer["gaps"], manifest["cwe_catalog"]), (["cwe"], None))
        self.assertIn("not a zip", manifest["sources"]["cwe"]["error"])
        mitre_feed.resolve(self.root, now=T0)
        with self.assertRaises(SnapshotBlocked):
            mitre_feed.resolve_cwe(self.root, now=T0)

    def test_pin_change_never_carries_the_old_release(self):
        self.sync()
        specs = {**SPECS, "cwe": {**CWE_SPEC, "url": "https://example.test/cwec_v4.21.xml.zip", "upstream_version": "4.21"}}
        pointer = self.sync(T0 + timedelta(hours=1), specs=specs, cwe=OSError("down"))
        self.assertEqual(pointer["gaps"], ["cwe"])

    def test_tampered_table_is_invalid(self):
        pointer = self.sync()
        path = self.root / "snapshots" / pointer["snapshot_id"] / "cwe-catalog.json"
        os.unlink(path); path.write_text("{}")
        with self.assertRaises(SnapshotInvalid):
            mitre_feed.resolve_cwe(self.root, now=T0)

    def test_cli_resolve_cwe_reports_the_cwe_gap_code(self):
        self.sync()
        with unittest.mock.patch("builtins.print") as printed:
            code = mitre_feed.main(["resolve", "--cwe", "--root", str(self.root), "--now", "2026-10-29T00:00:00Z"])
        self.assertEqual(code, 3)
        self.assertIn("CWE_REFERENCE_STALE", printed.call_args[0][0])


class CatalogTests(Base):
    def test_feed_catalog_accepts_an_id_outside_the_curated_subset(self):
        pointer = self.sync()
        self.assertNotIn(OUTSIDE, {row["cwe_id"] for row in CURATED})
        catalog = cwe_catalog.current(self.root, now=T0 + timedelta(days=1))
        self.assertIsNone(catalog.gap)
        self.assertEqual((catalog.used, catalog.source), (pointer["snapshot_id"], "mitre-feed"))
        self.assertEqual(catalog.validate(OUTSIDE), OUTSIDE)
        self.assertEqual(catalog.validate("121"), "CWE-121")
        self.assertEqual(catalog.identity["catalog_source"], "mitre-feed")
        self.assertNotIn(pointer["snapshot_id"], json.dumps(catalog.identity))     # binding stable across re-syncs
        self.assertIsNone(catalog.limitation())
        self.assertEqual(catalog.for_lead("clang-static-analyzer", "security.insecureAPI.strcpy")[0],
                         cwe_catalog.Catalog().for_lead("clang-static-analyzer", "security.insecureAPI.strcpy")[0])

    def test_unknown_and_deprecated_ids_are_still_rejected(self):
        self.sync()
        catalog = cwe_catalog.current(self.root, now=T0)
        for bad in ("CWE-99999", DEPRECATED, "CWE-19", "prototype pollution"):
            with self.subTest(bad=bad), self.assertRaises(cwe_catalog.CWEError):
                catalog.validate(bad)
        ids, notes = catalog.for_lead("x", "y", ["CWE-99999", "CWE-71", "cwe-1321"])
        self.assertEqual(ids, [OUTSIDE])
        self.assertEqual(len(notes), 2)

    def test_stale_snapshot_falls_back_to_curated_with_the_gap(self):
        self.sync()
        catalog = cwe_catalog.current(self.root, now=T0 + timedelta(days=14, seconds=1))
        self.assertEqual((catalog.used, catalog.gap["code"]), ("committed-curated", "CWE_REFERENCE_STALE"))
        self.assertEqual(catalog.identity["reference_gap"], "CWE_REFERENCE_STALE")
        self.assertEqual(len(catalog.names), len(CURATED))
        self.assertIn("CWE_REFERENCE_STALE", catalog.limitation())
        self.assertIn("committed curated catalog", catalog.limitation())
        with self.assertRaises(cwe_catalog.CWEError):
            catalog.validate(OUTSIDE)
        self.assertEqual(catalog.validate("CWE-120"), "CWE-120")

    def test_missing_snapshot_falls_back(self):
        catalog = cwe_catalog.current(self.root, now=T0)
        self.assertEqual((catalog.used, catalog.gap["code"]), ("committed-curated", "CWE_REFERENCE_MISSING"))
        with self.assertRaises(cwe_catalog.CWEError):
            catalog.validate("CWE-99999")

    def test_bad_zip_falls_back(self):
        self.sync(cwe=b"not a zip")
        catalog = cwe_catalog.current(self.root, now=T0)
        self.assertEqual((catalog.used, catalog.gap["code"]), ("committed-curated", "CWE_REFERENCE_MISSING"))

    def test_invalid_snapshot_falls_back(self):
        pointer = self.sync()
        (self.root / "snapshots" / pointer["snapshot_id"] / "manifest.json").write_text("{}")
        catalog = cwe_catalog.current(self.root, now=T0)
        self.assertEqual((catalog.used, catalog.gap["code"]), ("committed-curated", "CWE_REFERENCE_INVALID"))

    def test_rule_map_outside_the_feed_catalog_falls_back(self):
        import re
        xml = re.sub(rb'(<Weakness ID="120" [^>]*Status=")Stable', rb"\1Deprecated", cwe_xml())
        self.assertIn(b"Deprecated", xml.split(b'ID="120"')[1][:300])
        self.sync(cwe=cwe_zip(xml))
        catalog = cwe_catalog.current(self.root, now=T0)
        self.assertEqual((catalog.used, catalog.gap["code"]), ("committed-curated", "CWE_REFERENCE_INVALID"))
        self.assertIn("rule map", catalog.gap["detail"])

    def test_bound_reproduces_and_falls_back_when_unpublished(self):
        self.sync()
        identity = cwe_catalog.current(self.root, now=T0).identity
        again = cwe_catalog.bound(identity, self.root)            # not re-aged: the ceiling applied at binding
        self.assertEqual(again.identity, identity)
        self.assertEqual(again.validate(OUTSIDE), OUTSIDE)
        moved = cwe_catalog.bound({**identity, "catalog_sha256": "sha256:" + "0" * 64}, self.root)
        self.assertEqual((moved.used, moved.gap["code"]), ("committed-curated", "CWE_REFERENCE_INVALID"))
        curated = cwe_catalog.bound({**cwe_catalog.Catalog().identity, "reference_gap": "CWE_REFERENCE_STALE"})
        self.assertEqual((curated.used, curated.gap["code"]), ("committed-curated", "CWE_REFERENCE_STALE"))

    def test_cli_current(self):
        self.sync()
        with unittest.mock.patch.object(mitre_feed, "utcnow", return_value=T0), \
                unittest.mock.patch("builtins.print") as printed:
            code = cwe_catalog.main(["current", "--root", str(self.root), "--validate", OUTSIDE])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(printed.call_args[0][0])["validated"], OUTSIDE)


class ClaimPathTests(Base):
    """The claim path validates against the bound catalog and records which one it used."""

    def setUp(self):
        super().setUp()
        import claim_lifecycle_core
        self.core = claim_lifecycle_core
        self.core._CATALOG.clear()
        self.addCleanup(self.core._CATALOG.clear)
        patcher = unittest.mock.patch.dict(os.environ, {"APPSEC_MITRE_FEED_ROOT": str(self.root)})
        patcher.start(); self.addCleanup(patcher.stop)

    def test_red_team_judgment_records_the_feed_snapshot(self):
        pointer = self.sync()
        identity = cwe_catalog.current(self.root, now=T0).identity
        judgment = self.core._cwe_judgment("07-red-team-adversarial",
                                           {"cwe": {"cwe_id": OUTSIDE, "rationale": "merge into __proto__"}}, identity)
        self.assertEqual((judgment["cwe_id"], judgment["cwe_catalog"]), (OUTSIDE, pointer["snapshot_id"]))
        self.assertTrue(judgment["cwe_name"].startswith("Improperly Controlled Modification"))
        from schema_validate import validate_document
        self.assertEqual(validate_document(judgment, "cwe-judgment.schema.json"), [])

    def test_curated_binding_rejects_an_id_outside_the_subset(self):
        from execution_state import Blocked
        identity = cwe_catalog.current(self.root, now=T0).identity            # no feed -> curated + gap
        self.assertEqual(identity["reference_gap"], "CWE_REFERENCE_MISSING")
        with self.assertRaisesRegex(Blocked, "not in the pinned CWE catalog"):
            self.core._cwe_judgment("09-independent-verification", {"cwe": {"cwe_id": OUTSIDE, "rationale": "x"}},
                                    identity)
        ok = self.core._cwe_judgment("12-scoring-prioritization", {"cwe": {"cwe_id": "CWE-120", "rationale": "x"}},
                                     identity)
        self.assertEqual(ok["cwe_catalog"], "committed-curated")


if __name__ == "__main__":
    unittest.main()
