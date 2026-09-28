"""Pinned CWE catalog / rule map, offline EPSS-KEV snapshot intake, verified snippets (ADR-0020)."""
from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import code_snippets
import cwe_catalog
import epss_kev_snapshot as snapshot


class CWECatalogTests(unittest.TestCase):
    def test_pinned_catalog_validates_and_maps_rules(self):
        catalog = cwe_catalog.Catalog()
        self.assertEqual(catalog.validate("121"), "CWE-121")
        self.assertEqual(catalog.name("CWE-120"), "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')")
        for bad in ("CWE-99999", "CWE-0", "buffer overflow", True):
            with self.assertRaises(cwe_catalog.CWEError):
                catalog.validate(bad)
        ids, notes = catalog.for_lead("clang-static-analyzer", "security.insecureAPI.strcpy",
                                      ["external/cwe/cwe-787", "CWE-99998"])
        self.assertEqual(ids, ["CWE-120", "CWE-676", "CWE-787"])
        self.assertEqual(len(notes), 1)
        self.assertEqual(catalog.for_lead("semgrep-repository-rules-v1", "appsec.c.strcpy")[0][0], "CWE-120")
        self.assertEqual(catalog.for_lead("cppcheck", "variableScope"), ([], []))

    def test_tampered_map_fails_closed_and_intake_replaces_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name in (cwe_catalog.CATALOG, cwe_catalog.RULE_MAP, cwe_catalog.LOCK):
                shutil.copyfile(cwe_catalog.CWE_DIR / name, target / name)
            (target / cwe_catalog.RULE_MAP).write_text((target / cwe_catalog.RULE_MAP).read_text() + " ")
            with self.assertRaisesRegex(cwe_catalog.CWEError, "pinned hash"):
                cwe_catalog.Catalog(target)
            rows = json.loads((cwe_catalog.CWE_DIR / cwe_catalog.CATALOG).read_text())["entries"]
            extra = [{"cwe_id": f"CWE-{9000 + n}", "name": f"Synthetic {n}"} for n in range(120)]
            csv_text = "CWE-ID,Name,Status\n" + "".join(
                f"{row['cwe_id'][4:]},\"{row['name']}\",Stable\n" for row in rows + extra)
            source = target / "cwec.csv"; source.write_text(csv_text)
            lock = cwe_catalog.intake(source, "CWE 4.99", "2026-09-28", target)
            loaded = cwe_catalog.Catalog(target)
            self.assertEqual(loaded.version, "CWE 4.99")
            self.assertEqual(loaded.identity["catalog_sha256"], lock[cwe_catalog.CATALOG])
            self.assertIn("CWE-9001", loaded.names)


class EPSSKEVSnapshotTests(unittest.TestCase):
    def write_sources(self, directory: Path) -> tuple[Path, Path]:
        epss = directory / "epss_scores-2026-09-27.csv.gz"
        epss.write_bytes(gzip.compress(b"#model_version:v2025.03.14,score_date:2026-09-27T00:00:00+0000\n"
                                       b"cve,epss,percentile\nCVE-2025-0001,0.91234,0.99812\nCVE-2025-0002,0.00100,0.10000\n"))
        kev = directory / "known_exploited_vulnerabilities.json"
        kev.write_text(json.dumps({"catalogVersion": "2026.09.26", "dateReleased": "2026-09-26T17:00:00.000Z",
            "vulnerabilities": [{"cveID": "CVE-2025-0001", "dateAdded": "2026-01-02", "dueDate": "2026-01-23",
                                 "knownRansomwareCampaignUse": "Known"}]}))
        return epss, kev

    def test_intake_pins_dated_snapshot_and_lookup_uses_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root / "snap"
            self.assertIsNone(snapshot.load(out))
            epss, kev = self.write_sources(root)
            lock = snapshot.intake(epss, kev, out)
            self.assertEqual(lock["as_of"], "2026-09-26")
            loaded = snapshot.load(out)
            hit = loaded.lookup(["GHSA-aaaa-bbbb-cccc", "CVE-2025-0001", "CVE-2025-0002"])
            self.assertEqual((hit["epss"], hit["epss_cve"], hit["kev"], hit["as_of"]),
                             (0.91234, "CVE-2025-0001", True, "2026-09-26"))
            self.assertFalse(loaded.lookup(["CVE-2025-0002"])["kev"])
            (out / snapshot.SNAPSHOT).write_bytes((out / snapshot.SNAPSHOT).read_bytes() + b" ")
            with self.assertRaisesRegex(snapshot.SnapshotError, "pinned hash"):
                snapshot.load(out)
        self.assertFalse(snapshot.not_assessed(["CVE-2025-0001"])["assessed"])

    def test_malformed_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / "epss.csv"; bad.write_text("cve,epss,percentile\nCVE-2025-0001,0.5,0.5\n")
            _, kev = self.write_sources(root)
            with self.assertRaisesRegex(snapshot.SnapshotError, "score_date"):
                snapshot.intake(bad, kev, root / "out")


class SnippetTests(unittest.TestCase):
    def test_verified_redacted_bounded_or_withheld(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "tree"; (tree / "src").mkdir(parents=True)
            lines = [f"line {n}" for n in range(1, 31)]
            lines[11] = 'const char *aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";'
            data = ("\n".join(lines) + "\n").encode()
            (tree / "src/a.c").write_bytes(data)
            sha = "sha256:" + hashlib.sha256(data).hexdigest()
            result = code_snippets.extract([tree], "src/a.c", sha, [14])
            self.assertEqual((result["status"], result["start"], result["end"]), ("VERIFIED", 9, 19))
            self.assertEqual(result["flaw"], [14])
            self.assertNotIn("wJalrXUtnFEMI", "\n".join(result["source"]))
            self.assertGreater(result["redaction_markers"], 0)
            self.assertEqual(code_snippets.extract([tree], "src/a.c", "sha256:" + "0" * 64, [14])["status"], "WITHHELD")
            self.assertEqual(code_snippets.extract([tree], "../a.c", sha, [14])["status"], "WITHHELD")
            self.assertEqual(code_snippets.extract([tree], "src/a.c", sha, [99])["status"], "WITHHELD")


if __name__ == "__main__":
    unittest.main()
