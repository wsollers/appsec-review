"""Acceptance tests for gap punch list P43 (follow-up to P41, appsec-multi-vuln case-081/082): 02-sbom-inventory
reads the accepted base-image inventory of 02-iac-config-scan over an optional, skip-propagated edge.

Each installed OS package of a resolved base image becomes a CycloneDX component with its pkg:deb/pkg:apk purl
and distro qualifier, scope ``container-base``, the image reference, digest and inventory record as evidence and
the EOL status as a property; rows dedupe with Syft and P37 rows by purl; unresolved images and a missing
inventory are gaps, while a target without a Dockerfile gains none; Grype's CycloneDX input carries them and
OSV registers Debian and Alpine. The Dagster wiring test needs Dagster and is skipped without it.

Fixtures: the synthetic case-081 (Debian 10) / case-082 (Alpine 3.24.2) layers and fake registry of
test_gap_punchlist_baseimages, the dependency-worker harness of test_gap_punchlist_builddeps.

See docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md.
"""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_paths  # noqa: E402

import dependency_workers as workers  # noqa: E402
import execution_state  # noqa: E402
from execution_state import Blocked, file_hash, read_json  # noqa: E402
import osv_feed  # noqa: E402
import sbom_family_contracts as contracts  # noqa: E402
from schema_validate import validate_document  # noqa: E402
import vendor_evidence_workers as vendor_workers  # noqa: E402
import test_dependency_workers as tdw  # noqa: E402  (modules, so their tests do not re-run here)
import test_gap_punchlist_baseimages as tbi  # noqa: E402
import test_gap_punchlist_builddeps as tbd  # noqa: E402
import test_gap_punchlist_sbomwire as tsw  # noqa: E402

IAC = "02-iac-config-scan"
ZLIB = "pkg:deb/debian/zlib1g@1:1.2.11.dfsg-1?arch=amd64&distro=debian-10"
MUSL = "pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.24.2"
CASE_081 = (tbi.FIXTURE / "case-081/Dockerfile").read_text()


def _base_image_binding(*args, **kwargs):
    import automatic_evidence_inputs
    function = getattr(automatic_evidence_inputs, "_base_image_binding", None)
    if function is None:
        raise AssertionError("P43: automatic_evidence_inputs has no base-image inventory binding")
    return function(*args, **kwargs)


class _Harness:
    """An accepted 02-iac-config-scan generation and SBOM requests in one dependency-worker harness run."""

    def __init__(self, test: unittest.TestCase):
        self.case = tbd.SbomBuildDependencyTests("test_p37_deb_rows_dedupe_with_syft")
        self.case.setUp()
        test.addCleanup(self.case.doCleanups)
        test.addCleanup(self.case.tearDown)
        self.h = self.case.h
        self.cache_root = self.h.root / "base-images"
        self.counter = 0

    def debian(self) -> str:
        registry = tbi.BaseImageTests.debian(None)
        token = f"debian:buster-20190708-slim@{registry.index_digest}"
        tbi.cache.fetch([token], self.cache_root, transport=registry, now=tbi.NOW)
        return token

    def alpine(self) -> str:
        registry = tbi.FakeRegistry("library/alpine", "3.24.2", [tbi.layer(tbi.tree("alpine-3.24"))])
        token = f"alpine:3.24.2@{registry.index_digest}"
        tbi.cache.fetch([token], self.cache_root, transport=registry, now=tbi.NOW)
        return token

    @staticmethod
    def verified(tool: str) -> dict:
        """A successful, B13-authenticated vendor result with no records (as test_vendor_evidence_workers builds)."""
        raw = b"[]"
        receipt = {"schema": "appsec-review/vendor-b13-execution-receipt/1", "tool_id": tool,
                   "attempt_id": f"{tool}-verified-1", "request_sha256": "sha256:" + "1" * 64,
                   "result_sha256": "sha256:" + "2" * 64, "output_sha256": tdw.sha_bytes(raw),
                   "permission_sha256": "sha256:" + "3" * 64, "permission_fingerprint_sha256": "sha256:" + "4" * 64,
                   "image_id": "tool-" + tool, "image_digest": "sha256:" + "5" * 64,
                   "argv": ["/opt/tool/bin/" + tool, "--offline"], "tool_version": "1.0.0", "tool_name": tool}
        return {"status": "OK", "raw": raw, "records": [], "auth": {
            "attempt_id": receipt["attempt_id"], "argv": receipt["argv"], "exit_code": 0, "receipt": receipt,
            "identity": {"repository": "docker.io/library/" + receipt["image_id"], "digest": receipt["image_digest"],
                         "tool_version": "1.0.0", "tool_name": tool}}}

    def iac(self, files: dict[str, str], vendor: tuple[str, ...] = ()) -> dict:
        """Publish an accepted 02-iac-config-scan attempt over ``files`` (``vendor``: scanners that completed) and
        return the SBOM's binding."""
        self.counter += 1
        source = self.h.root / f"iac-source-{self.counter}"
        for name, text in files.items():
            path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        base = self.h.out / IAC / "whole"; attempt = base / "attempts" / f"iac-{self.counter}"
        documents = vendor_workers.build_documents(IAC, source, run_id=self.h.run_id, attempt_id=attempt.name,
            source_snapshot_sha256=self.h.source, base_image_root=self.cache_root, now=tbi.NOW,
            vendor_results={tool: self.verified(tool) for tool in vendor})
        vendor_workers.materialize_attempt(documents, attempt, dagster_run_id="dagster-p43",
                                           started_at=tbi.NOW, finished_at=tbi.NOW)
        envelope = read_json(attempt / "result.json")
        pointer = {"schema": "appsec-review/accepted-worker-result/1.0", "run_id": self.h.run_id, "job": IAC,
                   "attempt_id": attempt.name, "status": envelope["execution_status"],
                   "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
                   "envelope_sha256": file_hash(attempt / "result.json")}
        if envelope.get("skip_reason"):
            pointer["reason"] = envelope["skip_reason"]
        (base / "accepted.json").write_bytes(tdw.payload(pointer))
        inventory = attempt / "outputs/base-image-inventory.json"
        return {"attempt_id": attempt.name, "path": str(inventory), "sha256": "sha256:" + file_hash(inventory),
                "accepted_path": str(base / "accepted.json")}

    def sbom(self, base_images, *, syft_components=(), extra_files=None, native_build="omit"):
        h = self.h
        files = {"package-lock.json": "sha256:" + "2" * 64, **(extra_files or {})}
        output, receipt, expected = h.tool("02-sbom-inventory", "syft", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": list(syft_components)})
        extra = {"base_image_inventory": base_images}
        if native_build != "omit":
            extra["native_build"] = native_build
        envelope = h.run_request("sbom", "sbombase-" + str(h.tool_counter), h.request(
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected, source_files=files, **extra))
        result = json.loads(h.result_path(envelope, "outputs/sbom-manifest.json").read_text())
        cdx = json.loads(h.result_path(envelope, "outputs/sbom.cdx.json").read_text())
        return envelope, result, cdx


def _dockerfile(token: str) -> str:
    return f"FROM {token}\nRUN true\n"


class SbomBaseImageTests(unittest.TestCase):
    def setUp(self):
        self.x = _Harness(self)

    def contract_errors(self, envelope: dict, result: dict) -> list[str]:
        attempt = self.x.h.result_path(envelope, "")
        descriptor = result.get("base_image_document")
        self.assertIsNotNone(descriptor, "P43: the SBOM manifest binds no base-image document")
        raw = (attempt / descriptor["path"]).read_bytes()
        errors = contracts.base_image_enrichment_errors(result, raw)
        errors += [e for e in contracts._component_errors(result["components"]) if not e.startswith("record-id-order")]
        errors += contracts._cdx_errors((attempt / "outputs/sbom.cdx.json").read_bytes(), result)
        return errors + validate_document(result, "sbom-inventory.schema.json")

    def test_p43_debian_base_packages_become_container_base_components(self):
        """P43: case-081-like Debian 10 base: pkg:deb purls with the distro qualifier, scope container-base, the image
        reference, digest and inventory record as evidence, end-of-life as a property; contract-valid."""
        token = self.x.debian()
        binding = self.x.iac({"case-081/Dockerfile": _dockerfile(token)})
        envelope, result, cdx = self.x.sbom(binding)
        rows = {row["purl"]: row for row in result["components"] if row.get("purl")}
        self.assertIn(ZLIB, rows, envelope["gaps"])
        zlib = rows[ZLIB]
        self.assertEqual((zlib["name"], zlib["version"], zlib["ecosystem"], zlib["cpe"]),
                         ("zlib1g", "1:1.2.11.dfsg-1", "deb", None))
        self.assertEqual(zlib.get("scope"), "container-base")
        self.assertEqual(zlib["source"]["path"], "outputs/base-image-inventory.json")
        self.assertEqual(zlib["source"]["sha256"], binding["sha256"])
        images = (zlib.get("image_evidence") or {}).get("images", [])
        self.assertEqual(len(images), 1)
        image = images[0]
        inventory = read_json(Path(binding["path"]))["base_images"][0]
        self.assertEqual((image["reference_id"], image["repository"], image["tag"], image["digest"]),
                         ("BI-000001", "debian", "buster-20190708-slim", token.split("@", 1)[1]))
        self.assertEqual(image["manifest_digest"], inventory["resolution"]["resolved"]["manifest"]["digest"])
        self.assertEqual(image["dockerfile"], {"path": "case-081/Dockerfile", "start_line": 1})
        self.assertEqual((image["eol_status"], image["support_end"]), ("end-of-life", "2024-06-30"))
        listed = {item.get("purl"): item for item in cdx["components"]}
        properties = {p["name"]: p["value"] for p in listed[ZLIB].get("properties", [])}
        self.assertEqual(properties.get("appsec-review:dependency-scope"), "container-base")
        self.assertEqual(properties.get("appsec-review:base-image-eol-status"), "end-of-life")
        self.assertIn(f"debian:buster-20190708-slim@{token.split('@', 1)[1]}", properties.get("appsec-review:base-image", ""))
        self.assertFalse(any(gap.startswith("base-image") for gap in envelope["gaps"]), envelope["gaps"])
        self.assertEqual(self.contract_errors(envelope, result), [])

    def test_p43_alpine_base_packages_are_apk_components_and_supported(self):
        """P43: case-082-like Alpine 3.24.2 control: pkg:apk purls with distro=alpine-3.24.2, EOL supported."""
        binding = self.x.iac({"case-082/Dockerfile": _dockerfile(self.x.alpine())})
        envelope, result, cdx = self.x.sbom(binding)
        rows = {row["purl"]: row for row in result["components"] if row.get("purl")}
        self.assertIn(MUSL, rows, envelope["gaps"])
        self.assertEqual((rows[MUSL]["ecosystem"], rows[MUSL]["scope"]), ("apk", "container-base"))
        self.assertEqual(rows[MUSL]["image_evidence"]["images"][0]["eol_status"], "supported")
        properties = {p["name"]: p["value"] for p in next(c for c in cdx["components"] if c.get("purl") == MUSL)["properties"]}
        self.assertEqual(properties.get("appsec-review:base-image-eol-status"), "supported")
        self.assertEqual(self.contract_errors(envelope, result), [])

    def test_p43_rows_dedupe_by_purl_with_syft_p37_and_each_other(self):
        """P43: a package Syft or the P37 build inference already lists is not repeated; two Dockerfiles naming one
        image yield one component citing both references."""
        token = self.x.debian()
        binding = self.x.iac({"a/Dockerfile": _dockerfile(token), "b/Dockerfile": _dockerfile(token)})
        target = self.x.h.target
        (target / "var/lib/dpkg").mkdir(parents=True)
        (target / "var/lib/dpkg/status").write_text("Package: apt\n")
        status = {"var/lib/dpkg/status": "sha256:" + file_hash(target / "var/lib/dpkg/status")}
        syft = {"name": "apt", "version": "1.8.2", "type": "library",
                "purl": "pkg:deb/debian/apt@1.8.2?arch=amd64&distro=debian-10",
                "properties": [{"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"}]}
        record = tbd._record(
            {"path": "/usr/lib/x86_64-linux-gnu/libz.so.1", "class": "system-package", "kinds": ["shared-library", "needed"],
             "sha256": "sha256:" + "b" * 64, "size_bytes": 10, "packages": ["zlib1g:amd64"]},
            packages=[{"package": "zlib1g:amd64", "name": "zlib1g", "arch": "amd64", "version": "1:1.2.11.dfsg-1",
                       "source": "zlib", "source_version": "1:1.2.11.dfsg-1"}],
            binaries=[{"path": "bin/hello", "needed": [{"soname": "libz.so.1", "file": 0, "via": "cache"}],
                       "runpath": [], "rpath": []}],
            distro={"id": "debian", "version_id": "10", "codename": "buster"})
        envelope, result, _cdx = self.x.sbom(binding, syft_components=[syft], extra_files=status,
                                             native_build=self.x.case.native_build([record]))
        names = [row["name"] for row in result["components"]]
        self.assertEqual(names.count("apt"), 1)
        self.assertEqual(names.count("zlib1g"), 1)
        self.assertEqual(next(r for r in result["components"] if r["name"] == "zlib1g")["scope"], "load-time")
        base = [row for row in result["components"] if row.get("scope") == "container-base"]
        self.assertTrue(base)
        self.assertEqual({len(row["image_evidence"]["images"]) for row in base}, {2})
        self.assertEqual(len({row["purl"] for row in base}), len(base))
        self.assertEqual(self.contract_errors(envelope, result), [])

    def test_p43_unresolved_image_carries_through_as_a_gap(self):
        """P43: an image the host cache does not hold contributes no component and stays a named SBOM gap."""
        binding = self.x.iac({"case-081/Dockerfile": CASE_081})
        envelope, result, _cdx = self.x.sbom(binding)
        self.assertEqual(envelope["execution_status"], "OK_WITH_GAPS")
        gaps = [gap for gap in envelope["gaps"] if gap.startswith("base-image-unresolved")]
        self.assertEqual(len(gaps), 1, envelope["gaps"])
        self.assertIn("BI-000001", gaps[0])
        self.assertIn("cache-unavailable", gaps[0])
        self.assertFalse(any(row.get("scope") == "container-base" for row in result["components"]))
        self.assertEqual(self.contract_errors(envelope, result), [])

    def test_p43_missing_inventory_is_a_gap_only_when_the_target_has_a_dockerfile(self):
        """P43: no accepted 02-iac-config-scan is a gap for a target with a Dockerfile, and nothing for one without;
        a skipped IaC scan binds nothing and is no gap."""
        absent, result, _cdx = self.x.sbom(None, extra_files={"docker/Dockerfile": "sha256:" + "5" * 64})
        self.assertTrue(any(gap.startswith("base-image-inventory-not-published") for gap in absent["gaps"]), absent["gaps"])
        self.assertEqual(self.contract_errors(absent, result), [])
        for binding in (None, {"skipped": vendor_workers.SKIP}):
            envelope, result, _cdx = self.x.sbom(binding)
            self.assertFalse(any(gap.startswith("base-image") for gap in envelope["gaps"]), envelope["gaps"])
            self.assertEqual(self.contract_errors(envelope, result), [])

    def test_p43_dockerfile_free_target_gains_no_gap(self):
        """P43: an accepted IaC scan of a target with no Dockerfile (Terraform only) yields no base-image gap or row;
        nor does a Dockerfile that only builds FROM scratch."""
        for files, vendor in (({"main.tf": 'resource "null_resource" "x" {}\n'}, ("tfsec",)),
                              ({"Dockerfile": "FROM scratch\nCOPY a /a\n"}, ())):
            binding = self.x.iac(files, vendor)
            self.assertIn(read_json(Path(binding["accepted_path"]))["status"], {"OK", "OK_WITH_GAPS"})
            envelope, result, _cdx = self.x.sbom(binding)
            self.assertFalse(any(gap.startswith("base-image") for gap in envelope["gaps"]), (files, envelope["gaps"]))
            self.assertFalse(any(row.get("scope") == "container-base" for row in result["components"]))
            self.assertEqual(self.contract_errors(envelope, result), [])

    def test_p43_contract_rejects_a_relabelled_or_unbound_base_image_component(self):
        """P43: the contract binds produced rows to the retained document and the inventory binding."""
        binding = self.x.iac({"Dockerfile": _dockerfile(self.x.debian())})
        envelope, result, _cdx = self.x.sbom(binding)
        self.assertIsNotNone(result.get("base_image_document"), "P43: the SBOM manifest binds no base-image document")
        raw = self.x.h.result_path(envelope, result["base_image_document"]["path"]).read_bytes()
        forged = copy.deepcopy(result)
        row = next(r for r in forged["components"] if r.get("scope") == "container-base")
        row["scope"] = "load-time"
        self.assertTrue(contracts.base_image_enrichment_errors(forged, raw))
        forged = copy.deepcopy(result)
        row = next(r for r in forged["components"] if r.get("scope") == "container-base")
        row["source"]["sha256"] = "sha256:" + "0" * 64
        self.assertTrue(contracts.base_image_enrichment_errors(forged, raw))

    def test_p43_grype_input_carries_base_image_purls_and_matches_resolve(self):
        """P43: the CycloneDX export Grype reads lists the base-image purls, and a Grype match on one resolves to its
        SBOM component."""
        h = self.x.h
        envelope, result, cdx = self.x.sbom(self.x.iac({"Dockerfile": _dockerfile(self.x.debian())}))
        self.assertIn(ZLIB, {item.get("purl") for item in cdx["components"]})
        component = next(row for row in result["components"] if row.get("purl") == ZLIB)
        databases = [{"database_kind": kind, "vendor_build": "build-1", "schema_version": "1.0",
                      "snapshot_id": kind + "-20260927", "sha256": tdw.sha_bytes(kind.encode()),
                      "data_timestamp": "2026-09-27T11:00:00Z"} for kind in ("grype-db", "osv")]
        output, receipt, expected = h.tool("02-sca-vulnerability-match", "grype", {"matches": [{
            "artifact": {"name": "zlib1g", "version": "1:1.2.11.dfsg-1", "purl": ZLIB, "cpes": []},
            "vulnerability": {"id": "CVE-2018-25032", "relatedVulnerabilities": []}}]})
        sca = h.run_request("sca", "sca-p43", h.request(sbom=h.binding(envelope, "outputs/sbom-manifest.json"),
            tool_output=str(output), tool_receipt=str(receipt), expected_tool=expected, databases=databases,
            max_database_age_seconds=7200, **h.osv()))
        matches = json.loads(h.result_path(sca, "outputs/sca-vulnerability-match.json").read_text())["matches"]
        self.assertEqual([(m["component_ref"], m["advisory_id"]) for m in matches],
                         [(component["component_id"], "CVE-2018-25032")])


class OsvEcosystemTests(unittest.TestCase):
    def test_p43_osv_feed_registers_debian_and_alpine(self):
        """P43: the OSV bulk feed fetches the Debian and Alpine archives (GCS directory names)."""
        self.assertLessEqual({"Debian", "Alpine"}, set(osv_feed.ECOSYSTEMS))
        self.assertEqual(osv_feed.source_url("Debian"), f"{osv_feed.BASE_URL}/Debian/all.zip")
        self.assertEqual(osv_feed.source_url("Alpine"), f"{osv_feed.BASE_URL}/Alpine/all.zip")

    def test_p43_os_package_purls_map_to_osv_ecosystems(self):
        """P43: deb/apk purls name OSV's Debian/Ubuntu/Alpine ecosystems; a missing versioned database is no coverage."""
        self.assertEqual(workers.osv_ecosystem(ZLIB), "Debian")
        self.assertEqual(workers.osv_ecosystem("pkg:deb/ubuntu/zlib1g@1:1.3?arch=amd64&distro=ubuntu-24.04"), "Ubuntu")
        self.assertEqual(workers.osv_ecosystem(MUSL), "Alpine")
        self.assertTrue(workers.osv_covers(ZLIB, ["Alpine"]))
        self.assertFalse(workers.osv_covers(ZLIB, ["Debian:10"]))
        self.assertFalse(workers.osv_covers(MUSL, ["Alpine"]))
        self.assertTrue(workers.osv_covers("pkg:npm/lodash@4.17.15", ["github:actions"]))

    def test_p43_osv_result_without_purl_binds_back_by_os_ecosystem(self):
        """P43: osv-scanner reports Debian:10 / Alpine:v3.24 without a purl; name, version and ecosystem bind back."""
        components = {"SC-1": {"name": "zlib1g", "version": "1:1.2.11.dfsg-1", "ecosystem": "deb", "purl": ZLIB},
                      "SC-2": {"name": "musl", "version": "1.2.5-r10", "ecosystem": "apk", "purl": MUSL}}
        self.assertEqual(workers._component_for(components, name="zlib1g", version="1:1.2.11.dfsg-1", ecosystem="Debian:10"),
                         ("SC-1", "purl"))
        self.assertEqual(workers._component_for(components, name="musl", version="1.2.5-r10", ecosystem="Alpine:v3.24"),
                         ("SC-2", "purl"))


class GraphAndBindingTests(unittest.TestCase):
    def test_p43_sbom_takes_an_optional_skip_propagated_iac_edge(self):
        """P43: 02-sbom-inventory depends optionally on 02-iac-config-scan with its no-input skip reason."""
        graph = read_json(registry_paths.REGISTRY / "job-graph.json")
        edges = {dep["job"]: dep for dep in graph["jobs"]["02-sbom-inventory"]["dependencies"]}
        self.assertIn(IAC, edges)
        self.assertEqual((edges[IAC]["kind"], edges[IAC]["contract"]), ("optional", "iac-config-evidence"))
        self.assertEqual(edges[IAC]["allowed_skip_reasons"], ["not-applicable-no-matching-inputs"])
        template = read_json(registry_paths.JOB_TEMPLATES_DIR / "02-sbom-inventory.json")
        self.assertTrue(any(IAC in item for item in template["inputs"]["optional"]))
        import dependency_orchestration as orchestration
        self.assertIn("base_image_inventory", orchestration._OPTIONAL_PAYLOAD_KEYS["sbom"])

    def test_p43_automatic_binding_is_accepted_skipped_or_absent(self):
        """P43: the automatic SBOM request binds the accepted inventory, a skip, or None (absent or stale)."""
        x = _Harness(self)
        h = x.h
        self.assertIsNone(_base_image_binding(h.run_id, h.source, h.out))
        binding = x.iac({"Dockerfile": "FROM scratch\n"})
        self.assertEqual(_base_image_binding(h.run_id, h.source, h.out), binding)
        self.assertIsNone(_base_image_binding(h.run_id, "sha256:" + "e" * 64, h.out), "a stale generation binds nothing")
        skipped = x.iac({"README": "no iac\n"})
        self.assertEqual(read_json(Path(skipped["accepted_path"]))["status"], "SKIPPED")
        self.assertEqual(_base_image_binding(h.run_id, h.source, h.out), {"skipped": vendor_workers.SKIP})


class AssemblyBindingTests(unittest.TestCase):
    def setUp(self):
        # The borrowed P42 case patches source_projection and RUNS on itself; its doCleanups undoes them.
        self.case = tsw.AssemblyBindingTests("test_p42_assembly_sbom_request_without_native_build_binds_the_gap")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_p43_assembly_sbom_request_binds_the_base_image_inventory(self):
        """P43: the assembled SBOM request carries the accepted inventory binding, or None without one."""
        payload = self.case._sbom_request()["payload"]
        self.assertIn("base_image_inventory", payload)
        self.assertIsNone(payload["base_image_inventory"])

    def test_p43_assembly_binds_an_accepted_inventory(self):
        fixture = self.case.case
        base = fixture.run / "data/jobs" / IAC / "whole"; attempt = base / "attempts/iac-1"
        source = fixture.run / "iac-source"; source.mkdir(); (source / "Dockerfile").write_text("FROM scratch\n")
        documents = vendor_workers.build_documents(IAC, source, run_id="review-1", attempt_id="iac-1",
            source_snapshot_sha256=fixture.generation, base_image_root=fixture.run / "no-cache", now=tbi.NOW)
        vendor_workers.materialize_attempt(documents, attempt, dagster_run_id="d", started_at=tbi.NOW, finished_at=tbi.NOW)
        envelope = read_json(attempt / "result.json")
        execution_state.atomic_json(base / "accepted.json", {"schema": "appsec-review/accepted-worker-result/1.0",
            "status": envelope["execution_status"], "run_id": "review-1", "job": IAC, "attempt_id": "iac-1",
            "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
            "envelope_sha256": file_hash(attempt / "result.json")})
        binding = self.case._sbom_request()["payload"].get("base_image_inventory", "missing")
        self.assertIsInstance(binding, dict, binding)
        inventory = attempt / "outputs/base-image-inventory.json"
        self.assertEqual((binding["attempt_id"], binding["path"], binding["sha256"]),
                         ("iac-1", str(inventory), "sha256:" + file_hash(inventory)))


@unittest.skipUnless(importlib.util.find_spec("dagster"), "dagster is not installed")
class DagsterWiringTests(unittest.TestCase):
    def test_p43_failing_iac_scan_still_runs_the_sbom_and_holds_required_consumers(self):
        """P43: a raising 02-iac-config-scan lets 02-sbom-inventory run; 15-deployment-hardening is still held."""
        from dagster import In, job, op
        import dagster_workflow as dw
        ran = []

        @op
        def stub_config():
            return {"engagement_run_id": "review-1", "force": False}

        @op(ins={"configured": In(dict)})
        def seed(configured):
            return {"status": "OK"}

        @op(name="job_15_deployment_hardening", ins={"configured": In(dict), "upstream": In(list)})
        def required_consumer(configured, upstream):
            ran.append("15-deployment-hardening")
            return {}

        def automatic(context, configured, job_id):
            if job_id == IAC:
                raise Blocked("stub IaC scan crashed")
            ran.append(job_id)
            return {"job_id": job_id, "status": "OK_WITH_GAPS"}

        ops = {name: dw.LIFECYCLE_OPS[name] for name in (IAC, "02-sbom-inventory")}
        ops["15-deployment-hardening"] = required_consumer

        @job
        def probe():
            configured = stub_config()
            outputs = {name: seed.alias("seed_" + name.replace("-", "_"))(configured)
                       for name in ("00-intake", "02-build-index", "02-native-build", "01-component-characterization",
                                    "15-stig-srg-validation-worklist")}
            dw.wire_lifecycle(configured, outputs, ops)

        with patch.object(dw, "run_automatic_evidence_job", side_effect=automatic):
            result = probe.execute_in_process(raise_on_error=False)
        self.assertEqual(ran, ["02-sbom-inventory"])
        self.assertFalse(result.success)
        failed = {event.step_key for event in result.all_events if event.event_type_value == "STEP_FAILURE"}
        self.assertEqual(failed, {"job_02_iac_config_scan_published"}, "the gate still fails the run")


if __name__ == "__main__":
    unittest.main()
