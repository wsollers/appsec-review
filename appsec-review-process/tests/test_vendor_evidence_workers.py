from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import container_mobile_binary_contracts as cmb
import evidence_redaction
import secrets_iac_contracts as sic
import vendor_evidence_workers as workers
import vendor_evidence_b13 as b13
import tool_instance_shapes as shapes

SOURCE_SHA = "sha256:" + "a" * 64
PERMITTED = ["OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED"]


class VendorEvidenceWorkerTests(unittest.TestCase):
    def make_source(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        for relative, data in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def documents(self, job, files):
        root = self.make_source(files)
        return root, workers.build_documents(job, root, run_id="run-1", attempt_id="attempt-1",
                                              source_snapshot_sha256=SOURCE_SHA)

    def materialize(self, job, files):
        root, documents = self.documents(job, files)
        attempt = root.parent / "attempt-1"
        workers.materialize_attempt(documents, attempt, dagster_run_id="dagster-1")
        return root, documents, attempt

    def test_platform_probe_requires_real_markers(self):
        root = self.make_source({"src/App.kt": b"class App\n", "src/View.swift": b"struct View {}\n"})
        found = workers.probe("02-mobile-sast", root)
        self.assertEqual(found["candidates"], {"mobsfscan-android": [], "mobsfscan-ios": []})

    def test_clean_tree_skips_every_applicability_gated_worker(self):
        root = self.make_source({"README.md": b"bounded fixture\n"})
        for job in workers.SPECS:
            if job == "02-secrets-inventory":
                continue
            with self.subTest(job=job):
                document = workers.build_documents(job, root, run_id="run-1", attempt_id="attempt-1",
                                                   source_snapshot_sha256=SOURCE_SHA)
                self.assertEqual(document["status"], "SKIPPED")
                self.assertEqual(document["probe"]["skip_reason"], workers.SKIP)

    def test_deterministic_workers_emit_real_locations_but_vendor_absence_is_a_gap(self):
        _, secrets = self.documents("02-secrets-inventory", {
            "keys/service.pem": b"-----BEGIN PRIVATE KEY-----\nsynthetic\n",
        })
        self.assertEqual(secrets["status"], "OK_WITH_GAPS")
        entry = secrets["secrets-inventory.redacted.json"]["entries"][0]
        self.assertEqual(entry["location"]["path"], "keys/service.pem")
        self.assertNotIn("synthetic", repr(secrets))
        _, iac = self.documents("02-iac-config-scan", {"deploy/Dockerfile": b"FROM alpine:3.20\n"})
        self.assertEqual(iac["status"], "OK_WITH_GAPS")
        self.assertEqual(iac["base-image-inventory.json"]["base_images"][0]["repository"], "alpine")
        self.assertTrue(any(g["kind"] == "tool-instance-blocked" for g in iac["coverage.json"]["gaps"]))

    def test_vendor_only_workers_fail_closed_with_explicit_gaps(self):
        cases = {
            "02-container-image-inventory": {"images/service.tar": b"archive"},
            "02-binary-hardening": {"bin/service.so": b"\x7fELF" + b"x" * 32},
            "02-mobile-sast": {"app/AndroidManifest.xml": b"<manifest/>\n"},
        }
        for job, files in cases.items():
            with self.subTest(job=job):
                _, doc = self.documents(job, files)
                self.assertEqual(doc["status"], "BLOCKED")
                self.assertTrue(doc["coverage.json"]["gaps"])
                self.assertTrue(all(instance["terminal_status"] in ("BLOCKED", "SKIPPED")
                                    for instance in doc["tool-results.json"]["tool_instances"]))

    def test_all_five_attempt_layouts_pass_the_accepted_contract_verifiers(self):
        cases = {
            "02-secrets-inventory": {"key.pem": b"-----BEGIN PRIVATE KEY-----\nx\n"},
            "02-iac-config-scan": {"Dockerfile": b"FROM alpine:3.20\n"},
            "02-container-image-inventory": {"image.tar": b"archive"},
            "02-binary-hardening": {"a.so": b"\x7fELFxxxx"},
            "02-mobile-sast": {"AndroidManifest.xml": b"<manifest/>\n"},
        }
        for job, files in cases.items():
            with self.subTest(job=job):
                source, doc, attempt = self.materialize(job, files)
                if job == "02-secrets-inventory":
                    errors = sic.validate_secrets_attempt(
                        attempt, tool_outputs_root=attempt, node_status=doc["status"],
                        declared_tool_ids=workers.SPECS[job][1], permitted_node_statuses=sic.NEVER_SKIPS,
                        on_unhandled="refuse", limits=evidence_redaction.DEFAULT_LIMITS,
                        expected_dagster_run_id="dagster-1")
                elif job == "02-iac-config-scan":
                    errors = sic.validate_iac_attempt(
                        attempt, tool_outputs_root=attempt, node_status=doc["status"],
                        declared_tool_ids=workers.SPECS[job][1], permitted_node_statuses=sic.CAN_SKIP,
                        on_unhandled="refuse", limits=evidence_redaction.DEFAULT_LIMITS,
                        expected_dagster_run_id="dagster-1")
                else:
                    errors = cmb.verify_attempt(
                        workers.SPECS[job][0], attempt, source, expected_header=doc["header"],
                        expected_dagster_run_id="dagster-1", node_status=doc["status"],
                        declared_tool_ids=workers.SPECS[job][1], permitted_node_statuses=PERMITTED,
                        on_unhandled="refuse", limits=evidence_redaction.DEFAULT_LIMITS)
                self.assertEqual(errors, [])

    def test_attempt_is_immutable_and_tamper_is_detected(self):
        source, doc, attempt = self.materialize("02-binary-hardening", {"a.so": b"\x7fELFxxxx"})
        with self.assertRaises(FileExistsError):
            workers.materialize_attempt(doc, attempt, dagster_run_id="dagster-1")
        result = attempt / "outputs" / "binary-hardening.json"
        result.write_bytes(result.read_bytes() + b" ")
        errors = cmb.verify_attempt(
            "binary-hardening", attempt, source, expected_header=doc["header"],
            expected_dagster_run_id="dagster-1", node_status=doc["status"], declared_tool_ids=["binskim"],
            permitted_node_statuses=PERMITTED, on_unhandled="refuse", limits=evidence_redaction.DEFAULT_LIMITS)
        self.assertTrue(any(error.startswith("redaction-receipt:") for error in errors))

    def test_fingerprint_changes_with_input_bytes(self):
        root = self.make_source({"Dockerfile": b"FROM alpine:3.20\n"})
        first = workers.fingerprint("02-iac-config-scan", root, SOURCE_SHA)
        (root / "Dockerfile").write_bytes(b"FROM debian:12\n")
        self.assertNotEqual(first, workers.fingerprint("02-iac-config-scan", root, SOURCE_SHA))

    def test_every_worker_has_a_canonical_zero_capability_permission_receipt(self):
        for job in workers.SPECS:
            with self.subTest(job=job):
                receipt = workers.permission_receipt(job, "run-1", SOURCE_SHA, now="2026-09-27T12:00:00Z")
                self.assertEqual(receipt["decision"]["decision"], "GRANTED")
                self.assertEqual(receipt["requirement"]["capabilities"], [])
                self.assertTrue(receipt["fingerprint_sha256"].startswith("sha256:"))

    def test_authenticated_vendor_success_projects_into_all_five_contracts(self):
        cases={
          "02-secrets-inventory":({"src/a.py":b"x\n"},{"gitleaks":{"status":"OK","raw":b'[{"RuleID":"generic","File":"/inputs/src/a.py","StartLine":1,"EndLine":1}]',"records":[{"rule_id":"generic","path":"src/a.py","start_line":1,"end_line":1}]}}),
          "02-iac-config-scan":({"Dockerfile":b"FROM alpine:3.20\n"},{"hadolint":{"status":"OK","raw":b'[{"code":"DL3002","file":"Dockerfile","line":1}]',"records":[{"rule_id":"DL3002","path":"Dockerfile","start_line":1,"end_line":1}]}}),
          "02-mobile-sast":({"AndroidManifest.xml":b"<manifest/>\n","App.kt":b"class App\n"},{"mobsfscan-android":{"status":"OK","raw":b'{"runs":[]}',"records":[{"rule_id":"android_logging","path":"App.kt","line":1}]}}),
          "02-binary-hardening":({"a.exe":b"MZ"+b"x"*40},{"binskim":{"status":"OK","raw":b'{"runs":[]}',"records":[{"rule_id":"BA2002","path":"a.exe","line":1}]}}),
          "02-container-image-inventory":({"image.tar":b"archive"},{
             "oci-archive-inventory":{"status":"OK","raw":json.dumps({"artifacts":[],"source":{"metadata":{"manifestDigest":"sha256:"+"b"*64,"layers":[{"digest":"sha256:"+"c"*64,"size":7}],"config":{"digest":"sha256:"+"d"*64,"architecture":"amd64","os":"linux","user":None,"entrypoint":None,"entrypointArgs":0,"command":None,"commandArgs":0,"ports":[],"envNames":[]}}}}).encode(),"records":[]},
             "image-package-and-config-inspection":{"status":"OK","raw":b'{"Results":[]}',"records":[{"name":"openssl","version":"3.0","ecosystem":"deb","layer_index":0}]}}),
        }
        for job,(files,vendor) in cases.items():
            with self.subTest(job=job):
                for tool,result in vendor.items():
                    receipt={"schema":"appsec-review/vendor-b13-execution-receipt/1","tool_id":tool,
                             "attempt_id":f"{tool}-verified-1","request_sha256":"sha256:"+"1"*64,
                             "result_sha256":"sha256:"+"2"*64,"permission_sha256":"sha256:"+"3"*64,
                             "permission_fingerprint_sha256":"sha256:"+"4"*64,"image_id":"tool-"+tool.replace("-android","").replace("-ios",""),
                             "image_digest":"sha256:"+"5"*64,"argv":["/opt/tool/bin/"+tool,"--offline"],"tool_version":"1.0.0","tool_name":tool}
                    result["auth"]={"attempt_id":receipt["attempt_id"],"argv":receipt["argv"],"exit_code":0,
                        "identity":{"repository":"docker.io/library/"+receipt["image_id"],"digest":receipt["image_digest"],"tool_version":"1.0.0","tool_name":tool},"receipt":receipt}
                root=self.make_source(files)
                def collector(*args,**kwargs): return vendor
                doc=workers.execute_and_build(job,root,run_id="run-1",attempt_id="attempt-1",source_snapshot_sha256=SOURCE_SHA,execution_root=root.parent/"execution",now="2026-09-27T12:00:00Z",collector=collector)
                attempt=root.parent/"attempt-1"; workers.materialize_attempt(doc,attempt,dagster_run_id="dagster-1",started_at="2026-09-27T12:00:00Z",finished_at="2026-09-27T12:00:01Z")
                if job=="02-secrets-inventory": errors=sic.validate_secrets_attempt(attempt,tool_outputs_root=attempt,node_status=doc["status"],declared_tool_ids=workers.SPECS[job][1],permitted_node_statuses=sic.NEVER_SKIPS,on_unhandled="refuse",limits=evidence_redaction.DEFAULT_LIMITS,expected_dagster_run_id="dagster-1")
                elif job=="02-iac-config-scan": errors=sic.validate_iac_attempt(attempt,tool_outputs_root=attempt,node_status=doc["status"],declared_tool_ids=workers.SPECS[job][1],permitted_node_statuses=sic.CAN_SKIP,on_unhandled="refuse",limits=evidence_redaction.DEFAULT_LIMITS,expected_dagster_run_id="dagster-1")
                else: errors=cmb.verify_attempt(workers.SPECS[job][0],attempt,root,expected_header=doc["header"],expected_dagster_run_id="dagster-1",node_status=doc["status"],declared_tool_ids=workers.SPECS[job][1],permitted_node_statuses=PERMITTED,on_unhandled="refuse",limits=evidence_redaction.DEFAULT_LIMITS)
                self.assertEqual(errors,[])
                self.assertIn(doc["status"],("OK","OK_WITH_GAPS"))
                self.assertEqual(json.loads((attempt/"result.json").read_text())["acceptance_status"],"CURRENT")
                aggregate=json.loads((attempt/"outputs/tool-results.json").read_text())
                authenticated=next((i for i in aggregate["tool_instances"] if i.get("execution_receipt")),None)
                self.assertIsNotNone(authenticated)
                authenticated["argv"]=["/fabricated/tool"]
                self.assertTrue(any("mismatch" in e for e in shapes.verify_vendor_execution_receipts(aggregate,attempt)))


if __name__ == "__main__":
    unittest.main()
