from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import container_mobile_binary_contracts as cmb
import evidence_redaction
import secrets_iac_contracts as sic
import vendor_evidence_workers as workers
import vendor_evidence_b13 as b13
import tool_instance_shapes as shapes
import validate_job_output as validator

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
                permission = json.loads((attempt / "permission.json").read_text())
                lineage = json.loads((attempt / "lineage.json").read_text())
                template = json.loads((registry_paths.template(job)).read_text())
                self.assertEqual(permission, {"schema": workers.PERMISSION_SCHEMA, "run_id": "run-1",
                    "job_id": job, "source_snapshot_sha256": SOURCE_SHA,
                    "permissions": template["permissions"]})
                self.assertEqual(lineage["source_snapshot_sha256"], SOURCE_SHA)
                self.assertRegex(lineage["build_lineage_sha256"], r"^sha256:[0-9a-f]{64}$")
                if (attempt / "result.json").is_file():
                    envelope = json.loads((attempt / "result.json").read_text())
                    self.assertTrue({"permission.json", "lineage.json"}.issubset(
                        {item["path"] for item in envelope["artifacts"]}))

    def test_v04_canonical_run_layout_passes_the_real_dispatch(self):
        for job, files in {
                "02-secrets-inventory": {"key.pem": b"-----BEGIN PRIVATE KEY-----\nx\n"},
                "02-iac-config-scan": {"Dockerfile": b"FROM alpine:3.20\n"}}.items():
            with self.subTest(job=job), tempfile.TemporaryDirectory() as folder:
                run_id, attempt_id = "run-canonical-v04", "attempt-canonical-v04"
                run = Path(folder) / run_id
                manifest = run / "inputs" / "artifact-manifest.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_bytes(json.dumps({"run_id": run_id}, sort_keys=True).encode() + b"\n")
                source_sha = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
                source = run / "data" / "source"; source.mkdir(parents=True)
                for relative, data in files.items():
                    path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
                documents = workers.build_documents(job, source, run_id=run_id, attempt_id=attempt_id,
                                                     source_snapshot_sha256=source_sha)
                attempt = run / "data/jobs" / job / "whole/attempts" / attempt_id
                workers.materialize_attempt(documents, attempt, dagster_run_id="dagster-canonical-v04",
                    started_at="2026-09-27T12:00:00Z", finished_at="2026-09-27T12:00:01Z")
                contract = json.loads((registry_paths.contract(workers.SPECS[job][0])).read_text())
                errors = validator.validate_vendor_prepass_attempt(attempt, contract, run_id=run_id,
                    job_id=job, attempt_id=attempt_id, node_status=documents["status"],
                    orchestration=validator.OrchestrationFacts(
                        "dagster-canonical-v04", source_sha,
                        validator.datetime.fromisoformat("2026-09-27T12:00:00+00:00")))
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

    def test_fingerprint_version_prevents_receiptless_attempt_reuse(self):
        root = self.make_source({"Dockerfile": b"FROM alpine:3.20\n"})
        listing = [(name, workers.HASH(path.read_bytes())) for name, path in workers._files(root)]
        legacy = workers.HASH(workers._dump({"job_id": "02-iac-config-scan",
            "source_snapshot_sha256": SOURCE_SHA, "files": listing}))
        self.assertNotEqual(legacy, workers.fingerprint("02-iac-config-scan", root, SOURCE_SHA))

    def test_producer_lineage_binds_tool_and_applicability_evidence(self):
        _root, documents = self.documents("02-iac-config-scan", {"Dockerfile": b"FROM alpine:3.20\n"})
        first = workers.producer_receipts(documents)[1]["build_lineage_sha256"]
        changed = {**documents, "probe": {**documents["probe"],
                                          "files_examined_count": documents["probe"]["files_examined_count"] + 1}}
        self.assertNotEqual(first, workers.producer_receipts(changed)[1]["build_lineage_sha256"])

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
                             "result_sha256":"sha256:"+"2"*64,
                             "output_sha256":"sha256:"+hashlib.sha256(result["raw"]).hexdigest(),
                             "permission_sha256":"sha256:"+"3"*64,
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
                authenticated["argv"]=vendor[authenticated["tool_id"]]["auth"]["argv"]
                authenticated["execution_receipt"]["output_sha256"]="sha256:"+"f"*64
                self.assertTrue(any("mismatch" in e for e in shapes.verify_vendor_execution_receipts(aggregate,attempt)))


if __name__ == "__main__":
    unittest.main()


class ToolFailureReportingTests(unittest.TestCase):
    """Run 20261001T032047Z-fd64eb: checkov (ran, output path), hadolint (exit 1, wrong input) and
    kube-linter (could not start) were all reported BLOCKED / image-unavailable."""

    def test_failed_tool_keeps_its_status_and_cause(self):
        import vendor_evidence_workers as workers
        header = {"run_id": "r", "job_id": "02-iac-config-scan", "attempt_id": "a",
                  "source_snapshot_sha256": "sha256:" + "0" * 64}
        tools = ["hadolint", "kube-linter"]
        candidates = {"hadolint": ["dockerfiles/case-021/Dockerfile"], "kube-linter": ["k.yaml"]}
        _, results, coverage, _, _ = workers._aggregate(
            header, tools, candidates, {}, can_skip=True,
            failures={"hadolint": ("FAILED", "CONTAINER_EXIT_NONZERO", 1)})
        by_tool = {i["tool_id"]: i for i in results["tool_instances"]}
        self.assertEqual((by_tool["hadolint"]["terminal_status"], by_tool["hadolint"]["cause_code"]),
                         ("FAILED", "tool-error"))
        self.assertEqual(by_tool["hadolint"]["exit"]["exit_code"], 1)
        self.assertEqual(by_tool["kube-linter"]["terminal_status"], "BLOCKED")   # never reported: not run
        gap_ids = [g["gap_id"] for g in coverage["gaps"]]
        self.assertIn("gap-hadolint-failed-container-exit-nonzero", gap_ids)
        self.assertIn("gap-kube-linter-blocked", gap_ids)


class HadolintInputTests(unittest.TestCase):
    def test_hadolint_lints_every_dockerfile_in_the_checkout(self):
        import tempfile
        import vendor_evidence_b13 as b13
        with tempfile.TemporaryDirectory() as root:
            for rel in ("dockerfiles/case-021/Dockerfile", "svc/api.Dockerfile", "node_modules/x/Dockerfile",
                        "README.md"):
                path = Path(root, rel); path.parent.mkdir(parents=True, exist_ok=True); path.write_text("FROM x\n")
            argv = b13.argv_for("hadolint", Path(root))
            self.assertEqual(argv[-2:], ["/workspace/dockerfiles/case-021/Dockerfile", "/workspace/svc/api.Dockerfile"])
            self.assertNotIn("/workspace/Dockerfile", argv)
            self.assertEqual(b13.argv_for("checkov", Path(root))[-1], "--soft-fail")
            with tempfile.TemporaryDirectory() as empty:
                with self.assertRaises(b13.VendorToolBlocked):
                    b13.argv_for("hadolint", Path(empty))


    def test_p38_probe_uses_the_assembly_containerfile_rules(self):
        """P38: every container definition that launches 02-iac-config-scan is a probe and hadolint input."""
        import tempfile
        import full_review_input_assembly as assembly
        names = ("Dockerfile", "docker/api.Dockerfile", "Containerfile", "Dockerfile.dev", "svc/dockerfile")
        with tempfile.TemporaryDirectory() as root:
            for rel in names + ("README.md", "main.tf"):
                path = Path(root, rel); path.parent.mkdir(parents=True, exist_ok=True); path.write_text("FROM x\n")
            found = workers.probe("02-iac-config-scan", Path(root))["candidates"]
            argv = b13.argv_for("hadolint", Path(root))
        self.assertTrue(all(assembly._iac_input(name) for name in names))
        for tool in ("hadolint", "dockerfile-base-image-inventory"):
            self.assertEqual(found[tool], sorted(names), tool)
        self.assertEqual(sorted(found["checkov"]), sorted(names + ("main.tf",)))
        self.assertEqual(sorted(argv[-len(names):]), sorted("/workspace/" + name for name in names))


class CheckovFileLevelSpanTests(unittest.TestCase):
    def test_file_level_check_with_line_zero_cites_line_one(self):
        doc = [{"check_type": "github_actions", "results": {"failed_checks": [
            {"check_id": "CKV2_GHA_1", "file_path": "/.github/workflows/ci.yml", "file_line_range": [0, 1]}]}}]
        self.assertEqual(b13.normalize("checkov", json.dumps(doc).encode()),
                         [{"rule_id": "CKV2_GHA_1", "path": ".github/workflows/ci.yml", "start_line": 1, "end_line": 1,
                           "framework": "github_actions"}])


class IacFailureValidationTests(unittest.TestCase):
    """Run 20261001T032047Z-fd64eb relaunch: the validator refused 02-iac-config-scan because a tool that
    never started was FAILED/tool-error with exit_code None, and checkov github_actions hits were published
    as kubernetes with a Dockerfile-only address disposition."""

    def test_failed_tools_pass_the_real_validator(self):
        results = {"kube-linter": {"status": "FAILED", "cause": "CONTAINER_START_FAILED", "exit_code": None},
                   "hadolint": {"status": "FAILED", "cause": "CONTAINER_EXIT_NONZERO", "exit_code": 1},
                   "checkov": {"status": "FAILED", "cause": "expected-output-missing", "exit_code": 0}}
        job = "02-iac-config-scan"
        with tempfile.TemporaryDirectory() as folder:
            run_id, attempt_id = "run-iac-fail", "attempt-iac-fail"
            run = Path(folder) / run_id
            manifest = run / "inputs" / "artifact-manifest.json"; manifest.parent.mkdir(parents=True)
            manifest.write_bytes(json.dumps({"run_id": run_id}, sort_keys=True).encode() + b"\n")
            source_sha = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
            source = run / "data" / "source"; source.mkdir(parents=True)
            (source / "Dockerfile").write_bytes(b"FROM alpine:3.20\n")
            (source / "deploy.yaml").write_bytes(b"apiVersion: v1\nkind: Pod\n")
            documents = workers.build_documents(job, source, run_id=run_id, attempt_id=attempt_id,
                                                 source_snapshot_sha256=source_sha, vendor_results=results)
            by_tool = {i["tool_id"]: i for i in documents["tool-results.json"]["tool_instances"]}
            self.assertEqual((by_tool["hadolint"]["terminal_status"], by_tool["hadolint"]["exit"]["exit_code"]),
                             ("FAILED", 1))
            self.assertEqual((by_tool["checkov"]["terminal_status"], by_tool["checkov"]["cause_code"]),
                             ("FAILED", "output-invalid"))
            self.assertEqual(by_tool["kube-linter"]["terminal_status"], "BLOCKED")
            gap_ids = [g["gap_id"] for g in documents["coverage.json"]["gaps"]]
            self.assertIn("gap-kube-linter-blocked-container-start-failed", gap_ids)
            attempt = run / "data/jobs" / job / "whole/attempts" / attempt_id
            workers.materialize_attempt(documents, attempt, dagster_run_id="dagster-iac-fail",
                started_at="2026-09-27T12:00:00Z", finished_at="2026-09-27T12:00:01Z")
            contract = json.loads((registry_paths.contract(workers.SPECS[job][0])).read_text())
            errors = validator.validate_vendor_prepass_attempt(attempt, contract, run_id=run_id,
                job_id=job, attempt_id=attempt_id, node_status=documents["status"],
                orchestration=validator.OrchestrationFacts(
                    "dagster-iac-fail", source_sha, validator.datetime.fromisoformat("2026-09-27T12:00:00+00:00")))
            self.assertEqual(errors, [])

    def test_iac_kind_by_checkov_framework(self):
        kind = workers._iac_kind
        self.assertEqual(kind("checkov", {"path": "dockerfiles/case-021/Dockerfile", "framework": "secrets"}), "dockerfile")
        self.assertEqual(kind("checkov", {"path": ".github/workflows/ci.yml", "framework": "github_actions"}),
                         "github-actions")
        self.assertIsNone(kind("checkov", {"path": "conf/app.yml", "framework": "openapi"}))
        self.assertEqual(kind("zizmor", {"path": ".github/workflows/ci.yml"}), "github-actions")
        self.assertEqual(kind("checkov", {"path": "k8s/pod.yaml", "framework": "kubernetes"}), "kubernetes")
        self.assertEqual(kind("tfsec", {"path": "main.tf"}), "terraform")
        self.assertEqual(kind("kube-linter", {"path": "k8s/pod.yaml"}), "kubernetes")


class ChecksecRelroTests(unittest.TestCase):
    def test_partial_relro_is_a_hit(self):
        doc = {"projects/cpp/case-001/build/case001": {"relro": "partial", "canary": "yes", "nx": "yes",
                                                        "pie": "yes", "fortify_source": "yes"}}
        records = b13.normalize("binskim", json.dumps(doc).encode())
        self.assertEqual([r["rule_id"] for r in records], ["CHECKSEC-FULL-RELRO"])


REAL = ROOT / "tests" / "fixtures" / "binary-hardening-real"
MAGIC = {"pe": b"MZ\x90\x00", "elf": b"\x7fELF\x02\x01\x01\x00", "macho": b"\xcf\xfa\xed\xfe"}


def real_paths():
    """binary_id -> path, from the recorded run."""
    return dict(line.split() for line in (REAL / "binary-ids.txt").read_text().splitlines())


def real_format(path):
    return "pe" if path.endswith(".exe") else "macho" if path.startswith("mac/") else "elf"


class BinaryHardeningRealOutputTests(unittest.TestCase):
    """02-binary-hardening 1.1 against output the tools actually printed (fixtures/binary-hardening-real):
    checksec 2.6.0 and blint 3.4.0 over ELF, PE32, PE32+ and Mach-O files, recorded 2026-10-01."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.paths = real_paths()
        self.source = self.tmp / "source"
        for path in self.paths.values():
            target = self.source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(MAGIC[real_format(path)] + hashlib.sha256(path.encode()).digest())

    def observations(self, metadata_name):
        bid = metadata_name.removesuffix("-metadata.json")
        metadata = json.loads((REAL / "blint-3.4.0" / metadata_name).read_text())
        return {i["check"]: i["reported"] for i in b13.blint_observations(real_format(self.paths[bid]), metadata)}

    def by_path(self, path):
        bid = cmb.binary_id(path)
        return self.observations(f"{bid}-metadata.json")

    def test_checksec_values_map_to_closed_verdicts(self):
        found = b13.checksec_observations((REAL / "checksec-2.6.0.json").read_bytes())
        self.assertEqual(set(found), {"case001", "case030", "nowrelro", "u1/a.out", "u2/a.out", "weak"})
        weak = {i["check"]: i["reported"] for i in found["weak"]}
        self.assertEqual(weak, {"position_independent": "absent", "non_executable_data": "absent",
                                "stack_protector": "absent", "relro": "absent", "fortify_source": "absent"})
        nowrelro = {i["check"]: i["reported"] for i in found["nowrelro"]}
        self.assertEqual(nowrelro["relro"], "absent")   # no GNU_RELRO segment although BIND_NOW is set
        self.assertEqual({i["check"]: i["reported"] for i in found["case001"]}["fortify_source"], "present")
        self.assertEqual(b13.checksec_reported((REAL / "checksec-2.6.0.json").read_bytes()), set(found))

    def test_blint_fields_known_to_be_wrong_are_never_read(self):
        # relro: blint says "full" for nowrelro (no GNU_RELRO segment): never taken from blint.
        self.assertNotIn("relro", self.by_path("nowrelro"))
        # aslr: blint says false for every PE (LIEF 1.0 prints UNKNOWN(64)); pie tracks DYNAMIC_BASE.
        self.assertEqual(self.by_path("win/t64.exe")["position_independent"], "present")
        self.assertEqual(self.by_path("win/nodyn.exe")["position_independent"], "absent")
        # Mach-O: MH_PIE exists only for executables, so a bundle gets no position_independent verdict.
        self.assertEqual(self.by_path("mac/speedups.so"), {"non_executable_data": "present", "stack_protector": "absent"})

    def test_blint_pe_load_configuration_and_dll_characteristics(self):
        t32, t64, heva = self.by_path("win/t32.exe"), self.by_path("win/t64.exe"), self.by_path("win/heva.exe")
        self.assertEqual(t32["safe_seh"], "present")
        self.assertEqual(t32["control_flow_guard"], "absent")
        self.assertNotIn("high_entropy_aslr", t32)              # PE32: not observed
        self.assertNotIn("control_flow_guard", t64)             # no load configuration: not observed
        self.assertNotIn("stack_protector", t64)
        self.assertEqual(t64["high_entropy_aslr"], "absent")    # UNKNOWN(64), UNKNOWN(256), UNKNOWN(32768)
        self.assertEqual(heva["high_entropy_aslr"], "present")  # UNKNOWN(32) set
        self.assertIsNone(b13._dll_characteristics("UNKNOWN(64), SOMETHING_NEW"))
        self.assertEqual(b13._dll_characteristics("DYNAMIC_BASE, NX_COMPAT"), 0x140)

    def test_blint_elf_matches_checksec_on_the_shared_checks(self):
        checksec = b13.checksec_observations((REAL / "checksec-2.6.0.json").read_bytes())
        for path in ("case001", "case030", "nowrelro", "u1/a.out", "u2/a.out", "weak"):
            blint = self.by_path(path)
            ours = {i["check"]: i["reported"] for i in checksec[path]}
            for name in ("position_independent", "non_executable_data", "stack_protector"):
                self.assertEqual(blint[name], ours[name], f"{path} {name}")

    def test_view_keeps_same_basename_binaries_apart_and_projection_names_skipped_files(self):
        view_root = self.tmp / "view"
        view = b13.blint_view(self.source, sorted(self.paths.values()), view_root)
        self.assertNotEqual(cmb.binary_id("u1/a.out"), cmb.binary_id("u2/a.out"))
        self.assertEqual(view, {cmb.binary_id(p): p for p in self.paths.values()})
        projection = json.loads(b13.blint_projection(REAL / "blint-3.4.0", view, view_root))
        self.assertEqual(projection["not_reported"], [{"binary_id": cmb.binary_id("win/broken.exe"), "path": "win/broken.exe"}])
        self.assertEqual(len(projection["binaries"]), len(self.paths) - 1)
        stray = self.tmp / "stray"; stray.mkdir()
        (stray / "bin-000000000000-metadata.json").write_text("{}")
        with self.assertRaises(b13.VendorToolFailed):
            b13.blint_projection(stray, view, view_root)

    def vendor_results(self, checksec=None):
        raw_checksec = checksec if checksec is not None else (REAL / "checksec-2.6.0.json").read_bytes()
        view_root = self.tmp / "view"
        view = b13.blint_view(self.source, sorted(self.paths.values()), view_root)
        raw_blint = b13.blint_projection(REAL / "blint-3.4.0", view, view_root)
        results = {"binskim": {"status": "OK", "raw": raw_checksec, "records": b13.normalize("binskim", raw_checksec)},
                   "blint": {"status": "OK", "raw": raw_blint, "records": b13.normalize("blint", raw_blint)}}
        for tool, result in results.items():
            receipt = {"schema": "appsec-review/vendor-b13-execution-receipt/1", "tool_id": tool,
                       "attempt_id": f"{tool}-verified-1", "request_sha256": "sha256:" + "1" * 64,
                       "result_sha256": "sha256:" + "2" * 64,
                       "output_sha256": "sha256:" + hashlib.sha256(result["raw"]).hexdigest(),
                       "permission_sha256": "sha256:" + "3" * 64, "permission_fingerprint_sha256": "sha256:" + "4" * 64,
                       "image_id": "tool-" + tool, "image_digest": "sha256:" + "5" * 64,
                       "argv": ["/opt/tool/bin/" + tool], "tool_version": "1.0.0", "tool_name": tool}
            result["auth"] = {"attempt_id": receipt["attempt_id"], "argv": receipt["argv"], "exit_code": 0,
                              "identity": {"repository": "docker.io/library/" + receipt["image_id"],
                                           "digest": receipt["image_digest"], "tool_version": "1.0.0", "tool_name": tool},
                              "receipt": receipt}
        return results

    def publish(self, vendor):
        doc = workers.execute_and_build("02-binary-hardening", self.source, run_id="run-1", attempt_id="attempt-1",
                                        source_snapshot_sha256=SOURCE_SHA, execution_root=self.tmp / "execution",
                                        now="2026-10-01T12:00:00Z", collector=lambda *a, **k: vendor)
        attempt = self.tmp / "attempt-1"
        workers.materialize_attempt(doc, attempt, dagster_run_id="dagster-1",
                                    started_at="2026-10-01T12:00:00Z", finished_at="2026-10-01T12:00:01Z")
        errors = cmb.verify_attempt("binary-hardening", attempt, self.source, expected_header=doc["header"],
                                    expected_dagster_run_id="dagster-1", node_status=doc["status"],
                                    declared_tool_ids=workers.SPECS["02-binary-hardening"][1],
                                    permitted_node_statuses=PERMITTED, on_unhandled="refuse",
                                    limits=evidence_redaction.DEFAULT_LIMITS)
        self.assertEqual(errors, [])
        return doc, {b["path"]: b for b in doc["binary-hardening.json"]["binaries"]}

    def test_real_output_publishes_a_valid_attempt_with_honest_verdicts(self):
        doc, binaries = self.publish(self.vendor_results())
        self.assertEqual(doc["status"], "OK_WITH_GAPS")
        self.assertEqual(doc["binary-hardening.json"]["schema"], "appsec-review/binary-hardening/1.1")
        weak = binaries["weak"]["checks"]
        self.assertEqual({k: weak[k] for k in ("position_independent", "non_executable_data", "stack_protector", "relro",
                                               "fortify_source")}, dict.fromkeys(
            ("position_independent", "non_executable_data", "stack_protector", "relro", "fortify_source"), "absent"))
        self.assertEqual(binaries["nowrelro"]["checks"]["relro"], "absent")
        self.assertEqual(binaries["u1/a.out"]["checks"]["stack_protector"], "absent")
        self.assertEqual(binaries["u2/a.out"]["checks"]["stack_protector"], "present")
        t64 = binaries["win/t64.exe"]
        self.assertEqual({i["tool_id"] for i in t64["observations"]}, {"blint"})
        self.assertEqual(t64["checks"]["control_flow_guard"], "not-assessed")   # was `present` before 1.1
        self.assertEqual(t64["checks"]["position_independent"], "present")
        self.assertEqual(binaries["win/heva.exe"]["checks"]["high_entropy_aslr"], "present")
        self.assertEqual(binaries["mac/speedups.so"]["checks"]["position_independent"], "not-assessed")
        broken = binaries["win/broken.exe"]
        self.assertEqual(broken["observations"], [])
        self.assertEqual({v for v in broken["checks"].values()}, {"not-assessed", "not-applicable-for-format"})
        coverage = {t["tool_id"]: t for t in doc["coverage.json"]["tools"]}
        self.assertIn({"path": "win/broken.exe", "reason_code": "parse-failed"}, coverage["blint"]["not_analyzed_inputs"])
        self.assertIn({"path": "win/t32.exe", "reason_code": "unsupported-format"}, coverage["binskim"]["unsupported_inputs"])
        instances = {i["tool_id"]: i for i in doc["tool-results.json"]["tool_instances"]}
        self.assertEqual(instances["binskim"]["result_record_count"], 6)
        self.assertEqual(instances["blint"]["result_record_count"], 11)

    def test_tools_that_disagree_are_published_as_not_assessed(self):
        checksec = json.loads((REAL / "checksec-2.6.0.json").read_text())
        checksec["/workspace/case001"]["canary"] = "no"
        _doc, binaries = self.publish(self.vendor_results(json.dumps(checksec).encode()))
        case001 = binaries["case001"]
        self.assertEqual(case001["checks"]["stack_protector"], "not-assessed")
        self.assertEqual(case001["tool_disagreements"], ["stack_protector"])


class GitHubActionsScanTests(unittest.TestCase):
    """D-34: GitHub Actions workflows are scanned (zizmor, plus checkov's github_actions checks) and published
    as iac_kind github-actions."""

    ZIZMOR_SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zizmor"}}, "results": [
        {"ruleId": "zizmor/template-injection", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": ".github/workflows/ci.yml"}, "region": {"startLine": 12, "endLine": 12}}}]},
        {"ruleId": "zizmor/dangerous-triggers", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": ".github/workflows/ci.yml"}, "region": {"startLine": 2}}}]}]}]}

    def test_zizmor_sarif_normalizes(self):
        records = b13.normalize("zizmor", json.dumps(self.ZIZMOR_SARIF).encode())
        self.assertEqual(records[0], {"rule_id": "template-injection", "path": ".github/workflows/ci.yml",
                                      "start_line": 12, "end_line": 12})
        self.assertEqual(records[1]["end_line"], 2)

    def test_probe_finds_workflows_and_actions(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in (".github/workflows/ci.yml", ".github/workflows/sub/x.yml", "tools/act/action.yml",
                        "deploy/k8s.yml", ".github/dependabot.yml"):
                path = Path(root, rel); path.parent.mkdir(parents=True, exist_ok=True); path.write_text("on: push\n")
            found = workers.probe("02-iac-config-scan", Path(root))["candidates"]["zizmor"]
        self.assertEqual(sorted(found), [".github/workflows/ci.yml", "tools/act/action.yml"])

    def test_workflow_hits_pass_the_iac_validator(self):
        job = "02-iac-config-scan"
        checkov_raw = json.dumps([{"check_type": "github_actions", "results": {"failed_checks": [
            {"check_id": "CKV2_GHA_1", "file_path": "/.github/workflows/ci.yml", "file_line_range": [0, 1]}]}}]).encode()
        vendor = {
            "zizmor": {"status": "OK", "raw": json.dumps(self.ZIZMOR_SARIF).encode(),
                       "records": b13.normalize("zizmor", json.dumps(self.ZIZMOR_SARIF).encode())},
            "checkov": {"status": "OK", "raw": checkov_raw, "records": b13.normalize("checkov", checkov_raw)}}
        for tool, result in vendor.items():
            receipt = {"schema": "appsec-review/vendor-b13-execution-receipt/1", "tool_id": tool,
                       "attempt_id": f"{tool}-verified-1", "request_sha256": "sha256:" + "1" * 64,
                       "result_sha256": "sha256:" + "2" * 64,
                       "output_sha256": "sha256:" + hashlib.sha256(result["raw"]).hexdigest(),
                       "permission_sha256": "sha256:" + "3" * 64, "permission_fingerprint_sha256": "sha256:" + "4" * 64,
                       "image_id": "tool-" + tool, "image_digest": "sha256:" + "5" * 64,
                       "argv": ["/opt/tool/bin/" + tool, "--offline"], "tool_version": "1.0.0", "tool_name": tool}
            result["auth"] = {"attempt_id": receipt["attempt_id"], "argv": receipt["argv"], "exit_code": 0,
                              "identity": {"repository": "docker.io/library/" + receipt["image_id"],
                                           "digest": receipt["image_digest"], "tool_version": "1.0.0", "tool_name": tool},
                              "receipt": receipt}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "source"
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/ci.yml").write_bytes(b"on: pull_request_target\n" + b"x: y\n" * 12)
            doc = workers.execute_and_build(job, root, run_id="run-1", attempt_id="attempt-1",
                                            source_snapshot_sha256=SOURCE_SHA, execution_root=Path(folder) / "execution",
                                            now="2026-09-27T12:00:00Z", collector=lambda *a, **k: vendor)
            hits = doc["iac-config-evidence.json"]["rule_hits"]
            self.assertEqual(sorted((h["tool_id"], h["resource"]["iac_kind"]) for h in hits),
                             [("checkov", "github-actions"), ("zizmor", "github-actions"), ("zizmor", "github-actions")])
            attempt = Path(folder) / "attempt-1"
            workers.materialize_attempt(doc, attempt, dagster_run_id="dagster-1",
                                        started_at="2026-09-27T12:00:00Z", finished_at="2026-09-27T12:00:01Z")
            errors = sic.validate_iac_attempt(attempt, tool_outputs_root=attempt, node_status=doc["status"],
                declared_tool_ids=workers.SPECS[job][1], permitted_node_statuses=sic.CAN_SKIP, on_unhandled="refuse",
                limits=evidence_redaction.DEFAULT_LIMITS, expected_dagster_run_id="dagster-1")
            self.assertEqual(errors, [])
