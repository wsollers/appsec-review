"""Focused nominal tests for the isolated E03 native-SAST core."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
FIXTURE = ROOT / "tests/fixtures/native-sast"
sys.path.insert(0, str(ROOT))
import registry_paths

import native_sast as worker  # noqa: E402
import native_sast_adapters as adapters  # noqa: E402
import evidence_assembly as assembly  # noqa: E402
from execution_state import Blocked, atomic_json, digest, file_hash, tree_hashes  # noqa: E402
from publish_job_output import ACCEPTED_SCHEMA  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402

VARIANT = {"variant_id": "locked-0123456789abcdef", "source": "accepted-native-build-unit",
           "image_id": "image_build_123456789abc", "image_digest": "sha256:" + "5" * 64,
           "commands_sha256": "sha256:" + "6" * 64}


def sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def accepted_native_build(folder: Path, *, source_revision="a" * 40,
                          result_revision=None, db_hash_override=None,
                          extra_entries=(), mutate_target=None):
    run_id, attempt_id = "run-e03", "native-attempt"
    base = folder / "native-build"; attempt = base / "attempts" / attempt_id
    output = attempt / "outputs/u/compile_commands.json"; output.parent.mkdir(parents=True)
    database = json.loads((FIXTURE / "compile_commands.json").read_text()) + list(extra_entries)
    output.write_text(json.dumps(database, indent=2) + "\n")
    binary = attempt / "outputs/u/binaries/hello"; binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELFfixture")
    target = folder / "target"; shutil.copytree(FIXTURE / "target", target)
    if mutate_target is not None:
        mutate_target(target)
    inputs = {"run_id": run_id, "job": worker.UPSTREAM_JOB,
              "source_snapshot_sha256": "sha256:" + "1" * 64,
              "source_revision": source_revision, "target_path": str(target.resolve()),
              "source_tree_sha256": worker._source_tree_identity(target.resolve())}
    atomic_json(attempt / "inputs.json", inputs)
    result = {"schema": "appsec-review/native-build/1", "run_id": run_id,
        "source_revision": result_revision or source_revision,
        "upstream": {"resolution": {"job": "02-build-resolution", "attempt_id": "r1",
                                     "lock_sha256": "sha256:" + "2" * 64},
                     "configured": {"job": "02-build-configure", "attempt_id": "c1",
                                    "result_sha256": "sha256:" + "3" * 64,
                                    "envelope_sha256": "sha256:" + "4" * 64}},
        "status": "OK", "units": [{"unit_id": "dir:.", "status": "OK",
            "image_id": "image_build_123456789abc", "image_digest": "sha256:" + "5" * 64,
            "commands": [{"phase": "configure"}, {"phase": "build"}],
            "compile_database": {"path": "outputs/u/compile_commands.json",
                "sha256": db_hash_override or sha(output), "entries": len(database)},
            "binaries": [{"source_path": "hello", "artifact_path": "outputs/u/binaries/hello",
                          "sha256": sha(binary), "size_bytes": binary.stat().st_size}]}],
        "coverage_gaps": []}
    atomic_json(attempt / "native-build.json", result)
    atomic_json(attempt / "b13-receipts.json", [])
    (attempt / "native-build-summary.md").write_text("# Native build\n")
    status = {"process": worker.UPSTREAM_JOB, "status": "OK", "source_revision": source_revision,
              "units": 1, "permissions": ["target-execution:native-build-v1@."], "network": "none"}
    atomic_json(attempt / "status.json", status)
    fingerprint = "sha256:" + "6" * 64
    artifacts = artifact_records(attempt, ["native-build.json", "b13-receipts.json",
        "native-build-summary.md", "status.json", "outputs/u/compile_commands.json",
        "outputs/u/binaries/hello"])
    envelope = terminal_envelope(run_id=run_id, job_id=worker.UPSTREAM_JOB,
        attempt_id=attempt_id, worker_kind="pinned_container",
        input_fingerprint=fingerprint, output_contract="native-build",
        started_at="2026-09-27T00:00:00Z", finished_at="2026-09-27T00:00:01Z",
        summary="native build complete", artifacts=artifacts, execution_status="OK",
        acceptance_status="CURRENT")
    atomic_json(attempt / "result.json", envelope)
    atomic_json(base / "latest.json", {"attempt_id": attempt_id})
    pointer = {"schema": ACCEPTED_SCHEMA, "status": "OK", "run_id": run_id,
        "job": worker.UPSTREAM_JOB, "attempt_id": attempt_id, "fingerprint": fingerprint,
        "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json"),
        "hashes": tree_hashes(attempt), "accepted_at": "2026-09-27T00:00:02Z"}
    atomic_json(base / "accepted.json", pointer)
    return base, attempt, target, fingerprint


def trial_tree(attempt: Path):
    clang = attempt / "tools/u/clang-cppcheck/scratch/native-sast"; clang.mkdir(parents=True)
    csa = attempt / "tools/u/csa/scratch/csa"; csa.mkdir(parents=True)
    for name in ("findings-clang-tidy.json", "native-sast-manifest.json", "cppcheck.xml"):
        shutil.copyfile(FIXTURE / name, clang / name)
    (clang / "clang-tidy.log").write_text("raw diagnostic\n")
    for name in ("findings-csa.json", "csa-summary.json"):
        shutil.copyfile(FIXTURE / name, csa / name)
    return clang.parents[1], csa.parents[1]


class NativeSastTests(unittest.TestCase):
    IMAGE = {"image_id": "audit-native", "digest": "sha256:" + "7" * 64}

    def test_missing_build_directory_rebases_to_nearest_existing_ancestor(self):
        raw = json.loads((FIXTURE / "compile_commands.json").read_text())
        for entry in raw:
            entry["directory"] = "/scratch/src/projects/x/build"
        adapted, _ = adapters.adapt_compile_database(raw, directory_exists=lambda rel: rel in ("projects", "projects/x"))
        self.assertEqual({e["directory"] for e in adapted}, {"/workspace/projects/x"})
        adapted, _ = adapters.adapt_compile_database(raw, directory_exists=lambda rel: False)
        self.assertEqual({e["directory"] for e in adapted}, {"/workspace"})

    def test_compile_database_adapter_is_deterministic_and_names_unsupported_units(self):
        raw = json.loads((FIXTURE / "compile_commands.json").read_text())
        first, unsupported = adapters.adapt_compile_database(raw)
        second, _ = adapters.adapt_compile_database(raw)
        self.assertEqual(first, second)
        self.assertEqual(unsupported, ["README.md"])
        self.assertEqual(first[0]["file"], "/workspace/src/greet.c")
        self.assertIn("-I/workspace/include", first[0]["arguments"])
        self.assertNotIn("/scratch/src", json.dumps(first))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "compile_commands.json"); atomic_json(path, first)
            self.assertEqual(adapters.canonical_sha(first), sha(path))

    def test_compile_database_rejects_escape_duplicate_and_no_supported_unit(self):
        raw = json.loads((FIXTURE / "compile_commands.json").read_text())
        hostile = copy.deepcopy(raw[0]); hostile["arguments"].extend(["-Xclang", "-load", "/workspace/plugin.so"])
        response = copy.deepcopy(raw[0]); response["arguments"].append("@/workspace/flags.rsp")
        command_only = copy.deepcopy(raw[0]); command_only["command"] = " ".join(command_only.pop("arguments"))
        for value in ([{**raw[0], "file": "/host/greet.c"}], [raw[0], copy.deepcopy(raw[0])],
                      [raw[1]], [hostile], [response], [command_only]):
            with self.subTest(value=value), self.assertRaises(adapters.AdapterError):
                adapters.adapt_compile_database(value)

    def test_exact_accepted_native_build_and_lineage_are_revalidated(self):
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(Path(folder))
            loaded = worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        self.assertEqual(loaded["binding"]["attempt_id"], "native-attempt")
        self.assertEqual(loaded["units"][0]["unsupported"], ["README.md"])
        self.assertRegex(loaded["units"][0]["build_variant"]["variant_id"], r"^locked-[0-9a-f]{16}$")
        self.assertRegex(loaded["source_tree_sha256"], r"^sha256:[0-9a-f]{64}$")

    GENERATED = {"directory": "/scratch/src/build",
                 "file": "/scratch/src/build/app_autogen/mocs_compilation.cpp",
                 "arguments": ["/opt/llvm/bin/clang++", "-c",
                               "/scratch/src/build/app_autogen/mocs_compilation.cpp"]}

    def test_generated_sources_absent_from_checkout_are_recorded_gaps(self):
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(
                Path(folder), extra_entries=[self.GENERATED])
            loaded = worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        unit = loaded["units"][0]
        self.assertEqual(unit["generated"], ["build/app_autogen/mocs_compilation.cpp"])
        self.assertEqual([entry["file"] for entry in unit["adapted"]], ["/workspace/src/greet.c"])
        self.assertEqual(list(unit["sources"]), ["src/greet.c"])
        self.assertEqual(unit["compile_database"]["adapted_sha256"], adapters.canonical_sha(unit["adapted"]))
        self.assertEqual(loaded["excluded_units"], [])
        self.assertEqual(worker.generated_gaps(unit["generated"]), [
            "generated-sources-not-in-checkout:1",
            "generated-source-not-in-checkout:build/app_autogen/mocs_compilation.cpp"])
        many = worker.generated_gaps([f"b/{i}.cpp" for i in range(9)])
        self.assertEqual(many[0], "generated-sources-not-in-checkout:9")
        self.assertEqual(len(many), 1 + worker.GENERATED_SAMPLE)

    def test_unit_with_only_generated_sources_is_excluded_not_failed(self):
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(
                Path(folder), extra_entries=[self.GENERATED],
                mutate_target=lambda target: (target / "src/greet.c").unlink())
            loaded = worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        self.assertEqual(loaded["units"], [])
        self.assertEqual(loaded["excluded_units"], [{"unit_id": "dir:.", "unsupported": ["README.md"],
            "generated": ["build/app_autogen/mocs_compilation.cpp", "src/greet.c"]}])
        gaps = worker.excluded_unit_gaps(loaded)
        self.assertIn("unit-without-checkout-sources:dir:.", gaps)
        self.assertIn("generated-sources-not-in-checkout:2", gaps)

    def test_generated_path_through_symlink_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            outside = Path(folder, "outside"); outside.mkdir()
            base, _attempt, _target, fingerprint = accepted_native_build(
                Path(folder), extra_entries=[self.GENERATED],
                mutate_target=lambda target: (target / "build").symlink_to(outside))
            with self.assertRaisesRegex(Blocked, "does not resolve beneath"):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)

    def test_post_build_checkout_mutation_changes_bound_source_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, target, fingerprint = accepted_native_build(Path(folder))
            first = worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
            (target / "post-build-note.txt").write_text("changed after build\n", encoding="utf-8")
            with self.assertRaises(Blocked):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        self.assertRegex(first["source_tree_sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_native_build_without_attested_source_tree_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            base, attempt, _target, fingerprint = accepted_native_build(Path(folder))
            value = json.loads((attempt / "inputs.json").read_text())
            del value["source_tree_sha256"]
            atomic_json(attempt / "inputs.json", value)
            pointer = json.loads((base / "accepted.json").read_text())
            pointer["hashes"] = tree_hashes(attempt)
            atomic_json(base / "accepted.json", pointer)
            with self.assertRaisesRegex(Blocked, "E02 must attest"):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)

    def test_wrong_open_stale_or_mismatched_native_build_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(Path(folder))
            pointer = json.loads((base / "accepted.json").read_text()); pointer["extra"] = "open"
            atomic_json(base / "accepted.json", pointer)
            with self.assertRaises(Blocked):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(Path(folder))
            with self.assertRaises(Blocked):
                worker.load_native_build(base, run_id="run-e03",
                                         expected_fingerprint="sha256:" + "8" * 64)
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(
                Path(folder), result_revision="b" * 40)
            with self.assertRaises(Blocked):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        with tempfile.TemporaryDirectory() as folder:
            base, _attempt, _target, fingerprint = accepted_native_build(
                Path(folder), db_hash_override="sha256:" + "9" * 64)
            with self.assertRaises(Blocked):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
        with tempfile.TemporaryDirectory() as folder:
            base, attempt, _target, fingerprint = accepted_native_build(Path(folder))
            (attempt / "outputs/u/compile_commands.json").write_text("[]\n")
            with self.assertRaises(Blocked):
                worker.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)

    def test_normalized_three_tool_output_is_deterministic_hash_bound_and_has_no_promotion(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder, "attempt"); attempt.mkdir()
            target = Path(folder, "target"); shutil.copytree(FIXTURE / "target", target)
            clang, csa = trial_tree(attempt)
            adapted, unsupported = adapters.adapt_compile_database(
                json.loads((FIXTURE / "compile_commands.json").read_text()))
            unit = {"unit_id": "dir:.", "build_variant": VARIANT,
                    "compile_database": {"path": "outputs/u/compile_commands.json",
                        "sha256": "sha256:" + "1" * 64, "entries": 2,
                        "adapted_path": "adapted-inputs/0123456789abcdef/compile_commands.json",
                        "adapted_sha256": adapters.canonical_sha(adapted)},
                    "adapted": adapted, "unsupported": unsupported}
            inputs = {"image": self.IMAGE, "config": json.loads(worker.CONFIG.read_text()),
                      "config_sha256": sha(worker.CONFIG)}
            first = worker.normalize_unit(unit, target=target, attempt=attempt,
                clang_trial=clang, csa_trial=csa, inputs=inputs)
            second = worker.normalize_unit(unit, target=target, attempt=attempt,
                clang_trial=clang, csa_trial=csa, inputs=inputs)
        self.assertEqual(first, second)
        self.assertEqual([tool["tool_id"] for tool in first["tools"]], list(worker.TOOLS))
        self.assertEqual(len(first["leads"]), 3)
        encoded = json.dumps(first).lower()
        self.assertNotIn("raw analyzer message", encoded)
        self.assertNotIn("severity", encoded)
        self.assertNotIn("raw csa message", encoded)
        self.assertEqual(first["coverage_gaps"], ["unsupported-translation-unit:README.md"])

    def test_analyzer_errors_are_explicit_partial_coverage_gaps(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder, "attempt"); attempt.mkdir()
            target = Path(folder, "target"); shutil.copytree(FIXTURE / "target", target)
            clang, csa = trial_tree(attempt)
            manifest_path = clang / "scratch/native-sast/native-sast-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["clang_tidy"]["files_nonzero_exit"] = 1
            manifest["cppcheck"]["exit_code"] = 2
            atomic_json(manifest_path, manifest)
            summary_path = csa / "scratch/csa/csa-summary.json"
            summary = json.loads(summary_path.read_text()); summary["tu_error"] = 1
            atomic_json(summary_path, summary)
            adapted, unsupported = adapters.adapt_compile_database(
                json.loads((FIXTURE / "compile_commands.json").read_text()))
            unit = {"unit_id": "dir:.", "build_variant": VARIANT,
                    "compile_database": {"path": "db", "sha256": "sha256:" + "1" * 64,
                        "entries": 2, "adapted_path": "adapted-inputs/0123456789abcdef/compile_commands.json",
                        "adapted_sha256": adapters.canonical_sha(adapted)},
                    "adapted": adapted, "unsupported": unsupported}
            inputs = {"image": self.IMAGE, "config": json.loads(worker.CONFIG.read_text()),
                      "config_sha256": sha(worker.CONFIG)}
            result = worker.normalize_unit(unit, target=target, attempt=attempt,
                clang_trial=clang, csa_trial=csa, inputs=inputs)
        self.assertEqual([tool["status"] for tool in result["tools"]], ["PARTIAL", "ERROR", "PARTIAL"])
        self.assertTrue(any(gap.startswith("clang-tidy-tool-error") for gap in result["coverage_gaps"]))
        self.assertTrue(any(gap.startswith("cppcheck-tool-error") for gap in result["coverage_gaps"]))
        self.assertTrue(any(gap.startswith("clang-static-analyzer-tool-error") for gap in result["coverage_gaps"]))

    def test_requests_are_offline_read_only_pinned_and_never_execute_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "target"); target.mkdir()
            db = Path(folder, "db"); db.mkdir()
            inputs = {"target_path": str(target), "source_snapshot_sha256": "sha256:" + "1" * 64,
                      "image": self.IMAGE, "config": json.loads(worker.CONFIG.read_text())}
            unit = {"unit_id": "dir:."}
            with mock.patch.object(worker, "_permission", return_value={"requirement": {}, "grants": [], "decision": {}}):
                requests = [worker._request("run", "a", inputs, unit, db, group)
                            for group in ("clang-cppcheck", "csa")]
        for request in requests:
            self.assertEqual(request["network"], {"mode": "none", "destinations": []})
            self.assertEqual(request["image"], self.IMAGE)
            self.assertEqual(request["target_mounts"][0]["container_path"], "/workspace")
            command = " ".join(request["argv"])
            self.assertNotIn("/workspace/src/greet", command)
            self.assertNotIn("make", command)

    def test_result_schema_and_registry_are_nominal_not_executable_or_qualified(self):
        template = json.loads((registry_paths.template("02-native-sast")).read_text())
        contract = json.loads((registry_paths.contract("native-sast")).read_text())
        self.assertFalse(template["implemented"])
        self.assertEqual(template["composition"]["output_contract_id"], contract["contract_id"])
        self.assertEqual(contract["claim_class"], {
            "claim_class_id": "native_static_evidence",
            "allowed_assertions": ["static-analysis-lead", "source-citation", "coverage-gap"],
            "forbidden_promotions": ["finding", "severity", "runtime-state"],
        })
        self.assertIn("implemented_not_qualified", (ROOT / "native_sast.py").read_text())
        with tempfile.TemporaryDirectory() as folder:
            attempt = Path(folder, "attempt"); attempt.mkdir()
            target = Path(folder, "target"); shutil.copytree(FIXTURE / "target", target)
            clang, csa = trial_tree(attempt)
            adapted, unsupported = adapters.adapt_compile_database(
                json.loads((FIXTURE / "compile_commands.json").read_text()))
            unit = {"unit_id": "dir:.", "build_variant": VARIANT,
                    "compile_database": {"path": "outputs/u/compile_commands.json",
                        "sha256": "sha256:" + "1" * 64, "entries": 2,
                        "adapted_path": "adapted-inputs/0123456789abcdef/compile_commands.json",
                        "adapted_sha256": adapters.canonical_sha(adapted)},
                    "adapted": adapted, "unsupported": unsupported}
            inputs = {"image": self.IMAGE, "config": json.loads(worker.CONFIG.read_text()),
                      "config_sha256": sha(worker.CONFIG)}
            normalized = worker.normalize_unit(unit, target=target, attempt=attempt,
                clang_trial=clang, csa_trial=csa, inputs=inputs)
            result = {"schema": worker.SCHEMA, "run_id": "run-e03", "job_id": worker.JOB,
                "attempt_id": "attempt", "source_snapshot_sha256": "sha256:" + "1" * 64,
                "native_build": {"job_id": worker.UPSTREAM_JOB, "attempt_id": "native-attempt",
                    "fingerprint": "sha256:" + "2" * 64, "pointer_sha256": "sha256:" + "3" * 64,
                    "envelope_sha256": "sha256:" + "4" * 64, "result_sha256": "sha256:" + "5" * 64,
                    "source_revision": "a" * 40},
                "status": "OK_WITH_GAPS", "units": [normalized],
                "coverage_gaps": normalized["coverage_gaps"]}
            atomic_json(attempt / worker.RESULT, result)
            atomic_json(attempt / worker.RECEIPTS, [])
            (attempt / worker.SUMMARY).write_text("# Native SAST\n")
            status = {"process": worker.JOB, "status": "OK_WITH_GAPS",
                "source_snapshot_sha256": result["source_snapshot_sha256"],
                "native_build_attempt_id": "native-attempt", "build_variants": [VARIANT["variant_id"]],
                "tools_run": list(worker.TOOLS), "leads": 3, "network": "none",
                "qualification": "implemented_not_qualified"}
            atomic_json(attempt / "status.json", status)
            permissions = json.loads((registry_paths.template("02-native-sast")).read_text())["permissions"]
            atomic_json(attempt / "permission.json", {"schema": worker.PERMISSION_SCHEMA,
                "run_id": "run-e03", "job_id": worker.JOB,
                "source_snapshot_sha256": result["source_snapshot_sha256"],
                "permissions": permissions})
            atomic_json(attempt / "lineage.json", {"schema": worker.LINEAGE_SCHEMA,
                "run_id": "run-e03", "job_id": worker.JOB,
                "source_snapshot_sha256": result["source_snapshot_sha256"],
                "build_lineage_sha256": "sha256:" + digest(result["native_build"])})
            fingerprint = "sha256:" + "f" * 64
            envelope = terminal_envelope(run_id="run-e03", job_id=worker.JOB,
                attempt_id="attempt", worker_kind="pinned_container", execution_status="OK_WITH_GAPS",
                acceptance_status="CURRENT", input_fingerprint=fingerprint,
                output_contract=worker.CONTRACT, started_at="2026-09-27T00:00:00Z",
                finished_at="2026-09-27T00:00:01Z", summary="three analyzer leads",
                artifacts=artifact_records(attempt, [worker.RESULT, worker.RECEIPTS,
                    worker.SUMMARY, "status.json", "permission.json", "lineage.json"]),
                gaps=result["coverage_gaps"])
            self.assertEqual(validate_document(result, "native-sast.schema.json"), [])
            self.assertEqual(validate_job_output(attempt, envelope, fingerprint,
                expected_run_id="run-e03", expected_job_id=worker.JOB,
                orchestration=NO_ORCHESTRATION_FACTS), [])
            self.assertEqual(json.loads((attempt / "permission.json").read_text())["permissions"],
                             permissions)

    def test_claim_ceiling_rejects_finding_promotion(self):
        contract_path = registry_paths.contract("native-sast")
        contract = json.loads(contract_path.read_text())
        self.assertNotIn("claim_types", contract)
        from validate_job_output import _claim_class_errors
        self.assertEqual(_claim_class_errors(contract, {"lead": "source citation"}), [])
        errors = _claim_class_errors(contract, {"severity": "high"})
        self.assertTrue(any("severity promotion" in error for error in errors))

    def test_f02_accepts_exact_permission_and_lineage_receipts(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = Path(folder); producer = supply / "producers" / worker.JOB
            attempt_id = "native-sast-attempt"; attempt = producer / "attempts" / attempt_id
            attempt.mkdir(parents=True)
            source = "sha256:" + "1" * 64
            build = "sha256:" + "2" * 64
            atomic_json(attempt / "permission.json", {"schema": assembly.PERMISSION_SCHEMA,
                "run_id": "run-e03", "job_id": worker.JOB,
                "source_snapshot_sha256": source, "permissions": worker._permissions()})
            atomic_json(attempt / "lineage.json", {"schema": assembly.LINEAGE_SCHEMA,
                "run_id": "run-e03", "job_id": worker.JOB,
                "source_snapshot_sha256": source, "build_lineage_sha256": build})
            atomic_json(attempt / "native-sast.json", {"evidence": "fixture"})
            fingerprint = "sha256:" + "3" * 64
            envelope = terminal_envelope(run_id="run-e03", job_id=worker.JOB,
                attempt_id=attempt_id, worker_kind="pinned_container", execution_status="OK",
                acceptance_status="CURRENT", input_fingerprint=fingerprint,
                output_contract=worker.CONTRACT, started_at="2026-09-27T00:00:00Z",
                finished_at="2026-09-27T00:00:01Z", summary="native SAST fixture",
                artifacts=artifact_records(attempt, ["permission.json", "lineage.json", "native-sast.json"]))
            atomic_json(attempt / "result.json", envelope)
            pointer = {"schema": ACCEPTED_SCHEMA, "status": "OK", "run_id": "run-e03",
                "job": worker.JOB, "attempt_id": attempt_id, "fingerprint": fingerprint,
                "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json"),
                "hashes": tree_hashes(attempt), "accepted_at": "2026-09-27T00:00:02Z"}
            atomic_json(producer / "accepted.json", pointer)
            atomic_json(producer / "latest.json", {"attempt_id": attempt_id})
            instance_id = "a" * 32
            entry, copies = assembly._producer(supply, "run-e03", source,
                {"job": worker.JOB, "contract": worker.CONTRACT, "allowed_skip_reasons": []},
                {"source_snapshot_sha256": source, "build_lineage_sha256": build,
                 "permissions": worker._permissions(), "terminal_instance_ids": [instance_id]},
                {instance_id: {"instance_id": instance_id, "state": "succeeded",
                               "group_id": "native-sast"}})
            forged = json.loads((attempt / "permission.json").read_text())
            forged["permissions"] = [*worker._permissions(), "network"]
            atomic_json(attempt / "permission.json", forged)
            envelope["artifacts"] = artifact_records(
                attempt, ["permission.json", "lineage.json", "native-sast.json"])
            atomic_json(attempt / "result.json", envelope)
            pointer["envelope_sha256"] = file_hash(attempt / "result.json")
            pointer["hashes"] = tree_hashes(attempt)
            atomic_json(producer / "accepted.json", pointer)
            with self.assertRaises(Blocked):
                assembly._producer(supply, "run-e03", source,
                    {"job": worker.JOB, "contract": worker.CONTRACT, "allowed_skip_reasons": []},
                    {"source_snapshot_sha256": source, "build_lineage_sha256": build,
                     "permissions": worker._permissions(), "terminal_instance_ids": [instance_id]},
                    {instance_id: {"instance_id": instance_id, "state": "succeeded",
                                   "group_id": "native-sast"}})
        self.assertEqual(entry["disposition"], "accepted")
        self.assertEqual(entry["build_lineage_sha256"], build)
        self.assertEqual(len(copies), 3)

    def test_permissions_come_from_canonical_template(self):
        canonical = worker._permissions()
        self.assertEqual(canonical, json.loads((registry_paths.template("02-native-sast")).read_text())["permissions"])
        self.assertNotIn("execute-container-static-analysis", canonical)


class PerUnitFailureTests(unittest.TestCase):
    """B1: one bad unit is a recorded gap; only a broken job fails."""
    IMAGE = NativeSastTests.IMAGE

    def _unit(self, unit_id, adapted, unsupported):
        return {"unit_id": unit_id, "build_variant": VARIANT,
                "compile_database": {"path": "db", "sha256": "sha256:" + "1" * 64, "entries": 2,
                    "adapted_path": "adapted-inputs/0123456789abcdef/compile_commands.json",
                    "adapted_sha256": adapters.canonical_sha(adapted)},
                "adapted": adapted, "unsupported": unsupported, "generated": []}

    def _setup(self, folder):
        attempt = Path(folder, "attempt"); attempt.mkdir()
        target = Path(folder, "target"); shutil.copytree(FIXTURE / "target", target)
        clang, csa = trial_tree(attempt)
        adapted, unsupported = adapters.adapt_compile_database(
            json.loads((FIXTURE / "compile_commands.json").read_text()))
        inputs = {"image": self.IMAGE, "config": json.loads(worker.CONFIG.read_text()),
                  "config_sha256": sha(worker.CONFIG), "excluded_units": [],
                  "source_snapshot_sha256": "sha256:" + "1" * 64,
                  "native_build": {"job_id": "02-native-build"},
                  "units": [self._unit("good", adapted, unsupported), self._unit("bad", adapted, unsupported)]}
        return attempt, target, clang, csa, inputs

    def _outcomes(self, attempt, target, clang, csa, inputs, bad_causes, bad_trials=None):
        ok = {"clang-cppcheck": None, "csa": None}
        good = worker.unit_outcome(inputs["units"][0], ok, target=target, attempt=attempt,
            trials={"clang-cppcheck": clang, "csa": csa}, inputs=inputs)
        bad = worker.unit_outcome(inputs["units"][1], bad_causes, target=target, attempt=attempt,
            trials=bad_trials or {"clang-cppcheck": clang, "csa": csa}, inputs=inputs)
        return [good, bad]

    def test_terminal_cause_mapping_and_job_level_failures(self):
        f = lambda cause: {"execution_status": "FAILED", "cause": cause}
        self.assertIsNone(worker.terminal_failure_cause({"execution_status": "OK", "cause": None}))
        self.assertEqual(worker.terminal_failure_cause(f("TIMEOUT")), "TIMEOUT")
        self.assertEqual(worker.terminal_failure_cause(f("OOM_KILLED")), "OOM")
        self.assertEqual(worker.terminal_failure_cause(f("CONTAINER_EXIT_NONZERO")), "TOOL_ERROR")
        for terminal in (f("WORKER_LOST"), f("CLEANUP_FAILED"),
                         {"execution_status": "BLOCKED", "cause": "DOCKER_UNAVAILABLE"},
                         {"execution_status": "CANCELED", "cause": "CANCELED"}):
            with self.assertRaises(RuntimeError):
                worker.terminal_failure_cause(terminal)

    def test_one_failing_unit_is_ok_with_gaps_and_keeps_good_leads(self):
        for cause in worker.FAILURE_CAUSES[:1] + ("OOM", "TOOL_ERROR"):
            with tempfile.TemporaryDirectory() as folder:
                attempt, target, clang, csa, inputs = self._setup(folder)
                outcomes = self._outcomes(attempt, target, clang, csa, inputs,
                                          {"clang-cppcheck": cause, "csa": None})
                result = worker.assemble_result("run-e03", "a1", inputs, outcomes)
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        self.assertEqual([u["unit_id"] for u in result["units"]], ["good"])
        self.assertEqual(len(result["units"][0]["leads"]), 3)
        self.assertEqual(result["failed_units"], [{"unit_id": "bad", "cause": "TOOL_ERROR"}])
        self.assertIn("unit-analysis-failed:bad:TOOL_ERROR", result["coverage_gaps"])

    def test_failure_cause_precedence_and_enum_only(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt, target, clang, csa, inputs = self._setup(folder)
            outcomes = self._outcomes(attempt, target, clang, csa, inputs,
                                      {"clang-cppcheck": "TIMEOUT", "csa": "OOM"})
            result = worker.assemble_result("run-e03", "a1", inputs, outcomes)
        self.assertEqual(result["failed_units"], [{"unit_id": "bad", "cause": "OOM"}])

    def test_unparsable_analyzer_output_is_a_parse_error_gap(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt, target, clang, csa, inputs = self._setup(folder)
            bad_clang = Path(folder, "bad-clang"); shutil.copytree(clang, bad_clang)
            (bad_clang / "scratch/native-sast/findings-clang-tidy.json").write_text("{not json /etc/passwd")
            outcomes = self._outcomes(attempt, target, clang, csa, inputs,
                {"clang-cppcheck": None, "csa": None},
                {"clang-cppcheck": bad_clang, "csa": csa})
            result = worker.assemble_result("run-e03", "a1", inputs, outcomes)
        self.assertEqual(result["failed_units"], [{"unit_id": "bad", "cause": "PARSE_ERROR"}])
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        self.assertNotIn("passwd", json.dumps(result))

    def test_all_units_failing_fails_the_job(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt, target, clang, csa, inputs = self._setup(folder)
            outcomes = [worker.unit_outcome(unit, {"clang-cppcheck": "TIMEOUT", "csa": None},
                target=target, attempt=attempt, trials={"clang-cppcheck": clang, "csa": csa},
                inputs=inputs) for unit in inputs["units"]]
            with self.assertRaises(RuntimeError):
                worker.assemble_result("run-e03", "a1", inputs, outcomes)

    def test_schema_accepts_failed_units_and_downstream_reads_units_leads(self):
        with tempfile.TemporaryDirectory() as folder:
            attempt, target, clang, csa, inputs = self._setup(folder)
            inputs["native_build"] = {"job_id": "02-native-build", "attempt_id": "n1",
                "fingerprint": "sha256:" + "6" * 64, "pointer_sha256": "sha256:" + "a" * 64,
                "envelope_sha256": "sha256:" + "b" * 64, "result_sha256": "sha256:" + "c" * 64,
                "source_revision": "a" * 40}
            outcomes = self._outcomes(attempt, target, clang, csa, inputs,
                                      {"clang-cppcheck": "TIMEOUT", "csa": None})
            result = worker.assemble_result("run-e03", "a1", inputs, outcomes)
        self.assertEqual(validate_document(result, "native-sast.schema.json"), [])
        leads = [lead for unit in result.get("units", []) for lead in unit.get("leads", [])]
        self.assertEqual(len(leads), 3)
        result["failed_units"][0]["cause"] = "raw exception text"
        self.assertTrue(validate_document(result, "native-sast.schema.json"))


if __name__ == "__main__":
    unittest.main()
