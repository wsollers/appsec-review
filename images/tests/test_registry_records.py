"""B16 host-local container-image registry generation and Docker drift checks.

    cd images && python3 -B -m unittest tests.test_registry_records
    cd images && APPSEC_LIVE_DOCKER_TESTS=1 python3 -B -m unittest tests.test_registry_records.LiveDocker
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

IMAGES = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGES))

import registry_records as rr  # noqa: E402

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.images = self.root / "images"
        self.state = self.root / "state"
        self.output = self.root / "registry"
        folder = self.images / "tool-one"
        folder.mkdir(parents=True)
        (folder / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (folder / "image.json").write_text(json.dumps({
            "schema": "appsec-review/image-build/1",
            "builds": [{
                "image_id": "tool-one", "tag": "tool-one:local", "dockerfile": "Dockerfile",
                "context": ".", "build_args": {}, "requires_images": [], "prebuild": [],
                "timeout_seconds": 60,
            }],
        }), encoding="utf-8")
        latest = self.state / "tool-one" / "latest.json"
        latest.parent.mkdir(parents=True)
        latest.write_text(json.dumps({
            "attempt_id": "2026-09-27T010203Z-deadbeef", "fingerprint": SHA_B,
            "finished_at": "2026-09-27T01:02:03+00:00", "image_digest": SHA_A,
            "image_id": "tool-one", "tag": "tool-one:local",
        }), encoding="utf-8")

    def collect(self, value=SHA_A):
        return rr.collect_records(images_root=self.images, state_root=self.state,
                                  image_ids=("tool-one",), inspect=lambda _tag: value,
                                  fingerprint=lambda _build: SHA_B)


class PureRecords(Workspace):
    def test_record_is_closed_schema_valid_and_contains_build_provenance(self):
        records = self.collect()
        rr.validate_records(records)
        record = records["tool-one"]
        self.assertEqual(record["repository"], "docker.io/library/tool-one")
        self.assertEqual((record["digest"], record["digest_kind"]), (SHA_A, "image-id"))
        self.assertEqual(record["build_fingerprint_sha256"], SHA_B)
        self.assertEqual(record["build_attempt_id"], "2026-09-27T010203Z-deadbeef")
        self.assertEqual(record["dockerfile_sha256"], rr.file_sha256(self.images / "tool-one" / "Dockerfile"))

    def test_repository_normalization_never_carries_a_tag(self):
        cases = {
            "tool:local": "docker.io/library/tool",
            "team/tool:v1": "docker.io/team/tool",
            "registry.example/team/tool:v1": "registry.example/team/tool",
            "localhost:5000/team/tool:v1": "localhost:5000/team/tool",
        }
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                self.assertEqual(rr.repository_from_tag(tag), expected)
        for bad in ("tool", ":local", ""):
            with self.subTest(bad=bad), self.assertRaises(rr.RegistryRecordError):
                rr.repository_from_tag(bad)

    def test_docker_or_state_drift_fails_before_any_record_is_written(self):
        self.output.mkdir()
        sentinel = self.output / "tool-one.json"
        sentinel.write_text("old\n", encoding="utf-8")
        with self.assertRaisesRegex(rr.RegistryRecordError, "drifted"):
            self.collect(SHA_B)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "old\n")

    def test_generate_then_check_is_byte_exact_and_tampering_fails(self):
        records = self.collect()
        rr.write_records(records, self.output)
        rr.check_records(self.collect(), self.output)
        path = self.output / "tool-one.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["build_attempt_id"] = "edited"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(rr.RegistryRecordError, "drifted"):
            rr.check_records(self.collect(), self.output)

    def test_latest_state_and_dockerfile_are_required_and_bound(self):
        latest = self.state / "tool-one" / "latest.json"
        for mutation in ("missing", "other-image", "extra-key", "bad-tag", "bad-time"):
            original = latest.read_bytes()
            with self.subTest(mutation=mutation):
                if mutation == "missing":
                    latest.unlink()
                else:
                    value = json.loads(original)
                    if mutation == "other-image":
                        value["image_id"] = "tool-two"
                    elif mutation == "bad-tag":
                        value["tag"] = None
                    elif mutation == "bad-time":
                        value["finished_at"] = "eventually"
                    else:
                        value["unexpected"] = True
                    latest.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(rr.RegistryRecordError):
                    self.collect()
                latest.write_bytes(original)
        (self.images / "tool-one" / "Dockerfile").unlink()
        with self.assertRaisesRegex(rr.RegistryRecordError, "Dockerfile"):
            self.collect()

    def test_changed_image_inputs_are_not_registered_under_an_old_success(self):
        with self.assertRaisesRegex(rr.RegistryRecordError, "build fingerprint"):
            rr.collect_records(images_root=self.images, state_root=self.state,
                               image_ids=("tool-one",), inspect=lambda _tag: SHA_A,
                               fingerprint=lambda _build: "sha256:" + "f" * 64)


class DeclaredSet(unittest.TestCase):
    def test_b16_set_is_the_seven_shared_images_and_sixteen_per_tool_images(self):
        self.assertEqual(len(rr.TOOL_IMAGE_IDS), 16)
        self.assertEqual(len(rr.STEP4_IMAGE_IDS), 23)
        self.assertEqual(len(rr.STEP4_IMAGE_IDS), len(set(rr.STEP4_IMAGE_IDS)))
        builds = __import__("image_build").load_builds(IMAGES)
        self.assertEqual(set(rr.STEP4_IMAGE_IDS) - set(builds), set())
        self.assertNotIn("audit-static", rr.STEP4_IMAGE_IDS)

    def test_code_location_generates_before_starting_dagster(self):
        script = (rr.REPO / "orchestrator" / "dagster" / "code-location.sh").read_text(encoding="utf-8")
        generate = '"$REPO/images/registry_records.py" generate'
        start = 'exec "$VENV/bin/dagster" code-server start'
        self.assertIn(generate, script)
        self.assertIn(start, script)
        self.assertLess(script.index(generate), script.index(start))

    def test_cli_can_generate_only_osv_without_loading_unrelated_build_state(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(rr, "collect_records", return_value={"tool-osv-scanner": {}}) as collect, \
                mock.patch.object(rr, "write_records") as write:
            self.assertEqual(rr.main(["generate", "--image-id", "tool-osv-scanner",
                                      "--output-dir", temporary]), 0)
        self.assertEqual(collect.call_args.kwargs["image_ids"], ("tool-osv-scanner",))
        write.assert_called_once()


@unittest.skipUnless(os.environ.get("APPSEC_LIVE_DOCKER_TESTS") == "1",
                     "set APPSEC_LIVE_DOCKER_TESTS=1 for the host-image drift test")
class LiveDocker(unittest.TestCase):
    def test_every_generated_record_matches_build_state_and_docker_inspect(self):
        if not shutil.which("docker"):
            self.skipTest("docker CLI not installed")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            records = rr.collect_records()
            self.assertEqual(len(records), 20)
            rr.write_records(records, output)
            rr.check_records(rr.collect_records(), output)


if __name__ == "__main__":
    unittest.main()
