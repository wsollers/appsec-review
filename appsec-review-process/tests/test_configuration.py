from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import date
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import configuration as cfg
import run_configuration as bootstrap


DEFAULT_TEXT = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, text: str, name: str = "config.toml") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_default_load_is_typed_and_immutable(self):
        document = cfg.load_document(ROOT / "appsec-review.toml")
        defaults = cfg.get_global_defaults()
        self.assertEqual(defaults.worker_pool_size, 4)
        self.assertEqual(defaults.timeout_seconds, 3600)
        with self.assertRaises(TypeError):
            document.data["global"]["timeout_seconds"] = 1
        with self.assertRaises(FrozenInstanceError):
            defaults.timeout_seconds = 1

    def test_global_resolution_applies_the_run_owned_layer(self):
        overlay = self.write(DEFAULT_TEXT.replace("worker_pool_size = 4", "worker_pool_size = 9", 1))
        self.assertEqual(cfg.resolve_global_defaults(overlay).worker_pool_size, 9)

    def test_uri_resolution_is_closed_and_local(self):
        local = self.write(DEFAULT_TEXT)
        cases = [
            (None, cfg.DEFAULT_CONFIG.resolve()),
            ("", cfg.DEFAULT_CONFIG.resolve()),
            (str(local), local.resolve()),
            (local.as_uri(), local.resolve()),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(cfg.resolve_config_uri(value), expected)
        for value in ("https://example.invalid/config.toml", "s3://bucket/key", "file://remote/share/config.toml"):
            with self.subTest(value=value), self.assertRaises(cfg.ConfigurationError):
                cfg.resolve_config_uri(value)

    def test_layer_precedence_global_then_step_then_task(self):
        overlay = DEFAULT_TEXT.replace("budget_usd = 2.0", "budget_usd = 3.0", 1)
        overlay = overlay.replace("timeout_seconds = 30", "timeout_seconds = 29", 1)
        overlay = overlay.replace("timeout_seconds = 15", "timeout_seconds = 14", 1)
        resolved = cfg.resolve_layered("job_0000", "run_configuration", "task_0001", self.write(overlay))
        self.assertEqual(resolved.values.budget_usd, 3.0)       # run-owned global
        self.assertEqual(resolved.values.worker_pool_size, 1)  # step
        self.assertEqual(resolved.values.timeout_seconds, 14)  # task
        self.assertEqual(resolved.layers,
                         ("tracked.global", "run.global", "tracked.step", "run.step", "tracked.task", "run.task"))

    def test_namespace_and_identity_failures_are_not_guessed(self):
        cases = {
            "malformed namespace": DEFAULT_TEXT.replace("[job_0000.run_configuration]", "[job_000.run_configuration]"),
            "divergent identity": DEFAULT_TEXT.replace('job_id = "00-run-configuration"', 'job_id = "00-intake"', 1),
            "unknown runtime": DEFAULT_TEXT.replace('job_id = "00-run-configuration"', 'job_id = "00-not-registered"', 1),
            "malformed task": DEFAULT_TEXT.replace("task_0001", "task_one"),
            "duplicate key": DEFAULT_TEXT.replace("worker_pool_size = 4", "worker_pool_size = 4\nworker_pool_size = 5", 1),
        }
        for label, text in cases.items():
            with self.subTest(label=label), self.assertRaises(cfg.ConfigurationError):
                cfg.load_document(self.write(text, label.replace(" ", "_") + ".toml"))

    def test_unknown_keys_and_invalid_values_include_source_location(self):
        cases = [
            DEFAULT_TEXT.replace("worker_pool_size = 4", "worker_pool_size = 0", 1),
            DEFAULT_TEXT.replace("timeout_seconds = 3600", "timeout_seconds = true", 1),
            DEFAULT_TEXT.replace("cache_policy = \"validated_reuse\"", "cache_policy = \"maybe\"", 1),
            DEFAULT_TEXT.replace("model = \"haiku\"", "model = \"HAIKU\"", 1),
            DEFAULT_TEXT.replace("retrieval_max_results = 200", "retrieval_max_results = 10001", 1),
            DEFAULT_TEXT.replace("applicability_threshold = 0.5", "applicability_threshold = 1.1", 1),
            DEFAULT_TEXT.replace("worker_pool_size = 4", "worker_pool_size = 4\nsurprise = 1", 1),
        ]
        for index, text in enumerate(cases):
            path = self.write(text, f"bad-{index}.toml")
            with self.subTest(index=index), self.assertRaises(cfg.ConfigurationError) as raised:
                cfg.load_document(path)
            self.assertIn(str(path.resolve()) + ":", str(raised.exception))

    def test_fingerprint_is_stable_across_toml_key_order_and_changes_with_values(self):
        ordered = self.write(DEFAULT_TEXT, "ordered.toml")
        global_lines = [
            "applicability_threshold = 0.5", "retrieval_max_results = 200",
            'cache_policy = "validated_reuse"', "timeout_seconds = 3600", "budget_usd = 2.0",
            'reasoning_level = "medium"', 'model = "haiku"', "worker_pool_size = 4",
        ]
        start = DEFAULT_TEXT.index("[global]")
        end = DEFAULT_TEXT.index("[job_0000.run_configuration]")
        reordered_text = DEFAULT_TEXT[:start] + "[global]\n" + "\n".join(global_lines) + "\n\n" + DEFAULT_TEXT[end:]
        reordered = self.write(reordered_text, "reordered.toml")
        first = cfg.resolve_layered("job_0000", "run_configuration", run_config=ordered)
        second = cfg.resolve_layered("job_0000", "run_configuration", run_config=reordered)
        changed = cfg.resolve_layered("job_0000", "run_configuration",
                                      run_config=self.write(DEFAULT_TEXT.replace("timeout_seconds = 30", "timeout_seconds = 31"), "changed.toml"))
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.fingerprint, changed.fingerprint)

    def test_redaction_is_deterministic_and_recursive(self):
        value = {"z": 1, "api_token": "do-not-print", "nested": {"password_hint": "also-secret", "a": 2}}
        first = cfg.canonical_json(value)
        second = cfg.canonical_json(dict(reversed(list(value.items()))))
        self.assertEqual(first, second)
        self.assertNotIn("do-not-print", first)
        self.assertNotIn("also-secret", first)
        self.assertEqual(json.loads(first)["api_token"], "[REDACTED]")

    def test_environment_override_is_used_only_by_central_selection(self):
        path = self.write(DEFAULT_TEXT)
        selected = cfg.selected_config_path(environ={cfg.CONFIG_ENVIRONMENT_VARIABLE: str(path)})
        self.assertEqual(selected, path.resolve())


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runs = Path(self.temp.name) / "runs"
        self.day = date(2026, 10, 7)

    def tearDown(self):
        self.temp.cleanup()

    def test_default_is_copied_and_artifacts_are_immutable(self):
        status = bootstrap.create_run(runs_root=self.runs, day=self.day)
        self.assertEqual(status["status"], "OK")
        run = self.runs / status["run_id"]
        artifact = run / cfg.RUN_CONFIG_RELATIVE
        effective = artifact.with_name("effective-config.json")
        self.assertEqual(artifact.read_bytes(), (ROOT / "appsec-review.toml").read_bytes())
        self.assertTrue(effective.is_file())
        self.assertFalse(artifact.stat().st_mode & 0o200)
        with self.assertRaises(FileExistsError):
            artifact.open("xb")

    def test_supplied_file_uri_is_copied(self):
        source = Path(self.temp.name) / "override.toml"
        source.write_text(DEFAULT_TEXT.replace("timeout_seconds = 30", "timeout_seconds = 29"), encoding="utf-8")
        status = bootstrap.create_run(source.as_uri(), runs_root=self.runs, day=self.day)
        artifact = self.runs / status["run_id"] / cfg.RUN_CONFIG_RELATIVE
        self.assertEqual(status["status"], "OK")
        self.assertEqual(artifact.read_bytes(), source.read_bytes())

    def test_daily_serial_is_monotonic_and_not_reused(self):
        first = bootstrap.allocate_run_directory(self.runs, day=self.day)
        second = bootstrap.allocate_run_directory(self.runs, day=self.day)
        shutil.rmtree(second)
        third = bootstrap.allocate_run_directory(self.runs, day=self.day)
        self.assertEqual(first.name, "2026-10-07-0001")
        self.assertEqual(third.name, "2026-10-07-0003")

    def test_concurrent_allocation_has_unique_serials(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            allocated = list(pool.map(lambda _: bootstrap.allocate_run_directory(self.runs, day=self.day), range(24)))
        names = sorted(path.name for path in allocated)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names, [f"2026-10-07-{index:04d}" for index in range(1, 25)])

    def test_first_job_failure_is_terminal_and_publishes_no_config(self):
        status = bootstrap.create_run("https://example.invalid/config.toml", runs_root=self.runs, day=self.day)
        self.assertEqual(status["status"], "FAILED")
        run = self.runs / status["run_id"]
        self.assertFalse((run / cfg.RUN_CONFIG_RELATIVE).exists())
        recorded = json.loads(next(run.glob("data/jobs/00-run-configuration/whole/attempts/*/status.json")).read_text())
        self.assertEqual(recorded["status"], "FAILED")
        self.assertIn("unsupported configuration URI scheme", recorded["error"])


if __name__ == "__main__":
    unittest.main()
