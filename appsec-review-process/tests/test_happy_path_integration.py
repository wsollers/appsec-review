"""Integration qualification for the report happy-path Dagster surfaces.

These tests stop at Dagster's run-config boundary.  They prove that the repository can
load each public job and that launch_job addresses the op which actually exists in that
standalone job, without requiring a daemon or repeating the long OWASP live qualification.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PROCESS = HERE.parent
sys.path[:0] = [str(PROCESS), str(PROCESS.parent / "orchestrator" / "dagster")]

from dagster import validate_run_config
from definitions import defs
import launch_job
from schema_validate import validate_document


class HappyPathDagsterIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runs = Path(self.temp.name) / "runs"
        self.run_id = "happy-path-qualification"
        self.run = self.runs / self.run_id
        inputs = self.run / "inputs"
        inputs.mkdir(parents=True)
        (inputs / "artifact-manifest.json").write_text(json.dumps({
            "orchestration_version": 1,
            "intake_config": {"executor_platform": "posix"},
        }))
        self.repository = defs.get_repository_def()
        self.repository.load_all_definitions()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def resource_config():
        return {"resources": {"workflow_settings": {"config": {
            "engagement_run_id": "happy-path-qualification", "force": False,
        }}}}

    def test_repository_jobs_and_standalone_op_config_names_validate(self):
        cases = {
            "full_review_input_assembly": ("full_review_input_assembly_standalone_work", {
                "plan_path": "/tmp/plan.json", "output_root": "/tmp/assembly", "attempt_id": "attempt-1",
            }),
            "owasp_join_report": ("owasp_join_report_standalone_work", {
                "facts_path": "/tmp/dispatch-facts.json",
            }),
        }
        jobs = {job.name: job for job in self.repository.get_all_jobs()}
        for name in (*cases, "synthesis_report"):
            self.assertIn(name, jobs)
        for name, (op_name, op_config) in cases.items():
            with self.subTest(job=name):
                run_config = self.resource_config()
                run_config["ops"] = {op_name: {"config": op_config}}
                resolved = validate_run_config(jobs[name], run_config)
                self.assertIn(op_name, resolved["ops"])
        resolved = validate_run_config(jobs["synthesis_report"], self.resource_config())
        self.assertIn("synthesis_report_standalone_work", resolved["ops"])

    def test_launcher_generates_configs_for_the_actual_standalone_ops(self):
        launches = []

        def graphql(query, variables):
            if query == launch_job.FIND:
                return {"runsOrError": {"__typename": "Runs", "results": []}}
            launches.append(variables["params"])
            return {"launchRun": {"__typename": "LaunchRunSuccess",
                                  "run": {"runId": "dagster-run", "status": "STARTING"}}}

        def run_path(run_id):
            self.assertEqual(run_id, self.run_id)
            return self.run

        def data_path(run_id, *parts):
            return run_path(run_id) / "data" / Path(*parts)

        cases = (
            ("full_review_input_assembly", {"input_path": "/tmp/plan.json",
                "output_root": "/tmp/assembly", "attempt_id": "attempt-1"},
             "full_review_input_assembly_standalone_work",
             {"plan_path": "/tmp/plan.json", "output_root": "/tmp/assembly", "attempt_id": "attempt-1"}),
            ("owasp_join_report", {"input_path": "/tmp/dispatch-facts.json"},
             "owasp_join_report_standalone_work", {"facts_path": "/tmp/dispatch-facts.json"}),
        )
        with patch.object(launch_job, "run_path", side_effect=run_path), \
             patch.object(launch_job, "data_path", side_effect=data_path), \
             patch.object(launch_job, "graphql", side_effect=graphql):
            for number, (job, arguments, op_name, expected) in enumerate(cases, 1):
                with self.subTest(job=job):
                    launch_job.launch(self.run_id, launch_id=f"launch-{number}", job=job, **arguments)
                    config = launches[-1]["runConfigData"]
                    self.assertEqual(config["ops"], {op_name: {"config": expected}})
                    validate_run_config(self.repository.get_job(job), config)
            launch_job.launch(self.run_id, launch_id="launch-3", job="synthesis_report")
            config = launches[-1]["runConfigData"]
            self.assertNotIn("ops", config)
            validate_run_config(self.repository.get_job("synthesis_report"), config)

    def test_authoritative_templates_and_contracts_are_closed_and_schema_valid(self):
        registry = PROCESS / "registry"
        cases = (
            ("02-full-review-input-assembly", "full-review-input-assembly"),
            ("04-asvs-masvs", "owasp-join-report"),
            ("10-synthesis-report", "synthesis-report-publication"),
        )
        for job_id, contract_id in cases:
            with self.subTest(job=job_id):
                template = json.loads((registry / "job-templates" / f"{job_id}.json").read_text())
                contract = json.loads((registry / "output-contracts" / f"{contract_id}.json").read_text())
                self.assertEqual(validate_document(template, "job-template.schema.json"), [])
                self.assertEqual(validate_document(contract, "output-contract.schema.json"), [])
                self.assertTrue(template["implemented"])
                self.assertEqual(template["composition"]["output_contract_id"], contract_id)
                self.assertEqual(contract["contract_id"], contract_id)


if __name__ == "__main__":
    unittest.main()
