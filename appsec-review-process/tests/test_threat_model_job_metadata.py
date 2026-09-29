"""Job 03 metadata describes the job that runs (brief M3, ADR-0019).

``03-threat-model-dfd-stride`` coordinates the threat-workbench persona cells, so its graph node,
registry template, parity manifest and worker envelope must say so, and every file the output
contract requires must be a required artifact of the node.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JOB = "03-threat-model-dfd-stride"


def load(relative: str):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class ThreatModelJobMetadataTests(unittest.TestCase):
    def test_required_artifacts_match_the_output_contract(self):
        node = load("job-graph.json")["jobs"][JOB]
        contract = load(f"registry/output-contracts/{node['contract']}.json")
        template = load(f"registry/job-templates/{node['template']}.json")
        self.assertEqual(sorted(node["required_artifacts"]), sorted(contract["required_files"]))
        self.assertEqual(sorted(template["outputs"]["files"]), sorted(contract["required_files"]))
        for name in ("attack-trees.mmd", "dfd.mmd", "ranked-threat-scenarios.json", "intercom-transcript.jsonl"):
            self.assertIn(name, node["required_artifacts"])

    def test_template_and_worker_describe_the_persona_cell_job(self):
        template = load(f"registry/job-templates/{JOB}.json")
        self.assertNotEqual(template["model"]["model"], "deterministic-python")
        cells = [load(f"registry/job-templates/{path.name}")
                 for path in sorted((ROOT / "registry" / "job-templates").glob("threat-workbench-*.json"))]
        self.assertTrue(cells)
        self.assertIn(template["model"]["model"], {cell["model"]["model"] for cell in cells})
        source = (ROOT / "threat_model_core.py").read_text(encoding="utf-8")
        self.assertEqual(set(re.findall(r'worker_kind="([a-z_]+)"', source)), {"pool_coordinator"})
        record = next(row for row in load("design-parity-manifest.json")["jobs"] if row["id"] == JOB)
        self.assertEqual(record["execution"]["mode"], "pool_coordinator")
        self.assertEqual(record["resource_pool"], "persona_llm")


if __name__ == "__main__":
    unittest.main()
