"""The generated job and artifact catalog (docs/processes/job-catalog.md) is current and consistent.

Fails when a job, contract, template, lane config, BPMN task or catalog source changed without
regenerating the catalog: run `python3 docs/processes/job_catalog.py` and commit the result.
Pure test: standard library only, no Dagster.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
GENERATOR = REPO / 'docs' / 'processes' / 'job_catalog.py'


class JobCatalogTest(unittest.TestCase):
    def test_catalog_is_current_and_references_resolve(self):
        result = subprocess.run([sys.executable, '-B', str(GENERATOR), '--check'],
                                capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
