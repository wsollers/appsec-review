"""Brief N / decision log D-13: fingerprints cover the files that change a job's output, not shared
runtime or whole modules of unrelated wiring."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dev_restart
from execution_state import SHARED_RUNTIME
import workflow


class BuildDiscoveryScope(unittest.TestCase):
    """D-13(a): only dagster_workflow.py's branch_op is part of the preparation branches' code."""

    def test_code_hashes_name_branch_op_not_the_whole_dagster_module(self):
        code = workflow.code_hashes()
        self.assertNotIn('dagster_workflow.py', code)
        self.assertEqual(sorted(code), ['build_discovery.py', 'dagster_workflow.py:branch_op',
                                        'workflow-plan.json', 'workflow.py'])
        self.assertEqual(dev_restart.current_code(code, ROOT), code)

    def test_op_wiring_edits_elsewhere_do_not_move_the_hash_but_branch_op_edits_do(self):
        text = (ROOT / 'dagster_workflow.py').read_text(encoding='utf-8')
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / 'dagster_workflow.py'
            copy.write_text(text + '\n\ndef another_op():\n    return 1\n', encoding='utf-8')
            self.assertEqual(workflow.dagster_op_hashes(copy), workflow.dagster_op_hashes())
            marker = "    @op(name=op_name or name,pool=CPU_POOL)"
            self.assertIn(marker, text)
            copy.write_text(text.replace(marker, marker + "  # changed", 1), encoding='utf-8')
            self.assertNotEqual(workflow.dagster_op_hashes(copy), workflow.dagster_op_hashes())
            copy.write_text('x = 1\n', encoding='utf-8')
            with self.assertRaises(workflow.Blocked):
                workflow.dagster_op_hashes(copy)

    def test_dev_explain_resolves_function_keys(self):
        with tempfile.TemporaryDirectory() as scratch:
            (Path(scratch) / 'm.py').write_text('def f():\n    return 1\n\ndef g():\n    return 2\n')
            values = dev_restart.current_code({'m.py:f': 'x', 'm.py:missing': 'y', 'm.py': 'z'}, Path(scratch))
            self.assertEqual(values['m.py:f'], dev_restart.function_source_hash(Path(scratch) / 'm.py', 'f'))
            self.assertIsNone(values['m.py:missing'])
            self.assertIsNotNone(values['m.py'])


class SharedRuntimeScope(unittest.TestCase):
    """D-13(b): these lifecycles no longer hash shared runtime into their code record."""

    def assertNoSharedRuntime(self, code, job):
        self.assertFalse(set(code) & SHARED_RUNTIME, f'{job}: {sorted(set(code) & SHARED_RUNTIME)}')

    def test_analysis_feature_lifecycle(self):
        import analysis_feature_lifecycle as lifecycle
        for job in lifecycle.JOBS:
            code = lifecycle._code(job)
            self.assertNoSharedRuntime(code, job)
            self.assertIn('analysis_feature_lifecycle.py', code)
            self.assertEqual('dependency_workers.py' in code, job == '06-cve-reachability')


if __name__ == '__main__':
    unittest.main()
