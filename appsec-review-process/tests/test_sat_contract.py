"""scripts/sat_contract.py: the system acceptance test's pre/post contract enforcement.

Each case builds a tiny repository, runs a pretend command between two snapshots and checks that
the contract catches exactly what it must: missing or invalid inputs, inputs that must be absent,
a wrong exit code, unexpected writes and deletes, missing required writes, invalid outputs.
Pure test: standard library only.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / 'scripts' / 'sat_contract.py'


class SatContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / 'repo'
        (self.repo / 'appsec-review-process').mkdir(parents=True)
        (self.repo / 'schemas').mkdir()
        shutil.copy(REPO / 'appsec-review-process' / 'schema_validate.py', self.repo / 'appsec-review-process')
        shutil.copy(REPO / 'schemas' / 'intake.schema.json', self.repo / 'schemas')
        (self.repo / 'in.json').write_text('{"run_id": "r1", "status": "READY"}')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_tool(self, *args):
        r = subprocess.run([sys.executable, '-B', str(TOOL), *args], capture_output=True, text=True)
        return r.returncode, r.stdout

    def contract(self, value):
        path = self.tmp / 'c.json'
        path.write_text(json.dumps(value))
        return str(path)

    def pre(self, contract, variables='{}'):
        rc, out = self.run_tool('pre', '--repo', str(self.repo), '--contract', self.contract(contract), '--vars', variables)
        return rc, json.loads(out)['problems']

    def post(self, contract, change, exit_code=0):
        b, a, r = self.tmp / 'b.json', self.tmp / 'a.json', self.tmp / 'r.json'
        self.run_tool('snapshot', str(b), '--repo', str(self.repo))
        change()
        self.run_tool('snapshot', str(a), '--repo', str(self.repo))
        rc, out = self.run_tool('post', '--repo', str(self.repo), '--contract', self.contract(contract), '--vars', '{}',
                                '--before', str(b), '--after', str(a), '--exit', str(exit_code), '--report', str(r))
        return rc, json.loads(out)['problems']

    def test_inputs_present_valid_and_absent(self):
        rc, problems = self.pre({'inputs': [{'path': 'in.json', 'equals': {'run_id': '{run_id}'}},
                                            {'path': 'nothing.json', 'kind': 'absent'}]}, '{"run_id": "r1"}')
        self.assertEqual((rc, problems), (0, []))

    def test_inputs_missing_wrong_or_present_when_absent_required(self):
        (self.repo / 'nothing.json').write_text('{}')
        rc, problems = self.pre({'inputs': [{'path': 'missing.json'}, {'path': 'in.json', 'equals': {'status': 'OK'}},
                                            {'path': 'nothing.json', 'kind': 'absent'}]})
        self.assertEqual(rc, 1)
        self.assertEqual(len(problems), 3, problems)

    def test_exact_write_set_passes(self):
        def change():
            (self.repo / 'out').mkdir()
            (self.repo / 'out' / 'a.json').write_text('{"x": 1}')
        rc, problems = self.post({'writes': {'required': ['out/a.json'], 'allowed': []},
                                  'outputs': [{'path': 'out/a.json', 'equals': {'x': 1}}]}, change)
        self.assertEqual((rc, problems), (0, []))

    def test_stray_write_missing_write_delete_and_exit(self):
        def change():
            (self.repo / 'stray.txt').write_text('x')
            (self.repo / 'in.json').unlink()
        rc, problems = self.post({'writes': {'required': ['out/a.json'], 'allowed': []}}, change, exit_code=2)
        self.assertEqual(rc, 1)
        text = '\n'.join(problems)
        for needle in ('exit code 2', 'unexpected write: stray.txt', 'unexpected delete: in.json', 'required write missing: out/a.json'):
            self.assertIn(needle, text)

    def test_output_schema_violation(self):
        def change():
            (self.repo / 'intake.json').write_text('{"schema": "wrong"}')
        rc, problems = self.post({'writes': {'required': ['intake.json']},
                                  'outputs': [{'path': 'intake.json', 'schema': 'intake.schema.json'}]}, change)
        self.assertEqual(rc, 1)
        self.assertTrue(any('schema intake.schema.json' in p for p in problems), problems)

    def test_ambient_changes_are_not_counted(self):
        def change():
            (self.repo / 'data' / 'feeds' / 'nvd').mkdir(parents=True)
            (self.repo / 'data' / 'feeds' / 'nvd' / 'x.json').write_text('{}')
        rc, problems = self.post({'writes': {'required': [], 'allowed': []}}, change)
        self.assertEqual((rc, problems), (0, []))


if __name__ == '__main__':
    unittest.main()
