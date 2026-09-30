"""The generated job and artifact catalog (docs/processes/job-catalog.md) is current and consistent.

Fails when a job, contract, template, lane config, BPMN task or catalog source changed without
regenerating the catalog: run `python3 docs/processes/job_catalog.py` and commit the result.
Pure test: standard library only, no Dagster.
"""
from __future__ import annotations

from pathlib import Path
import importlib.util
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
GENERATOR = REPO / 'docs' / 'processes' / 'job_catalog.py'
CARDS = REPO / 'docs' / 'processes' / 'bpmn' / 'card.py'


def load_generator():
    spec = importlib.util.spec_from_file_location('job_catalog', GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def step(sid, consumes=(), produces=(), **extra):
    return {'id': sid, 'name': sid, 'kind': 'script', 'consumes': list(consumes), 'produces': list(produces), **extra}


def flow_problems(steps):
    problems = []
    flow = load_generator().io_flow(steps, {s['id']: s for s in steps}, {}, problems)
    return flow, problems


class JobCatalogTest(unittest.TestCase):
    def test_catalog_is_current_and_references_resolve(self):
        result = subprocess.run([sys.executable, '-B', str(GENERATOR), '--check'],
                                capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cards_are_current(self):
        result = subprocess.run([sys.executable, '-B', str(CARDS), '--check'],
                                capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class IoFlowTest(unittest.TestCase):
    def test_inputs_resolve_to_the_nearest_earlier_producer_or_external(self):
        flow, problems = flow_problems([
            step('a', ['seed'], ['x'], preceded_by=None),
            step('b', ['x'], ['y'], preceded_by='step:a'),
        ])
        self.assertEqual(problems, [])
        self.assertEqual(flow['a']['inputs'], [{'ref': 'seed', 'from': 'external'}])
        self.assertEqual(flow['b']['inputs'], [{'ref': 'x', 'from': 'step:a'}])

    def test_input_produced_only_later_in_the_chain_is_a_problem(self):
        _, problems = flow_problems([
            step('a', ['y'], ['x'], preceded_by=None),
            step('b', ['x'], ['y'], preceded_by='step:a'),
        ])
        self.assertEqual(len(problems), 1)
        self.assertIn('step:a: consumes y', problems[0])

    def test_sub_jobs_read_from_siblings_and_cover_the_parent_outputs(self):
        steps = [
            step('p', ['m'], ['out', 'extra'], preceded_by=None, sub_jobs=['step:s1', 'step:s2']),
            step('s1', ['m'], ['mid']),
            step('s2', ['mid'], ['out']),
        ]
        flow, problems = flow_problems(steps)
        self.assertEqual(flow['p']['sub_jobs'][1]['inputs'], [{'ref': 'mid', 'from': 'step:s1'}])
        self.assertEqual(problems, ['step:p: produces extra, which none of its sub-jobs produces'])

    def test_sub_job_takes_no_preceded_by_and_cycles_are_reported(self):
        _, problems = flow_problems([
            step('p', [], [], preceded_by='step:q', sub_jobs=['step:s']),
            step('q', [], [], preceded_by='step:p'),
            step('s', [], [], preceded_by=None),
        ])
        self.assertTrue(any('cycle' in p for p in problems), problems)
        self.assertTrue(any('takes no preceded_by' in p for p in problems), problems)


if __name__ == '__main__':
    unittest.main()
