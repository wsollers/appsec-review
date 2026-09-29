"""ADR-0025 generic item executor: the ported 02-operations-doc-ingest item publishes byte-identical
outputs to the legacy lifecycle; dev decisions (reuse, early cutoff, rewind, force) on real item
attempts; guard rails; item definition rules; registration from job-graph.json.

Everything runs locally: a real staged intake (phase1), real subprocess workers through the process
gate, no Dagster daemon, no model, no container.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dev_restart as dr
import execution_state as state
import job_executor as jx
import phase1
import publish_job_output
import run_process
import static_intelligence_core as core

JOB = '02-operations-doc-ingest'
PAYLOAD = ('operations-doc-intelligence.json', 'permission.json', 'lineage.json')
os.environ.setdefault('PHASE1_TEST_DATA', tempfile.mkdtemp(prefix='phase1-test-data-'))
EVIDENCE = Path(os.environ['PHASE1_TEST_DATA']).resolve()


class Frozen:
    """Fixed clock and attempt ids so two implementations can be compared byte for byte."""
    def __init__(self, attempt_id='a' * 32):
        self.attempt_id = attempt_id

    def __enter__(self):
        stamp = '2026-09-29T12:00:00+00:00'
        self.stack = [patch.object(module, 'now', return_value=stamp)
                      for module in (publish_job_output, core, jx)]
        self.stack.append(patch.object(publish_job_output.uuid, 'uuid4',
                                       return_value=uuid.UUID(self.attempt_id)))
        for item in self.stack:
            item.start()
        return self

    def __exit__(self, *exc):
        for item in reversed(self.stack):
            item.stop()


class ExecutorCase(unittest.TestCase):
    def setUp(self):
        self.root = EVIDENCE / ('jx-' + uuid.uuid4().hex[:8])
        self.root.mkdir(parents=True)
        self.old_runs, state.RUNS = state.RUNS, self.root / 'runs'
        self.env = patch.dict(os.environ, {'APPSEC_RUN_MODE': '', 'APPSEC_RUNS_ROOT': str(state.RUNS)})
        self.env.start()
        self.target = self.root / 'target'
        shutil.copytree(ROOT / 'tests/fixtures/static-intelligence', self.target)
        (self.target / 'runbooks' / 'incident-playbook.md').write_text(
            '# Incident playbook\nOn-call must rotate the deploy api_key=sk-abcdefghijklmnopqrstuvwxyz0123 '
            'after an incident.\nThe service owner should page support.\n')
        self.run_id = 'jx-' + uuid.uuid4().hex[:8]
        run_process.init_run(self.run_id)
        phase1.stage(self.run_id, self.target, 'fixture', 'Executor qualification', ['Linux'])
        phase1.run_intake(self.run_id)

    def tearDown(self):
        self.env.stop()
        state.RUNS = self.old_runs

    def job_root(self, job=JOB):
        return state.data_path(self.run_id, 'jobs', job)

    def attempt(self, pointer, job=JOB):
        return self.job_root(job) / 'attempts' / pointer['attempt_id']


class ByteIdentityTests(ExecutorCase):
    def test_ported_item_publishes_byte_identical_outputs(self):
        with Frozen():
            legacy = core.run(self.run_id, 'dagster-1', JOB)
        legacy_dir = self.root / 'legacy'
        shutil.copytree(self.attempt(legacy), legacy_dir)
        shutil.rmtree(self.job_root())
        with Frozen():
            ported = jx.run_item(JOB, self.run_id, 'dagster-1', mode='prod')
        new_dir = self.attempt(ported)
        self.assertEqual(ported['attempt_id'], legacy['attempt_id'])
        for name in PAYLOAD:
            self.assertEqual((new_dir / name).read_bytes(), (legacy_dir / name).read_bytes(), name)
        # status.json differs only in the fingerprint: the executor's covers the item definition too.
        old, new = (json.loads((d / 'status.json').read_text()) for d in (legacy_dir, new_dir))
        self.assertNotEqual(old.pop('fingerprint'), new.pop('fingerprint'))
        self.assertEqual(old, new)
        # The fixture exercises redaction and gaps, not just the happy path.
        payload = json.loads((new_dir / PAYLOAD[0]).read_text())
        self.assertNotIn('sk-abcdefghijklmnopqrstuvwxyz0123', json.dumps(payload))
        self.assertTrue(any(s['status'] == 'REDACTED' for s in payload['sources']))
        self.assertGreater(len(payload['records']), 0)
        # Same envelope contract: consumers read accepted.json + result.json exactly as before.
        envelope = json.loads((new_dir / 'result.json').read_text())
        self.assertEqual([a['path'] for a in envelope['artifacts']], [PAYLOAD[0], 'status.json', *PAYLOAD[1:]])
        self.assertEqual(envelope['worker_kind'], 'deterministic_python')
        receipt = json.loads((new_dir / dr.RECEIPT_NAME).read_text())
        self.assertEqual((receipt['mode'], receipt['evidence_grade'], receipt['status']), ('prod', True, payload['status']))
        self.assertIsNone(receipt['resume_from'])
        self.assertIn('--force', receipt['rerun_command'])
        self.assertEqual([m['input'] for m in receipt['redaction']], ['source'])
        self.assertNotIn('sk-', json.dumps(receipt))
        coverage = json.loads((new_dir / 'coverage.json').read_text())
        self.assertEqual((coverage['tool_ran'], coverage['complete']), (True, payload['status'] == 'OK'))

    def test_prod_reuse_and_prod_never_reuses_dev(self):
        first = jx.run_item(JOB, self.run_id, 'd1', mode='prod')
        again = jx.run_item(JOB, self.run_id, 'd2', mode='prod')
        self.assertEqual((again['attempt_id'], again['decision']['action']), (first['attempt_id'], dr.REUSE))
        dev = jx.run_item(JOB, self.run_id, 'd3', mode='dev')
        self.assertEqual(dev['decision']['action'], dr.REUSE)  # dev may reuse a prod result
        forced = jx.run_item(JOB, self.run_id, 'd4', mode='dev', force_jobs=[JOB])
        self.assertEqual(forced['decision'], {'job': JOB, 'action': dr.RERUN, 'causes': ['--force']})
        receipt = json.loads((self.attempt(forced) / dr.RECEIPT_NAME).read_text())
        self.assertEqual((receipt['mode'], receipt['evidence_grade']), ('dev', False))
        with self.assertRaisesRegex(state.Blocked, 'not evidence'):
            dr.assert_deliverable(state.run_path(self.run_id), {})
        back = jx.run_item(JOB, self.run_id, 'd5', mode='prod')
        self.assertNotEqual(back['attempt_id'], forced['attempt_id'])
        self.assertEqual(back['decision']['causes'], ['the accepted result is not a prod receipt'])
        dr.assert_deliverable(state.run_path(self.run_id), {})


PRODUCER, CONSUMER = 'fx-producer', 'fx-consumer'
WORKER = '''import argparse, json, sys
from pathlib import Path
p = argparse.ArgumentParser()
for n in ("--job", "--run-id", "--attempt-id", "--input", "--output"): p.add_argument(n)
a = p.parse_args()
doc = json.loads(Path(a.input).read_text())
{body}
Path(a.output, "worker-result.json").write_text(json.dumps({{"execution_status": "OK", "gaps": [],
    "summary": "fixture", "status": {{}}, "artifacts": [NAME]}}))
'''
PRODUCER_BODY = '''NAME = "p.json"
value = {"files": len(doc["needs"]["source"]["source_files"])}
Path(a.output, NAME).write_text(json.dumps(value, sort_keys=True))
'''
CONSUMER_BODY = '''NAME = "c.json"
Path(a.output, NAME).write_text(json.dumps({"seen": sorted(doc["needs"]["p"]["p.json"])}))
'''
OPEN_SCHEMA = {'type': 'object'}


class DevDecisionTests(ExecutorCase):
    """Rules 2-6 on real item attempts with two fixture items: producer (needs the intake) and
    consumer (needs the producer's p.json). Contract validation belongs to the byte-identity test
    above; here the registry does not know the fixture contracts, so it is stubbed."""

    def setUp(self):
        super().setUp()
        self.items = self.root / 'items'
        self.write_item(PRODUCER, [{'job': '00-intake', 'as': 'source', 'resolve': 'intake-source'}],
                        PRODUCER_BODY, 'p.json')
        self.write_item(CONSUMER, [{'job': PRODUCER, 'as': 'p', 'resolve': 'accepted-artifacts',
                                    'artifacts': ['p.json']}], CONSUMER_BODY, 'c.json')
        stub = patch.object(publish_job_output, 'validate_job_output', return_value=[])
        stub.start()
        self.addCleanup(stub.stop)

    def write_item(self, job, needs, body, artifact):
        root = self.items / job
        root.mkdir(parents=True, exist_ok=True)
        spec = {'schema': jx.ITEM_SCHEMA, 'job_id': job, 'output_contract': 'fixture', 'worker_kind': 'deterministic_python',
                'needs': needs, 'params': {},
                'worker': {'argv': ['{python}', '-B', '{item}/worker.py', '--job', '{job_id}', '--run-id', '{run_id}',
                                   '--attempt-id', '{attempt_id}', '--input', '{input}', '--output', '{output}'],
                           'grants': {'container': None, 'network': False}, 'timeout_seconds': 60},
                'implementation': {'own': [f'items/{job}/worker.py']},
                'outputs': {'artifacts': [artifact, 'status.json']}, 'normalise': None}
        state.atomic_json(root / 'item.json', spec)
        state.atomic_json(root / 'input.schema.json', OPEN_SCHEMA)
        state.atomic_json(root / 'output.schema.json', OPEN_SCHEMA)
        (root / 'worker.py').write_text(WORKER.format(body=body))

    def edit_producer(self, body):
        (self.items / PRODUCER / 'worker.py').write_text(WORKER.format(body=body))

    def go(self, job, dagster_id, **kw):
        return jx.run_item(job, self.run_id, dagster_id, mode='dev', items_root=self.items, **kw)

    def pass_(self, dagster_id, **kw):
        return {job: self.go(job, dagster_id, **kw)['decision'] for job in (PRODUCER, CONSUMER)}

    def test_reuse_then_early_cutoff_then_content_rerun(self):
        first = self.pass_('d1')
        self.assertEqual({j: d['action'] for j, d in first.items()}, {PRODUCER: dr.RERUN, CONSUMER: dr.RERUN})
        self.assertEqual({j: d['action'] for j, d in self.pass_('d2').items()}, {PRODUCER: dr.REUSE, CONSUMER: dr.REUSE})
        # Rule 5: an own-code edit that does not change the producer's bytes.
        self.edit_producer(PRODUCER_BODY + '# refactor, same output\n')
        third = self.pass_('d3')
        self.assertEqual(third[PRODUCER], {'job': PRODUCER, 'action': dr.RERUN,
                                           'causes': [f'own items/{PRODUCER}/worker.py changed']})
        self.assertEqual(third[CONSUMER]['causes'], [f'early cutoff: {PRODUCER} reran with byte-identical output'])
        # Rule 3: same shape, different content.
        self.edit_producer(PRODUCER_BODY.replace('len(doc["needs"]["source"]["source_files"])', '12345'))
        fourth = self.pass_('d4')
        self.assertEqual(fourth[CONSUMER], {'job': CONSUMER, 'action': dr.RERUN,
                                            'causes': [f'input content of {PRODUCER}/p changed']})

    def test_shape_change_behind_the_consumer_rewinds_the_producer(self):
        self.pass_('d1')
        # The producer reruns alone with a new output shape; the consumer does not run (failed, or
        # was not launched), so its record still has the old shape.
        self.edit_producer(PRODUCER_BODY.replace('value = {', 'value = {"extra": [1], '))
        self.assertEqual(self.go(PRODUCER, 'd2')['decision']['action'], dr.RERUN)
        # Next pass: the producer alone would REUSE; the consumer sees the shape change and rewinds it.
        self.assertEqual(self.go(PRODUCER, 'd3')['decision']['action'], dr.REUSE)
        consumer = self.go(CONSUMER, 'd3')['decision']
        producer = json.loads((self.job_root(PRODUCER) / 'accepted.json').read_text())
        rewound = json.loads((self.attempt(producer, PRODUCER) / dr.RECEIPT_NAME).read_text())['decision']
        self.assertEqual(rewound, {'job': PRODUCER, 'action': dr.REWIND,
                                   'causes': [f'shape of {PRODUCER}/p consumed by {CONSUMER} changed']})
        self.assertEqual(consumer['action'], dr.RERUN)
        self.assertEqual(consumer['causes'], [f'input shape of {PRODUCER}/p changed ({PRODUCER} reran in this pass)'])

    def test_explain_items_reads_the_run_without_side_effects(self):
        self.pass_('d1')
        self.edit_producer(PRODUCER_BODY + '# same output\n')
        before = sorted(p.as_posix() for p in state.run_path(self.run_id).rglob('*'))
        upstream = {'00-intake': [], PRODUCER: ['00-intake'], CONSUMER: [PRODUCER]}
        entries = {e['job']: e for e in jx.explain_items(state.run_path(self.run_id), upstream, mode='dev',
                                                          items_root=self.items)}
        self.assertEqual(sorted(p.as_posix() for p in state.run_path(self.run_id).rglob('*')), before)
        self.assertEqual(entries[PRODUCER]['decision']['action'], dr.RERUN)
        self.assertIn(f'code hash of items/{PRODUCER}/worker.py changed', entries[PRODUCER]['prod_note'])
        self.assertEqual(entries[CONSUMER]['decision']['action'], dr.REUSE)
        lines = dr.explain_run(state.run_path(self.run_id), {'jobs': {
            job: {'dependencies': [{'job': d} for d in deps]} for job, deps in upstream.items()}},
            ROOT, mode='dev', item_explain=lambda *a, **k: jx.explain_items(*a, items_root=self.items, **k))
        self.assertTrue(lines[3].startswith(f'RERUN  {CONSUMER}: provisional: {PRODUCER} reruns first'))

    def test_missing_upstream_is_a_blocked_attempt_in_dev_too(self):
        with self.assertRaisesRegex(state.Blocked, f'{PRODUCER} has no accepted result'):
            self.go(CONSUMER, 'd1')
        pointer = json.loads((self.job_root(CONSUMER) / 'accepted.json').read_text())
        self.assertEqual(pointer['status'], 'BLOCKED')

    def test_worker_failure_is_a_gap_never_no_findings(self):
        self.edit_producer('raise SystemExit(3)\n')
        with self.assertRaises(RuntimeError):
            self.go(PRODUCER, 'd1')
        pointer = json.loads((self.job_root(PRODUCER) / 'accepted.json').read_text())
        self.assertEqual(pointer['status'], 'FAILED')
        attempt = self.attempt(pointer, PRODUCER)
        coverage = json.loads((attempt / 'coverage.json').read_text())
        self.assertEqual((coverage['tool_ran'], coverage['complete']), (True, False))
        self.assertEqual(coverage['gaps'], ['process: worker exit code 3'])
        receipt = json.loads((attempt / dr.RECEIPT_NAME).read_text())
        self.assertEqual((receipt['status'], receipt['resume_from'], receipt['mode']), ('FAILED', 'process', 'dev'))


class DefinitionTests(unittest.TestCase):
    def item(self, **changes):
        spec = json.loads((ROOT / 'items' / JOB / 'item.json').read_text())
        for key, value in changes.items():
            target, *path = key.split('.')
            node = spec
            for part in [target, *path][:-1]:
                node = node[part]
            node[[target, *path][-1]] = value
        return jx.Item(ROOT / 'items' / JOB, spec)

    def test_ported_item_is_valid_and_registers_from_the_graph(self):
        self.assertEqual(jx.check_item(self.item()), [])
        graph = json.loads((ROOT / 'job-graph.json').read_text())['jobs']
        ops = {}
        with patch.object(jx, 'dagster_item_op', side_effect=lambda job, pool: f'op:{job}'):
            self.assertEqual(jx.register_item_ops(graph, ops, 'cpu'), [JOB])
        self.assertEqual(ops, {JOB: f'op:{JOB}'})

    def test_needs_must_match_graph_dependencies(self):
        graph = {JOB: {'dependencies': [{'job': '00-intake'}, {'job': '02-other'}]}}
        with patch.object(jx, 'dagster_item_op'), self.assertRaisesRegex(state.Blocked, 'graph says'):
            jx.register_item_ops(graph, {}, 'cpu')

    def test_argv_grants_and_outputs_rules(self):
        self.assertTrue(jx.check_item(self.item(**{'worker.argv': ['bash', '-c', 'python x']})))
        self.assertTrue(jx.check_item(self.item(**{'worker.argv': 'python worker.py'})))
        self.assertTrue(jx.check_item(self.item(**{'worker.argv': ['{python}', '{secret}']})))
        self.assertTrue(jx.check_item(self.item(**{'worker.grants': {'container': 'audit-x', 'network': False}})))
        self.assertTrue(jx.check_item(self.item(**{'worker.grants': {'container': None}})))
        self.assertTrue(jx.check_item(self.item(**{'outputs.artifacts': ['operations-doc-intelligence.json']})))
        self.assertTrue(jx.check_item(self.item(**{'outputs.artifacts': ['receipt.json', 'status.json']})))
        self.assertTrue(jx.check_item(self.item(normalise={'format': 'csv', 'mode': 'pass-through',
                                                           'artifact': 'status.json'})))

    def test_run_tags_must_match_the_process_mode(self):
        self.assertEqual(jx.run_tags(JOB, {}, {}), ('prod', []))
        self.assertEqual(jx.run_tags(JOB, {'appsec/run_mode': 'dev', 'appsec/force_jobs': 'a,b'},
                                     {'APPSEC_RUN_MODE': 'dev'}), ('dev', ['a', 'b']))
        with self.assertRaisesRegex(state.Blocked, 'refusing'):
            jx.run_tags(JOB, {'appsec/run_mode': 'dev'}, {})
        with self.assertRaisesRegex(state.Blocked, 'refusing'):
            jx.run_tags(JOB, {}, {'APPSEC_RUN_MODE': 'dev'})

    def test_normaliser_is_pass_through_only(self):
        with tempfile.TemporaryDirectory() as d:
            item = self.item(normalise={'format': 'sarif-2.1.0', 'mode': 'pass-through',
                                        'artifact': 'operations-doc-intelligence.json'})
            state.atomic_json(Path(d) / 'operations-doc-intelligence.json', {'version': '2.1.0', 'runs': []})
            self.assertEqual(jx._normalise(item, Path(d))['mode'], 'pass-through')
            state.atomic_json(Path(d) / 'operations-doc-intelligence.json', {'records': []})
            with self.assertRaisesRegex(state.Blocked, 'no normaliser converts it'):
                jx._normalise(item, Path(d))


if __name__ == '__main__':
    unittest.main()
