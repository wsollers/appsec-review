"""Real FTS5/libfuzzy with a small source fixture; injected lifecycle failures."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence_store as store
import evidence_mcp
import execution_state as state


@unittest.skipUnless(sys.platform == 'linux', 'qualified in the pinned Linux ssdeep runtime')
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        location = Path(os.environ['PHASE1_TEST_DATA']) / 'evidence-fixtures'
        location.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=location)
        self.base = Path(self.tmp.name)
        self.runs = patch.object(state, 'RUNS', self.base / 'runs'); self.runs.start()
        self.intake = self.base / 'intake' / 'attempts' / 'producer'
        self.source = self.base / 'source'; self.source.mkdir()
        self.content = ('harbor fleet route ownership allocation\n' * 200).encode()
        files = {}
        for name, content in [('a.cpp', self.content), ('b.cpp', self.content), ('blob', b'\x00\x01binary')]:
            (self.source / name).write_bytes(content)
            files[name] = {'kind': 'file', 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        state.atomic_json(self.intake / 'evidence/source.json', {'target': str(self.source), 'files': files,
                          'fingerprint': 'source-fingerprint', 'revision': 'fixture'})
        state.atomic_json(self.intake / 'outputs/intake.json', {'scope': {'excluded_paths': []}})
        state.atomic_bytes(self.intake / 'outputs/build-discovery.md', b'no build executed\n')
        self.plan = {'producers': [{'kind': 'intake', 'pointer': {'attempt_id': 'producer'}}]}
        self.input_patch = patch.object(store, 'inputs', side_effect=lambda _: self.plan.copy()); self.input_patch.start()
        self.root_patch = patch.object(store.phase1, 'job_root', return_value=self.base / 'intake'); self.root_patch.start()
        self.execute_patch = patch.object(store, 'execute', side_effect=self.execute); self.execute_patch.start()

    def tearDown(self):
        self.execute_patch.stop(); self.root_patch.stop(); self.input_patch.stop(); self.runs.stop(); self.tmp.cleanup()

    def execute(self, argv, attempt, logs, timeout, **kwargs):
        state.atomic_bytes(logs / 'stdout.log', b'fixture work\n')
        state.atomic_bytes(logs / 'stderr.log', b'fixture separate stream\n')
        store.collect('fixture', attempt)
        return {'exit_code': 0}

    def test_search_citations_similarity_and_immutable_reuse(self):
        first = store.run('fixture', 'launch1')
        before = state.tree_hashes(store.root('fixture') / 'attempts')
        self.assertEqual(first, store.run('fixture', 'launch2'))
        self.assertEqual(before, state.tree_hashes(store.root('fixture') / 'attempts'))
        results = store.query('fixture', 'search', text='harbor ownership')['results']
        self.assertTrue(results)
        self.assertEqual(results[0]['start_line'], 1)
        self.assertEqual(results[0]['sha256'], hashlib.sha256(self.content).hexdigest())
        similar = store.query('fixture', 'similar', path='source/a.cpp')['results']
        self.assertTrue(any(r['path'] == 'source/b.cpp' and r['exact'] for r in similar))
        self.assertIn('harbor', store.query('fixture', 'read', path='source/a.cpp')['results'][0]['excerpt'])
        with self.assertRaises(ValueError): store.query('fixture', 'read', path='../../etc/passwd')
        with self.assertRaises(ValueError): store.query('fixture', 'read', path='source/blob')
        with self.assertRaises(ValueError): store.query('fixture', 'search', text='x', limit=51)

    def test_failed_force_preserves_success_but_never_falls_back(self):
        first = store.run('fixture', 'launch1')
        attempt = store.root('fixture') / 'attempts' / first['attempt_id']
        hashes = state.tree_hashes(attempt)
        with patch.object(store, 'execute', return_value={'exit_code': 7}):
            with self.assertRaises(state.Blocked): store.run('fixture', 'launch2', True)
        with self.assertRaises(state.Blocked): store.query('fixture', 'search', text='harbor')
        self.assertEqual(hashes, state.tree_hashes(attempt))
        recovered = store.run('fixture', 'launch3')
        self.assertNotEqual(first['attempt_id'], recovered['attempt_id'])

    def test_staleness_tamper_and_source_race_fail_closed(self):
        pointer = store.run('fixture', 'launch1')
        self.plan['changed'] = True
        with self.assertRaises(state.Blocked): store.validate('fixture')
        del self.plan['changed']
        attempt = store.root('fixture') / 'attempts' / pointer['attempt_id']
        with (attempt / 'index.sqlite').open('ab') as stream: stream.write(b'tampered')
        with self.assertRaises(state.Blocked): store.validate('fixture')
        (self.source / 'a.cpp').write_text('changed source')
        with self.assertRaises(state.Blocked): store.run('fixture', 'launch2', True)

    def test_mcp_discovery_readonly_and_error_envelope(self):
        store.run('fixture', 'launch1')
        tools = evidence_mcp.handle('fixture', {'method': 'tools/list'})['tools']
        self.assertEqual(len(tools), 3)
        result = evidence_mcp.handle('fixture', {'method': 'tools/call', 'params':
            {'name': 'evidence_search', 'arguments': {'text': 'harbor'}}})
        self.assertFalse(result['isError'])
        result = evidence_mcp.handle('fixture', {'method': 'tools/call', 'params':
            {'name': 'evidence_read', 'arguments': {'path': '../../etc/passwd'}}})
        self.assertTrue(result['isError'])

    def test_scope_exclusions_are_not_collected(self):
        state.atomic_json(self.intake / 'outputs/intake.json', {'scope': {'excluded_paths': ['b.cpp']}})
        pointer = store.run('fixture', 'launch1')
        with self.assertRaises(ValueError): store.query('fixture', 'read', path='source/b.cpp')
        manifest = state.read_json(store.root('fixture') / 'attempts' / pointer['attempt_id'] / 'manifest.json')
        self.assertIn({'path': 'source/b.cpp', 'reason': 'excluded by accepted intake scope'}, manifest['excluded'])

    def test_interrupted_attempt_is_preserved_and_recovered(self):
        base = store.root('fixture')
        attempt = base / 'attempts/interrupted'
        state.atomic_json(attempt / 'status.json', {'status': 'RUNNING'})
        state.atomic_bytes(attempt / 'partial.log', b'preserve me')
        state.atomic_json(base / 'latest.json', {'attempt_id': 'interrupted'})
        state.atomic_json(base / 'accepted.json', {'status': 'PENDING', 'attempt_id': 'interrupted'})
        before = state.tree_hashes(attempt)
        result = store.run('fixture', 'recovery')
        self.assertEqual(result['status'], 'OK')
        self.assertEqual(before, state.tree_hashes(attempt))
        receipts = list((base / 'recoveries').glob('*.json'))
        self.assertEqual(state.read_json(receipts[0])['attempt_id'], 'interrupted')

    def test_changed_producer_during_post_validation_blocks_publication(self):
        def changed(*args, **kwargs):
            outcome = self.execute(*args, **kwargs)
            self.plan['new_producer'] = True
            return outcome
        with patch.object(store, 'execute', side_effect=changed):
            with self.assertRaises(state.Blocked): store.run('fixture', 'race')
        self.assertEqual(state.read_json(store.root('fixture') / 'accepted.json')['status'], 'FAILED')


if __name__ == '__main__': unittest.main()
