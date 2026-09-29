"""ADR-0025 dev-mode restart policy: data-only REUSE / RERUN / REWIND, early cutoff, guard rails,
`--explain`, and the proof that prod fingerprints do not move.

The policy tests drive dev_restart.run_pass over a fake job graph with an in-memory store: no
Dagster, no model, no container.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dev_restart as dr
import execution_state as state

# Fake graph:  A -> B -> C,  A -> D
GRAPH = {'A': [], 'B': ['A'], 'C': ['B'], 'D': ['A']}


def dump(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


class FakeJobs:
    """Deterministic fake workers. Each job's output is a function of its inputs' content and a
    per-job `behaviour` value, which a test edits to simulate a code change that does or does not
    alter the output."""
    def __init__(self):
        self.behaviour = {job: {'version': 1} for job in GRAPH}
        self.calls = []

    def __call__(self, job, current):
        self.calls.append(job)
        digest = hashlib.sha256(json.dumps(sorted((k, v['content']) for k, v in current['inputs'].items())).encode()).hexdigest()
        return {'out.json': dump({'job': job, 'from': digest[:12], **self.behaviour[job]})}


def fresh_store(own=None):
    return dr.MemoryStore(GRAPH, own=own or {job: {f'{job.lower()}.py': 'v1'} for job in GRAPH})


def actions(result):
    return {d['job']: d['action'] for d in result['decisions']}


def causes(result, job):
    return next(d['causes'] for d in result['decisions'] if d['job'] == job)


class ShapeTests(unittest.TestCase):
    def test_shape_ignores_values_and_key_order(self):
        self.assertEqual(dr.shape_hash({'a': 1, 'b': 'x'}), dr.shape_hash({'b': 'y', 'a': 2.5}))

    def test_shape_sees_keys_and_types(self):
        self.assertNotEqual(dr.shape_hash({'a': 1}), dr.shape_hash({'a': 1, 'b': 1}))
        self.assertNotEqual(dr.shape_hash({'a': 1}), dr.shape_hash({'a': '1'}))
        self.assertNotEqual(dr.shape_hash({'a': True}), dr.shape_hash({'a': 1}))
        self.assertNotEqual(dr.shape_hash({'a': None}), dr.shape_hash({'a': {}}))

    def test_array_shape_is_union_of_element_shapes(self):
        self.assertEqual(dr.shape_hash([{'a': 1}]), dr.shape_hash([{'a': 2}, {'a': 3}, {'a': 4}]))
        self.assertEqual(dr.shape_hash([1, 'x']), dr.shape_hash(['y', 2, 3]))
        self.assertNotEqual(dr.shape_hash([{'a': 1}]), dr.shape_hash([{'a': 1}, {'b': 1}]))
        self.assertNotEqual(dr.shape_hash([]), dr.shape_hash([1]))

    def test_nested_key_order_is_irrelevant(self):
        left = json.loads('{"x": {"b": [ {"d": 1, "c": 2} ], "a": null}}')
        right = json.loads('{"x": {"a": null, "b": [ {"c": 9, "d": 8} ]}}')
        self.assertEqual(dr.shape_hash(left), dr.shape_hash(right))

    def test_non_json_is_opaque(self):
        self.assertEqual(dr.observe_bytes(b'# notes\n')['shape'], dr.OPAQUE_SHAPE)
        self.assertEqual(dr.observe_bytes(b'\xef\xbb\xbf{"a": 1}')['shape'], dr.shape_hash({'a': 0}))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.store, self.jobs = fresh_store(), FakeJobs()
        first = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(set(actions(first).values()), {dr.RERUN})
        self.jobs.calls.clear()

    def test_rule2_unchanged_inputs_reuse(self):
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(actions(result), dict.fromkeys(GRAPH, dr.REUSE))
        self.assertEqual(self.jobs.calls, [])
        self.assertEqual(causes(result, 'C'), ['inputs and own files unchanged'])

    def test_rule3_content_change_same_shape_reruns(self):
        self.store.own_files['A']['a.py'] = 'v2'
        self.jobs.behaviour['A'] = {'version': 2}  # same keys and types, different value
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(actions(result), {'A': dr.RERUN, 'B': dr.RERUN, 'C': dr.RERUN, 'D': dr.RERUN})
        self.assertEqual(causes(result, 'A'), ['own a.py changed'])
        self.assertEqual(causes(result, 'B'), ['input content of A/out.json changed'])
        self.assertEqual(result['rewinds'], {})

    def test_rule5_early_cutoff_after_byte_identical_rerun(self):
        self.store.own_files['A']['a.py'] = 'v2'  # code edit that does not change A's output
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(actions(result), {'A': dr.RERUN, 'B': dr.REUSE, 'C': dr.REUSE, 'D': dr.REUSE})
        self.assertEqual(self.jobs.calls, ['A'])
        self.assertEqual(causes(result, 'B'), ['early cutoff: A reran with byte-identical output'])
        self.assertEqual(causes(result, 'C'), ['inputs and own files unchanged'])

    def test_rule5_cutoff_in_the_middle_of_a_chain(self):
        self.store.own_files['A']['a.py'] = 'v2'
        self.jobs.behaviour['A'] = {'version': 2}
        self.jobs.behaviour['B'] = {'version': 1, 'ignores_input': True}
        # B's output must not depend on A for the cutoff: make B constant.
        original = self.jobs.__call__
        def runner(job, current):
            if job == 'B':
                self.jobs.calls.append(job)
                return self.store.outputs['B']
            return original(job, current)
        result = dr.run_pass(self.store, GRAPH, runner)
        self.assertEqual(actions(result), {'A': dr.RERUN, 'B': dr.RERUN, 'C': dr.REUSE, 'D': dr.RERUN})
        self.assertEqual(causes(result, 'C'), ['early cutoff: B reran with byte-identical output'])

    def test_rule4_shape_change_rewinds_the_producer(self):
        # A's published output changed shape behind B's back (e.g. produced by an older shared
        # runtime that dev mode does not fingerprint): B must not consume it; A reruns first.
        self.store.outputs['A'] = {'out.json': dump({'job': 'A', 'stale_extra_key': [1]})}
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(result['rewinds'], {'A': 'shape of A/out.json consumed by B changed'})
        self.assertEqual(result['rewind_points'], ['A'])
        self.assertEqual(actions(result)['A'], dr.REWIND)
        self.assertEqual(self.jobs.calls[0], 'A')
        # A's rerun restored its real output, so everything downstream is byte-identical again.
        self.assertEqual(actions(result)['B'], dr.REUSE)
        self.assertEqual(causes(result, 'B'), ['early cutoff: A reran with byte-identical output'])

    def test_rule4_rewind_is_transitive(self):
        # B's recorded input from A and C's recorded input from B both have a different shape now.
        self.store.outputs['A'] = {'out.json': dump({'job': 'A', 'new': 1})}
        self.store.outputs['B'] = {'out.json': dump({'job': 'B', 'new': 1})}
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(set(result['rewinds']), {'A', 'B'})
        self.assertEqual(result['rewind_points'], ['A'])
        self.assertEqual(actions(result)['A'], dr.REWIND)
        self.assertEqual(actions(result)['B'], dr.REWIND)
        self.assertEqual(self.jobs.calls[:2], ['A', 'B'])

    def test_rule4_genuine_shape_change_reruns_consumers(self):
        self.store.own_files['A']['a.py'] = 'v2'
        self.jobs.behaviour['A'] = {'version': 2, 'added_field': 'x'}
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(result['rewinds'], {})
        self.assertEqual(actions(result)['B'], dr.RERUN)
        self.assertEqual(causes(result, 'B'), ['input shape of A/out.json changed (A reran in this pass)'])

    def test_rule4_legacy_producer_is_not_rewound(self):
        store = dr.MemoryStore(GRAPH, own=self.store.own_files, outputs=self.store.outputs,
                               ledgers=self.store.ledgers)
        store.rewindable = lambda job: job != 'A'
        store.outputs['A'] = {'out.json': dump({'job': 'A', 'new': 1})}
        result = dr.run_pass(store, GRAPH, self.jobs)
        self.assertEqual(result['rewinds'], {})
        self.assertEqual(actions(result), {'A': dr.REUSE, 'B': dr.RERUN, 'C': dr.RERUN, 'D': dr.RERUN})

    def test_rule6_shared_and_foreign_code_is_not_an_input(self):
        # The store carries only own files; shared runtime or another job's module never appears, so
        # editing one changes nothing. This is the relaunch tax dev mode removes.
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(actions(result), dict.fromkeys(GRAPH, dr.REUSE))

    def test_rule6_own_contract_counts(self):
        self.store.own_files['C']['registry/output-contracts/c.json'] = 'v1'
        result = dr.run_pass(self.store, GRAPH, self.jobs)
        self.assertEqual(actions(result), {'A': dr.REUSE, 'B': dr.REUSE, 'C': dr.RERUN, 'D': dr.REUSE})
        self.assertEqual(causes(result, 'C'), ['own registry/output-contracts/c.json added'])

    def test_force_reruns_one_job_regardless(self):
        result = dr.run_pass(self.store, GRAPH, self.jobs, forced={'B'})
        self.assertEqual(actions(result), {'A': dr.REUSE, 'B': dr.RERUN, 'C': dr.REUSE, 'D': dr.REUSE})
        self.assertEqual(causes(result, 'B'), ['--force'])
        self.assertEqual(self.jobs.calls, ['B'])

    def test_explain_marks_downstream_of_a_rerun_provisional(self):
        self.store.own_files['A']['a.py'] = 'v2'
        result = dr.run_pass(self.store, GRAPH)  # no runner: prediction only
        self.assertEqual(actions(result), {'A': dr.RERUN, 'B': dr.RERUN, 'C': dr.RERUN, 'D': dr.RERUN})
        self.assertIn('provisional: A reruns first', causes(result, 'B')[0])
        line = dr.explain_line(result['decisions'][0], 'prod would have invalidated because code hash of x.py changed')
        self.assertTrue(line.startswith('RERUN  A: own a.py changed; prod would have invalidated'))

    def test_cycle_and_unknown_dependency_are_refused(self):
        with self.assertRaises(ValueError):
            dr.topological({'A': ['B'], 'B': ['A']})
        with self.assertRaises(ValueError):
            dr.topological({'A': ['Z']})


class GuardRailTests(unittest.TestCase):
    def test_mode_defaults_to_prod_and_fails_closed(self):
        self.assertEqual(dr.run_mode({}), 'prod')
        self.assertEqual(dr.run_mode({'APPSEC_RUN_MODE': ' DEV '}), 'dev')
        with self.assertRaises(ValueError):
            dr.run_mode({'APPSEC_RUN_MODE': 'fast'})

    def test_dev_receipt_is_never_evidence_or_prod_reusable(self):
        self.assertEqual(dr.mode_fields('dev'), {'mode': 'dev', 'evidence_grade': False})
        self.assertEqual(dr.mode_fields('prod'), {'mode': 'prod', 'evidence_grade': True})
        self.assertFalse(dr.prod_may_reuse({'mode': 'dev', 'evidence_grade': False}))
        self.assertFalse(dr.prod_may_reuse({'mode': 'dev', 'evidence_grade': True}))
        self.assertFalse(dr.prod_may_reuse(None))
        self.assertTrue(dr.prod_may_reuse({'mode': 'prod', 'evidence_grade': True}))

    def _run_with_receipt(self, mode):
        root = Path(tempfile.mkdtemp()) / 'run-a'
        attempt = root / 'data' / 'jobs' / '02-x' / 'attempts' / 'a1'
        attempt.mkdir(parents=True)
        state.atomic_json(attempt.parent.parent / 'accepted.json', {'attempt_id': 'a1'})
        state.atomic_json(attempt / 'receipt.json', {'schema': dr.RECEIPT_SCHEMA, **dr.mode_fields(mode)})
        return root

    def test_deliverable_refused_for_accepted_dev_result(self):
        with self.assertRaisesRegex(state.Blocked, 'not evidence.*02-x'):
            dr.assert_deliverable(self._run_with_receipt('dev'), {})
        dr.assert_deliverable(self._run_with_receipt('prod'), {})

    def test_deliverable_refused_in_a_dev_process(self):
        with self.assertRaisesRegex(state.Blocked, 'never publishes'):
            dr.assert_deliverable(self._run_with_receipt('prod'), {'APPSEC_RUN_MODE': 'dev'})

    def test_final_publication_refuses_a_dev_run_first(self):
        import final_publication
        run_root = self._run_with_receipt('dev')
        with self.assertRaisesRegex(state.Blocked, 'not evidence'):
            final_publication.publish(run_root / 'missing-draft', {}, run_root / 'final', run_root=run_root,
                                      completeness_ref={}, feedback_ref={}, authorization_key=b'k',
                                      expected_ledger_anchor='a', expected_ledger_head='h')


class ExplainRunTests(unittest.TestCase):
    """`launch_job.py --explain` for legacy lifecycles, which keep their prod fingerprint."""
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.process = self.base / 'process'
        (self.process / 'registry').mkdir(parents=True)
        (self.base / 'schemas').mkdir()
        for name, text in (('x.py', 'x = 1\n'), ('y.py', 'y = 1\n'), ('z.py', 'z = 1\n')):
            (self.process / name).write_text(text)
        (self.base / 'schemas' / 'x.schema.json').write_text('{}\n')
        self.run = self.base / 'run-a'
        self.graph = {'jobs': {'X': {'dependencies': []}, 'Y': {'dependencies': [{'job': 'X'}]},
                               'Z': {'dependencies': []}}}
        for job, files in (('X', ['x.py', 'schemas/x.schema.json']), ('Y', ['y.py']), ('Z', ['z.py'])):
            self._accept(job, files)

    def _accept(self, job, files):
        base = self.run / 'data' / 'jobs' / job
        attempt = base / 'attempts' / 'a1'
        attempt.mkdir(parents=True)
        code = {name: state.file_hash((self.base if name.startswith('schemas/') else self.process) / name)
                for name in files}
        state.atomic_json(attempt / 'inputs.json', {'code': code})
        state.atomic_json(base / 'accepted.json', {'attempt_id': 'a1', 'status': 'OK'})

    def test_unchanged_run_reuses_everything(self):
        lines = dr.explain_run(self.run, self.graph, self.process, mode='dev')
        self.assertTrue(lines[0].startswith('# mode=dev run=run-a jobs=3'))
        self.assertEqual([line.split()[0] for line in lines[1:]], ['REUSE'] * 3)
        self.assertIn('prod would also reuse on code', lines[1])

    def test_code_change_and_cascade_are_predicted(self):
        (self.base / 'schemas' / 'x.schema.json').write_text('{"type": "object"}\n')
        lines = dict((line.split()[1].rstrip(':'), line) for line in
                     dr.explain_run(self.run, self.graph, self.process, mode='prod')[1:])
        self.assertTrue(lines['X'].startswith('RERUN  X: legacy fingerprint: code hash of schemas/x.schema.json changed'))
        self.assertIn('upstream X reruns', lines['Y'])
        self.assertTrue(lines['Z'].startswith('REUSE'))

    def test_force_and_missing_results(self):
        (self.run / 'data' / 'jobs' / 'Z' / 'accepted.json').unlink()
        lines = dr.explain_run(self.run, self.graph, self.process, mode='dev', forced=['X'])
        self.assertEqual([line.split()[1] for line in lines[1:]], ['X:', 'Z:', 'Y:'])  # topological, ties by name
        self.assertIn('RERUN  X: --force', lines[1])
        self.assertIn('RERUN  Z: no accepted result', lines[2])
        self.assertIn('RERUN  Y: upstream X reruns', lines[3])
        with self.assertRaises(ValueError):
            dr.explain_run(self.run, self.graph, self.process, mode='dev', forced=['nope'])


class LaunchFlagTests(unittest.TestCase):
    def setUp(self):
        import launch_job
        self.lj = launch_job
        self.runs = Path(tempfile.mkdtemp())
        manifest = self.runs / 'r1' / 'inputs' / 'artifact-manifest.json'
        manifest.parent.mkdir(parents=True)
        state.atomic_json(manifest, {'orchestration_version': 1, 'intake_config': {'executor_platform': 'posix'}})
        self.submitted = []

    def _launch(self, **kw):
        def graphql(query, variables):
            self.submitted.append(variables['params'])
            return {'launchRun': {'__typename': 'LaunchRunSuccess', 'run': {'runId': 'd1', 'status': 'QUEUED'}}}
        with patch.object(state, 'RUNS', self.runs), patch.object(self.lj, 'find_run', return_value=None), \
                patch.object(self.lj, 'graphql', side_effect=graphql):
            return self.lj.launch('r1', launch_id=kw.pop('launch_id', 'l1'), job='full_review', **kw)

    def test_prod_request_and_tags_are_unchanged(self):
        record = self._launch()
        self.assertNotIn('mode', record)
        self.assertNotIn('force_jobs', record)
        self.assertEqual([t['key'] for t in self.submitted[0]['executionMetadata']['tags']],
                         ['appsec/request_id', 'engagement_run_id'])
        self.assertNotIn('--mode', record['resume_argv'])

    def test_dev_request_is_marked_and_tagged(self):
        record = self._launch(mode='dev', force_jobs=['02-b', '02-a'])
        self.assertEqual((record['mode'], record['evidence_grade'], record['force_jobs']), ('dev', False, ['02-a', '02-b']))
        tags = {t['key']: t['value'] for t in self.submitted[0]['executionMetadata']['tags']}
        self.assertEqual((tags['appsec/run_mode'], tags['appsec/force_jobs']), ('dev', '02-a,02-b'))
        self.assertEqual(record['resume_argv'][-6:], ['--mode', 'dev', '--force', '02-a', '--force', '02-b'])

    def test_mode_cannot_change_on_reattach(self):
        self._launch(mode='dev')
        with self.assertRaisesRegex(state.Blocked, 'cannot change'):
            self._launch()

    def test_force_job_is_dev_only_and_final_publication_is_prod_only(self):
        with self.assertRaisesRegex(state.Blocked, 'dev-mode restart control'):
            self._launch(force_jobs=['02-a'])
        with patch.object(state, 'RUNS', self.runs):
            with self.assertRaisesRegex(state.Blocked, 'never review deliverables'):
                self.lj.launch('r1', launch_id='l2', job='final_publication_gate', mode='dev',
                               input_path='i', output_root='o')

    def test_cli_parses_force_forms_and_explain(self):
        seen = {}
        def fake_launch(run_id, force, *args):
            seen.update(force=force, mode=args[-2], force_jobs=args[-1])
            return {'status': 'QUEUED'}
        quiet = contextlib.ExitStack()
        quiet.enter_context(contextlib.redirect_stdout(io.StringIO()))
        quiet.enter_context(contextlib.redirect_stderr(io.StringIO()))
        with quiet, patch.object(self.lj, 'launch', side_effect=fake_launch), patch.dict(os.environ, {'APPSEC_RUN_MODE': ''}):
            self.assertEqual(self.lj.main(['--run-id', 'r1', '--force', '--job', 'full_review']), 0)
            self.assertEqual(seen, {'force': True, 'mode': 'prod', 'force_jobs': []})
            self.lj.main(['--run-id', 'r1', '--mode', 'dev', '--force', '02-a', '--force', '02-b'])
            self.assertEqual(seen, {'force': False, 'mode': 'dev', 'force_jobs': ['02-a', '02-b']})
        with patch.object(self.lj, 'explain', return_value=['# mode=dev', 'REUSE  X: ok']) as explain, \
                patch.dict(os.environ, {'APPSEC_RUN_MODE': 'dev'}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.lj.main(['--run-id', 'r1', '--explain']), 0)
            explain.assert_called_once_with('r1', 'dev', [])


# Files this brief adds or edits (I1 + I2). None may be a prod fingerprint input.
BRIEF_I_FILES = ('dev_restart.py', 'job_executor.py', 'launch_job.py', 'final_publication.py', 'items/')


class ProdFingerprintTests(unittest.TestCase):
    """Prod fingerprints are byte-identical before and after this brief: (1) no file the brief adds
    or edits is named by any fingerprint (`_code_hashes`, CODE_FILES, definition_hash, workflow
    branch code, ...), and (2) the run mode never leaks into a prod fingerprint computation."""

    def test_no_brief_file_is_a_fingerprint_input(self):
        own = {'dev_restart.py', 'job_executor.py', 'launch_job.py'}
        offenders = []
        for path in sorted(ROOT.glob('*.py')):
            if path.name in own:
                continue
            text = path.read_text(encoding='utf-8')
            for name in BRIEF_I_FILES:
                pattern = (r'''["']items/''' if name.endswith('/') else r'''["']''' + re.escape(name) + r'''["']''')
                if re.search(pattern, text):
                    offenders.append(f'{path.name} names {name}')
        orchestrator = ROOT.parent / 'orchestrator' / 'dagster' / 'definitions.py'
        if orchestrator.exists() and re.search(r'dev_restart|job_executor', orchestrator.read_text(encoding='utf-8')):
            offenders.append('orchestrator/dagster/definitions.py')
        self.assertEqual(offenders, [])

    def test_shared_runtime_list_is_unchanged(self):
        # ADR-0013's list is part of every job's fingerprint scope; brief I must not move it.
        self.assertEqual(hashlib.sha256('\n'.join(sorted(state.SHARED_RUNTIME)).encode()).hexdigest(),
                         '0f7ac42d3ad120130a40cbe6fb0e0c879ec2242174b02453d83c767587ad56df')

    def test_run_mode_does_not_change_prod_code_fingerprints(self):
        import build_classify
        import control_feature_lifecycle
        import static_intelligence_core
        def snapshot():
            return {'static': {job: static_intelligence_core._code_hashes(job) for job in static_intelligence_core.SPECS},
                    'classify': build_classify._code_hashes(),
                    'control': {job: control_feature_lifecycle._code(job) for job in control_feature_lifecycle.JOBS}}
        with patch.dict(os.environ, {'APPSEC_RUN_MODE': ''}):
            base = snapshot()
        for mode in ('prod', 'dev'):
            with patch.dict(os.environ, {'APPSEC_RUN_MODE': mode}):
                self.assertEqual(snapshot(), base, mode)


class FingerprintScopeTests(unittest.TestCase):
    """Brief I3: documentation is not a fingerprint input."""
    def test_intake_definition_hash_reads_no_documentation(self):
        import job_graph
        hashed = []
        real = job_graph.file_hash
        def spy(path):
            hashed.append(Path(path).resolve())
            return real(path)
        template = state.read_json(ROOT / 'registry' / 'job-templates' / '00-intake.json')
        with patch.object(job_graph, 'file_hash', side_effect=spy):
            job_graph.definition_hash(template)
        names = {path.relative_to(ROOT.parent).as_posix() for path in hashed}
        for doc in ('appsec-review-process/phase-1-implementation-prompt.md',
                    'appsec-review-process/00-intake-recovery/config.md',
                    'appsec-review-process/00-intake-recovery/prompt.md'):
            self.assertNotIn(doc, names)
        self.assertFalse([name for name in names if name.lower().endswith(('.md', 'readme'))])
        self.assertIn('appsec-review-process/intake.py', names)


if __name__ == '__main__':
    unittest.main()
