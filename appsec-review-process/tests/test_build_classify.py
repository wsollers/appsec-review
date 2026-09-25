"""Focused tests for 02-build-classify (build_classify.py; TODO Phase 5g item 3, ADR-0012 Revision 2).

No model call anywhere: the live call is the SAT's job. These cover what must hold whatever the model
says -- the deterministic validator (coverage of every index unit, part ids, signal ids, roots,
unclassified-in-gaps, build set), the orchestrator-owned fields, the claim builder, and the worker on
the common envelope with the persona dispatch stubbed (accept, reuse, gaps, rejection, tamper).
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_classify as bc
import build_index as bi
import claude_cli_invoker as cci
from execution_state import Blocked, atomic_json, file_hash, read_json
from tests import test_build_index as tbi


def hello_value(index):
    """A correct model response for the hello-autotools fixture index (orchestrator fields unset)."""
    sig = {s['label']: s['signal_id'] for s in index['signals']}
    return {
        'schema': 'appsec-review/build-classification/1', 'target': 'model-guess',
        'source_revision': 'model-guess', 'index': None, 'build_set': None,
        'units': [
            {'unit_id': 'dir:.', 'index_unit_id': 'dir:.', 'root': '.', 'class': 'compiled-native',
             'languages': ['c++', 'c'], 'rationale': 'autotools C++ program; the vendored C library is compiled in',
             'signal_ids': [sig['AC_PROG_CXX'], sig['libcjson_a_SOURCES']],
             'evidence_citations': [{'source_type': 'source_file', 'path': 'configure.ac', 'line_range': '4',
                                     'content_hash': None}],
             'confidence': 'high'},
            {'unit_id': 'file:Dockerfile', 'index_unit_id': 'file:Dockerfile', 'root': '.', 'class': 'container',
             'languages': ['dockerfile'], 'rationale': 'container definition', 'signal_ids': [sig['FROM']],
             'evidence_citations': [{'source_type': 'source_file', 'path': 'Dockerfile', 'line_range': '1',
                                     'content_hash': None}],
             'confidence': 'high'}],
        'index_review': [], 'coverage_gaps': []}


class Base(tbi.WorkerFixture):
    """A fixture run with an accepted build index; the persona dispatch is stubbed."""

    def setUp(self):
        super().setUp()
        self.index_pointer = bi.run(self.run_id, 'dagster-index')
        self.index_attempt = bi.root(self.run_id) / 'attempts' / self.index_pointer['attempt_id']
        self.index = read_json(self.index_attempt / 'build-index.json')
        self.index_sha = file_hash(self.index_attempt / 'build-index.json')
        self.response = hello_value(self.index)
        self.calls = 0
        stub = patch.object(bc, 'dispatch', self.fake_dispatch)
        stub.start()
        self.patches.append(stub)

    def fake_dispatch(self, run_id, base, record, attempt_id):
        self.calls += 1
        pinned = {p: file_hash(self.target / p) for p in ('configure.ac', 'Makefile.am', 'Dockerfile')}
        return (copy.deepcopy(self.response), '# summary\n',
                {'dispatch_mode': 'automatic', 'persona_job_id': bc.PERSONA_JOB_ID,
                 'persona_attempt_id': attempt_id, 'persona_result_sha256': 'f' * 64,
                 'model': {'family': 'claude-sonnet-5'}}, pinned)

    def finalized(self, value=None):
        value = copy.deepcopy(value or self.response)
        return bc.finalize(value, index=self.index, index_attempt_id=self.index_pointer['attempt_id'],
                           index_sha256=self.index_sha, source_revision=self.index['source_revision'],
                           pinned={p: file_hash(self.target / p) for p in ('configure.ac', 'Dockerfile')})

    def errors(self, value):
        return bc.check(value, self.index, index_attempt_id=self.index_pointer['attempt_id'],
                        index_sha256=self.index_sha, source_revision=self.index['source_revision'])


class Check(Base):
    def assertRejected(self, mutate, message):
        value = self.finalized()
        mutate(value)
        errors = self.errors(value)
        self.assertTrue(any(message in e for e in errors), errors)

    def test_correct_response_passes(self):
        value = self.finalized()
        self.assertEqual(self.errors(value), [])
        self.assertEqual(value['build_set'], ['dir:.'])
        self.assertEqual(value['index'], {'attempt_id': self.index_pointer['attempt_id'], 'sha256': self.index_sha})
        self.assertEqual(value['source_revision'], self.index['source_revision'])
        self.assertEqual(value['target'], self.index['target'])
        self.assertTrue(all(len(c['content_hash']) == 64 for u in value['units'] for c in u['evidence_citations']))

    def test_every_index_unit_must_be_classified(self):
        self.assertRejected(lambda v: v['units'].pop(), 'is not classified')

    def test_unknown_unit(self):
        def add(v):
            extra = copy.deepcopy(v['units'][0])
            extra['unit_id'] = extra['index_unit_id'] = 'dir:ghost'
            v['units'].append(extra)
        self.assertRejected(add, 'not a unit of the accepted index')

    def test_split_into_two_parts_is_valid(self):
        value = self.finalized()
        part_a = copy.deepcopy(value['units'][0])
        part_b = copy.deepcopy(value['units'][0])
        part_a['unit_id'], part_b['unit_id'] = 'dir:.::app', 'dir:.::vendored-c'
        part_b['root'] = 'vendor/cJSON-1.7.18'
        value['units'][0:1] = [part_a, part_b]
        value['build_set'] = bc.derived_build_set(value)
        self.assertEqual(self.errors(value), [])

    def test_single_part_and_whole_plus_part_rejected(self):
        def single(v):
            v['units'][0]['unit_id'] = 'dir:.::app'
            v['build_set'] = bc.derived_build_set(v)
        self.assertRejected(single, 'single part')

        def both(v):
            part = copy.deepcopy(v['units'][0])
            part['unit_id'] = 'dir:.::app'
            v['units'].append(part)
            v['build_set'] = bc.derived_build_set(v)
        self.assertRejected(both, 'both whole and in parts')

    def test_bad_part_id_and_part_outside_root(self):
        def bad_id(v):
            a, b = copy.deepcopy(v['units'][1]), copy.deepcopy(v['units'][1])
            a['unit_id'], b['unit_id'] = 'file:Dockerfile::Build', 'file:Other::x'
            v['units'][1:2] = [a, b]
        self.assertRejected(bad_id, 'part id')

        def outside(v):
            a, b = copy.deepcopy(v['units'][0]), copy.deepcopy(v['units'][0])
            a['unit_id'], b['unit_id'] = 'dir:.::a', 'dir:.::b'
            b['root'] = '../elsewhere'
            v['units'][0:1] = [a, b]
            v['build_set'] = bc.derived_build_set(v)
        self.assertRejected(outside, 'root')

    def test_whole_unit_root_must_match(self):
        self.assertRejected(lambda v: v['units'][0].update(root='src'), 'is not the index unit root')

    def test_unknown_signal(self):
        self.assertRejected(lambda v: v['units'][0]['signal_ids'].append('s9999'), 'signal s9999')

    def test_unclassified_needs_a_gap(self):
        def unclassified(v):
            v['units'][1]['class'] = 'unclassified'
        self.assertRejected(unclassified, 'coverage_gaps')
        value = self.finalized()
        value['units'][1]['class'] = 'unclassified'
        value['coverage_gaps'] = ['file:Dockerfile: the base image could not be read']
        self.assertEqual(self.errors(value), [])

    def test_build_set_must_be_derived(self):
        self.assertRejected(lambda v: v.update(build_set=['dir:.', 'file:Dockerfile']), 'build_set')

    def test_index_identity_and_revision(self):
        self.assertRejected(lambda v: v.update(index={'attempt_id': 'x', 'sha256': '0' * 64}), 'index does not name')
        self.assertRejected(lambda v: v.update(source_revision='other'), 'source_revision')

    def test_index_review_paths_and_units(self):
        cite = [{'source_type': 'source_file', 'path': 'Makefile.am', 'line_range': None, 'content_hash': None}]
        self.assertRejected(lambda v: v['index_review'].append(
            {'kind': 'other', 'path': '../x', 'unit_id': None, 'statement': 's', 'evidence_citations': cite}), 'index_review[0].path')
        self.assertRejected(lambda v: v['index_review'].append(
            {'kind': 'other', 'path': 'x', 'unit_id': 'dir:ghost', 'statement': 's', 'evidence_citations': cite}), 'index_review[0].unit_id')

    def test_model_may_leave_orchestrator_fields_null(self):
        from schema_validate import validate_document
        self.assertEqual(validate_document(self.response, 'build-classification.schema.json'), [])


class Claims(Base):
    def inputs(self, *paths):
        return tuple(cci_item(p) for p in paths)

    def test_one_claim_per_unit_and_review_item(self):
        value = copy.deepcopy(self.response)
        value['index_review'] = [{'kind': 'missed-signal', 'path': 'Makefile.am', 'unit_id': 'dir:.',
                                  'statement': 'TESTS = tests/run.sh is not indexed',
                                  'evidence_citations': [{'source_type': 'source_file', 'path': 'Makefile.am',
                                                          'line_range': '9', 'content_hash': None}]}]
        claims = cci._claims_from_build_classification(
            value, self.inputs('configure.ac', 'Dockerfile', 'Makefile.am'),
            ('build_unit_classification', 'index_review', 'evidence_gap'), bc.RESULT)
        self.assertEqual([c['claim_class'] for c in claims],
                         ['build_unit_classification', 'build_unit_classification', 'index_review'])

    def test_unresolvable_citation_rejected(self):
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_build_classification(self.response, self.inputs('Dockerfile'),
                                                  ('build_unit_classification', 'index_review'), bc.RESULT)

    def test_empty_needs_a_gap(self):
        empty = dict(self.response, units=[], coverage_gaps=[])
        with self.assertRaises(cci.InvokerOutputError):
            cci._claims_from_build_classification(empty, (), ('build_unit_classification', 'index_review'), bc.RESULT)
        self.assertEqual(cci._claims_from_build_classification(
            dict(empty, coverage_gaps=['no unit in the index']), (),
            ('build_unit_classification', 'index_review'), bc.RESULT), [])

    def test_registered_for_the_schema(self):
        self.assertIs(cci._CLAIM_BUILDERS['build-classification.schema.json'], cci._claims_from_build_classification)


def cci_item(path):
    from types import SimpleNamespace
    return SimpleNamespace(root='target-repository', path=path, sha256='a' * 64, data=b'')


class Worker(Base):
    def test_run_publishes_and_validates(self):
        pointer = bc.run(self.run_id, 'dagster-1')
        self.assertEqual(pointer['status'], 'OK')
        attempt = bc.validate(self.run_id)
        value = read_json(attempt / bc.RESULT)
        self.assertEqual(value['build_set'], ['dir:.'])
        self.assertEqual(value['index']['attempt_id'], self.index_pointer['attempt_id'])
        status = read_json(attempt / 'status.json')
        self.assertEqual(status['persona_job_id'], bc.PERSONA_JOB_ID)
        self.assertEqual(status['source_revision'], self.index['source_revision'])
        envelope = read_json(attempt / 'result.json')
        self.assertEqual(envelope['worker_kind'], 'persona')

    def test_reuse_does_not_call_the_model_again(self):
        first = bc.run(self.run_id, 'dagster-1')
        second = bc.run(self.run_id, 'dagster-2')
        self.assertEqual(first['attempt_id'], second['attempt_id'])
        self.assertEqual(self.calls, 1)

    def test_unclassified_is_ok_with_gaps_and_disagreement_alone_is_not(self):
        self.response['index_review'] = [{'kind': 'other', 'path': 'tests/run.sh', 'unit_id': 'dir:.',
                                          'statement': 'test driver', 'evidence_citations': [
                                              {'source_type': 'source_file', 'path': 'Makefile.am',
                                               'line_range': None, 'content_hash': None}]}]
        self.assertEqual(bc.run(self.run_id, 'dagster-1')['status'], 'OK')
        self.response['units'][1]['class'] = 'unclassified'
        self.response['coverage_gaps'] = ['file:Dockerfile: base image not determinable']
        pointer = bc.run(self.run_id, 'dagster-2', force=True)
        self.assertEqual(pointer['status'], 'OK_WITH_GAPS')
        self.assertEqual(read_json(bc.validate(self.run_id) / bc.RESULT)['build_set'], ['dir:.'])

    def test_invalid_response_is_not_published(self):
        self.response['units'].pop()
        with self.assertRaisesRegex(ValueError, 'is not classified'):
            bc.run(self.run_id, 'dagster-1')
        self.assertNotEqual(read_json(bc.root(self.run_id) / 'accepted.json').get('status'), 'OK')

    def test_stale_citation_is_not_published(self):
        self.response['units'][0]['evidence_citations'][0]['path'] = 'src/main.cpp'  # not in pinned map
        with self.assertRaisesRegex(ValueError, 'content_hash'):
            bc.run(self.run_id, 'dagster-1')

    def test_tampered_attempt_fails_validation(self):
        pointer = bc.run(self.run_id, 'dagster-1')
        attempt = bc.root(self.run_id) / 'attempts' / pointer['attempt_id']
        value = read_json(attempt / bc.RESULT)
        value['units'][0]['class'] = 'interpreted'
        atomic_json(attempt / bc.RESULT, value)
        with self.assertRaises(Blocked):
            bc.validate(self.run_id)

    def test_changed_index_means_new_inputs(self):
        bc.run(self.run_id, 'dagster-1')
        record = bc.current_inputs(self.run_id)
        self.assertEqual(record['upstream']['attempt_id'], self.index_pointer['attempt_id'])
        self.assertEqual(record['upstream'][bc.UPSTREAM_NAME], self.index_sha)
        self.assertIn('02-evidence-pregather/task-build-classify.md', record['code'])

    def test_shared_contract_validator_checks_content(self):
        import validate_job_output as vjo
        pointer = bc.run(self.run_id, 'dagster-1')
        attempt = bc.root(self.run_id) / 'attempts' / pointer['attempt_id']
        contract = read_json(ROOT / 'registry' / 'output-contracts' / 'build-classification.json')
        self.assertEqual(vjo.validate_contract_result(attempt, contract, run_id=self.run_id), [])
        value = read_json(attempt / bc.RESULT)
        value['units'].pop()
        atomic_json(attempt / bc.RESULT, value)
        errors = vjo.validate_contract_result(attempt, contract, run_id=self.run_id)
        self.assertTrue(any(e.startswith('build classification:') and 'not classified' in e for e in errors), errors)


class Request(Base):
    """The real request the live dispatch sends, built without a model call (D01 lesson 1: check
    the template, prompt sections, contract and envelope before the first live run)."""

    def test_request_reads_checkout_and_the_staged_index(self):
        import discovery_gate
        import model_version_registry as mvr
        import persona_dispatch as pd
        import review_cli as rc
        identity = {'provider': 'anthropic', 'family': 'claude-sonnet-5', 'model_id': 'claude-sonnet-5-x',
                    'snapshot': 'claude-sonnet-5-x'}
        resolved = rc.resolve_model(bc.JOB, 'standard')
        self.assertEqual((resolved['model'], resolved['effort']), ('claude-sonnet-5', 'medium'))
        record = bc.current_inputs(self.run_id)
        index_path, _index = bc._accepted_index(self.run_id, record)
        upstream = discovery_gate._stage_upstream_files(bc.root(self.run_id),
                                                        {bc.UPSTREAM_NAME: (index_path, record['upstream'][bc.UPSTREAM_NAME])})
        with patch.object(mvr, 'model_identity_for', lambda run_id, alias: dict(identity, family=alias)):
            request = pd.build_request(bc.JOB, run_id=self.run_id, job_id=bc.PERSONA_JOB_ID, attempt_id='a' * 32,
                                       target_root=self.target, source_snapshot_sha256=record['source_snapshot_sha256'],
                                       now='2026-09-25T00:00:00Z', upstream_root=upstream)
        roots = {(e['root'], e['path']) for e in request['readable_inputs']}
        self.assertIn((pd.UPSTREAM_ROOT_ID, 'build-index.json'), roots)
        self.assertIn((pd.DEFAULT_READABLE_ROOT, 'configure.ac'), roots)
        self.assertIn((pd.DEFAULT_READABLE_ROOT, 'src/main.cpp'), roots)  # the whole checkout (Revision 2)
        self.assertEqual(set(request['allowed_claim_classes']),
                         {'build_unit_classification', 'index_review', 'evidence_gap'})
        self.assertEqual(request['model']['family'], 'claude-sonnet-5')
        prompt = (ROOT / request['outer_prompt']['path']).read_text(encoding='utf-8')  # gitignored prompt-cache
        self.assertIn('# Build Unit Classification', prompt)  # the task prompt section
        self.assertIn('build-unit-classifier', prompt)  # the role section
        contract = read_json(ROOT / 'registry' / 'output-contracts' / 'build-classification.json')
        self.assertEqual([f[0] for f in cci._envelope_fields(contract)], [bc.RESULT, bc.SUMMARY])


if __name__ == '__main__':
    unittest.main()
