"""Build discovery integration semantics, freshness, recovery and catalog coverage."""
import unittest
from unittest.mock import patch
import test_phase1 as fixtures
import execution_state as state
import phase1
import workflow
import job_graph


class BuildDiscoveryTests(unittest.TestCase):
    setUp=fixtures.Phase1Tests.setUp
    tearDown=fixtures.Phase1Tests.tearDown
    new_run=fixtures.Phase1Tests.new_run

    def start(self):
        (self.target/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.21)\nproject(example CXX)\nfind_package(Qt6 REQUIRED)\n')
        return phase1.run_intake(self.run_id)[0]

    def test_build_plan_citations_streams_and_reuse(self):
        pointer=self.start()
        first=workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')
        path=workflow.validate_branch(self.run_id,'build_discovery',first)
        output=state.read_json(path/'output.json')
        self.assertEqual(output['primary_build_file'],'CMakeLists.txt')
        self.assertEqual(output['declarations'][2]['line'],3)
        self.assertEqual(output['proposed_argv'][0][0],'cmake')
        self.assertFalse(output['target_execution'])
        for stream in ('stdout','stderr'): self.assertTrue((path/'logs'/(stream+'.log')).read_text())
        self.assertEqual(first,workflow.run_branch(self.run_id,'build_discovery',pointer,'build-b'))

    def test_source_changes_block_reuse(self):
        pointer=self.start()
        workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')
        (self.target/'CMakeLists.txt').write_text('changed')
        with self.assertRaises(state.Blocked): workflow.run_branch(self.run_id,'build_discovery',pointer,'build-b')

    def test_failed_worker_then_recovery(self):
        pointer=self.start()
        with patch.object(workflow,'execute',return_value={'exit_code':7}):
            with self.assertRaises(RuntimeError): workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')
        base=state.data_path(self.run_id,'jobs','00-workflow-preparation','build_discovery')
        failed=state.read_json(base/'latest.json')['attempt_id']
        before=state.tree_hashes(base/'attempts'/failed)
        result=workflow.run_branch(self.run_id,'build_discovery',pointer,'build-b')
        self.assertNotEqual(failed,result['attempt_id'])
        self.assertEqual(before,state.tree_hashes(base/'attempts'/failed))

    # Registered job templates that are deliberately NOT full_review lifecycle nodes. 00-validation
    # is the validator composition. docs/dagster/critical-findings-sarif-job.md: the SARIF transform "is a
    # standalone registered job rather than a completed full_review lifecycle node" -- its own Dagster
    # job, fed by a staged input, consumed by no graph node. This test was added in the same commit
    # as that template and failed from then on (Linux baseline 2026-09-20) because it exempted only
    # the first. Pinned both ways: adding a template, or moving one of these into the graph, has to
    # be a decision recorded here.
    STANDALONE_TEMPLATES={'00-validation','10-critical-findings-sarif'}

    def test_all_registry_jobs_have_lifecycle_nodes(self):
        graph=job_graph.load_graph()['jobs']
        templates={path.stem for path in (state.ROOT/'registry/job-templates').glob('*.json')}
        self.assertLessEqual(self.STANDALONE_TEMPLATES,templates)
        for name in sorted(templates-self.STANDALONE_TEMPLATES): self.assertIn(name,graph)
        for name in sorted(self.STANDALONE_TEMPLATES): self.assertNotIn(name,graph)

    def test_target_text_never_becomes_executable_argv(self):
        pointer=self.start()
        (self.target/'README.md').write_text('cmake && touch /tmp/unsafe\n')
        pointer=phase1.run_intake(self.run_id)[0]
        result=workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')
        output=state.read_json(workflow.validate_branch(self.run_id,'build_discovery',result)/'output.json')
        self.assertTrue(any('unsafe' in c['text'] for c in output['observed_build_text']))
        self.assertNotIn('unsafe',str(output['proposed_argv']))

    def test_unknown_build_records_gap_without_invented_commands(self):
        pointer=phase1.run_intake(self.run_id)[0]
        result=workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')
        output=state.read_json(workflow.validate_branch(self.run_id,'build_discovery',result)/'output.json')
        self.assertEqual(output['proposed_argv'],[])
        self.assertEqual(output['readiness'],'BLOCKED_UNSUPPORTED_OR_AMBIGUOUS_BUILD')

    def test_oversized_evidence_fails_prevalidation(self):
        (self.target/'README.md').write_text('x'*262145)
        pointer=phase1.run_intake(self.run_id)[0]
        with self.assertRaisesRegex(state.Blocked,'budget'):
            workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')

    def test_zero_exit_with_invalid_output_fails_postvalidation(self):
        pointer=self.start()
        def invalid(argv,cwd,*args,**kwargs):
            state.atomic_json(cwd/'output.json',{'build_status':'SUCCESS'})
            return {'exit_code':0}
        with patch.object(workflow,'execute',side_effect=invalid):
            with self.assertRaisesRegex(state.Blocked,'mismatch'):
                workflow.run_branch(self.run_id,'build_discovery',pointer,'build-a')
        self.assertEqual(state.read_json(state.data_path(self.run_id,'jobs','00-workflow-preparation',
                              'build_discovery','accepted.json'))['status'],'FAILED')

    def test_comments_are_not_build_declarations(self):
        import build_discovery
        result=build_discovery.discover({'source_fingerprint':'x','source_revision':'y'},
               {'files':[{'path':'CMakeLists.txt','sha256':'z','text':'# project(fake)\nproject(real)\n'}],
                'composition':{},'buildenv_catalog':{'images':[]}})
        self.assertEqual([d['line'] for d in result['declarations']],[2])
