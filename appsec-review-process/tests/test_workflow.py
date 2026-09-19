"""Behavioral coverage for independent, immutable workflow preparation units."""
import copy
import unittest
from unittest.mock import patch
import test_phase1 as fixtures
import execution_state as state
import phase1
import workflow


class WorkflowTests(unittest.TestCase):
    setUp=fixtures.Phase1Tests.setUp
    tearDown=fixtures.Phase1Tests.tearDown
    new_run=fixtures.Phase1Tests.new_run

    def intake(self):
        pointer,_=phase1.run_intake(self.run_id)
        state.atomic_json(workflow.root(self.run_id)/'status.json',{'status':'RUNNING','dagster_run_id':'workflow-a'})
        return pointer

    def test_independent_branches_join_and_reuse(self):
        pointer=self.intake()
        results=[workflow.run_branch(self.run_id,name,pointer,'workflow-a') for name in workflow.plan()['branches']]
        with self.assertRaises(state.Blocked): workflow.publish(self.run_id,'workflow-a',pointer,results[:2])
        result=workflow.publish(self.run_id,'workflow-a',pointer,results)
        self.assertEqual(result['status'],'OK')
        for first in results:
            second=workflow.run_branch(self.run_id,first['branch'],pointer,'workflow-b')
            self.assertEqual(first,second)
            workflow.validate_branch(self.run_id,first['branch'],first)

    def test_failure_preserves_successful_sibling_and_resume(self):
        pointer=self.intake()
        first=workflow.run_branch(self.run_id,'scope_check',pointer,'workflow-a')
        path=workflow.validate_branch(self.run_id,'scope_check',first)
        before=state.tree_hashes(path)
        with patch.object(workflow,'execute',side_effect=RuntimeError('lost worker')):
            with self.assertRaises(RuntimeError): workflow.run_branch(self.run_id,'native_plan_check',pointer,'workflow-a')
        self.assertFalse((workflow.root(self.run_id)/'accepted.json').exists())
        resumed=workflow.run_branch(self.run_id,'native_plan_check',pointer,'workflow-b')
        self.assertEqual(resumed['status'],'OK')
        self.assertEqual(state.tree_hashes(path),before)

    def test_job_lock_is_local_to_branch(self):
        pointer=self.intake()
        with state.Lock(state.data_path(self.run_id,'jobs','00-workflow-preparation','scope_check','job.lock')):
            with self.assertRaises(state.Blocked): workflow.run_branch(self.run_id,'scope_check',pointer,'workflow-a')
            self.assertEqual(workflow.run_branch(self.run_id,'native_plan_check',pointer,'workflow-a')['status'],'OK')

    def test_tampering_force_and_stale_source(self):
        pointer=self.intake()
        first=workflow.run_branch(self.run_id,'scope_check',pointer,'workflow-a')
        path=workflow.validate_branch(self.run_id,'scope_check',first)
        original=state.tree_hashes(path)
        second=workflow.run_branch(self.run_id,'scope_check',pointer,'workflow-b',force=True)
        self.assertNotEqual(first['attempt_id'],second['attempt_id'])
        self.assertEqual(state.tree_hashes(path),original)
        damaged=workflow.validate_branch(self.run_id,'scope_check',second)
        state.atomic_json(damaged/'output.json',{'wrong':True})
        with self.assertRaises(state.Blocked): workflow.validate_branch(self.run_id,'scope_check',second)
        third=workflow.run_branch(self.run_id,'scope_check',pointer,'workflow-c')
        self.assertNotEqual(second['attempt_id'],third['attempt_id'])
        results=[third]+[workflow.run_branch(self.run_id,name,pointer,'workflow-c') for name in workflow.plan()['branches'][1:]]
        (self.target/'main.py').write_text('changed')
        with self.assertRaises(state.Blocked): workflow.publish(self.run_id,'workflow-a',pointer,results)

    def test_handoffs_preserve_discovery_dependencies_and_claim_limits(self):
        pointer=self.intake()
        result=workflow.run_branch(self.run_id,'discovery_handoffs',pointer,'workflow-a')
        output=state.read_json(workflow.validate_branch(self.run_id,'discovery_handoffs',result)/'output.json')
        self.assertFalse(output['target_execution'])
        self.assertEqual(output['findings'],[])
        self.assertEqual(len(output['jobs']),4)
        for job in output['jobs']:
            self.assertEqual(job['status'],'PLANNED_NOT_EXECUTED')
            self.assertNotIn('scratch/',job['output_root'])
            if job['job']!='02-repository-partition-discovery':
                self.assertEqual(job['prerequisites'],['02-repository-partition-discovery'])

    def test_publication_rechecks_upstream_at_commit(self):
        pointer=self.intake()
        results=[workflow.run_branch(self.run_id,name,pointer,'workflow-a') for name in workflow.plan()['branches']]
        with patch.object(workflow,'accepted',side_effect=[pointer,None]):
            with self.assertRaisesRegex(state.Blocked,'at workflow commit'):
                workflow.publish(self.run_id,'workflow-a',pointer,results)
        self.assertFalse((workflow.root(self.run_id)/'accepted.json').exists())

    def test_status_reports_workflow_failure_and_invalidated_upstream(self):
        pointer=self.intake()
        self.assertEqual(workflow.inspect_status(self.run_id)['status'],'RUNNING')
        results=[workflow.run_branch(self.run_id,name,pointer,'workflow-a') for name in workflow.plan()['branches']]
        workflow.publish(self.run_id,'workflow-a',pointer,results)
        self.assertEqual(workflow.inspect_status(self.run_id)['status'],'OK')
        phase1.stage(self.run_id,self.target,'fixture','Changed goal',['Linux','Windows'])
        self.assertEqual(workflow.inspect_status(self.run_id)['status'],'BLOCKED')
        state.atomic_json(workflow.root(self.run_id)/'status.json',{'status':'FAILED','dagster_run_id':'workflow-a','error':'branch failed'})
        self.assertEqual(workflow.inspect_status(self.run_id)['status'],'FAILED')
        import contextlib, io, json, review_cli
        from types import SimpleNamespace
        output=io.StringIO()
        with patch.object(review_cli,'manifest_for_run',return_value={'orchestration_version':1}), contextlib.redirect_stdout(output):
            self.assertEqual(review_cli.cmd_status(SimpleNamespace(run_id=self.run_id)),1)
        self.assertEqual(json.loads(output.getvalue())['error'],'branch failed')


if __name__=='__main__': unittest.main()
