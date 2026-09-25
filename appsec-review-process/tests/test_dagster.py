"""Dagster transition tests. Run with the code location's Python (Dagster is installed there):

    cd appsec-review-process
    ../orchestrator/dagster/code-location.sh run -B -m unittest tests.test_dagster

PHASE1_TEST_DATA, when set, keeps the fixture runs there for inspection; otherwise a temporary
directory is used. (Written when the code location ran in a container with the app at /opt/app;
since the code location moved to the host the paths are found from this file's own location.)"""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1] / 'orchestrator' / 'dagster'), str(HERE), str(HERE.parent)]
os.environ.setdefault('PHASE1_TEST_DATA', tempfile.mkdtemp(prefix='phase1-test-data-'))
from dagster import DagsterInstance
from definitions import phase1_intake
import test_phase1 as fixtures
import phase1
import execution_state as state


class DagsterTests(unittest.TestCase):
    setUp=fixtures.Phase1Tests.setUp
    tearDown=fixtures.Phase1Tests.tearDown
    new_run=fixtures.Phase1Tests.new_run

    def test_repository_loads_complete_lifecycle(self):
        from definitions import defs
        from dagster_workflow import full_review, LIFECYCLE
        repository=defs.get_repository_def()
        repository.load_all_definitions()
        self.assertIn('critical_findings_sarif',{job.name for job in repository.get_all_jobs()})
        self.assertIn('ossf_scorecard',{job.name for job in repository.get_all_jobs()})
        self.assertIn('repository_partition_discovery',{job.name for job in repository.get_all_jobs()})
        self.assertIn('nvd_reference_sync',{job.name for job in repository.get_all_jobs()})
        self.assertIn('nvd_reference_schedule',{schedule.name for schedule in repository.schedule_defs})
        names={node.name for node in full_review.graph.node_defs}
        for name in LIFECYCLE:
            if name not in ('00-intake','02-evidence-index'): self.assertIn('job_'+name.replace('-','_'),names)
        self.assertIn('build_discovery_work',names)
        self.assertIn('evidence_index_work',names)
        self.assertIn('job_02_ossf_scorecard',names)

    def test_build_publication_rejects_mixed_generations(self):
        from dagster import build_op_context, Failure
        from dagster_workflow import build_discovery_publish
        (self.root/'dagster').mkdir()
        with DagsterInstance.local_temp(str(self.root/'dagster')) as instance:
            with build_op_context(instance=instance) as context:
                with self.assertRaisesRegex(Failure,'mixed intake generations'):
                    build_discovery_publish(context,{'engagement_run_id':self.run_id,'intake':{'fingerprint':'new'}},
                                            {'upstream':'old'})

    def test_unavailable_worker_records_resume_command(self):
        from dagster import build_op_context, Failure
        from dagster_workflow import LIFECYCLE_OPS
        (self.root/'dagster').mkdir()
        with DagsterInstance.local_temp(str(self.root/'dagster')) as instance:
            with build_op_context(instance=instance) as context:
                with self.assertRaisesRegex(Failure,'WORKER_NOT_IMPLEMENTED'):
                    LIFECYCLE_OPS['02-evidence-assembly'](context,{'engagement_run_id':self.run_id},[])
                record=state.read_json(state.data_path(self.run_id,'orchestration','dagster',context.run_id,
                                                     '02-evidence-assembly','pre.json'))
                self.assertEqual(record['status'],'BLOCKED')
                self.assertEqual(record['resume_command'],
                    'python -B appsec-review-process/launch_job.py --run-id '+self.run_id+' --job full_review --wait')

    def dispatch(self):
        (self.root/'dagster').mkdir()
        with DagsterInstance.local_temp(str(self.root/'dagster')) as instance:
            result=phase1_intake.execute_in_process(instance=instance,raise_on_error=False,
                run_config={'resources':{'session':{'config':{'engagement_run_id':self.run_id,'force':False}}}})
            self.events=[(e.step_key,e.event_type_value) for e in result.all_events]
            return result

    def test_config_resolution_and_worker_arguments(self):
        result=self.dispatch()
        self.assertTrue(result.success)
        self.assertEqual([k for k,v in self.events if v=='STEP_SUCCESS'],
            ['intake_config','intake_pre_validation','intake_work','intake_post_validation'])
        config=state.read_json(state.data_path(self.run_id,'orchestration','dagster',result.run_id,'resolved-config.json'))
        self.assertEqual(config['job']['execution']['worker'],'intake.py')
        pointer=phase1.accepted(self.run_id)
        status=state.read_json(phase1.job_root(self.run_id)/'attempts'/pointer['attempt_id']/'status.json')
        self.assertEqual(status['dagster_run_id'],result.run_id)

    def test_config_failure_blocks_every_later_step(self):
        with patch.object(phase1.Session,'configure',side_effect=state.Blocked('bad configuration')):
            result=self.dispatch()
        self.assertFalse(result.success)
        self.assertNotIn(('intake_pre_validation','STEP_START'),self.events)
        self.assertEqual(state.read_json(state.run_path(self.run_id)/'run-status.json')['phase1_status'],'BLOCKED')

    def test_work_failure_blocks_post(self):
        with patch.object(phase1.Session,'work',side_effect=RuntimeError('worker failed')):
            result=self.dispatch()
        self.assertFalse(result.success)
        self.assertNotIn(('intake_post_validation','STEP_START'),self.events)
        self.assertIsNone(phase1.accepted(self.run_id))
        self.assertEqual(state.read_json(state.run_path(self.run_id)/'run-status.json')['phase1_status'],'FAILED')

    def test_post_failure_does_not_publish(self):
        with patch.object(phase1,'validate_intake',side_effect=ValueError('bad output')):
            result=self.dispatch()
        self.assertFalse(result.success)
        self.assertIn(('intake_work','STEP_SUCCESS'),self.events)
        self.assertIn(('intake_post_validation','STEP_FAILURE'),self.events)
        self.assertIsNone(phase1.accepted(self.run_id))


if __name__=='__main__': unittest.main()
