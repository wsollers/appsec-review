"""Dagster transition tests; run in code-server with PHASE1_TEST_DATA set."""
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,'/opt/app')
from dagster import DagsterInstance
from definitions import phase1_intake
import test_phase1 as fixtures
import phase1
import execution_state as state


class DagsterTests(unittest.TestCase):
    setUp=fixtures.Phase1Tests.setUp
    tearDown=fixtures.Phase1Tests.tearDown
    new_run=fixtures.Phase1Tests.new_run

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
