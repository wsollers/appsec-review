"""Required ordering and independence of the planned evidence collection graph."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from execution_state import Blocked
from job_graph import load_graph, dependency_ok


class IntelGraphTests(unittest.TestCase):
    def setUp(self):
        self.jobs=load_graph()['jobs']

    def ancestors(self,name):
        result=set()
        for dep in self.jobs[name]['dependencies']:
            if dep.get('enabled',True):
                result.add(dep['job']); result.update(self.ancestors(dep['job']))
        return result

    def test_source_consumers_do_not_wait_for_build_or_re(self):
        for name in ('02-source-sast','02-doc-intelligence-ingest','02-api-collection-intelligence-ingest',
                     '02-test-intelligence-ingest','02-operations-doc-ingest','02-standards-source-ingest'):
            self.assertEqual(self.ancestors(name),{'00-intake'},name)

    def test_binary_analysis_waits_for_successful_build(self):
        for name in ('02-binary-triage','02-binary-cfg','02-binary-intelligence-ingest','02-debug-symbol-index'):
            self.assertIn('02-native-build',self.ancestors(name))
        dep=self.jobs['02-binary-triage']['dependencies'][0]
        for status in ('FAILED','BLOCKED','RUNNING'):
            with self.assertRaises(Blocked):dependency_ok(dep,{'status':status})

    def test_ir_uses_build_outputs_and_link_precedes_facts(self):
        self.assertIn('02-native-build',self.ancestors('02-ir-capture'))
        self.assertEqual(self.jobs['02-ir-link']['dependencies'][0]['job'],'02-ir-capture')
        self.assertEqual(self.jobs['02-ir-facts']['dependencies'][0]['job'],'02-ir-link')
        self.assertNotIn('02-binary-cfg',self.ancestors('02-native-sast'))
        self.assertNotIn('02-ir-capture',self.ancestors('02-native-sast'))

    def test_no_symbols_is_explicit_and_not_a_binary_failure(self):
        dep=next(d for d in self.jobs['02-binary-cfg']['dependencies'] if d['job']=='02-debug-symbol-index')
        dependency_ok(dep,{'status':'SKIPPED','reason':'no-debug-symbols'})
        with self.assertRaises(Blocked):dependency_ok(dep,{'status':'SKIPPED','reason':'tool-crashed'})

    def test_assembly_requires_independent_intel_and_rejects_failure(self):
        deps={d['job']:d for d in self.jobs['02-evidence-assembly']['dependencies']}
        for name in ('02-source-sast','02-native-sast','02-ir-facts','02-binary-intelligence-ingest',
                     '02-doc-intelligence-ingest','02-test-intelligence-ingest','02-test-result-ingest',
                     '02-test-coverage-ingest','02-operations-doc-ingest'):
            self.assertIn(name,deps)
            with self.assertRaises(Blocked):dependency_ok(deps[name],None)
            with self.assertRaises(Blocked):dependency_ok(deps[name],{'status':'FAILED'})

    def test_test_source_results_and_coverage_are_separate(self):
        self.assertNotIn('02-test-execution',self.ancestors('02-test-intelligence-ingest'))
        for name in ('02-test-result-ingest','02-test-coverage-ingest'):
            self.assertIn('02-test-execution',self.ancestors(name))

    def test_non_native_skip_propagates_through_binary_consumers(self):
        for dep in self.jobs['02-binary-intelligence-ingest']['dependencies']:
            dependency_ok(dep,{'status':'SKIPPED','reason':'not-applicable-non-native'})
        dep=next(d for d in self.jobs['02-evidence-assembly']['dependencies'] if d['job']=='02-binary-intelligence-ingest')
        dependency_ok(dep,{'status':'SKIPPED','reason':'not-applicable-non-native'})


if __name__=='__main__':unittest.main()
