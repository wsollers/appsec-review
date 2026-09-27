from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from owasp_dispatch_support import DispatchCase

import execution_state
import owasp_join_publisher as publisher
import owasp_join_report as join
from schema_validate import SchemaStore,validate_document


class OwaspJoinPublisherTests(DispatchCase):
    chapters=("V1",)

    def publish(self):
        self.dispatch()
        return publisher.run(self.run_id,"dagster-t14-fixture",self.facts())

    def test_exact_verified_join_publishes_one_common_envelope_and_canonical_receipts(self):
        pointer=self.publish(); self.assertIn(pointer["status"],{"OK","OK_WITH_GAPS"})
        attempt=publisher.validate(self.run_id,self.facts(),pointer)
        envelope=execution_state.read_json(attempt/"result.json")
        self.assertEqual(envelope["output_contract"],publisher.CONTRACT)
        self.assertEqual({item["path"] for item in envelope["artifacts"]},
            {*publisher.PUBLISHED,"permission.json","lineage.json","status.json"})
        outputs=join.derive(join.load_verified_inputs(self.run_id,facts=self.facts()))
        for name in publisher.PUBLISHED:
            self.assertEqual(execution_state.read_json(attempt/name),outputs[name])
        permission=execution_state.read_json(attempt/"permission.json")
        self.assertEqual(permission,{"schema":"appsec-review/producer-permission-receipt/1.0",
            "run_id":self.run_id,"job_id":publisher.JOB,
            "source_snapshot_sha256":self.facts().source_snapshot_sha256,
            "permissions":publisher.PERMISSIONS})
        lineage=execution_state.read_json(attempt/"lineage.json")
        self.assertEqual(lineage["job_id"],publisher.JOB)
        self.assertRegex(lineage["build_lineage_sha256"],r"^sha256:[0-9a-f]{64}$")
        status=execution_state.read_json(attempt/"status.json")
        self.assertEqual({key:status[key] for key in ("selected","applicable","assessed","satisfied")},
                         outputs[join.MATRIX]["denominators"])
        command=publisher._resume_command(self.run_id,"dagster-t14-fixture",self.facts())
        self.assertIn("--allowed-model-json",command); self.assertNotIn("...",command)

    def test_attempt_artifact_tamper_and_stale_trusted_facts_fail_closed(self):
        pointer=self.publish(); attempt=publisher.root(self.run_id)/"attempts"/pointer["attempt_id"]
        matrix=execution_state.read_json(attempt/join.MATRIX); matrix["denominators"]["selected"]+=1
        execution_state.atomic_json(attempt/join.MATRIX,matrix)
        with self.assertRaisesRegex(execution_state.Blocked,"changed"):
            publisher.validate(self.run_id,self.facts(),pointer)
        with self.assertRaises(Exception):
            publisher.current_inputs(self.run_id,self.facts(source_snapshot_sha256="sha256:"+"0"*64))

    def test_resealed_permission_or_output_forgery_fails_deterministic_attempt_validation(self):
        pointer=self.publish(); attempt=publisher.root(self.run_id)/"attempts"/pointer["attempt_id"]
        inputs=execution_state.read_json(attempt/"inputs.json")
        permission=execution_state.read_json(attempt/"permission.json")
        permission["permissions"].append("target-execution")
        execution_state.atomic_json(attempt/"permission.json",permission)
        with self.assertRaisesRegex(execution_state.Blocked,"permission"):
            publisher._validate_attempt(attempt,inputs,self.facts())

    def test_output_contract_and_owned_schema_are_valid(self):
        contract=json.loads((Path(publisher.ROOT)/"registry/output-contracts/owasp-join-report.json").read_text())
        self.assertEqual(validate_document(contract,"output-contract.schema.json",SchemaStore()),[])
        self.assertEqual(contract["required_files"],
            [join.MATRIX,join.GAPS,join.ROUTES,"permission.json","lineage.json","status.json"])


if __name__=="__main__": unittest.main()
