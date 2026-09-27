from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent))
from owasp_dispatch_support import DispatchCase

import execution_state
import owasp_join_publisher as publisher
import owasp_join_report as join
from schema_validate import SchemaStore,validate_document


class OwaspJoinPublisherTests(DispatchCase):
    chapters=("V1","V2","V3")

    def publish(self):
        self.dispatch()
        return publisher.run(self.run_id,"dagster-t14-fixture",self.facts())

    def test_exact_verified_join_publishes_one_common_envelope_and_canonical_receipts(self):
        pointer=self.publish(); self.assertIn(pointer["status"],{"OK","OK_WITH_GAPS"})
        attempt=publisher.validate(self.run_id,self.facts(),pointer)
        envelope=execution_state.read_json(attempt/"result.json")
        self.assertEqual(envelope["output_contract"],publisher.CONTRACT)
        expected=publisher._derive(self.run_id,self.facts())
        self.assertEqual({item["path"] for item in envelope["artifacts"]},
            {*publisher.published_names(expected),"permission.json","lineage.json","status.json"})
        outputs=join.derive(join.load_verified_inputs(self.run_id,facts=self.facts()))
        for name in publisher.published_names(expected):
            self.assertEqual(execution_state.read_json(attempt/name),expected[name])
        manifest=execution_state.read_json(attempt/publisher.MATRIX_MANIFEST)
        self.assertEqual(manifest["row_count"],len(outputs[join.MATRIX]["rows"]))
        self.assertEqual(manifest["matrix_header"]["denominators"],outputs[join.MATRIX]["denominators"])
        self.assertEqual(manifest["logical_matrix_sha256"],execution_state.digest(outputs[join.MATRIX]))
        cursor=0; reconstructed=[]
        for index,record in enumerate(manifest["pages"]):
            page=execution_state.read_json(attempt/record["path"])
            self.assertEqual(record["page_index"],index)
            self.assertEqual(record["first_row_index"],cursor)
            self.assertEqual(record["last_row_index"],cursor+record["row_count"]-1)
            self.assertEqual(record["sha256"],execution_state.file_hash(attempt/record["path"]))
            self.assertLessEqual(record["byte_size"],publisher.PAGE_BYTE_LIMIT)
            reconstructed.extend(page["rows"]); cursor+=record["row_count"]
        self.assertEqual(reconstructed,outputs[join.MATRIX]["rows"])
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
        manifest=execution_state.read_json(attempt/publisher.MATRIX_MANIFEST)
        page_path=attempt/manifest["pages"][0]["path"]
        page=execution_state.read_json(page_path); page["rows"][0]["status"]="not_satisfied"
        execution_state.atomic_json(page_path,page)
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
            [publisher.MATRIX_MANIFEST,join.GAPS,join.ROUTES,"permission.json","lineage.json","status.json"])

    def test_missing_reordered_duplicate_and_substituted_pages_fail_closed(self):
        pointer=self.publish(); attempt=publisher.root(self.run_id)/"attempts"/pointer["attempt_id"]
        inputs=execution_state.read_json(attempt/"inputs.json")
        logical=join.derive(join.load_verified_inputs(self.run_id,facts=self.facts()))[join.MATRIX]
        one_row_limit=max(len(publisher._json_bytes(publisher._page(logical,0,0,[row])))
                          for row in logical["rows"])
        with mock.patch.object(publisher,"PAGE_BYTE_LIMIT",one_row_limit):
            expected=publisher._derive(self.run_id,self.facts())
            for path in (attempt/publisher.PAGE_DIRECTORY).glob("*.json"): path.unlink()
            for name,value in expected.items(): execution_state.atomic_json(attempt/name,value)
            permission,lineage=publisher._receipts(inputs,expected,attempt)
            execution_state.atomic_json(attempt/"permission.json",permission)
            execution_state.atomic_json(attempt/"lineage.json",lineage)
            publisher._validate_attempt(attempt,inputs,self.facts())
            manifest=execution_state.read_json(attempt/publisher.MATRIX_MANIFEST)
            self.assertGreater(len(manifest["pages"]),1)
            first=attempt/manifest["pages"][0]["path"]
            original=first.read_bytes()

            first.unlink()
            with self.assertRaisesRegex(execution_state.Blocked,"page set"):
                publisher._validate_attempt(attempt,inputs,self.facts())
            first.parent.mkdir(parents=True,exist_ok=True); first.write_bytes(original)

            reordered=dict(manifest); reordered["pages"]=[*reversed(manifest["pages"])]
            execution_state.atomic_json(attempt/publisher.MATRIX_MANIFEST,reordered)
            with self.assertRaisesRegex(execution_state.Blocked,"differs"):
                publisher._validate_attempt(attempt,inputs,self.facts())

            duplicate=dict(manifest); duplicate["pages"]=[manifest["pages"][0],*manifest["pages"][:-1]]
            execution_state.atomic_json(attempt/publisher.MATRIX_MANIFEST,duplicate)
            with self.assertRaisesRegex(execution_state.Blocked,"differs"):
                publisher._validate_attempt(attempt,inputs,self.facts())
            execution_state.atomic_json(attempt/publisher.MATRIX_MANIFEST,manifest)

            page=execution_state.read_json(first); page["rows"][0]["control_id"]="V1.0.0"
            execution_state.atomic_json(first,page)
            with self.assertRaisesRegex(execution_state.Blocked,"differs"):
                publisher._validate_attempt(attempt,inputs,self.facts())


if __name__=="__main__": unittest.main()
