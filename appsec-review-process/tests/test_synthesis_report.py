from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state
from execution_state import Blocked
from publish_job_output import ACCEPTED_SCHEMA, artifact_records, terminal_envelope
import synthesis_report as synthesis
from schema_validate import SchemaStore, validate_document


H = lambda char: "sha256:" + char * 64


class SynthesisReportTests(unittest.TestCase):
    def reseal_ledger(self,inputs):
        previous=None
        for entry in inputs["documents"]["ledger"]["entries"]:
            entry["previous_entry_hash"]=previous
            entry["event_id"]="event-"+synthesis.digest({key:value for key,value in entry.items()
                if key not in {"event_id","entry_hash"}})[:24]
            entry["entry_hash"]=synthesis._sha({key:value for key,value in entry.items() if key!="entry_hash"})
            previous=entry["entry_hash"]
        ledger=inputs["documents"]["ledger"]; ledger["head_hash"]=previous
        latest={entry["claim_id"]:entry for entry in ledger["entries"]}
        ledger["claim_states"]=[{"claim_id":key,"latest_event_id":latest[key]["event_id"],"status":latest[key]["status"]}
            for key in sorted(latest)]
        inputs["ledger_head_sha256"]=previous; inputs["ledger_head_id"]=ledger["entries"][-1]["event_id"]
        origin = next(entry for entry in reversed(ledger["entries"])
                      if entry["event_type"] == "candidate_admitted")
        inputs["lifecycle_origin_head_sha256"] = origin["entry_hash"]
        inputs["lifecycle_origin_head_id"] = origin["event_id"]
        for name in ("verification","scoring"):
            inputs["documents"][name]["ledger_head_sha256"] = origin["entry_hash"]
            inputs["documents"][name]["ledger_head_id"] = origin["event_id"]

    def inputs(self):
        citation = {"citation_id": "citation-a", "producer_job_id": "evidence-job",
            "producer_attempt_id": "evidence-1", "artifact_path": "evidence.json",
            "artifact_sha256": H("e"), "locator_json": "/facts/0", "observed_fact": "A cited fact."}
        producer={"job_id":"threat-job","attempt_id":"threat-1","artifact_sha256":H("a")}
        base = {"sequence": 0, "event_id": "", "event_type": "candidate_admitted",
            "claim_id": "", "route_id": "route-a", "claim_class": "candidate_only",
            "hypothesis": "Parser accepts untrusted bytes.", "status": "candidate", "confidence": "high",
            "component_ids": ["parser"], "source_generation": H("1"), "component_generation": H("2"),
            "producer": producer, "citations": [citation], "proof_obligations": [{"obligation_id": "po-a", "statement": "Trace input."}],
            "dissent_ids": ["dissent-a"], "causal_claim_ids": [], "supersedes_claim_id": None,
            "from_status": None, "decision_authority": None, "previous_entry_hash": None, "entry_hash": ""}
        base["claim_id"]="claim-"+synthesis.digest({"route_id":base["route_id"],"producer":producer["job_id"],
            "attempt":producer["attempt_id"],"artifact":producer["artifact_sha256"],
            "source_generation":base["source_generation"],"component_generation":base["component_generation"]})[:24]
        base["event_id"]="event-"+synthesis.digest({key:value for key,value in base.items() if key not in {"event_id","entry_hash"}})[:24]
        base["entry_hash"] = synthesis._sha({key: value for key, value in base.items() if key != "entry_hash"})
        second = deepcopy(base); second.update(sequence=1, event_id="", claim_id="", route_id="route-b",
            hypothesis="Administrative control remains uncertain.", status="candidate", confidence="low",
            proof_obligations=[{"obligation_id":"po-b","statement":"Observe deployment."}], dissent_ids=[],
            previous_entry_hash=base["entry_hash"], entry_hash="")
        second["claim_id"]="claim-"+synthesis.digest({"route_id":second["route_id"],"producer":producer["job_id"],
            "attempt":producer["attempt_id"],"artifact":producer["artifact_sha256"],
            "source_generation":second["source_generation"],"component_generation":second["component_generation"]})[:24]
        second["event_id"]="event-"+synthesis.digest({key:value for key,value in second.items() if key not in {"event_id","entry_hash"}})[:24]
        second["entry_hash"] = synthesis._sha({key: value for key, value in second.items() if key != "entry_hash"})
        decision=deepcopy(base); decision.update(sequence=2,event_id="",event_type="status_decision",status="verified",
            from_status="candidate",previous_entry_hash=second["entry_hash"],decision_authority={},entry_hash="")
        decision["event_id"]="event-"+synthesis.digest({key:value for key,value in decision.items() if key not in {"event_id","entry_hash"}})[:24]
        decision["entry_hash"]=synthesis._sha({key:value for key,value in decision.items() if key!="entry_hash"})
        ledger = {"run_id":"run1","source_generation":H("1"),"component_generation":H("2"),
            "entries":[base,second,decision],"head_hash":decision["entry_hash"],"claim_states":[
                {"claim_id":item["claim_id"],"latest_event_id":item["event_id"],"status":item["status"]}
                for item in sorted((decision,second),key=lambda item:item["claim_id"])]}
        preserved = {key: base[key] for key in ("claim_id","route_id","hypothesis","confidence","component_ids","source_generation","component_generation")}
        verification = {"run_id":"run1","ledger_head_id":second["event_id"],"ledger_head_sha256":second["entry_hash"],
            "verifications":[{**preserved,"status":"VERIFIED","verification_citations":[citation]},
                             {**{key: second[key] for key in preserved},"status":"UNRESOLVED","verification_citations":[citation]}]}
        scoring = {"run_id":"run1","ledger_head_id":second["event_id"],"ledger_head_sha256":second["entry_hash"],
            "priorities":[{**preserved,"verification_status":"VERIFIED","severity":"HIGH","priority":"P1","score":13},
                          {**{key: second[key] for key in preserved},"verification_status":"UNRESOLVED","severity":None,"priority":"UNRESOLVED","score":None}]}
        component = {"target":"fixture","functional_components":[{"component_id":"parser","name":"Parser","observed_purpose":"Parse input."}],
                     "classification_gaps":[{"reason":"Generated sources were unavailable."}],
                     "unknowns":[{"question":"Is runtime hardening enabled?"}]}
        threat = {"run_id":"run1","gaps":[{"statement":"Deployment state is not observed."}],
                  "coverage":{"unmodeled_components":[{"reason":"External service omitted."}]}}
        matrix = {"run_id":"run1","denominators":{"selected":4,"applicable":3,"assessed":2,"satisfied":1},
                  "applicability_counts":{"applicable":3,"conditional":0,"not_applicable":1,"cannot_determine":0,"out_of_scope":0},
                  "assessment_counts":{"satisfied":1,"partially_satisfied":0,"not_satisfied":1,"cannot_verify":0,
                    "dynamic_test_required":0,"human_decision_required":0,"not_assessed":2,"not_applicable":0,
                    "cannot_determine":0,"out_of_scope":0}}
        docs = {"component":component,"threat":threat,"owasp":matrix,"owasp_gaps":{"gaps":[{"statement":"One control lacks evidence."}]},
                "owasp_routes":{"routes":[]},"ledger":ledger,"verification":verification,"scoring":scoring}
        binding = {"job_id":"evidence-job","attempt_id":"evidence-1","contract_id":"evidence",
            "artifact_path":"evidence.json","artifact_sha256":H("e"),"accepted_pointer_sha256":H("a"),
            "permission_receipt_sha256":H("b"),"lineage_receipt_sha256":H("c"),"envelope_sha256":H("d")}
        bindings = {name:{**binding,"job_id":name,"attempt_id":name+"-1","contract_id":name,
                          "artifact_path":name+".json"} for name in synthesis.INPUT_NAMES}
        return {"schema":"appsec-review/synthesis-input/0.1","run_id":"run1","source_generation":H("1"),
            "component_generation":H("2"),"ledger_head_id":decision["event_id"],"ledger_head_sha256":decision["entry_hash"],
            "lifecycle_origin_head_id":second["event_id"],"lifecycle_origin_head_sha256":second["entry_hash"],
            "input_manifest_sha256":H("9"),
            "inputs":{},"evidence_artifacts":[],"limitations":["Source SAST did not cover PHP."],
            "documents":docs,"bindings":bindings,"evidence_bindings":[binding]}

    def test_deterministic_report_preserves_verified_unresolved_coverage_and_dissent(self):
        inputs = self.inputs(); first = synthesis.build_report(inputs); second = synthesis.build_report(deepcopy(inputs))
        self.assertEqual(first, second); report, trace = first
        expected = json.loads((ROOT / "tests/fixtures/synthesis-report/expectations.json").read_text())
        self.assertEqual(report["status"], expected["status"])
        self.assertEqual(len(report["verified_findings"]), expected["verified_findings"])
        self.assertEqual(len(report["unresolved_candidates"]), expected["unresolved_candidates"])
        self.assertEqual(report["owasp_coverage"]["denominators"], expected["owasp_denominators"])
        self.assertEqual(report["dissent_ids"], ["dissent-a"]); self.assertEqual(len(trace["citations"]), 2)
        self.assertFalse(report["claim_limits"]["final"]); self.assertFalse(report["claim_limits"]["scoring_derived"])

    def test_stale_heads_mixed_generation_and_uncited_evidence_fail_closed(self):
        inputs = self.inputs(); inputs["documents"]["verification"]["ledger_head_sha256"] = H("f")
        with self.assertRaisesRegex(Blocked, "stale"): synthesis.build_report(inputs)
        inputs = self.inputs(); inputs["documents"]["ledger"]["component_generation"] = H("f")
        with self.assertRaisesRegex(Blocked, "generation"): synthesis.build_report(inputs)
        inputs = self.inputs(); inputs["documents"]["ledger"]["entries"][0]["citations"][0]["artifact_sha256"] = H("f")
        self.reseal_ledger(inputs)
        with self.assertRaisesRegex(Blocked, "citation"): synthesis.build_report(inputs)

    def test_candidate_cannot_be_promoted_by_verification_or_score_alone(self):
        inputs = self.inputs(); inputs["documents"]["ledger"]["entries"][-1]["status"] = "unresolved"
        self.reseal_ledger(inputs)
        report, _ = synthesis.build_report(inputs)
        self.assertEqual(report["verified_findings"], []); self.assertEqual(len(report["unresolved_candidates"]), 2)

    def test_unverified_tool_leads_are_listed_in_the_draft(self):
        inputs = self.inputs(); report, _ = synthesis.build_report(inputs)
        report_md, appendix = synthesis.render_markdown(report)
        self.assertNotIn("static-tool leads", report_md)
        report = deepcopy(report)
        report["unresolved_candidates"][0]["hypothesis"] = ("Tool lead (P1, unsafe-copy): 2 static analysis "
            "lead(s) from 2 tool(s) at src/main.c:7 [cppcheck bufferAccessOutOfBounds]. Candidate: unreviewed.")
        report_md, appendix = synthesis.render_markdown(report)
        self.assertIn("1 of them are static-tool leads not independently verified (P1 1, P2 0, P3 0)", report_md)
        self.assertIn("## Tool leads not independently verified", appendix)
        self.assertIn("| P1 | `" + report["unresolved_candidates"][0]["claim_id"] + "` |", appendix)
        with tempfile.TemporaryDirectory() as directory:
            jobs = Path(directory) / "data" / "jobs" / "02-secrets-inventory" / "whole" / "attempts" / "a1"
            jobs.mkdir(parents=True); (jobs / "x.json").write_text("{}")
            import report_input_assembly
            row = report_input_assembly._verify_citation(Path(directory) / "data" / "jobs",
                ("02-secrets-inventory", "a1", "x.json", "sha256:" + execution_state.file_hash(jobs / "x.json")))
            self.assertEqual(row["artifact_path"], "x.json")

    def test_render_and_publication_are_draft_only_and_hash_bound(self):
        inputs = self.inputs(); report, trace = synthesis.build_report(inputs)
        report_md, appendix = synthesis.render_markdown(report)
        self.assertIn("DRAFT_EVIDENCE_BACKED", report_md); self.assertIn("Selected | Applicable | Assessed | Satisfied", report_md)
        self.assertNotIn("remediation plan", report_md.lower()); self.assertIn("Unresolved candidates", appendix)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/"output"
            with mock.patch.object(synthesis,"load_inputs",return_value=inputs):
                publication=synthesis.run(Path(directory),Path(directory)/"input.json",output)
            self.assertEqual(publication["status"],synthesis.STATUS)
            self.assertEqual([item["path"] for item in publication["artifacts"]],
                json.loads((ROOT/"tests/fixtures/synthesis-report/expectations.json").read_text())["publication_artifacts"])
            self.assertTrue(all((output/name).is_file() for name in
                (synthesis.REPORT_JSON,synthesis.REPORT_MD,synthesis.APPENDIX,synthesis.TRACE,
                 synthesis.PUBLICATION,"permission.json","lineage.json","status.json")))

    def test_load_reference_rejects_tampered_current_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            run_root=Path(directory); base=run_root/"data/jobs/upstream"; attempt=base/"attempts/a1"; attempt.mkdir(parents=True)
            execution_state.atomic_json(attempt/"artifact.json", {"value":1})
            execution_state.atomic_json(attempt/"permission.json", {"value":2})
            execution_state.atomic_json(attempt/"lineage.json", {"value":3})
            execution_state.atomic_json(attempt/"status.json", {"status":"OK"})
            envelope=terminal_envelope(run_id="run1",job_id="upstream",attempt_id="a1",worker_kind="deterministic_python",
                execution_status="OK",acceptance_status="CURRENT",input_fingerprint=H("f"),output_contract="upstream-contract",
                started_at="2026-01-01T00:00:00Z",finished_at="2026-01-01T00:00:01Z",summary="fixture",
                artifacts=artifact_records(attempt,["artifact.json","permission.json","lineage.json","status.json"]),gaps=[])
            execution_state.atomic_json(attempt/"result.json",envelope); execution_state.atomic_json(base/"latest.json",{"attempt_id":"a1","updated_at":"2026-01-01T00:00:01Z"})
            pointer={"schema":ACCEPTED_SCHEMA,"status":"OK","run_id":"run1","job":"upstream","attempt_id":"a1","fingerprint":H("f"),
                "envelope_path":"result.json","envelope_sha256":execution_state.file_hash(attempt/"result.json"),
                "hashes":execution_state.tree_hashes(attempt),"accepted_at":"2026-01-01T00:00:02Z"}
            execution_state.atomic_json(base/"accepted.json",pointer)
            ref={"job_id":"upstream","attempt_id":"a1","contract_id":"upstream-contract","artifact_path":"artifact.json",
                "artifact_sha256":"sha256:"+execution_state.file_hash(attempt/"artifact.json"),
                "accepted_pointer_sha256":"sha256:"+execution_state.file_hash(base/"accepted.json"),
                "permission_receipt_sha256":"sha256:"+execution_state.file_hash(attempt/"permission.json"),
                "lineage_receipt_sha256":"sha256:"+execution_state.file_hash(attempt/"lineage.json")}
            self.assertEqual(synthesis.load_reference(run_root,"run1",ref)[0],{"value":1})
            execution_state.atomic_json(attempt/"artifact.json",{"value":2})
            with self.assertRaisesRegex(Blocked,"changed"): synthesis.load_reference(run_root,"run1",ref)

    def test_owned_registry_records_and_schemas_are_closed(self):
        store = SchemaStore()
        records = (("personas/synthesis-report-drafter.json","persona.schema.json"),
            ("roles/synthesis-report-drafter.json","role.schema.json"),
            ("domains/synthesis-report-core.json","domain.schema.json"),
            ("tooling-profiles/synthesis-report-static.json","tooling-profile.schema.json"),
            ("output-contracts/synthesis-report-draft.json","output-contract.schema.json"),
            ("job-templates/10-synthesis-report.json","job-template.schema.json"))
        for relative,schema in records:
            value=json.loads((ROOT/"registry"/relative).read_text())
            self.assertEqual(validate_document(value,schema,store),[],relative)
        def closed(value,path="$",store=None):
            if isinstance(value,dict):
                if value.get("type")=="object" or "properties" in value:
                    self.assertFalse(value.get("additionalProperties",True),path)
                for key,item in value.items(): closed(item,path+"."+key,store)
            elif isinstance(value,list):
                for index,item in enumerate(value): closed(item,f"{path}[{index}]",store)
        for name in ("synthesis-artifact-ref.schema.json","synthesis-owasp-ref.schema.json",
            "synthesis-input.schema.json","synthesis-citation.schema.json","synthesis-proof-obligation.schema.json",
            "synthesis-upstream-binding.schema.json","synthesis-l08-record.schema.json",
            "synthesis-l08-adapter.schema.json","synthesis-report.schema.json",
            "evidence-trace-index.schema.json","report-publication-manifest.schema.json"):
            closed(store.load(name),name)


if __name__ == "__main__": unittest.main()
