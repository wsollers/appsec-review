"""Deterministic scripted ``Infer`` double for the inference security review.

Answers are a pure function of (role, task, persona, package leads or claim) so that the slice 1
definition-of-done states arise from the fixture accepted index set:

* lane A ``sast_critical``: claim C1 (CWE-120) with direct support for every predicate; the blind
  verifier re-retrieves the evidence itself -> ``confirmed``. The failure-modes lens also probes
  forbidden capabilities (an evaluator path and an out-of-scope identity).
* lane A ``sast_high``: claim C2 (CWE-89) with partial support -> ``supported``.
* lane A ``codeql_high``: claim C3 whose ``blue_control`` finds a direct guard -> ``contradicted``.
* lane A ``dep_high``: claim C4 whose verifier provider always fails -> ``insufficient_evidence``
  plus a cell ``worker_gap``.
* lane B native unit: the memory-safety sweep re-proposes C1 (a duplicate proposal) and H1 with
  partial support; the injection sweep proposes H2 (no support, over the cap) and H3 (closed
  vocabulary violation, rejected by the gate).

The scenario is a JSON file named by ``APPSEC_C7_SCENARIO`` (``ids``: fixture key -> identity;
``calls``: JSONL call log; ``captures``: directory for verifier request bytes; ``fail_roles``:
roles whose provider always fails; ``gate``: glob that must exist before the first lane A red
turn, proving the lanes overlap).
"""
from __future__ import annotations

from dataclasses import asdict
import glob
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping

from appsec_review.inference import ModelResult, ReviewModelRequest
from tests.fixtures.inference_review.red import Proposal, red_result

TURN = "appsec-review/worker-turn/1"
PREDICATES = ("affected_construct", "attacker_input_control", "source_to_sink_reachability",
              "missing_or_ineffective_guard", "security_impact")
NARRATIVES = {
    "C1-lead": "C1 lead narrative: strcpy copies the attacker request field into an eight byte stack buffer",
    "C1-hunt": "C1 hunt narrative: the sweep found the same unbounded strcpy into a fixed stack buffer",
    "C2": "C2 lead narrative: the handler concatenates the query string into raw SQL",
    "C3": "C3 lead narrative: the multiplication n times four can overflow a signed int",
    "C4": "C4 lead narrative: requests 2.0.0 allows unbounded resource consumption",
    "H1": "H1 hunt narrative: io.c reaches system() with a constant string after an early return",
    "H2": "H2 hunt narrative: a freed buffer might be reused in io.c on the error path",
    "H3": "H3 hunt narrative: root attacker variant that uses a precondition outside the vocabulary",
    "blue": "blue rationale {claim} {task}: no effective guard or reachability break was found here",
    "blue-guard": "C3 blue control rationale: an explicit bound check guards the multiplication input",
    "verifier": "verifier rationale: re-retrieved the affected construct and the build action itself",
}


class ScriptedInfer:
    def __init__(self, scenario: Mapping[str, Any]) -> None:
        self.scenario = dict(scenario)
        self.ids: dict[str, str] = dict(scenario["ids"])
        self.keys = {value: key for key, value in self.ids.items()}
        self.lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "ScriptedInfer":
        return _EnvInfer()  # type: ignore[return-value]

    # -- helpers -----------------------------------------------------------------------------------
    def _log(self, request: ReviewModelRequest, kind: str) -> None:
        path = self.scenario.get("calls")
        if not path:
            return
        line = json.dumps({"role": request.role, "task": request.task_input.get("task"), "persona": request.persona,
                           "cell_id": request.cell_id, "kind": kind, "turn": len(request.transcript) // 2 + 1},
                          sort_keys=True) + "\n"
        with self.lock:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                os.write(descriptor, line.encode("utf-8"))
            finally:
                os.close(descriptor)

    def _capture(self, request: ReviewModelRequest) -> None:
        directory = self.scenario.get("captures")
        if not directory:
            return
        Path(directory).mkdir(parents=True, exist_ok=True)
        name = f"{request.cell_id}-{len(request.transcript):03d}.json"
        (Path(directory) / name).write_bytes(json.dumps(asdict(request), sort_keys=True, default=str).encode())

    @staticmethod
    def _final(result: Mapping[str, Any]) -> ModelResult:
        return ModelResult(proposal={"schema": TURN, "action": "final", "result": dict(result)},
                           input_tokens=120, output_tokens=40)

    @staticmethod
    def _retrieve(requests: list[Mapping[str, Any]]) -> ModelResult:
        return ModelResult(proposal={"schema": TURN, "action": "retrieve", "requests": list(requests)},
                           input_tokens=100, output_tokens=20)

    def _relation(self, predicate: str, key: str, kind: str = "supports", rationale: str = "") -> dict[str, Any]:
        return {"predicate": predicate, "kind": kind, "entity_id": self.ids[key],
                "rationale": rationale or f"{kind} {predicate} via {key} for the scripted review"}

    def _proposal(self, local: str, affected: str, cwe: str | None, predicate: str, preconditions: list[str],
                  narrative: str, support: list[tuple[str, str]], lead: str | None = None) -> Proposal:
        """One red proposal; ``support`` is (R4 predicate, fixture key) supporting references."""
        return Proposal(local, [self.ids[affected]], cwe, predicate, preconditions, NARRATIVES[narrative],
                        [(item, self.ids[key]) for item, key in support], [self.ids[lead]] if lead else [])

    def _red(self, request: ReviewModelRequest, proposals: list[Proposal]) -> ModelResult:
        return self._final(red_result(request.task_input, proposals))

    # -- dispatch ------------------------------------------------------------------------------------
    def __call__(self, request: ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        task = request.task_input.get("task")
        payload = request.task_input.get("input", {})
        self._log(request, "call")
        if request.role in self.scenario.get("fail_roles", ()):
            raise RuntimeError("scripted provider outage")
        if request.role == "red_team_analyst":
            self._gate()
            return self._lead_red(request, task, payload)
        if request.role == "hypothesis_hunter":
            return self._hunter(request, payload)
        if request.role == "blue_team_refuter":
            return self._blue(payload)
        if request.role == "independent_verifier":
            self._capture(request)
            return self._verifier(request, payload)
        raise AssertionError(f"unexpected role {request.role}")

    def _gate(self) -> None:
        pattern = self.scenario.get("gate")
        if not pattern:
            return
        deadline = time.monotonic() + 90
        while not glob.glob(pattern):
            if time.monotonic() > deadline:
                raise TimeoutError("lane B never started while lane A was running")
            time.sleep(0.05)

    def _lead(self, payload: Mapping[str, Any]) -> str:
        menu = payload["package"]["lead_menu"]
        return self.keys.get(menu[0]["observation_id"], "?") if menu else "?"

    def _lead_red(self, request: ReviewModelRequest, task: str, payload: Mapping[str, Any]) -> ModelResult:
        lead = self._lead(payload)
        if lead == "sast_critical" and task == "lead_red_failure_modes":
            if not request.transcript:
                return self._retrieve([
                    {"tool": "find", "parameters": {"path": "../appsec-multi-vuln-guide/expected-findings.json"}},
                    {"tool": "read_excerpt", "parameters": {"identity": self.ids["history:parse"]}},
                    {"tool": "find", "parameters": {"identity": self.ids["unit:native-main"]}}])
            return self._red(request, [])
        if lead == "sast_critical" and task in ("lead_red_stack", "lead_red_preconditions"):
            support = [(item, "unit:native-main") for item in PREDICATES] + [("affected_construct", "sast_critical")]
            return self._red(request, [self._proposal(
                "c1", "native/src/parse.c", "CWE-120", "memory_corruption", ["attacker_controls_request_field"],
                "C1-lead", support, lead="sast_critical")])
        if lead == "sast_high" and task == "lead_red_stack":
            return self._red(request, [self._proposal(
                "c2", "svc/api/handler.py", "CWE-89", "sql_injection", [], "C2",
                [("affected_construct", "sast_high"), ("attacker_input_control", "unit:py-svc")], lead="sast_high")])
        if lead == "codeql_high" and task == "lead_red_stack":
            return self._red(request, [self._proposal(
                "c3", "native/src/parse.c", "CWE-190", "integer_error", [], "C3",
                [("affected_construct", "unit:native-main")], lead="codeql_high")])
        if lead == "dep_high" and task == "lead_red_stack":
            return self._red(request, [self._proposal(
                "c4", "dep_high", "CWE-400", "resource_exhaustion", [], "C4", [], lead="dep_high")])
        return self._red(request, [])

    def _hunter(self, request: ReviewModelRequest, payload: Mapping[str, Any]) -> ModelResult:
        leads = {self.keys.get(item["observation_id"]) for item in payload["package"]["lead_menu"]}
        proposals: list[Proposal] = []
        if "sast_critical" in leads and request.persona == "memory_safety_native":
            proposals = [
                self._proposal("c1", "native/src/parse.c", "CWE-120", "memory_corruption",
                               ["attacker_controls_request_field"], "C1-hunt",
                               [("affected_construct", "unit:native-main")], lead="sast_critical"),
                self._proposal("h1", "native/src/io.c", "CWE-78", "command_injection", [], "H1",
                               [("affected_construct", "unit:native-main")]),
            ]
        elif "sast_critical" in leads and request.persona == "injection_interpreters":
            proposals = [
                self._proposal("h2", "native/src/io.c", "CWE-416", "use_after_free", [], "H2", []),
                self._proposal("h3", "native/src/io.c", "CWE-78", "command_injection", ["attacker_has_root"], "H3", []),
            ]
        return self._red(request, proposals)

    def _blue(self, payload: Mapping[str, Any]) -> ModelResult:
        claim, task = payload["claim"], payload["task"]
        result = {"schema": "appsec-review/blue-result/1", "claim_id": claim["claim_id"], "citations": {},
                  "proposed_relations": [], "evidence_requests": [], "task": task, "disposition": "unresolved",
                  "rationale": NARRATIVES["blue"].format(claim=claim["security_predicate"], task=task)}
        if claim["security_predicate"] == "integer_error" and task == "blue_control":
            relation = self._relation("missing_or_ineffective_guard", "unit:native-main", "contradicts",
                                      NARRATIVES["blue-guard"])
            result.update(disposition="contradicts", rationale=NARRATIVES["blue-guard"],
                          proposed_relations=[relation],
                          citations={"missing_or_ineffective_guard": [relation["entity_id"]]})
        return self._final(result)

    def _verifier(self, request: ReviewModelRequest, payload: Mapping[str, Any]) -> ModelResult:
        claim = payload["claim"]
        predicate = claim["security_predicate"]
        if predicate == "resource_exhaustion":
            raise RuntimeError("scripted verifier provider failure")
        base = {"schema": "appsec-review/verifier-result/1", "claim_id": claim["claim_id"], "citations": {},
                "proposed_relations": [], "evidence_requests": [], "rationale": NARRATIVES["verifier"],
                "proposed_disposition": "insufficient_evidence"}
        plan = {"memory_corruption": [(item, "unit:native-main") for item in PREDICATES],
                "sql_injection": [("affected_construct", "sast_high")],
                "command_injection": [("affected_construct", "unit:native-main")]}.get(predicate, [])
        if not plan:
            base["evidence_requests"] = [{"predicate": "missing_or_ineffective_guard", "requested_kind": "symbol",
                                          "anchors": list(claim["affected_entities"]),
                                          "question": "which guard bounds the affected construct"}]
            return self._final(base)
        if not request.transcript:
            return self._retrieve([{"tool": "find", "parameters": {"identity": self.ids[key]}}
                                   for key in sorted({key for _, key in plan})])
        relations = [self._relation(item, key, rationale=f"verifier re-resolved {key} for {item}") for item, key in plan]
        citations: dict[str, list[str]] = {}
        for relation in relations:
            citations.setdefault(relation["predicate"], []).append(relation["entity_id"])
        base.update(proposed_relations=relations, citations=citations,
                    proposed_disposition="confirmed" if len(plan) == len(PREDICATES) else "supported")
        return self._final(base)


class _EnvInfer:
    """Reload the scenario from ``APPSEC_C7_SCENARIO`` on every call (it works across processes)."""

    def __call__(self, request: ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        scenario = json.loads(Path(os.environ["APPSEC_C7_SCENARIO"]).read_text(encoding="utf-8"))
        return ScriptedInfer(scenario)(request, timeout_seconds=timeout_seconds)
