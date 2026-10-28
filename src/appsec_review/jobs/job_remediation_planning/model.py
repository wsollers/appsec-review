"""Bounded no-tools model turns, shared by the independent remediation writer and reviewer."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path
import subprocess
import time
from typing import Any, Callable, Mapping

from appsec_review.config.remediation import RemediationModel
from appsec_review.inference import Infer, ModelOutputError, ReviewModelRequest
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import publish_named

TURN_SCHEMA = "appsec-review/worker-turn/1"


def guidance(repository_root: Path, run_root: Path, role: str) -> tuple[str, str]:
    paths = (Path("pipeline") / "prompt-fragments" / "governing-rules.md",
             Path("pipeline") / "prompt-fragments" / "roles" / f"{role}.md")
    files = {path.name: (repository_root / path).read_bytes() for path in paths}
    digest = hashlib.sha256(b"\0".join(files[key] for key in sorted(files))).hexdigest()
    for name, payload in files.items():
        publish_named(run_root, run_root / "data" / "guidance" / digest / name, payload,
                      namespace="guidance", computation={"role": role, "sha256": digest})
    return "\n\n".join(payload.decode("utf-8") for payload in files.values()), digest


def run_model(*, infer: Infer, profile: RemediationModel, role: str, cell_id: str,
              guidance_text: str, guidance_sha256: str, task: Mapping[str, Any],
              validate: Callable[[Any], Mapping[str, Any]],
              retrieve: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None
              ) -> tuple[Mapping[str, Any] | None, dict[str, Any]]:
    transcript: list[Mapping[str, Any]] = []
    turns: list[dict[str, Any]] = []
    receipt: dict[str, Any] = {"role": role, "cell_id": cell_id, "model": asdict(profile),
                               "guidance_bundle_sha256": guidance_sha256, "turns": turns,
                               "status": "failed", "reason": "turn_bound_reached"}
    queries, response_bytes = 0, 0
    started = time.monotonic()
    for number in range(1, profile.max_turns + 1):
        request = ReviewModelRequest(
            TURN_SCHEMA, role, "", "", guidance_sha256, guidance_text,
            {"task": dict(task), "protocol": {"actions": ["retrieve", "final"] if retrieve else ["final"],
              "retrieve_shape": {"action": "retrieve", "request": {"path": "<admitted path>",
                                 "start_line": 1, "end_line": 40}},
              "final_shape": {"action": "final", "result": "<task output object>"},
              "queries_remaining": max(0, profile.max_queries - queries)}},
            tuple(transcript), profile.provider, profile.model, profile.reasoning,
            profile.max_input_tokens, profile.max_output_tokens, cell_id=cell_id)
        if len(canonical_json({"task": request.task_input, "transcript": transcript,
                               "guidance": guidance_text})) > profile.max_input_tokens * 3:
            receipt["reason"] = "input_budget_exceeded"
            break
        try:
            turn_started = time.monotonic()
            result = infer(request, timeout_seconds=profile.timeout_seconds)
        except (ModelOutputError, TimeoutError, subprocess.TimeoutExpired, RuntimeError, OSError) as exc:
            receipt["reason"] = f"model_failure:{type(exc).__name__}"
            break
        value = result.proposal
        payload = canonical_json(value)
        response_bytes += len(payload)
        turns.append({"number": number, "response_sha256": hashlib.sha256(payload).hexdigest(),
                      "input_tokens": result.input_tokens, "output_tokens": result.output_tokens,
                      "duration_ms": max(0, int((time.monotonic() - turn_started) * 1000))})
        if len(payload) > profile.max_output_tokens * 8 or response_bytes > profile.max_output_tokens * 8:
            receipt["reason"] = "output_budget_exceeded"
            break
        try:
            if not isinstance(value, Mapping) or value.get("schema", TURN_SCHEMA) != TURN_SCHEMA:
                raise ValueError("reply must be a worker-turn object")
            body = {key: item for key, item in value.items() if key != "schema"}
            if body.get("action") == "final" and set(body) == {"action", "result"}:
                answer = validate(body["result"])
                receipt.update(status="answered", reason="", queries=queries,
                               duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                               result_sha256=hashlib.sha256(
                    canonical_json(answer)).hexdigest())
                return answer, receipt
            if (body.get("action") != "retrieve" or set(body) != {"action", "request"}
                    or retrieve is None or queries >= profile.max_queries):
                raise ValueError("invalid action or retrieval budget exhausted")
            queries += 1
            response = retrieve(body["request"])
            transcript.extend(({"speaker": "worker", "turn": dict(body)},
                               {"speaker": "application", "response": dict(response)}))
        except IntegrityError:
            raise
        except (ValueError, TypeError, KeyError) as exc:
            receipt["reason"] = f"invalid_output:{str(exc)[:180]}"
            # Invalid final output is a terminal outcome, not a policy-bypass repair opportunity.
            break
    receipt["queries"] = queries
    receipt["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
    return None, receipt


def emit_model_event(events: Any, receipt: Mapping[str, Any]) -> None:
    """Only finite outcomes and aggregate usage enter telemetry; never source, prompts or answers."""
    events.write("REMEDIATION_MODEL_COMPLETED", role=receipt["role"], cell_id=receipt["cell_id"],
                 outcome=receipt["status"], duration_ms=receipt["duration_ms"],
                 turn_count=len(receipt["turns"]), query_count=receipt["queries"],
                 input_tokens=sum(turn["input_tokens"] or 0 for turn in receipt["turns"]),
                 output_tokens=sum(turn["output_tokens"] or 0 for turn in receipt["turns"]),
                 timeout_count=int(receipt["reason"] in {"model_failure:TimeoutError",
                                                         "model_failure:TimeoutExpired"}))
