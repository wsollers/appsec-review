"""The application's single path to a language model.

Every job reaches a model by calling `infer`. Each provider module holds one transport function,
and the provider named on the request is resolved to that function only here. Jobs never import
a provider module, and nothing else in the application opens a model connection.

`check_models` is the matching availability question, asked once at the start of a review run:
does each provider serve every model the configuration names?
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

# Initialize the runtime before transports load errors: its runner imports recording, while
# the cancellation contract derives from runtime.execution_safety.ReviewStopped.
from appsec_review.runtime import execution_safety as safety

from . import anthropic_api, claude_cli, copilot_sdk, openai_api
from .claude_cli import ModelOutputError, parse_model_payload
from .errors import ExecutionContractError, ModelCancelled, ModelTimeout, ProviderError
from .request import Infer, ModelRequest, ModelResult, ReviewModelRequest
from .usage import Usage


PROVIDERS: dict[str, Infer] = {
    "anthropic-api": anthropic_api.send,
    "claude-cli": claude_cli.send,
    "copilot-sdk": copilot_sdk.send,
}


def infer(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
    """Send one bounded request to the provider it names and return the validated proposal.

    A `ReviewModelRequest` is one review-cell turn; its validated proposal is the worker turn.
    """
    try:
        send = PROVIDERS[request.provider]
    except KeyError as exc:
        raise ValueError(f"unsupported inference provider: {request.provider}") from exc
    planning = request.schema == "appsec-review/target-analysis-proposal/3"
    failure = None
    repairable = False
    with safety.operation(f"inference.{request.provider}.{request.model}"):
        try:
            result = send(request, timeout_seconds=timeout_seconds)
            result = Usage.from_result(result).normalize(result)
        except (ModelOutputError, TimeoutError) as exc:
            if not planning:
                safety.retain_failure("inference", exc, provider=request.provider, model=request.model)
                raise
            repairable = True
            failure = (ModelOutputError("planning model output could not be decoded")
                       if isinstance(exc, ModelOutputError) else
                       ModelTimeout("planning model call timed out",
                                    code=getattr(exc, "code", "provider_timeout")))
        except ProviderError as exc:
            if not planning:
                safety.retain_failure("inference", exc, provider=request.provider, model=request.model)
                raise
            failure = ProviderError("planning inference provider failed", code=exc.code,
                                    retryable=exc.retryable)
        except Exception as exc:
            evidence = ExecutionContractError("inference application contract failed")
            safety.retain_failure("inference", evidence, provider=request.provider, model=request.model,
                                  exception_type=type(exc).__name__, category="contract")
            if not planning:
                raise
            failure = ExecutionContractError(
                f"planning inference application contract failed ({type(exc).__name__})")
        except BaseException as exc:
            try:
                safety.retain_failure("inference", ModelCancelled("model call cancelled"),
                                      provider=request.provider, model=request.model, category="cancelled")
            except Exception as publication_error:
                exc.add_note("model cancellation evidence could not be published")
                raise exc from publication_error
            raise
        if failure is not None:
            safety.retain_failure("inference", failure, provider=request.provider, model=request.model,
                                  outcome="REJECTED", repairable=repairable)
            if not repairable or safety.active():
                raise failure from None
    # A rejected bounded reply spends a call, not the global stop latch. Admission's final
    # cancellation check still runs before the sanitized repair signal leaves this boundary.
    if failure is not None:
        raise failure from None
    return result


MODEL_CHECKS: dict[str, Callable[..., dict[str, Any]]] = {
    "anthropic-api": anthropic_api.models,
    "claude-cli": claude_cli.models,
    "copilot-sdk": copilot_sdk.models,
    "openai": openai_api.models,
}


def check_models(provider: str, names: Sequence[str], *, timeout_seconds: int) -> dict[str, Any]:
    """Ask one provider whether it serves each named model; failures are returned, never raised.

    A provider that cannot be reached, is not authenticated, or has no inference transport makes
    every one of its models unavailable, with the provider's error retained.
    """
    wanted = sorted(set(names))
    report: dict[str, Any] = {"provider": provider, "transport": provider in PROVIDERS,
                              "method": None, "listed": None, "error": None, "models": {}}
    check = MODEL_CHECKS.get(provider)
    try:
        if check is None:
            raise ValueError(f"unsupported inference provider: {provider}")
        with safety.operation(f"model_catalog.{provider}"):
            report.update(check(wanted, timeout_seconds=timeout_seconds))
    except Exception as exc:  # every provider failure is evidence for the preflight report
        safety.fail(f"model catalog failed: {type(exc).__name__}", action=f"model_catalog.{provider}")
        report["error"] = f"{type(exc).__name__}: {exc}"[:2048]
    for name in wanted:
        entry = dict(report["models"].get(name) or {
            "available": False, "detail": report["error"] or "the provider did not report this model"})
        if not report["transport"]:
            entry = {"available": False,
                     "detail": f"no inference transport is implemented for provider {provider}"}
        report["models"][name] = entry
    return report


__all__ = ["Infer", "MODEL_CHECKS", "ModelOutputError", "ModelRequest", "ModelResult", "PROVIDERS",
           "ReviewModelRequest", "check_models", "infer", "parse_model_payload"]
