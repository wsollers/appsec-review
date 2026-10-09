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

from . import anthropic_api, claude_cli, openai_api
from .claude_cli import ModelOutputError, parse_model_payload
from .request import Infer, ModelRequest, ModelResult


PROVIDERS: dict[str, Infer] = {
    "anthropic-api": anthropic_api.send,
    "claude-cli": claude_cli.send,
}


def infer(request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
    """Send one bounded request to the provider it names and return the validated proposal."""
    try:
        send = PROVIDERS[request.provider]
    except KeyError as exc:
        raise ValueError(f"unsupported inference provider: {request.provider}") from exc
    return send(request, timeout_seconds=timeout_seconds)


MODEL_CHECKS: dict[str, Callable[..., dict[str, Any]]] = {
    "anthropic-api": anthropic_api.models,
    "claude-cli": claude_cli.models,
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
        report.update(check(wanted, timeout_seconds=timeout_seconds))
    except Exception as exc:  # every provider failure is evidence for the preflight report
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
           "check_models", "infer", "parse_model_payload"]
