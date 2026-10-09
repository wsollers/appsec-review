"""The application's single path to a language model.

Every job reaches a model by calling `infer`. Each provider module holds one transport function,
and the provider named on the request is resolved to that function only here. Jobs never import
a provider module, and nothing else in the application opens a model connection.
"""

from __future__ import annotations

from . import anthropic_api, claude_cli
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


__all__ = ["Infer", "ModelOutputError", "ModelRequest", "ModelResult", "PROVIDERS", "infer",
           "parse_model_payload"]
