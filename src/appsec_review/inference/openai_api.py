from __future__ import annotations

import json
import os
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MODELS_ENDPOINT = "https://api.openai.com/v1/models"


def models(names: Sequence[str], *, timeout_seconds: int,
           endpoint: str = MODELS_ENDPOINT) -> dict[str, Any]:
    """List the account's OpenAI models and confirm each named model is among them."""
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is unavailable to the configured inference provider")
    http_request = Request(endpoint, method="GET", headers={
        "authorization": f"Bearer {key}", "user-agent": "appsec-review/0.0.0"})
    try:
        with urlopen(http_request, timeout=timeout_seconds) as response:
            value = json.loads(response.read(4 * 1024 * 1024))
    except HTTPError as exc:
        raise RuntimeError(f"OpenAI API returned HTTP {exc.code}: "
                           f"{exc.read(1024).decode('utf-8', 'replace')}") from exc
    except URLError as exc:
        raise RuntimeError(f"OpenAI API request failed: {exc.reason}") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError("OpenAI API model response is not an object")
    listed = sorted(str(item["id"]) for item in value.get("data", ())
                    if isinstance(item, Mapping) and isinstance(item.get("id"), str))
    return {"method": "catalog", "listed": listed, "models": {
        name: ({"available": True, "detail": "listed by the provider"} if name in listed else
               {"available": False, "detail": "the provider does not list this model"})
        for name in names}}
