"""Derived model-call accounting: unknown usage and subscription charges stay unknown."""
from __future__ import annotations

from collections import Counter
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

SCHEMA = "appsec-review/cost-provenance/1"


def _amount(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        return None
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        return None
    return number if number.is_finite() and number >= 0 else None


def _tokens(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def account_calls(events: Iterable[Mapping[str, Any]], *,
                  prices: Mapping[str, Any] | None = None,
                  finding_links: Mapping[str, list[str]] | None = None) -> dict[str, Any]:
    """One allocation per run/job/attempt/dispatch, not per retry counter or finding."""
    if prices is not None and (prices.get("schema") != "appsec-review/api-prices/1"
                               or not prices.get("version") or not isinstance(prices.get("rates"), dict)):
        raise ValueError("API price estimates require a versioned price document")
    seen: dict[str, dict[str, Any]] = {}
    starts: dict[str, Mapping[str, Any]] = {}
    duplicates, conflicts = 0, set()
    for event in events:
        if event.get("event_type") not in {"MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"}:
            continue
        details = event.get("details", {})
        invocation = details.get("model_invocation_id") or details.get("invocation_id")
        key = "/".join(str(event.get(field) or "-") for field in ("run_id", "job_id", "attempt_id"))
        key += "/" + str(invocation or f"uncorrelated-{event.get('sequence')}")
        if event["event_type"] == "MODEL_CALL_STARTED":
            starts[key] = event
            continue
        row = {
            "call_id": key, "job_id": str(event.get("job_id") or "-"),
            "invocation_id": invocation, "provider": details.get("served_provider") or details.get("provider"),
            "model": details.get("served_model") or details.get("model"),
            "terminal_status": details.get("terminal_status"),
            "request_sha256": details.get("request_sha256"),
            "execution_mode": details.get("execution_mode"),
            "input_tokens": _tokens(details.get("input_tokens")),
            "output_tokens": _tokens(details.get("output_tokens")),
            "cache_tokens": _tokens(details.get("cache_tokens")),
            "amount": None, "currency": None, "provenance": "unknown",
            "reason": "provider_charge_unavailable", "price_version": None,
        }
        if any(row[name] is None for name in ("input_tokens", "output_tokens", "cache_tokens")):
            row["reason"] = "provider_usage_unavailable_or_invalid"
        reused = (details.get("execution_mode") in {"replay", "cache", "cached", "reused"}
                  or details.get("terminal_status") in {"REUSED", "REPLAYED", "CACHED"}
                  or details.get("usage_unavailable_reason") == "recorded_replay")
        charge = details.get("provider_charge")
        if reused:
            row.update(provenance="reused", reason="no_new_dispatch_charge",
                       input_tokens=None, output_tokens=None, cache_tokens=None)
        elif isinstance(charge, Mapping) and _amount(charge.get("amount")) is not None and (
            isinstance(charge.get("currency"), str) and len(charge["currency"]) == 3
            and charge["currency"].isascii() and charge["currency"].isalpha()
            and charge.get("source") == "provider_reported"
        ):
            row.update(amount=str(_amount(charge["amount"])), currency=charge["currency"].upper(),
                       provenance="provider_reported", reason=None)
        elif details.get("billing_mode") == "subscription":
            row.update(provenance="subscription", reason="subscription_not_per_call_billing")
        elif prices is not None and invocation:
            rate = prices["rates"].get(f"{row['provider']}/{row['model']}")
            if isinstance(rate, Mapping) and all(row[field] is not None for field in (
                "input_tokens", "output_tokens", "cache_tokens"
            )) and rate.get("cache_semantics") == "included_in_input":
                amounts = [_amount(rate.get(name)) for name in ("input_per_million", "output_per_million",
                                                               "cache_per_million")]
                if (all(number is not None for number in amounts) and row["cache_tokens"] <= row["input_tokens"]
                        and rate.get("currency") == "USD"):
                    estimate = ((row["input_tokens"] - row["cache_tokens"]) * amounts[0]
                                + row["output_tokens"] * amounts[1] + row["cache_tokens"] * amounts[2]) / 1000000
                    row.update(amount=str(estimate), currency="USD", provenance="api_estimate",
                               reason=None, price_version=prices["version"])
        if not invocation:
            row.update(amount=None, currency=None, provenance="unknown", reason="missing_call_identity")
        if key in seen:
            duplicates += 1
            if seen[key] != row:
                conflicts.add(key)
        else:
            seen[key] = row
    for key in starts.keys() - seen.keys():
        event = starts[key]
        seen[key] = {"call_id": key, "job_id": str(event.get("job_id") or "-"),
                     "invocation_id": event["details"].get("model_invocation_id"),
                     "input_tokens": None, "output_tokens": None, "cache_tokens": None,
                     "amount": None, "currency": None, "provenance": "unknown",
                     "reason": "missing_completion", "price_version": None}
    for key in conflicts:
        seen[key].update(amount=None, currency=None, provenance="unknown",
                         reason="conflicting_call_records", input_tokens=None,
                         output_tokens=None, cache_tokens=None)
    rows = [seen[key] for key in sorted(seen)]

    def totals(items: list[dict[str, Any]]) -> dict[str, Any]:
        groups: dict[str, Decimal] = {}
        for row in items:
            if row["amount"] is not None:
                key = f"{row['provenance']}/{row['currency']}"
                groups[key] = groups.get(key, Decimal(0)) + Decimal(row["amount"])
        charged = [row for row in items if row["provenance"] != "reused"]
        return {"known_amounts": {key: str(value) for key, value in sorted(groups.items())},
                "status": "empty" if not items else "partial" if any(row["amount"] is None for row in charged)
                else "complete",
                "calls_by_provenance": dict(Counter(row["provenance"] for row in items)),
                "usage": {name: (sum(row[name] for row in charged)
                                if charged and all(row[name] is not None for row in charged) else None)
                          for name in ("input_tokens", "output_tokens", "cache_tokens")}}

    allocations = []
    for row in rows:
        findings = sorted(set((finding_links or {}).get(row["call_id"], [])))
        if findings:
            allocations.append({"call_id": row["call_id"], "finding_ids": findings,
                                "method": "equal_share_analytical_allocation_not_billing",
                                "total_amount": row["amount"], "currency": row["currency"],
                                "share_numerator": 1, "share_denominator": len(findings)})
    return {"schema": SCHEMA, "run": totals(rows),
            "jobs": {job: totals([row for row in rows if row["job_id"] == job])
                     for job in sorted({row["job_id"] for row in rows})},
            "calls": rows, "duplicate_records": duplicates, "conflicting_calls": sorted(conflicts),
            "finding_allocations": allocations}
