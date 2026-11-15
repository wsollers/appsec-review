"""Lane B receives lane A's sealed claims: prior ids for every unit, accepted seeds where they touch it."""
from __future__ import annotations

import threading
from types import SimpleNamespace

from appsec_review.jobs.job_inference_security_review.job import build_job
from appsec_review.jobs.job_inference_security_review.teams import (
    PackageWork, ReviewContext, lead_seeds, seeded_work,
)
from appsec_review.review.models import Lane

SYMBOL_A = "asr:symbol:" + "a" * 64
SYMBOL_B = "asr:symbol:" + "b" * 64
SINK = "asr:sink_site:" + "c" * 64
CALL = "asr:call_site:" + "d" * 64
ENTRY = "asr:entry_point:" + "e" * 64


def _work(entities, prior=()):
    return PackageWork("hunt-1", Lane.HUNT, "f" * 64, {}, (0, "hunt-1"), "basis", tuple(entities), "unit-1",
                       prior_claim_ids=tuple(prior))


def _seed(claim_id, state, affected, evidence):
    return {"claim_id": claim_id, "state": state, "affected_entities": list(affected),
            "evidence_entities": list(evidence), "adjudication_id": "adj-" + claim_id, "policy_sha256": "p" * 64}


def test_lead_seeds_carry_accepted_seeds_and_id_only_entries_for_the_rest() -> None:
    document = {
        "proposals": {"claim-3": ["lead-1"], "claim-1": ["lead-1", "lead-2"], "claim-2": ["lead-2"]},
        "variant_seeds": {"lead-2": [_seed("claim-2", "confirmed", [SYMBOL_B], [SYMBOL_B, ENTRY])],
                          "lead-1": [_seed("claim-1", "supported", [SYMBOL_A], [SYMBOL_A, SINK])]},
    }
    seeds = lead_seeds(document)
    assert [seed["claim_id"] for seed in seeds] == ["claim-1", "claim-2", "claim-3"]
    assert seeds[0]["state"] == "supported" and seeds[1]["state"] == "confirmed"
    assert seeds[2] == {"claim_id": "claim-3", "state": "proposed", "affected_entities": [], "evidence_entities": []}
    assert lead_seeds({"proposals": {}}) == ()


def test_seeded_work_knows_every_lead_claim_and_only_the_seeds_touching_the_unit() -> None:
    seeds = lead_seeds({
        "proposals": {"claim-1": ["lead-1"], "claim-2": ["lead-2"], "claim-3": ["lead-3"]},
        "variant_seeds": {"lead-1": [_seed("claim-1", "confirmed", [SYMBOL_A], [SYMBOL_A, SINK])],
                          "lead-2": [_seed("claim-2", "confirmed", [SYMBOL_B], [SYMBOL_B])]},
    })
    work = seeded_work(_work([SINK, CALL, ENTRY], prior=("claim-0",)), seeds)
    assert work.prior_claim_ids == ("claim-0", "claim-1", "claim-2", "claim-3")
    assert [seed["claim_id"] for seed in work.known_claims] == ["claim-1"]       # touches SINK; claim-2 does not
    assert work.known_claims[0]["state"] == "confirmed"
    untouched = seeded_work(_work([ENTRY]), seeds)
    assert untouched.known_claims == () and untouched.prior_claim_ids == ("claim-1", "claim-2", "claim-3")
    assert seeded_work(_work([SINK]), ()) == _work([SINK])


def test_hunt_review_unit_depends_on_the_sealed_lead_lane() -> None:
    units = {unit.unit_id: unit for unit in build_job(infer=lambda *a, **k: None).units}
    assert units["hunt_review.teams"].dependencies == ("packages.assemble_hunt_packages", "lead_review.teams")
    assert units["lead_review.teams"].dependencies == ("packages.assemble_lead_packages",)
    assert units["merge.claims"].dependencies == ("lead_review.teams", "hunt_review.teams")


class _Core:
    """A retrieval core double: ``find`` by identity or by (kind, path)."""

    def __init__(self, rows):
        self.rows = rows

    def find(self, *, identity=None, kind=None, path=None, limit=20, cursor=None):
        if identity is not None:
            return {"results": [row for row in self.rows if row["identity"] == identity][:1], "has_more": False}
        found = [row for row in self.rows if row["kind"] == kind and row["location"]["path"] == path]
        return {"results": found[:limit], "has_more": False}


def _context(rows):
    ctx = ReviewContext.__new__(ReviewContext)
    ctx.core = _Core(rows)
    ctx.max_page_size = 20
    ctx._symbols, ctx._resolves, ctx._lock = {}, {}, threading.Lock()
    return ctx


def _row(identity, kind, path, start, end, payload=None):
    return {"identity": identity, "kind": kind, "location": {"path": path, "start_line": start, "end_line": end},
            "payload": payload or {}}


def test_enclosing_symbol_prefers_the_graph_facts_function_then_the_tightest_symbol_range() -> None:
    outer = "asr:symbol:" + "1" * 64
    inner = "asr:symbol:" + "2" * 64
    elsewhere = "asr:symbol:" + "3" * 64
    rows = [
        _row(outer, "symbol", "src/a.c", 10, 60), _row(inner, "symbol", "src/a.c", 30, 40),
        _row(elsewhere, "symbol", "src/b.c", 30, 40),
        _row(SINK, "sink_site", "src/a.c", 35, 35,
             {"result": {"enclosing_function": {"symbol": inner, "display": "f"}}}),
        _row(CALL, "call_site", "src/a.c", 50, 50, {"result": {"enclosing_function": {"symbol": None}}}),
        _row("asr:tool_observation:" + "4" * 64, "tool_observation", "src/a.c", 33, 33),
        _row("asr:ast_node:" + "5" * 64, "ast_node", "src/a.c", 70, 70),
    ]
    ctx = _context(rows)
    assert ctx.enclosing_symbol(SINK) == inner                                # named by the fact
    assert ctx.enclosing_symbol(CALL) == outer                                # by range: only outer holds line 50
    assert ctx.enclosing_symbol("asr:tool_observation:" + "4" * 64) == inner  # tightest of two containing ranges
    assert ctx.enclosing_symbol("asr:ast_node:" + "5" * 64) is None           # no symbol holds line 70
    assert ctx.enclosing_symbol("asr:sink_site:" + "9" * 64) is None          # unknown identity
    assert ctx._symbols[SINK] == inner                                        # cached
