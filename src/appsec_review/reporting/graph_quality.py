"""The code-graph quality box of the report's coverage section (T-5016).

Reads the scorecard ``job_code_graph_index`` published (``graph-quality-scorecard.json``) and renders the
same one-screen text the job wrote beside it. A run without the graph job has no box; a scorecard that
does not validate is a named rendering gap, never a quiet omission.
"""
from __future__ import annotations

from .model import Box, Code, Para
from .sources import RunReader
from .text import bound, bound_lines
from .tokens import BoxKind, Limits

SCORECARD_GLOB = "data/jobs/job_code_graph_index/attempts/*/steps/acceptance/tasks/publish_handoff/graph-quality-scorecard.json"


def scorecard_box(reader: RunReader, limits: Limits) -> Box | None:
    """The scorecard box, or ``None`` when the run published no scorecard."""
    found = sorted(reader.run_dir.glob(SCORECARD_GLOB))
    if not found:
        return None
    path = found[-1]
    document = reader.read_json(path, "graph quality scorecard")
    if not isinstance(document, dict):
        return None
    from appsec_review.graph.scorecard import ScorecardError, render_scorecard, validate_scorecard
    try:
        validate_scorecard(document)
    except ScorecardError as error:
        reader.gap(f"graph quality scorecard: {error}")
        return Box(BoxKind.GAP, "Code-graph quality", items=(Para(bound(str(error), limits.text_chars)[0]),))
    text, truncation = bound_lines(render_scorecard(document), max(limits.code_lines, 60), max(limits.code_chars, 9000))
    totals = document["totals"]
    return Box(BoxKind.PROVENANCE, "Code-graph quality",
               meta=f"{totals['first_party_functions']} first-party functions · {totals['paths']} paths · "
                    f"{totals['call_sites_agreed']}/{totals['call_sites']} call sites agreed",
               items=(Para("A measurement of the published code graph: which producers vouch for each call edge and "
                           "path. A function without an agreeing producer is unverified, not wrong.", muted=True),
                      Code(text, truncation, caption=reader.rel(path))))


__all__ = ["SCORECARD_GLOB", "scorecard_box"]
