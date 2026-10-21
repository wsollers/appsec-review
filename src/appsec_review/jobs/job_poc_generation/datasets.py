"""Publication declarations for ``job_poc_generation``.

The reproducer files are developer-facing data: they are stored verbatim, hash-bound by the handoff and
read by the final report, and never indexed as text or executed. The writer's briefs and receipts carry
target source excerpts and untrusted model output, so they are protected.
"""
from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, protected


_A = "data/jobs/job_poc_generation/attempts/*/steps"
# The job reads the accepted gate (and through it the review) and the accepted native build; it writes
# beside them and is read only by the final report.
CONSUMES = ("job_final_publication_gate", "job_inference_security_review", "job_language_build")
DATASETS = (
    artifact_only(
        "poc_generation_summary", "publish", "inference_review", "appsec-review/poc-generation-handoff/1",
        "Hash-bound list of every proof-of-concept candidate with its status, bounded description, file "
        "references and named gaps, plus the verified inputs, the validator outcome and the compile record.",
        artifacts=(_A + "/load/**", _A + "/validate/**", _A + "/compile/**", _A + "/package/**",
                   _A + "/publish/**"),
        reason="the summary is read by the final report through the accepted handoff; a scoped finding query is "
               "planned with the retrieval finding index publisher"),
    protected(
        "poc_writer_cells", "write", "inference_review", "appsec-review/poc-writer-receipt/1",
        "The writer's briefs (target source excerpts and package views) and per-candidate receipts with hashes, "
        "counts and the validated answer; raw prompts are never stored.",
        artifacts=(_A + "/plan/**", _A + "/write/**"),
        reason="briefs carry target source text and the answers are untrusted model output kept for audit only"),
    artifact_only(
        "poc_reproducers", "package", "inference_review", "appsec-review/poc-provenance/1",
        "Per candidate: the proof-of-concept source (two functions, no main), compile.json, README.md and "
        "provenance.json under data/poc/<claim-id>/.",
        artifacts=("data/poc/**",),
        reason="model-written source is stored verbatim as data for developers and is never indexed as text, "
               "linked or executed; the report and the handoff carry its hashes"),
)
