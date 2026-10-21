"""Closed vocabularies of ``job_poc_generation`` (docs/architecture/review-judge-and-poc.md, section 5.4)."""
from __future__ import annotations

COMPILE_VERIFIED = "compile_verified"
COMPILE_FAILED = "compile_failed"
ARTIFACT_GENERATED = "artifact_generated"
POLICY_DENIED = "policy_denied"
INSUFFICIENT_EVIDENCE = "insufficient_evidence"
NOT_APPLICABLE = "not_applicable"
UNSAFE_TO_ATTEMPT = "unsafe_to_attempt"

#: The candidate statuses. Only ``compile_verified`` says the function builds against the project.
#: ``compile_failed`` says the generated code does not build; it never contradicts the finding.
STATUSES = (COMPILE_VERIFIED, COMPILE_FAILED, ARTIFACT_GENERATED, POLICY_DENIED, INSUFFICIENT_EVIDENCE,
            NOT_APPLICABLE, UNSAFE_TO_ATTEMPT)
#: Statuses whose source file and compile record are written under ``data/poc/<claim>/``.
SOURCE_STATUSES = frozenset({COMPILE_VERIFIED, COMPILE_FAILED, ARTIFACT_GENERATED, POLICY_DENIED})
#: Statuses the writer may choose by declining; the application decides every other one.
DECLINES = (INSUFFICIENT_EVIDENCE, NOT_APPLICABLE, UNSAFE_TO_ATTEMPT)

#: Named gaps the job records (never read as a clean target).
GAP_NO_CANDIDATES = "no_poc_candidates"
GAP_CANDIDATE_BOUND = "candidate_bound_reached"

JUDGE_VERDICTS = ("red_correct", "blue_correct", "partly", "neither", "unresolved")
CLAIM_STATES = ("supported", "confirmed")
