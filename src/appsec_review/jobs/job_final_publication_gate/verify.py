"""Accepted-review imports retained for callers of the original gate reader."""
from appsec_review.jobs.accepted_review import (
    REVIEW_JOB, VerifiedReview, load_accepted_review, project_finding, project_score,
)

ATTACK_CHAIN_UNAVAILABLE = ("No attack-chain manifest exists: attack-chain composition and refutation "
                            "(design slice 3) is not built, so no chain package can be published.")
POC_UNAVAILABLE = ("No proof-of-trigger status manifest exists: the PoC lane is plan-only and no execution "
                   "path is built (decision 3), so no PoC outcome can be published.")

__all__ = ["REVIEW_JOB", "VerifiedReview", "load_accepted_review", "project_finding", "project_score"]
