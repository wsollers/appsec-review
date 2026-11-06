"""Protected state of internal build transactions, not a review-graph publication lane."""

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import protected


DATASETS = (
    protected(
        "iteration_records", "execute", "build", "appsec-review/build-iterations/1",
        "Internal controller pointers, leases and immutable request/completion records.",
        artifacts=(
            "data/build/iterations/ledger.json", "data/build/iterations/controller.lock",
            "data/build/iterations/pending.json", "data/build/iterations/pending-invalidation.json",
            "data/build/iterations/retention.json", "data/build/iterations/selection.json",
            "data/build/iterations/prepared/*.json", "data/build/iterations/failures/*.json",
            "data/build/iterations/recompositions/*.json", "data/build/iterations/leases/*/*.json",
            *(f"artifacts/build/iterations/{category}/*.json" for category in (
                "graphs", "configurations", "requests", "receipts", "prepared", "failures",
                "completed", "invalidations", "failure-generation-selections", "contexts", "selections")),
        ),
        reason="requests and receipts retain exact recipes, host paths and environment; a controller "
               "record is not an accepted top-level build result", authority=EvidenceAuthority.OPERATIONAL),
    protected(
        "workspace_records", "execute", "build", "application/json",
        "Shared build workspace custody, generations, products and recovery records.",
        artifacts=(
            "data/build/workspace.lock", "data/build/workspace/owner.json",
            "data/build/workspace/state.json", "data/build/workspace/deletion.json",
            "data/build/workspace/replays/*/owner.json", "data/build/workspace/replays/*/state.json",
            "data/build/workspace/replays/*/writer.lock",
            "artifacts/build/workspace/input.json", "artifacts/build/workspace/generations/*.json",
            "artifacts/build/workspace/products/*.json", "artifacts/build/workspace/invalidations/*.json",
            "artifacts/build/workspace/invalidations/operations/*.json",
            *(f"artifacts/build/workspace/attempts/*/{event}.json" for event in (
                "intent", "failure", "recovery")),
        ),
        reason="workspace custody and product bindings are protected operational state; only the "
               "language-build producer publishes accepted review evidence", authority=EvidenceAuthority.OPERATIONAL),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

from dataclasses import replace
from appsec_review.jobs.job_language_build.datasets import CONTRACT as LANGUAGE_CONTRACT

CONTRACT = JobContract(
    inputs=(
        *(replace(item, availability=Availability.OPTIONAL, missing=MissingPolicy.GAP)
          for item in LANGUAGE_CONTRACT.inputs),
        InputRequirement("build_controller", "iteration_request",
                         "appsec-review/build-iteration-request/1", channel=InputChannel.TRANSACTION,
                         authority=EvidenceAuthority.OPERATIONAL,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
    ),
    schedule_after=(),
    dispatch=DispatchClass.INTERNAL_TRANSACTION,
    target_access=TargetAccess.CHECKOUT,
    always_execute=True,
    propagate_handoff=False,
)
CONSUMES = CONTRACT.consumes
