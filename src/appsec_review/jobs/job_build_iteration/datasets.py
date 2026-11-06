"""Protected state of internal build transactions, not a review-graph publication lane."""

from appsec_review.runtime.datasets import protected


CONSUMES = ()
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
               "record is not an accepted top-level build result"),
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
               "language-build producer publishes accepted review evidence"),
)
