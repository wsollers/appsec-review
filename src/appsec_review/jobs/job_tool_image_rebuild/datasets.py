"""Dataset declarations for the mandatory tool-image rebuild gate."""

from appsec_review.runtime.datasets import artifact_only


_A = "data/jobs/job_tool_image_rebuild/attempts/*"
CONSUMES = ()
DATASETS = (
    artifact_only(
        "tool_image_rebuild", "publication", "configuration", "appsec-review/tool-image-rebuild/1",
        "Fresh container tool-image rebuild receipts for one graph dispatch.",
        artifacts=(
            _A + "/steps/selection/tasks/resolve_images/tool-image-plan.json",
            # Rebuild summary, per-image receipts, builder output and the copied builder summary.
            _A + "/steps/build/tasks/build_images/**",
            _A + "/steps/publication/tasks/publish_handoff/tool-image-rebuild-handoff.json",
        ),
        reason="tool image build provenance; no target security evidence",
    ),
)
