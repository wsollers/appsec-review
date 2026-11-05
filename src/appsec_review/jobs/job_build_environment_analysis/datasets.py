from appsec_review.runtime.datasets import artifact_only

CONSUMES = ("job_target_catalog",)
DATASETS = (
    artifact_only(
        "build_environment", "environment_analysis", "build",
        "appsec-review/build-environment-analysis/1",
        "Redacted bounded static declarations and explicit environment coverage.",
        artifacts=("data/jobs/job_build_environment_analysis/attempts/*/steps/"
                   "environment_analysis/tasks/publish_handoff/build-environment.json",),
        reason="advisory source declarations; never recipe-enforced target proof",
        sensitivity="sensitive"),
)
