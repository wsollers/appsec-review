"""Dataset publication declarations for job_project_build.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_project_build/attempts/*"
CONSUMES = ('job_target_analysis_plan',)
DATASETS = (
    artifact_only("project_build_dispatch", "acceptance", "build", "appsec-review/project-build-dispatch/2",
                  "Accepted image, probe and build dispatch decisions per build unit.",
                  artifacts=(_A + "/artifacts/project-build/*.json",),
                  reason="carries exact recipes and environment values; language-build publishes the sanitized "
                         "build index", sensitivity="sensitive"),
    protected("probe_workspaces", "probe", "build", "application/octet-stream",
              "Probe workspaces, kernel execution capture, protected commands and build logs.",
              artifacts=("data/build/probes/**",),
              reason="exact argv, environment values, raw logs and file-access captures"),
    protected("image_build_streams", "image", "build", "text/plain",
              "Image build and repair streams, repair Dockerfiles and raw repair model responses.",
              artifacts=(_A + "/steps/image/tasks/*/*/**", _A + "/steps/probe/tasks/*/*/**"),
              reason="raw build output and raw model responses must not enter retrieval"),
)
