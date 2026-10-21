"""Publication declarations for ``job_sanitizer_build``.

The instrumented tree is protected, artifact-only evidence: nothing in it is indexed as text. The
accepted summary carries the sanitized facts (outputs, hashes, runtime evidence, gaps).
"""

from appsec_review.runtime.datasets import artifact_only, protected


_A = "data/jobs/job_sanitizer_build/attempts/*"
CONSUMES = ("job_language_build",)
DATASETS = (
    artifact_only(
        "sanitizer_build_summary", "acceptance", "build",
        "appsec-review/sanitizer-build-handoff/1",
        "Hash-bound catalog of the ASan/UBSan-instrumented native outputs per build unit, with the "
        "sanitizer runtime evidence read from each ELF and every named gap.",
        artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
        reason="instrumented binaries are artifact-only evidence for a later execution stage; "
               "the summary is the sanitized view and nothing here is indexed as text",
    ),
    protected(
        "sanitizer_build_workspaces", "build", "build", "application/octet-stream",
        "Instrumented build workspaces with the produced binaries, replayed argv and environment, "
        "build logs and workspace manifests.",
        artifacts=("data/sanitizer/**",),
        reason="exact argv, environment values, raw logs and instrumented binaries that must never "
               "be executed outside a separately authorized execution stage",
    ),
)
