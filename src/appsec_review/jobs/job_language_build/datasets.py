"""Dataset publication declarations for job_language_build.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_language_build/attempts/*"
CONSUMES = ('job_project_build',)
DATASETS = (
    indexed("build_actions", "acceptance", "build", "appsec-review/retrieval-index/2",
            "Sanitized build commands, produced artifacts and package relationships per build unit.",
            indexes=("build",), prefixes=("language-build",),
            route="find/trace index=build; query_precomputed query_set=build_provenance"),
    indexed("jvm_build_actions", "execute", "build", "appsec-review/retrieval-index/2",
            "Sanitized JVM build commands, observed tool invocations and artifacts.",
            indexes=("build",), prefixes=("jvm-",), route="find/trace index=build"),
    artifact_only("language_build_receipts", "acceptance", "build", "appsec-review/language-build-handoff/1",
                  "Accepted build receipts with topology, dependency identities and artifact hashes.",
                  artifacts=(_A + "/artifacts/language-build/*.json",),
                  reason="receipts embed exact recipes and environment values; sanitized facts are in the build "
                         "index", sensitivity="sensitive"),
    protected("build_workspaces", "execute", "build", "application/octet-stream",
              "Build workspaces, execution capture, protected argv and environment, link databases and logs.",
              artifacts=("data/build/native/**", "data/build/go/**", "data/build/dotnet/**", "data/build/node/**",
                         "data/build/python/**", "data/build/rust/**", "data/build/php/**", "data/build/jvm/**",
                         "data/build/java/**", "data/build/wasm/**"),
              reason="exact argv, environment values, raw logs, file-access captures and built binaries"),
)
