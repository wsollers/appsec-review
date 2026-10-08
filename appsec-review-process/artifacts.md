# Run Artifact Contract

Authoritative run data lives under:

```text
appsec-review-process/runs/<run-id>/data/
```

The current run-data contract is
[`../docs/dagster/run-data-and-job-execution.md`](../docs/dagster/run-data-and-job-execution.md).
Accepted pointers are the only discovery boundary. A directory, status message, scanner output or
model file that is not reached through a valid accepted record is not current evidence.

## Core layout

```text
configuration/                         immutable run configuration
guidance/<bundle-sha256>/              resolved model guidance bundle (target layout)
orchestration/launches/<launch-id>/    launch request and reconnect state
workflows/<workflow>/                  aggregate workflow status and acceptance
jobs/<job>/<partition>/attempts/<id>/  immutable work, validation, logs and outputs
imports/<import-id>/                   explicit hash-bound historical imports
```

The guidance directory is reserved for the exact repository-controlled instructions resolved for
a model invocation. Its manifest pins the source revision, configuration fingerprint, component
hashes and assembled prompt hash. Attempts reference a bundle by hash; they do not copy
`AGENTS.md`, read target guidance, or treat `appsec-review-process/prompt-cache/` as authoritative.
The cache remains transitional until the runtime migration described in
[`../docs/architecture/ai-guidance.md`](../docs/architecture/ai-guidance.md) is implemented.

## Evidence rules

- Every factual model input is a regular, bounded, hash-pinned file or a re-runnable query result.
- Tool/model output is untrusted until its schema, identity, citations and producer contract pass.
- Missing evidence becomes a named gap or blocker; it is never converted to a negative result.
- Raw secrets remain in ignored run data when retention is authorized. Reports cite a location and
  rule without reproducing a secret value.
- Explicit historical imports are copied and hash-bound beneath `data/imports/`; their source path
  never becomes authoritative.
