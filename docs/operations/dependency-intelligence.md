# Operating dependency intelligence

Run `job_dependency_intelligence` after target cataloging, accepted language builds, artifact
indexing, and evidence collection. Its central configuration must declare this topology in order:

1. `inputs.load_accepted`
2. `resolution.detect_dependencies`, `resolution.infer_repositories`
3. `scorecards.fetch`
4. `publication.publish_context`
5. `acceptance.publish_handoff`

Configure positive deterministic bounds for dependency count, native candidate count, command
tokens, metadata file count/bytes, and inference candidate bytes. Configure a repository-host
allowlist; model provider/name/reasoning/token/timeout/retry settings; and Scorecard HTTPS base URL,
host allowlist, request count, response bytes, timeout, and retry settings. Do not place these values
in prompts.

The accepted artifact is under the final task's run-owned directory. Verify it through
`load_accepted_dependency_intelligence`; that reader checks the framework handoff, artifact hashes,
manifest content hash, shard hash, and immutable SQLite metadata before returning content. Raw
successful Scorecard JSON is stored below the Scorecard task and referenced by SHA-256.

Operational triage should group gaps by `dependency_id`:

- unresolved or unsupported repository: improve accepted package metadata or inspect the retained
  native command/artifact evidence;
- no Scorecard/404: confirm the public repository identity and Scorecard availability;
- rate limit/request failure: repair service capacity or connectivity and rerun;
- malformed response: retain the exact response hash and investigate API compatibility;
- model unavailable/failure: the deterministic candidate remains usable, but repository coverage
  is incomplete;
- bounds: increase the specific central limit only after reviewing target scale and retained data.

Exposure triage should start with `maximal_exposure`, then inspect `exposure_evidence` before using
it to prioritize review. `PROD` with `exposure_inference_basis = conservative-default` means the
accepted observations had no recognized scope; it does not claim verified production deployment.
Conflicting evidence is expected and retained, with the maximum class chosen in the fixed order
`DEV < DEBUG < QA < PREPROD < PROD`. Improve upstream manifest, SBOM, build-configuration, or loader
observations when a conservative default is too broad; do not manually weaken the accepted output.

Focused verification:

```text
python -m pytest tests/test_dependency_intelligence.py -q --basetemp=test/tmp/dependency-intelligence
```

Mocked tests verify parser, inference, HTTP, gap, and publication contracts. They do not prove live
Scorecard reachability or provider availability; those remain explicit environment acceptance work.
