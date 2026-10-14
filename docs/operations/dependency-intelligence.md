# Operating dependency intelligence

Run `job_dependency_intelligence` after target cataloging, accepted language builds, artifact
indexing, and evidence collection. Its central configuration must declare this topology in order:

1. `inputs.load_accepted`
2. `resolution.detect_dependencies`, `resolution.infer_repositories`
3. `repositories.deduplicate`
4. `scorecards.fetch`
5. `publication.publish_context`
6. `acceptance.publish_handoff`

Configure positive deterministic bounds for dependency and unique-repository counts, native candidate count, command
tokens, metadata file count/bytes, and inference candidate bytes. Configure a repository-host
allowlist; model provider/name/reasoning/token/timeout/retry settings; and Scorecard HTTPS base URL,
host allowlist, request count, response bytes, timeout, retry, repository-relative cache root,
cache-lock timeout, and maximum cache age. The default maximum age is seven days, matching the
upstream weekly scan cadence; operators may tune it centrally. Do not place these values in prompts.

The accepted artifact is under the final task's run-owned directory. Verify it through
`load_accepted_dependency_intelligence`; that reader checks the framework handoff, artifact hashes,
manifest content hash, shard hash, and immutable SQLite metadata before returning content. Raw
successful Scorecard JSON is stored below the Scorecard task and referenced by SHA-256. Bounded
HTTP error and malformed response bytes are also retained there when the client received them, so
operators can distinguish service behavior from a missing request without trusting response text.
The accepted document includes the deduplicated repository groups and `scorecard_metrics` with
unique repository, cache-hit, and HTTP-request counts. A warm-cache rerun should normally report
zero HTTP requests until entries exceed the configured maximum age.

Operational triage should group gaps by `dependency_id`:

- unresolved or unsupported repository: improve accepted package metadata or inspect the retained
  native command/artifact evidence;
- no Scorecard/404: confirm the public repository identity and Scorecard availability;
- rate limit/request failure: repair service capacity or connectivity and rerun;
- malformed response: retain the exact response hash and investigate API compatibility;
- cache invalid/write failure: inspect `data/feeds/openssf-scorecard`; the run may still contain a
  fresh remote response, but the cache failure remains an explicit operational gap;
- repository bound: review the deduplicated repository count before increasing the central bound;
- model unavailable/failure: the deterministic candidate remains usable, but repository coverage
  is incomplete;
- bounds: increase the specific central limit only after reviewing target scale and retained data.

Exposure triage should start with `maximal_exposure`, then inspect `exposure_evidence` before using
it to prioritize review. `PROD` with `exposure_inference_basis = conservative-default` means the
accepted observations had no recognized scope; it does not claim verified production deployment.
Conflicting evidence is expected and retained, with the maximum class chosen in the fixed order
`DEV < DEBUG < QA < PREPROD < PROD`. Improve upstream manifest, SBOM, build-configuration, or loader
observations when a conservative default is too broad; do not manually weaken the accepted output.

After acceptance, review-data indexing offers every `dependency_package` entity to the bounded
`dependency_advisories` route. A supported purl selects one OSV ecosystem and package name;
otherwise a name-only lookup is bounded across the pinned ecosystems. Model-inferred native
identities take the same route. Inventory-only matches always remain
`applicability_verified = false` and carry an `applicability_unverified` gap until accepted scanner
or version-range evidence corroborates applicability. A package-name match, inferred repository,
maximal-exposure value, Scorecard response, or absence of any of them is not a vulnerability
finding.

Focused verification:

```text
python -m pytest tests/test_dependency_intelligence.py -q --basetemp=test/tmp/dependency-intelligence
```

Mocked tests verify parser, inference, HTTP, gap, and publication contracts. They do not prove live
Scorecard reachability or provider availability; those remain explicit environment acceptance work.
