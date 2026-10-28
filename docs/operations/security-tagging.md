# Operating the security-tagging stage

`security_tagging` assigns basis-qualified tags from the
[security tag taxonomy](../architecture/security-tag-taxonomy.md) to code subjects. It reads only
the accepted retrieval manifest (`data/indices/accepted.json`), never the target tree. In the
`wave1_review` Dagster graph it runs after CodeQL, review prioritization and code-graph indexing
when registered (`orchestration/topology.py`). The opt-in `job_owasp_control_assessment` then
consumes accepted tag assignments and a bounded component tag cloud as routing context, never
control proof. Tagging does not depend on OWASP. Review data indexing follows all enabled
producers, then package assembly, document issue analysis and inference review; final report
publication is terminal. Direct `start`/`resume`/`plan-resume` select the same enabled
prioritization → code graph → tagging → OWASP → indexing chain; `--force-from` cannot bypass a
disabled-job gate. OWASP is still shipped disabled. CI/post-build branches remain Dagster additions,
and third-party metadata sync remains standalone.
Run it standalone only after an accepted manifest exists; without one the input validator fails the
job.

The vocabulary, capability rules, and crosswalk are pinned by path and SHA-256 under
`jobs.job_security_tagging.settings.taxonomy` in `appsec-review.toml`. Editing any of the three
files without updating its pinned hash fails the job before any unit runs. A namespace marked
`proposed` in the vocabulary cannot be emitted until its catalog is pinned.

Two bounds sit beside the taxonomy pins in `jobs.job_security_tagging.settings`:

| Key | Default | Allowed | Effect when exceeded |
|---|---|---|---|
| `max_entities_per_shard` | 50000 | 1 to 1,000,000 | entities read per accepted shard; reaching it records a named gap |
| `max_assignments` | 500000 | 1 to 2,000,000 | assignments per collector; exceeding it fails that collector |

Check these outputs after a run:

- the job attempt's `artifacts/security-tagging/` directory: `taxonomy-identity.json`,
  `scope.json`, one assignment set per collector, `derived.json`, the validated `assignments.json`,
  `tag-cloud.json`, and `handoff.json`;
- `data/indices/tags/<family>/` for the immutable tag shards; and
- `data/indices/accepted.json`, which now points at `data/indices/manifests/tags-<attempt>.json`.
  That manifest carries every upstream shard plus the tag shards, so retrieval and MCP clients
  keep seeing earlier evidence.

Query assignments with the existing retrieval tools, for example `search` with
`indexes=["tags"]` and `kinds=["tag_assignment"]`, or `trace` from an assignment to its subject and
to the observed tags a derived tag came from.

Reading the results:

- A `derived` tag means the control, weakness, or technique is applicable or relevant to review. It
  never means present or satisfied. Only `reported` or `confirmed` weakness tags cite findings, and
  the job publishes no security findings itself.
- Every `gap:*` tag and every entry in the handoff `gaps` list is missing coverage. An empty region
  of the tag cloud is never evidence that the target is clean.
- The job completes with gaps by design. Its standing gaps are: invoked capability detection (`func`
  tags come from package inventory only), the upstream CWE->CAPEC->ATT&CK crosswalk (deferred until
  the MITRE feed is pinned into the run), and the unimplemented `taint_path`, `iac_resource`,
  `k8s_object`, and `container_stage` crosswalk scopes. The feed-backed rollups add the `rollup_gap`
  notes declared on their namespaces in `data/reference/taxonomy/vocabulary.json`. Each is named in
  the handoff.

A re-run in the same application run produces the same assignment set for the same accepted
manifest and pinned taxonomy, and replaces earlier tag shards in the accepted manifest instead of
duplicating them.
