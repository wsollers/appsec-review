# Test targets: where to get the repositories

Reviews and the acceptance tests run against target repositories that are **not** part of this
repository. `targets/` is ignored by Git, so a target never enters this repository.

| Target | Where it comes from | Where it goes | Used by |
| --- | --- | --- | --- |
| Acceptance target `appsec-multi-vuln` | <https://github.com/wsollers/appsec-multi-vuln> | `targets/appsec-multi-vuln` | Dagster default (`APPSEC_REVIEW_TARGET`), target-reading tests, `stepwise.py system --tag cpp-multivuln-v1` |
| Evaluator guide `appsec-multi-vuln-guide` (answer key, defect inventory) | the same owner's `appsec-multi-vuln-guide` repository | **outside** this repository; point `APPSEC_EVALUATOR_GUIDE` at it | Evaluation only |
| Paired case `appsec-multi-vuln` tag `appsec-multi-vuln-c094-v1` (`projects/native/case-094`) | the same remote, branch `case-094` (stacked on `polyglot-case-093`; pushed by the owner) | `targets/appsec-multi-vuln-c094`, so the pinned default target does not move | `stepwise.py system --tag appsec-multi-vuln-c094-v1`, detector scoring with negative controls |
| Public C corpus CASTLE-C250, blind tag `castle-c250-v1` | prepared from <https://github.com/CASTLE-Benchmark/CASTLE-Benchmark> at the commit in [`../../data/reference/castle/castle-c250.lock.json`](../../data/reference/castle/castle-c250.lock.json) by `python -m appsec_review.acceptance.castle prepare` | `targets/castle-c250` | Detector-scoring regression against the paper's numbers |
| Build-topology fixture monorepo | committed at [`../../test/topology/monorepo/`](../../test/topology/monorepo/README.md) (46 small text files, byte-pinned by `MANIFEST.json`); copied out by `python -m appsec_review.acceptance.topology prepare --into targets/topology-monorepo` | `targets/topology-monorepo` | `tests/test_topology_fixture.py` (fast, no Docker) and live `appsec-review start --target targets/topology-monorepo`, scored with `... topology score --run <run>` against `test/topology/monorepo.expectations.json` ([task](../tasks/2026-11-07-topology-fixture-monorepo.md)) |
| Any other target | its own remote | `targets/<name>`, passed with `--target` or `APPSEC_REVIEW_TARGET` | Ad hoc reviews |

```bash
git clone https://github.com/wsollers/appsec-multi-vuln.git targets/appsec-multi-vuln
git -C targets/appsec-multi-vuln checkout 29943842cc0c6a8ed5171417b0bccf5c6769f4ef   # the pinned commit
```

```powershell
git clone https://github.com/wsollers/appsec-multi-vuln.git targets\appsec-multi-vuln
```

- The pinned target and guide commits are in
  [`../reviews/native-evaluator-guide.lock.json`](../reviews/native-evaluator-guide.lock.json). Move the
  target only between runs, never while a run or a test suite reads it.
- The target is blind. `tests/test_blind_target_isolation.py` fails if its paths or prose name a
  weakness. Never clone the evaluator guide under `targets/` or anywhere a review can see it.
- The seeded C/C++ defects of the `cpp-multivuln-v1` acceptance set are scored against
  `test/acceptance/cpp-multivuln-v1/expectations.toml` (see [`acceptance-funnel.md`](acceptance-funnel.md)).
- Case-094's answers (seven defects and seven paired negative controls) are recorded only in the evaluator
  guide's `case-094` inventory records and `controls`; the corpus carries no hint of which code is which.
  Its scoring key is `test/acceptance/appsec-multi-vuln-c094-v1/expectations.toml`, pinned to the corpus
  and guide commits it was derived from. It has no baselines until a live acceptance is accepted.
- CASTLE-C250 is prepared into a blind git repository outside this checkout (renamed files, comments
  blanked with line numbers kept, one reproducible commit) and then cloned into `targets/`. Its key,
  `test/acceptance/castle-c250-v1/expectations.toml`, is derived from upstream metadata and never placed in
  the target. Steps: [`acceptance-funnel.md`](acceptance-funnel.md#manual-validation-user-owned).
- On a new host, clone the target before the first stack start; the Dagster compose file mounts
  `targets/` writable at `/opt/app/targets`, because acquisition and builds write into it.

The full download steps are in the README section "Download the acceptance target".
