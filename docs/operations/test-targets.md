# Test targets: where to get the repositories

Reviews and the acceptance tests run against target repositories that are **not** part of this
repository. `targets/` is ignored by Git, so a target never enters this repository.

| Target | Where it comes from | Where it goes | Used by |
| --- | --- | --- | --- |
| Acceptance target `appsec-multi-vuln` | <https://github.com/wsollers/appsec-multi-vuln> | `targets/appsec-multi-vuln` | Dagster default (`APPSEC_REVIEW_TARGET`), target-reading tests, `stepwise.py system --tag cpp-multivuln-v1` |
| Evaluator guide `appsec-multi-vuln-guide` (answer key, defect inventory) | the same owner's `appsec-multi-vuln-guide` repository | **outside** this repository; point `APPSEC_EVALUATOR_GUIDE` at it | Evaluation only |
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
- On a new host, clone the target before the first stack start; the Dagster compose file mounts
  `targets/` writable at `/opt/app/targets`, because acquisition and builds write into it.

The full download steps are in the README section "Download the acceptance target".
