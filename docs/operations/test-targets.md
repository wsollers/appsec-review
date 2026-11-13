---
title: "Test targets: where to get the repositories"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Test targets: where to get the repositories

Reviews and the acceptance tests run against target repositories that are **not** part of this
repository. `targets/` is ignored by Git, so a target never enters this repository.

| Target | Where it comes from | Where it goes | Used by |
| --- | --- | --- | --- |
| Acceptance target `appsec-multi-vuln` | <https://github.com/wsollers/appsec-multi-vuln> | `targets/appsec-multi-vuln` | Dagster default (`APPSEC_REVIEW_TARGET`), target-reading tests |
| Evaluator guide `appsec-multi-vuln-guide` (answer key, defect inventory) | the same owner's `appsec-multi-vuln-guide` repository | **outside** this repository; point `APPSEC_EVALUATOR_GUIDE` at it | Evaluation only |
| **First-run acceptance target (T-057):** `appsec-multi-vuln` at tag `appsec-multi-vuln-c094-v1` = `bd69bfe83fec…` (`projects/native/case-094`) | the same remote; the tag is on `main`'s ancestry, and `main`'s tip (`42284599…` on 2026-11-08) carries a byte-identical `projects/native/case-094` | `targets/appsec-multi-vuln-c094`, checked out **at the tag** (`stepwise.py accept` requires `HEAD` = tag commit), so the pinned default target does not move | T-057 first run, `stepwise.py system --tag appsec-multi-vuln-c094-v1`, detector scoring with negative controls |
| Public C corpus CASTLE-C250, blind tag `castle-c250-v1` | prepared from <https://github.com/CASTLE-Benchmark/CASTLE-Benchmark> at the commit in [`../../data/reference/castle/castle-c250.lock.json`](../../data/reference/castle/castle-c250.lock.json) by `python -m appsec_review.acceptance.castle prepare` | `targets/castle-c250` | Detector-scoring regression against the paper's numbers |
| Build-topology fixture monorepo | committed at [`../../test/topology/monorepo/`](../../test/topology/monorepo/README.md) (46 small text files, byte-pinned by `MANIFEST.json`); copied out by `python -m appsec_review.acceptance.topology prepare --into targets/topology-monorepo` | `targets/topology-monorepo` | `tests/test_topology_fixture.py` (fast, no Docker) and live `appsec-review start --target targets/topology-monorepo`, scored with `... topology score --run <run>` against `test/topology/monorepo.expectations.json` ([task](../tasks/2026-11-07-topology-fixture-monorepo.md)) |
| Freeciv at `b1b0768bfaca9b2fae68f9466defe1e80636e9fa` (whole repository; the parent of the fix for CVE-2026-90556, so that defect and CVE-2026-90557 are both present) | <https://github.com/freeciv/freeciv> | `targets/freeciv` | Job-by-job walk on a real game codebase; answers belong in the private `appsec-review-answers` repository, not here |
| Any other target | its own remote | `targets/<name>`, passed with `--target` or `APPSEC_REVIEW_TARGET` | Ad hoc reviews |

```bash
git clone https://github.com/wsollers/appsec-multi-vuln.git targets/appsec-multi-vuln
git -C targets/appsec-multi-vuln checkout 29943842cc0c6a8ed5171417b0bccf5c6769f4ef   # the pinned commit
# First-run acceptance target: the case-094 tag, in its own checkout.
git clone https://github.com/wsollers/appsec-multi-vuln.git targets/appsec-multi-vuln-c094
git -C targets/appsec-multi-vuln-c094 checkout appsec-multi-vuln-c094-v1              # bd69bfe83fec…
```

```bash
# Freeciv, pinned to the pre-fix commit (detached).
git clone https://github.com/freeciv/freeciv.git targets/freeciv
git -C targets/freeciv checkout --detach b1b0768bfaca9b2fae68f9466defe1e80636e9fa
git -C targets/freeciv rev-parse 75ecde3e86ddf2fe775768450e9a290a4f4d4387^   # prints the pinned commit
```

```powershell
git clone https://github.com/wsollers/appsec-multi-vuln.git targets\appsec-multi-vuln
```

- The pinned target and guide commits are in
  [`../reviews/native-evaluator-guide.lock.json`](../reviews/native-evaluator-guide.lock.json). Move the
  target only between runs, never while a run or a test suite reads it.
- The target is blind. `tests/test_blind_target_isolation.py` fails if its paths or prose name a
  weakness. Never clone the evaluator guide under `targets/` or anywhere a review can see it.
- `cpp-multivuln-v1` (`test/acceptance/cpp-multivuln-v1/`) is **historical**: its corpus was a separate
  local repository, `targets/cpp-multivuln` at commit `9acaa34035af…`, which is not in
  `appsec-multi-vuln`'s history and is not on GitHub (its key names `src/packet.cpp`, `src/session.cpp`
  … that exist in no `appsec-multi-vuln` commit). The six provenance records accepted against it on
  2026-10-19/20 stand for that corpus; it is not the T-057 target and `stepwise.py accept --tag
  cpp-multivuln-v1` cannot run against `appsec-multi-vuln`.
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
