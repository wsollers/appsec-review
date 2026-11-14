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
| Smoke target `appsec-review-smoke-cpp` (C/C++), tag `v1.0.0` = `bededb650d0c…` | <https://github.com/wsollers/appsec-review-smoke-cpp> | `targets/appsec-review-smoke-cpp`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `native`, planted advisory zlib 1.2.11 (CVE-2018-25032), vendored |
| Smoke target `appsec-review-smoke-java` (Java), tag `v1.0.0` = `3219d1700d69…` | <https://github.com/wsollers/appsec-review-smoke-java> | `targets/appsec-review-smoke-java`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `java`, planted advisory log4j-core 2.14.1 (CVE-2021-44228) |
| Smoke target `appsec-review-smoke-javascript` (JavaScript/TypeScript), tag `v1.0.0` = `84e3c01a2b31…` | <https://github.com/wsollers/appsec-review-smoke-javascript> | `targets/appsec-review-smoke-javascript`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `node`, planted advisory lodash 4.17.15 (CVE-2020-8203) |
| Smoke target `appsec-review-smoke-python` (Python), tag `v1.0.0` = `0821c008da6e…` | <https://github.com/wsollers/appsec-review-smoke-python> | `targets/appsec-review-smoke-python`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `python`, planted advisory urllib3 1.24 (CVE-2018-25091) |
| Smoke target `appsec-review-smoke-ruby` (Ruby), tag `v1.0.0` = `c82179dbe7a7…` | <https://github.com/wsollers/appsec-review-smoke-ruby> | `targets/appsec-review-smoke-ruby`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `none (no Ruby profile or image; T-139)`, planted advisory rack 2.0.0 (CVE-2018-16471) |
| Smoke target `appsec-review-smoke-go` (Go), tag `v1.0.0` = `5f83d5062052…` | <https://github.com/wsollers/appsec-review-smoke-go> | `targets/appsec-review-smoke-go`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `go`, planted advisory golang.org/x/text v0.3.0 (GO-2020-0015) |
| Smoke target `appsec-review-smoke-csharp` (C#), tag `v1.0.0` = `887af65120b0…` | <https://github.com/wsollers/appsec-review-smoke-csharp> | `targets/appsec-review-smoke-csharp`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `dotnet`, planted advisory Newtonsoft.Json 12.0.1 (CVE-2024-21907) |
| Smoke target `appsec-review-smoke-rust` (Rust), tag `v1.0.0` = `6a11cc967702…` | <https://github.com/wsollers/appsec-review-smoke-rust> | `targets/appsec-review-smoke-rust`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `rust`, planted advisory time 0.1.43 (RUSTSEC-2020-0071) |
| Smoke target `appsec-review-smoke-php` (PHP), tag `v1.0.0` = `ef0c942de7d2…` | <https://github.com/wsollers/appsec-review-smoke-php> | `targets/appsec-review-smoke-php`, checked out at the tag | Attribution walks (T-134); one build unit, build profile `php`, planted advisory guzzlehttp/guzzle 7.4.0 (CVE-2022-29248); substituted for monolog 1.23.0, which has no OSV record |
| Smoke answer key `appsec-review-smoke-guide` (per-language `answer-key.json`, fixture facts, verification reports) | <https://github.com/wsollers/appsec-review-smoke-guide> | **outside** this repository, a sibling of the checkout | Evaluation only |
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

```bash
# Smoke targets (T-134): nine single-build-unit repositories, each checked out at its v1.0.0 tag (detached).
for lang in cpp java javascript python ruby go csharp rust php; do
  git clone https://github.com/wsollers/appsec-review-smoke-$lang.git targets/appsec-review-smoke-$lang
  git -C targets/appsec-review-smoke-$lang checkout --detach v1.0.0
done
# The smoke answer key goes beside the checkout, never under targets/ or anywhere a review can see it.
git clone https://github.com/wsollers/appsec-review-smoke-guide.git ../appsec-review-smoke-guide
```

```powershell
foreach ($lang in "cpp","java","javascript","python","ruby","go","csharp","rust","php") {
  git clone https://github.com/wsollers/appsec-review-smoke-$lang.git targets\appsec-review-smoke-$lang
  git -C targets\appsec-review-smoke-$lang checkout --detach v1.0.0
}
git clone https://github.com/wsollers/appsec-review-smoke-guide.git ..\appsec-review-smoke-guide
```

- **Smoke tier.** Each `appsec-review-smoke-<language>` target is one build unit of under four hundred
  own lines, started from the matching synthetic code-graph fixture under
  `tests/fixtures/graph/codeql_export/` (kept byte-identical, so the fixture's `expected-facts.json`
  line numbers hold) and built offline in its pinned build image as user 10001 in under twenty
  seconds. Each plants a labelled inventory (`PLANTED.md` in the target; the key is the guide): code
  true positives with a source-to-sink path, three vulnerable dependencies visible to Syft from the
  lockfile (C/C++: vendored, visible only through version strings), two code items and one
  dependency fixed in history, at least four false positives that a mounted Semgrep rule reports and
  an exportable fact refutes (Ruby and Rust have no mounted rules, so theirs are recorded as
  unflagged), one function above cyclomatic 15 in the highest-churn file, and a scripted, backdated
  history of at least thirty commits (fix commits naming the CWE, a dependency upgrade, a rename, a
  revert and reapply, `SECURITY.md` and `CHANGELOG.md`) reproducible from the target's own
  `tools/make-history.sh`. A failure anywhere on a smoke target is a defect of the pipeline, not of
  the target, and whether the planted false positives are squelched is the measure the tier exists
  for. The tier proves nothing about recall or scale; Freeciv and `appsec-multi-vuln` keep that role.
  Known limits are in each `answer-key.json` under `expected_gaps`: no Ruby build image (T-139),
  `mvn -o` fails in the Java image for lack of Maven plugins, Python is not scored by the
  complexity pass, and vendored C libraries are invisible to Syft, Grype and OSV-Scanner.
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

## Smoke runs

A smoke review runs the checked-in `dev` profile (Haiku for every role) with the smoke capacity
overlay, which is the only checked-in setting that differs from an ordinary dev run:

```bash
scripts/review-start.sh --target appsec-review-smoke-cpp --overlay smoke-capacity-overlay.toml
```

[`test/acceptance/smoke-capacity-overlay.toml`](../../test/acceptance/smoke-capacity-overlay.toml)
sets 8 review teams (dev: 3), the `inference_teams` pool at 2, and prod's four I/O slots and scanner
pool of 4. An overlay is capacity only ([inference security review](inference-security-review.md#capacity-and-local-runs)):
it cannot change the models, the package partitioning or the job budgets, so a smoke run keeps the dev
job budget of 6,000,000 output tokens and 200 team packages. On the cpp smoke the hunt lane declares
about 500 packages and the budget is exhausted after roughly 1,700 model turns; the cells that follow
record budget gaps and the handoff is `DEGRADED`, which is expected under `dev`. Capacity is excluded
from cell fingerprints, so a run under the overlay reuses the cells of a run under `--overlay none`.
