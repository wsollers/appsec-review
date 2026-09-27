# 10 synthesis report retained happy-path qualification — 2026-09-27

## Result

The standalone `10-synthesis-report` worker completed an accepted common-envelope run from six
exact accepted fixture producers. It emitted deterministic report data, retained the evidence
trace and every gap/unknown, and rendered the same hash-bound presentation input to LaTeX and
self-contained HTML.

This is a representative lifecycle fixture qualification, not a production target assessment.
The fixture finding and limitations exist to exercise promotion, traceability, and gap retention.

| Item | Value |
|---|---|
| Run | `synthesis-report-live-20260927d` |
| Accepted attempt | `03b7072c4d7448ee9783f9b1ba7a7905` |
| Common-envelope status | `OK_WITH_GAPS` |
| Accepted envelope SHA-256 | `6b502146e43ca5b4f2ede4131d77a68a24a867cba2de767d6e1878bc91fa2c43` |
| Synthesis input SHA-256 | `0c6fc3968e57162c2b3fefb402121cccf864fd76b2c2198d2cfbcb06db739959` |
| Report data SHA-256 | `bd3b27da4f759778cac8171cad799c3412789554288862f52fc61feba9d0ee9e` |
| Evidence trace SHA-256 | `6bd7747d6267a279104bdd6429be4b6d5f5d3212f9b8861a2089a9f199814adb` |
| Draft publication manifest SHA-256 | `8e021abe5c3efcd01b512f2ebd74e99c7a0aa920e82df9006df55bfddc3769ff` |
| Renderer input SHA-256 | `3c549b9f0ffee9a442730f1e296e5e5dd6a6e7a9fcef46aef7e4ebfffbd00afe` |
| Render manifest SHA-256 | `a63a78c71b686018ee924d929308a3a33f9c79a276a8e8621bfa7b9cadb041e7` |
| LaTeX SHA-256 | `9b1fb617e236e9fd6582e61d287373da52fac3a2ff84fa16dcf8080a67d5b8be` |
| HTML SHA-256 | `bcfafa1b9d40742901cf02bf4dff90c11e2c55eb235880ddb3674d3bf47381b0` |

The report projected one independently verified fixture claim as `CRITICAL / P0 / score 16`, no
unresolved candidate, and eight limitations. OWASP accounting remained four distinct denominators:
`selected=1`, `applicable=1`, `assessed=1`, `satisfied=1`. The output remained
`DRAFT_EVIDENCE_BACKED`, with both `final` and `human_signoff` false.

## Exact accepted inputs

| Input | Producer attempt | Artifact SHA-256 |
|---|---|---|
| Component | `01-component-characterization/component-1` | `3a865837b6f3a6a4090a8d45070122f6905ec4c8691f145d35630006fba10fa1` |
| Threat | `03-threat-model-dfd-stride/threat-1` | `9083af1129b5772b0cb738c1b722b4b4f66bb4d4f55b1450c4bdfab3538d0c50` |
| OWASP | `04-owasp-join-report/owasp-1` | `025ec1e95de4015dc4d022b3b4c133b136e8708840151569f5fb2336dc4a5f68` |
| Claim ledger | `claim-ledger-routing/ledger-1` | `8f04f2d069ff2fbbcdd265804895cccaae058e7dd93b2d2512d17d6444dcdb71` |
| Independent verification | `09-independent-verification/verification-1` | `22edac0beac7c06340cdf306b3b877242914308ca649d029f2642ca18c86a350` |
| Scoring | `12-scoring-prioritization/scoring-1` | `9304042d3d15326fcaf4aea9d7e980038b9494c80104a0473fccc6b2c882e0cb` |

The worker revalidates each newest accepted pointer, immutable attempt tree, common envelope,
permission and lineage receipts, authoritative schema, generation, ledger head, citation, and
artifact hash before synthesis. A pointer mutation or render promotion fails validation.

## Determinism and tests

Two forced attempts from unchanged accepted inputs produced identical hashes for `report.json`,
`evidence-trace-index.json`, `report.review.json`, `presentation/report.tex`, and
`presentation/report.html`.

Focused command:

```text
python3 -m unittest \
  appsec-review-process/tests/test_synthesis_report_worker.py \
  appsec-review-process/tests/test_synthesis_report.py \
  appsec-review-process/tests/test_draft_report_fixture_runner.py -v
```

Result: 11 tests passed. Tests cover accepted publication and revalidation, deterministic forced
replacement, exact HTML/LaTeX production, upstream tamper refusal, draft-only promotion refusal,
schema validation, prior synthesis behavior, and staging recovery.

## Deliberately separate shared integration

The task prohibited edits to the shared graph, Dagster definitions, launcher, generated parity
views, and TODO surfaces. Therefore the retained qualification uses the report lane's bounded
standalone graph/registry overlay. Shared integration still must:

1. change the shared `10-synthesis-report` node from its legacy `10-synthesis-report` contract and
   `implemented: false` state to the chosen production contract and worker;
2. align the shared job template and trusted claim-class policy with that same contract;
3. register the worker in Dagster/launcher wiring and regenerate parity/catalog views; and
4. execute the worker against a real run's accepted upstream chain. The fixture qualification does
   not claim that those upstream production stages have completed together.

No PDF is produced by this worker. It retains the deterministic `.tex` and self-contained HTML;
the existing pinned report-image compilation remains a subsequent bounded publication step.
