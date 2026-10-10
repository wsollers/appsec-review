# SEI CERT coverage

appsec-review maps its Semgrep CE and OpenGrep rules to the
[SEI CERT Secure Coding Standards](https://cmu-sei.github.io/secure-coding-standards/) published
by the Carnegie Mellon University Software Engineering Institute
([source repository](https://github.com/cmu-sei/secure-coding-standards),
[SEI secure coding program](https://www.sei.cmu.edu/our-work/secure-development/)). The rule pack
was introduced in commit
[`ae95983`](https://github.com/wsollers/appsec-review/commit/ae959834ce15f86dc23a642684eb3c6411b0fc00).

This page is an overview. The design is in
[`architecture/sei-cert-rule-pack.md`](architecture/sei-cert-rule-pack.md), the procedures are in
[`operations/sei-cert-rule-pack.md`](operations/sei-cert-rule-pack.md), and the generated status of
every CERT rule is in [`../rules/sei-cert/COVERAGE.md`](../rules/sei-cert/COVERAGE.md).

## What is covered

The pack inventories all 412 rules of the official SEI CERT C (122), C++ (83), Oracle Java (176),
and draft Android (31) standards at source revision `98706f8`, retrieved 2026-10-10. Every rule has
an explicit status:

| Status | CERT rules |
| --- | --- |
| `SUPPORTED`: every syntactic form detected within pack-wide limits | 5 |
| `PARTIAL`: a named subset detected | 33 |
| `REQUIRES_DATAFLOW` | 108 |
| `REQUIRES_COMPILER_OR_IR` | 80 |
| `REQUIRES_CODEQL` | 68 |
| `REQUIRES_MANUAL_REVIEW` | 98 |
| `UNSUPPORTED_SEMANTIC` / `UNSUPPORTED_LANGUAGE` | 16 / 4 |

The 38 implemented CERT rules are covered by 48 engine rules. They are tested against annotated
fixtures under both pinned engines (Semgrep 1.178.0 and OpenGrep 1.30.2), which must agree
exactly. On the pinned `appsec-multi-vuln` corpus, the pack reports 16 findings across 13 CERT rules
in both engines. C++ rules without pack coverage are delegated to the vendored CERT C++ CodeQL
queries in [`../rules/cpp-cert/`](../rules/cpp-cert/README.md).

## Where it runs

`job_evidence_collection` runs the lock-verified pack under `tool-semgrep` (alongside its baseline
rules) and under the `tool-opengrep` image (C, C++, and Java only). Each evidence record carries the
CERT identifier, official URL, coverage status, and source-file hash. Engine errors and skipped files
are recorded as coverage gaps. See
[`operations/static-analysis.md`](operations/static-analysis.md).

## Local use

```text
python -m pip install -e ".[rulepacks]"          # adds PyYAML 6.0.3 to the project venv
python -m appsec_review.rulepacks.sei_cert validate
python -m appsec_review.rulepacks.sei_cert evaluate --output test/tmp/sei-cert-evaluation
```

Semgrep and OpenGrep are not project dependencies. Provide the pinned versions through
`APPSEC_REVIEW_SEMGREP` and `APPSEC_REVIEW_OPENGREP` or on `PATH`, as the operations guide
describes.

## What the results mean

A finding is a rule-pack observation tied to a CERT rule, not an accepted vulnerability. Neither
findings nor their absence establish that a target conforms to an SEI CERT standard: most rules are
delegated to analyzers or review outside this pack, C and C++ are analyzed without preprocessing,
and a rule with no findings is a coverage statement, never a passed rule. CERT and CERT Coordination
Center are registered marks of Carnegie Mellon University.
