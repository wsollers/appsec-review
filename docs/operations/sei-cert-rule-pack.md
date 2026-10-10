# Operating the SEI CERT rule pack

Design and status semantics are in
[`../architecture/sei-cert-rule-pack.md`](../architecture/sei-cert-rule-pack.md). Run every command
from the repository root.

## Environment

- The validator, evaluation harness, and tests need PyYAML. Install the project extra into the
  project virtual environment: `python -m pip install -e ".[rulepacks]"`. The extra pins
  `PyYAML==6.0.3`, the version locked for the Dagster image. The review runtime does not need it;
  the evidence job verifies hashes and reads engine JSON. Without the extra, the rule-pack tests
  skip with an explicit reason.
- Semgrep CE and OpenGrep are **not** project dependencies. Do not install them into the project
  virtual environment: production runs them in the pinned `tool-semgrep` and `tool-opengrep`
  images. For local evaluation, provide the exact versions pinned in `rules/sei-cert/pack.json`
  (Semgrep 1.178.0 and OpenGrep 1.30.2) through `APPSEC_REVIEW_SEMGREP` and
  `APPSEC_REVIEW_OPENGREP`, or on `PATH`. For example, install Semgrep in its own virtual
  environment and download `opengrep_manylinux_x86` v1.30.2, verifying the SHA-256 recorded in
  `pack.json`. A version mismatch makes the engine tests skip; it is never treated as passing.

## Commands

```text
python -m appsec_review.rulepacks.sei_cert validate          # static checks, no engines
python -m appsec_review.rulepacks.sei_cert report            # regenerate rules/sei-cert/COVERAGE.md
python -m appsec_review.rulepacks.sei_cert lock              # re-hash every pack file
python -m appsec_review.rulepacks.sei_cert evaluate --output test/tmp/sei-cert-evaluation
python -m appsec_review.rulepacks.sei_cert verify-evaluation --output test/tmp/sei-cert-evaluation
python -m appsec_review.rulepacks.sei_cert report --evaluation test/tmp/sei-cert-evaluation
python -m pytest tests/test_sei_cert_rule_pack.py tests/test_cpp_cert_rules.py
```

Use `PYTHONPATH=src` when the package is not installed. `evaluate` runs both engines over every
fixture and, when `targets/appsec-multi-vuln` is checked out at the commit pinned in
`rules/sei-cert/multivuln.json`, over its C, C++, and Java files (`--skip-multivuln` omits it).
It exits nonzero on any validation error, engine gap, fixture mismatch, cross-engine disagreement,
or multivuln deviation. Keep evaluation output under `test/tmp/` or a run directory.

After any change to rules, fixtures, mappings, or `multivuln.json`, run `report` then `lock`
(the report embeds the rule-tree hash, and the lock covers the report), then `validate`.

## Adding or extending a rule

1. Read the official page (`source.path` in the mapping, under the pinned source revision) and decide
   which noncompliant forms are syntactic. Pick the narrowest shapes that are wrong without context.
2. Write the rule in `rules/<standard>/<cert>.yml` with the ID convention and full metadata. Restrict
   `cwe` to the official identifiers. Use only the portable syntax in `pack.json`, with no anchors
   and no autofix.
3. Add fixtures in `fixtures/<standard>/<cert>.<ext>` with `// cert: <kind> <rule-id>` annotations
   on the line before each case. Each rule needs `positive`, `variant`, `negative` or
   `safe-alternative`, and `near-miss` cases. Each excluded exception needs
   `exception:<EXCEPTION-ID>`, and each exception reported for review needs
   `unmodeled-exception:<EXCEPTION-ID>`. Record known misses as `known-false-negative` rather than
   omitting them. Prefer real shapes from multivuln; add microfixtures only for cases it lacks.
4. Update the mapping entry: `status` (`PARTIAL` unless the `SUPPORTED` definition holds), the
   implementation block (rule IDs for both engines, rule files, fixtures, coverage note), exception
   handling, and risks. Add `pack.json` `rule_files` entries for new files.
5. If the rule fires on multivuln, add the finding to `expected_findings`, and add compliant
   counterparts to `expected_exclusions`.
6. Run `report`, `lock`, `validate`, `evaluate`, and the tests. If the engines disagree, fix the
   rule. If a disagreement is inherent, mark the fixture line `engines=<engine>` and explain it in
   the mapping's `implementation.engine_differences`, naming the fixture; the validator rejects
   unexplained engine-specific expectations.

## Refreshing the official source

1. Clone `https://github.com/cmu-sei/secure-coding-standards` into a scratch directory (it is data;
   do not run its tooling), and record the commit.
2. `python -m appsec_review.rulepacks.sei_cert source-index --checkout <dir> --retrieved YYYY-MM-DD`.
3. Run `validate`. New, removed, or changed rules, URLs, CWE lists, exceptions, or page hashes show up
   as mapping errors. Resolve each against the page; never edit the generated index by hand.
4. Regenerate the report and lock, then evaluate.

The canonical URLs come from the repository's content paths and the published base path. Live page
resolution must be checked separately where network policy permits.

## Updating an engine

Change the version in `pack.json`, every rule's `min_engine_versions`, and the catalog image. For
OpenGrep, also update `containers/tools/opengrep` (asset URL, size, SHA-256). Run the full
evaluation under both engines before relying on new findings. The `tool-opengrep` image runs the
pre-extracted `opengrep.bin`; it does not use the self-extracting launcher, because the runtime
`/tmp` tmpfs is 128 MB and `noexec`.

## Troubleshooting

- *An engine reports a rule parse error*: the whole run fails (exit status 2). Fix the pattern. C++
  class or template patterns and parenthesized declarations are common causes.
- *Findings differ between engines*: compare the normalized findings in `evaluation.json` under
  `differential.only_in`. Check for YAML merge keys and parenthesized declaration patterns.
- *A fixture produces no results at all*: pass explicit files. Directory targets can fall under the
  engines' default ignore of `test/` and `tests/`.
- *OpenGrep aborts at start-up*: its `XDG_CONFIG_HOME` must exist and be writable.
