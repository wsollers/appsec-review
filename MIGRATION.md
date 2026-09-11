# Migration from the vendor-audit toolbox

Everything under `scripts/` and `images/audit-static/` was copied verbatim from the previous
toolbox on 2026-09-11. Nothing has been refactored yet. This file tracks what has to change
and why; each item becomes its own commit.

## Known breakage in the as-copied state

- **`images/audit-static/Dockerfile` `COPY` paths are wrong for this layout.** It expects
  `build_symbol_index.py`, `md_to_sarif.py`, `build_semantic_index.py`,
  `query_semantic_index.py`, `scrub_evidence.py`, `php_parse_coverage.py`, `run-sast-php.sh`,
  `run-dockerfile-lint.sh`, and `psalm.xml` at the build-context root. They now live in
  `scripts/` (and `psalm.xml` alongside the Dockerfile). Fix: change the `COPY` lines to
  `scripts/...` and build with the repo root as context, or move the scripts the image
  needs into `images/audit-static/`. Do not build until this is fixed.
- `scripts/Build-AuditToolbox.ps1` and `scripts/Invoke-VendorAuditPrePass.ps1` assume the
  old flat directory and the image tag from the old build. Treat them as reference for step
  semantics only until the Python orchestrator exists.

## Planned changes

| # | Change | Reason | Design ref |
|---|---|---|---|
| 1 | Rename image to `audit-static`; strip `clang`, `clang-tidy`, `clang-tools`, `cppcheck`, Joern into `audit-native` | Native tooling must not share a container with evidence writers | §2.2, §17 |
| 2 | Pin Joern to a release tag (currently `releases/latest`) | Joern is the Tier C fallback; its C frontend changes between releases | ADR-0001 |
| 3 | Pin Trivy and Syft to release versions (currently `curl \| sh` from `main`) | Reproducibility | header note in Dockerfile |
| 4 | Pin the remaining Go/pip floats (gosec, osv-scanner, govulncheck, tfsec, scc, kube-linter, bandit, pip-audit, checkov, lizard, code2flow) | Same | same |
| 5 | Replace `Invoke-VendorAuditPrePass.ps1` with `orchestrator/` (Python) | Linux-host requirement; PowerShell→docker.exe argv marshalling bit four steps | ADR-0002 |
| 6 | `build_symbol_index.py` and Joern parse move to `audit-native` | They read C/C++ semantics; keep `audit-static` language-agnostic | §17 |
| 7 | Split `audit-iac` (terraform, checkov, tfsec, kube-linter, hadolint) out of `audit-static` | Image-per-lane matches §17 | §17 |
| 8 | Record every scan's rule-pack versions (Semgrep `p/*`) into `run-manifest.json` | Rule packs float at scan time regardless of binary pin | §9 |

## Files not carried over

Engagement-specific documents (process reviews, CVE triage, session status, continuation
prompts, the vendor playbook prompts) stay in the engagement's own project. This repo is the
tool, not the engagement. `vendor-audit-playbook.html` was copied because it documents the
prompt structure the lane prompts will be derived from; it will be superseded by
`prompts/`.
