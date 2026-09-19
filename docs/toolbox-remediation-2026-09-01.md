# Toolbox remediation — run of 2026-09-01

Remediates the findings in `claude/process-review-2026-09-01-findings.md` (fable's adversarial review of the audit pipeline). Applied directly against the real 11+ toolbox files once they were attached to the project (`claude/toolbox/*`), not against the prose description — so these are code fixes with real line context, not guesses.

## Fixed this pass

**S1-1 (High) / S1-2 (Med) — mobsfscan `--type auto` silently drops iOS coverage.**
`Invoke-VendorAuditPrePass.ps1`: the single `sast-mobile` step is replaced with `sast-mobile-android` and `sast-mobile-ios`, each running mobsfscan with an explicit `--type`, never `auto`. Each also writes a `*-coverage.txt` file recording how many matching source files were found under `/workspace` and warns explicitly when a SARIF should be treated as NOT-SCANNED rather than clean (the S1-2 zero-file/exit-0 case).

**E4-1 (High) — evidence directory leaks raw secret values outside gitleaks.**
New `scrub_evidence.py` (copied into the image, run by a new `evidence-scrub` step placed last in the pipeline) walks the whole `/evidence` tree and redacts high-entropy substrings from every JSON/SARIF/text file, writing a clean copy to `/evidence/_shareable`. Only that subdirectory is meant to leave the machine; the rest of `/evidence` — including gitleaks' own already-redacted output — stays internal-only. Binary artifacts (Joern's `cpg.bin`, the semantic-index vector store) are excluded from the shareable copy rather than scanned, and listed in `EXCLUDED_FROM_HANDOFF.txt`.

**S6-1 (High) — PHPStan/Psalm fail-open on PHP 5-era parse errors; "0 findings" can mean "never parsed."**
New `php_parse_coverage.py` (new `sast-php-parse-coverage` step) runs `php -l` independently against every `.php` file and records `NOT_ANALYZED` for anything that doesn't parse, regardless of what Psalm/PHPStan/PHPCS report. `sast-php`'s step Note now explicitly says it's secondary; `sast-multi-semgrep`'s Note says it's the primary PHP pass (Semgrep's tree-sitter parser was verified during the review to keep matching sinks in files that don't fully parse).

**S1-3 (Low, accuracy) — `p/security-audit` reasoned about but never shipped.**
Added `--config=p/security-audit` to the `sast-multi-semgrep` step's Cmd.

**S7-1 (High) — no automated hunt for binary credential stores.**
New `secrets-binary` step: a `find`-by-extension pass for `.p12/.pfx/.jks/.keystore` plus a grep for PEM private-key headers, writing `secrets/binary-cert-inventory.txt`. This is an inventory pass, not a scanner — anything it lists still needs the same manual validity/rotation review the original `.p12` finding got.

**E4-2 (Med) — `inspect-secrets.ps1 -ShowValue` had no guard against non-interactive/redirected use.**
Added a guard immediately after `param()`: `-ShowValue` now throws unless `[Environment]::UserInteractive` is true and `[Console]::IsOutputRedirected` is false (treating an inability to check the latter as "redirected," i.e. refuse).

**Version pinning (priority fix #5) — partial.**
Pinned `gitleaks` to `v8.30.1` and `mobsfscan` to `1.0.0` via new Dockerfile ARGs — both versions were live-verified against their real registries during the adversarial review. The remaining `@latest` Go installs (gosec, osv-scanner, govulncheck, callgraph, digraph, tfsec, scc, kube-linter) and the Trivy/Syft install-script pulls are **still unpinned** — this session had no GitHub API access to verify current versions for them (see "Still open" below). The Dockerfile now carries an explicit TODO block with the exact command to run per tool before the next real build.

**`Build-AuditToolbox.ps1` preflight check updated** to also require `scrub_evidence.py` and `php_parse_coverage.py` next to the Dockerfile (it previously only checked the original 4 COPY'd scripts) — otherwise this would fail late and confusingly inside `docker build`'s COPY step instead of with a clear preflight error.

## Verified while remediating (not previously checkable — the real files weren't attached yet)

**Step 2 (silent-failure patterns) — now confirmed against real code, not just reasoned about.**
Every step using `AllowNonZeroExit = $true` combined with a shell-level `|| true` (`sast-php`, `iac`, `binskim`, `iac-k8s`, `dockerfile-lint`, `docker-base-images`, and — via `&&`-chain rather than `|| true` — `joern-parse`) has the exact property the review predicted: a genuine tool crash and "ran, found nothing" both land as `treatedOk: true` in `MANIFEST.json`, indistinguishable without opening the matching `.stderr.log` by hand. This is now documented explicitly in the script's own `.DESCRIPTION` block and in `joern-parse`'s Note (the most consequential instance, since a failed `joern-parse` silently means "no CPG" for the rest of the C++ semantic-search phase). **Not structurally fixed** in this pass — that would mean per-tool output-sanity checks (e.g., "does binskim.sarif exist and contain a `runs` array," "does `/evidence/joern/README.txt` exist," independent of exit code), which is a larger change than this remediation round covers. Tracked as an open item below.

## Still open (need the real repo or the real Docker daemon — out of reach from here)

- **S5 (exclusion re-derivation)** — UGUI unmodified-copy diff vs. upstream, stale-Unity-project reachability, exclude-pattern over-breadth. Needs `F:\Barracuda\fsh-client` itself; `fsh-client-exclude.txt` was reviewed but not re-derived against the real tree.
- **S6-3** — real-vendor-PHP parse rate. `php_parse_coverage.py` is ready to produce this the moment it's run against the real `Server/www/gdip` / `Server/lib`.
- **Docker image ENTRYPOINT/CMD verification** — no live daemon here; `docker inspect` each baked/`docker run` image (especially `scancode-toolkit:local`) before the next real run.
- **Full version-pinning** — gosec/osv-scanner/govulncheck/callgraph/digraph/tfsec/scc/kube-linter/Trivy/Syft still float; see the Dockerfile's version-pinning TODO block.
- **Silent-failure structural fix** — per-step output-sanity assertions (file exists, has plausible shape) independent of exit code, for the steps listed under "Step 2" above. Documented as a known gap, not yet built.
- **`tfsec` is upstream-deprecated in favor of Trivy** — left running (it's free, already wired up), but flagged in the `iac` step's Note so it isn't relied on for new coverage going forward.

## Next run

Re-run `Invoke-VendorAuditPrePass.ps1` against `fsh-infra` first (cheap, already validated end-to-end) to confirm the new/changed steps (`sast-mobile-android`, `sast-mobile-ios`, `secrets-binary`, `sast-php-parse-coverage`, `evidence-scrub`) execute cleanly before relying on them for `fsh-client`/`fsh-server`. Rebuild the image first (`Build-AuditToolbox.ps1 -NoCache` recommended, since several `RUN` layers changed) — the two new Python scripts must exist next to the Dockerfile or the build will fail at the updated preflight check.

## 2026-09-01 (later same day) — first real test-run against `C:\Barracuda`, three fixes

The user began testing the process for real on their machine, working directly in `C:\Barracuda` (all toolbox files, scripts, and the `fsh-client`/`fsh-infra`/`fsh-server` folders sit flat in that one directory — earlier guidance in this doc that assumed a `F:\Barracuda\toolbox` subfolder layout was wrong; there is no separate `toolbox` subdirectory).

**Build failure — Psalm/PHP version mismatch.**
`Build-AuditToolbox.ps1 -NoCache` failed at the composer step: `vimeo/psalm:6.16.1 requires php ~8.1.31 || ~8.2.27 || ~8.3.16 || ~8.4.3 || ~8.5.0` but Ubuntu 22.04's apt-archive `php-cli` package resolved to `8.1.2` inside the build (the jammy release-pocket version, well behind what the composer.json platform check wants). Since Psalm/PHPStan/PHPCS are already documented above (S6-1) as the *secondary* PHP pass — Semgrep's `p/php` + `p/security-audit` is primary — the fix shipped was pragmatic rather than a full PHP-toolchain upgrade: a new `fix-composer-platform.ps1` patch script using an anchor-based `.NET File` read/write pattern adds `--ignore-platform-reqs` to the `composer global require` line. Real risk this doesn't cover: if Psalm actually crashes at *analysis* time (not just install time) under 8.1.2, that's a genuine signal worth recording, not a false alarm to dismiss. The alternative not taken (bigger change, real version guarantee instead of a bypass): add the `ondrej/php` PPA and move the whole PHP toolchain (php-cli, php-mbstring, php-xml, php-curl) to 8.3 together.

**New: `summarize_evidence.py` — deterministic markdown rollup of one evidence run.**
The user asked whether there's a process to generate a summary after a scan. There wasn't one for raw tool evidence — the playbook's Phase 6 (consolidation table) and Phase 8A (executive summary) both assume the LLM-driven Phase 1-5 findings pipeline has already run first. `summarize_evidence.py` (pure stdlib, same "run anywhere, no Docker" philosophy as `profile_repo.py`) fills the gap one level down: it reads `MANIFEST.json` plus each tool's own evidence file directly and writes a markdown report with (1) a run/status table that explicitly flags the steps already known to be silent-failure-prone (per the `|| true` finding above) regardless of `treatedOk`, (2) a mechanical "Critical / needs immediate attention" section built from severity fields the tools already emit (gitleaks hit counts, CRITICAL/HIGH/ERROR-level SAST findings, binary cert/key inventory hits, PHP parse-coverage gaps, floating Docker base images, zero-file mobile-scan warnings), and (3) a full per-tool raw-count table. Each per-tool parser is wrapped so an unexpected schema (a tool version bump, a changed CLI flag) degrades to "could not parse — check by hand" instead of crashing the whole summary — same discipline as `build_symbol_index.py`'s per-file error handling. Explicitly documented as NOT a replacement for the real triaged findings pipeline: it's untriaged, un-deduplicated, and can't see business-logic issues (auth bypass, client-authoritative trust decisions) at all, only what the raw tools already flag by severity.

Usage: `python summarize_evidence.py <EvidencePath> -o <EvidencePath>\SUMMARY.md --repo-label <name>`.

**Corrected file layout note:** every command line handed to the user for this engagement should now assume `C:\Barracuda` as the flat working directory containing the Dockerfile, every `.ps1`/`.py` script, and the `fsh-client`/`fsh-infra`/`fsh-server` checkouts side by side — not a `toolbox` subfolder.

## Next run (updated)

1. `cd C:\Barracuda`
2. `.\fix-composer-platform.ps1` (one-time, only needed if not already applied)
3. `.\Build-AuditToolbox.ps1 -NoCache`
4. `.\Invoke-VendorAuditPrePass.ps1 -RepoPath .\fsh-infra -EvidencePath .\evidence-infra` (cheap, already validated end-to-end; confirms the new/changed steps run cleanly before `fsh-client`/`fsh-server`)
5. `python summarize_evidence.py .\evidence-infra -o .\evidence-infra\SUMMARY.md --repo-label fsh-infra`
6. `.\inspect-secrets.ps1 -Summary` to triage the Terraform-state secrets findings
7. Once `fsh-infra` looks clean end-to-end, repeat steps 4-5 against `fsh-server` (`-RepoPath .\fsh-server -EvidencePath .\evidence-server`, `--repo-label fsh-server`) and, using `fsh-client-exclude.txt`, against `fsh-client`.
