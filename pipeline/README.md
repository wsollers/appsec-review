# pipeline — engagement job → pregather → assemble → handoff → report

| Phase | Script | LLM? | Output |
|---|---|---|---|
| engagement job | `engagement_job.sh` | no | broad static evidence, native scratch, LLM input index, coverage ledger |
| static prepass | `scripts/Invoke-VendorAuditPrePass.sh` / `.ps1` | no | Semgrep, gitleaks, Trivy/config, SBOM/SCA, BinSkim, Joern, symbol/semantic indexes, `MANIFEST.json` |
| pregather | `pregather.sh` / `pregather.ps1` (twins; logic in container scripts) | no | compile DB, feasibility, IR, linked modules, ir-facts, CSA, CodeQL traced DB + regular C/C++ SARIF + mythos custom-memory SARIF, `pregather-manifest.json` |
| assemble | `assemble.py` (Python, one impl) | no | `bundle.json` + `bundle.md`: verified / unresolved / refuted with IR evidence and `needs` |
| correlate | `correlate_findings.py` | no | cross-tool clusters by nearby file/line across Semgrep, native SAST, CSA/native bundle, CodeQL, and SARIF tools |
| deep confirmation | `deep_confirm.py` | no | per-cluster source/native/CodeQL/IR support plus candidate callers/callees from the symbol index |
| retrieval plan | `generate_retrieval_plan.py` | no | risky files, semantic queries, CodeQL follow-up commands, and source searches |
| handoff | (prompts/, orchestrator — next) | yes | lane runs over the bundle only |
| report | (audit-report image — next) | no | executive + technical |

`engagement_job.sh` is the high-level runner for real engagements. It runs the existing broad
static pre-pass (Semgrep, gitleaks, Trivy/config, BinSkim, SBOM/SCA, search/indexing, etc.),
then the native `pregather` lane, then `assemble.py`, then writes `llm/ENGAGEMENT_LLM_INPUT.md`
and `llm/coverage-ledger.json`. It also writes `llm/correlated-findings.json/.md`, a deterministic
cross-tool grouping of Semgrep, clang-tidy, cppcheck, SARIF tools, regular CodeQL,
custom mythos CodeQL memory queries, and CSA/native bundle results by nearby file/line.

`llm/deep-confirmation.json/.md` is the deeper confirmation layer. For every correlated cluster it
records the evidence substrates that saw the issue (source SAST, native/CSA bundle, CodeQL), whether
IR facts exist near the source location, the likely enclosing symbol, nearby callees, and candidate
callers from the tree-sitter symbol index. Candidate callers/callees are navigation hints, not
semantic reachability proof; use CodeQL, Joern, source review, or reviewer analysis before making a
final reachability claim.

`llm/retrieval-plan.json/.md` then points the LLM at risky files, symbol-index candidate callers,
semantic-index queries, CodeQL follow-up commands, and source-search patterns. The LLM should start
from those files, not from raw source.

Every top-level step records an exit code, duration, and log path in `job-manifest.jsonl`.
The final `job_status.py` pass writes `job-status.json/.md` and exits non-zero when an
enabled phase failed or a required artifact is missing. That means the job can keep gathering
partial evidence after CodeQL/Semgrep/etc. failures, while still ending with an explicit
degraded status instead of a quiet success.

The static prepass has two host runners over the same Docker toolbox image:
`scripts/Invoke-VendorAuditPrePass.sh` for bash/Linux/WSL and
`scripts/Invoke-VendorAuditPrePass.ps1` for PowerShell/Windows. `engagement_job.sh`
defaults to `--static-runner auto`, which prefers the bash runner. Use
`--static-runner powershell` only when you intentionally want the PowerShell path.

Tools live in the images (`images/*/Dockerfile`) — that is the catalog; digests are recorded in
every manifest. Run from WSL2 on Windows with sources on the WSL filesystem (fast); from a
Linux host identically. Host scripts have bash/PowerShell twins; anything with logic is Python.

Native Linux targets (EASTL, yquake2, Unreal): `--compile-db` with the cmake/bear/UBT
compile_commands.json, no `--msvc`; the gate and CodeQL replay detect the GNU driver.
Windows targets: converter + `--msvc`.
