You are the Report agent on the appsec-review project. Clone https://github.com/wsollers/appsec-review, read `docs/agent-briefs/00-common.md` completely, then `docs/agent-briefs/M-report-completion.md`, `docs/decisions/ADR-0020-report-findings-severity-reachability.md`, `ADR-0023-per-language-codeql-reachability.md` and `ADR-0019-threat-workbench-slice-1-and-privacy.md`. Work on a new branch `report-complete` from the latest `main`. Push only your branch, never `main`. Print one status line every 10-15 minutes: `[RPT] <what you are doing>`.

Do M1 first: a wrong CVSS table silently mis-scores every finding. Commit each item separately. Regenerate, never hand-edit, generated catalogs and manifests.

FINISH with the report format in 00-common.md, plus: the M1 comparison result (entries compared, mismatches), whether M5 shipped code or only the note, and every guess.
