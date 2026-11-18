# Job correctness audit results

This directory archives the completed 47-job source audit from 2026-11-18.

- [Cumulative findings, per-job index, validation results and limitations](job-audit-cumulative.md)
- [Original evidence bundle: cumulative report and all 47 job reports](job-audit-evidence-0e54e40b8.zip)

Reports 1-3 cover `3d1dc3d7304b829bd9750e359cb417661af54b9a`; reports 4-47 cover
`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`. They are historical audit records, not
certification of later code or of live review results. Findings are attributed to the
individual auditors, with known issues and cross-job confirmations distinguished.

The Markdown copies use repository-standard LF line endings; three trailing
Markdown hard-break whitespace sequences in the code-graph report were removed.
The ZIP preserves the original report bytes, including their original formatting. Its SHA-256 is
`1db97484b831aeeacf48af8d7b8ed801de3cf8a4e62e48fa81d9d03cb8b8326c`.

No runtime implementation changes or live validations were performed as part of this
audit. Detailed commands, failures, reproductions and coverage gaps remain in the
individual reports.
