# Config — Synthesis And Report

## Required Inputs

- verified findings
- unresolved risks
- coverage ledger
- component map
- threat model
- ASVS/MASVS assessment
- red/blue/verifier outputs

## Required Outputs

- final findings table
- merged/deduplicated finding set
- limitations
- go/no-go recommendation
- remediation plan
- report draft

## Report build (LaTeX -> PDF)

The delivered report is built as a PDF from LaTeX source, in `images/audit-report`
(`docker build -t audit-report:local images/audit-report`) — a pinned TeX Live image adapted
from the LRA governance project's standalone LaTeX build container, with `pandoc` added so this
lane's markdown report draft and findings tables can be converted into LaTeX section source
instead of retyped by hand.

**Open decision, not yet made:** the document class, style, and required section structure for
the LaTeX report. See the project TODO ("Decide on format and styleguide for LaTeX reporting of
results and sections needed"). Until that decision is made, treat "report draft" above as the
markdown/text output this lane already produces — do not invent a LaTeX section structure ad hoc
per run.
