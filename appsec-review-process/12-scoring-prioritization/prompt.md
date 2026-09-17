# Prompt — Scoring And Prioritization (L8)

Score only verified findings and explicitly unresolved risks that `09-independent-verification`
(and, where run, `11-remediation-proposal`'s retest) has already disposed. Do not re-litigate
whether a finding is real — that decision belongs to verification, not to this lane.

For each finding:

1. Derive as much of the CVSS 4.0 vector as possible directly from verified-fact attributes, per
   design-v3.md §14's mapping (e.g. trust boundary crossed → Attack Vector, authentication evidence
   → Privileges Required/User Interaction, blast-radius evidence → the Vulnerable/Subsequent System
   impact metrics). Cite the specific verified fact behind each derived metric.
2. For any remaining metric with no direct verified-fact mapping, assign it explicitly and mark it
   `LLM-assigned` rather than `derived` — never blend the two without saying which is which.
3. Record EPSS and CISA KEV status where applicable; state plainly when neither applies rather than
   omitting the field.
4. Assign a priority rank across all scored findings, and state the rationale (severity alone is not
   sufficient — factor in exposure, confidence, and remediation cost/availability where known).

Output one row per finding: finding ID, CVSS 4.0 vector string, per-metric derived-vs-LLM-assigned
breakdown, EPSS/KEV annotation, confidence (carried from verification, not re-derived), priority
rank, and rationale. This output is what `10-synthesis-report` consumes directly — do not produce a
narrative report here, that's synthesis's job.
