# Brief F: light PoC + proposed fix lane (branch `poc-fix`)

Goal: for every finding that is verified, scored Critical AND reachable, produce (1) a light proof-of-concept as STATIC TEXT that answers "how does it happen", and (2) a proposed fix. This is a defensive review feature.

## Binding guardrails (William)
- Static text only. The pipeline NEVER executes the PoC.
- The PoC should just trigger the crash or overflow (or show the faulty control flow). NOTHING HOSTILE: no shellcode, no persistence, no exfiltration, no credentials, no network callbacks, no destructive actions, no obfuscation.
- Limited to the target under review; labelled `UNVALIDATED`; cites the exact lines it relies on (file, line range, source hash); paired with a proposed fix (`PATCH_PROPOSED_UNVALIDATED` style, as lane 11 does).
- Not a full harness: a minimal snippet (an input, a call, or a short test) plus a plain-language explanation of the code path from source to sink.
- Python enforces: eligibility (verified + Critical + REACHABLE), size caps, a denylist scan of the PoC text (reject and record a gap if it contains process spawn/exec, sockets, file writes outside a temp name, encoded blobs, shell metacharacters piped to interpreters), citation hash checks; the model never supplies ids, hashes or file paths that do not exist in the finding.

## Steps
1. Read lane 11 (`11-remediation-proposal`), `ADR-0020` (report enrichment), `reachability.py`, and how synthesis consumes findings.
2. New lane after 12 (name `12b-poc-and-fix`; check the naming convention and confirm in the report): persona + reply schema (poc_text, explanation, trigger_condition, fix_diff/rationale, cited_lines), `poc_fix_derive.py` (ADR-0013), eligibility selector, denylist scanner, and merge into per-finding records.
3. Report: `10-synthesis-report` renders the PoC/fix under the finding, clearly labelled as unvalidated static text (optional edge; absence is a gap).
4. Job wiring: job graph, registry, contracts, parity, Dagster op; catalogs regenerated.
5. Tests: eligibility, each denylist rule with a hostile-looking fixture rejected, citation mismatch rejected, benign overflow PoC accepted, fake persona results only.
6. Docs + TODO section `F-poc-fix`.

## You own
`poc_fix_*.py`, their schemas/tests/persona files, job wiring for the new lane.
## Do not touch
`attack_chain_*`, `dep_reachability*`, `osv_*`, `owasp_*`.
