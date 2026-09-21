# 03 -- Make design-v3.md a stable authority again; rewrite ADR-0004

Goal: `docs/architecture/design-v3.md` stays the design authority (the parity manifest anchors to
its sections), but its dated appendices are session logs that now contradict the code. Separate
the two, and record that the repo copy -- not the Google Doc -- is canonical.

## Inputs
- `docs/architecture/design-v3.md` §2.2.1, §4.1, §4.2, §4.2.1, §5.5, §9 (the dated/contradicted parts).
- `docs/decisions/ADR-0004-design-doc-source-of-truth.md`; `README.md` line ~9 (repeats its claim).
- `appsec-review-process/design-parity-manifest.json` `design_authority` and section anchors
  (do not break an anchor the manifest uses).

## Steps
1. Rewrite ADR-0004 in place: status `Superseded 2026-09-21`; new decision: the repo file is the
   single source of truth, edited by PR like any other doc; the Google Doc is frozen as history.
   Fix `README.md`'s sentence to match.
2. In design-v3.md, move each dated appendix (§2.2.1, §4.1 table, §4.2/§4.2.1, §5.5) out of the
   numbered design into a short trailing "Decision log (historical)" section or into the ADR that
   decided it (§5.5 -> pools/rendezvous docs already carry the decision; §4.2 -> ADR-0010).
   Replace contradicted statements ("eleven lanes", "pools not yet implemented",
   `scripts/scrub_evidence.py`, `claude/TODO.md` link) with a pointer to the current doc.
3. Run `python -B appsec-review-process/validate_design_parity.py` -- it must still resolve every
   section anchor.

## Done when
No sentence in design-v3.md's numbered sections is contradicted by a current doc; ADR-0004 and
README agree; parity validator passes.

## Touches
`docs/architecture/design-v3.md`, `docs/decisions/ADR-0004-*.md`, `README.md`.
