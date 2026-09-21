# ADR-0004: Design document source of truth

Status: Superseded 2026-09-21 (decision below replaces the 2026-09-11 one)

## Decision (2026-09-21)

`docs/architecture/design-v3.md` in this repository is the single source of truth for the design.
It is edited by pull request like any other tracked document; the design-parity manifest anchors
to its numbered sections, so a section rename is a change that must update the manifest. Dated
narrative belongs in its §24 decision log or in an ADR, not in the numbered sections. The Google
Doc it was exported from on 2026-09-11 is frozen history and is not re-exported.

## Why the 2026-09-11 decision was replaced

The original decision kept the Google Doc canonical, with the markdown re-exported when the Doc
changed, until "this repo takes over editing". In practice the repo copy was edited in place from
2026-09-17 onward (the §4.1 mapping, the L12 note, §5.4, §5.5, §6.1) and later ADRs (0008, 0010)
record design-v3 wording follow-ups as repo edits. A re-export would have discarded those edits, so
the stated rule and the practised rule had diverged; this ADR records the practised one.

## Original decision (2026-09-11, superseded)

`docs/design-v3.md` is a markdown export of the Google Doc taken 2026-09-11. Until this repo takes
over editing, the Google Doc remains canonical and the markdown is re-exported when the doc changes.
Once ADR-0001..0003 decisions are folded into the doc, editing moves here and the Google Doc is
frozen with a pointer to this file.
