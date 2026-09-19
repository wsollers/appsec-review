# Config — Fuzz Target Triage

Added 2026-09-18. This lane does not run fuzzers. It identifies where fuzz testing would likely
provide benefit that exceeds its cost, so a human (or a later, explicitly-scoped fuzzing job) can
decide where to actually spend fuzzing budget instead of fuzzing everything or nothing. It also
formally produces "known coverage gaps" -- an input `07-red-team-adversarial/config.md` has always
listed as required but that nothing produced until this lane existed (see that lane's "Known
Coverage Gaps" section).

## Required Inputs

- component-purpose map (from `01-component-characterization`)
- DFD / trust boundaries (from `03-threat-model-dfd-stride`), if available
- native memory-safety findings and native bundle coverage (from `05-native-memory`)
- dependency/CVE/EOL evidence (from `06-cve-reachability`)
- native compile-feasibility tier (Tier A/B/C, ADR-0001) and per-TU `control-coverage.json`, if
  available
- existing test suite locations and any existing fuzz harnesses already in the target repo
- symbol/semantic indexes

## Required Outputs

Produce a ranked list of fuzz-target candidates. For each candidate, state both sides explicitly --
a candidate with only a benefit case or only a cost case is an incomplete entry:

- **Target**: component id, specific function(s)/entry point(s), and the untrusted-input path that
  reaches them (cite the DFD trust boundary it crosses, if one exists)
- **Benefit case** (why fuzzing here would likely find real bugs), grounded in evidence, not
  generic "parsing code is risky" reasoning -- e.g.: handles attacker-controlled byte-level input
  directly (decoders, deserializers, parsers, codec/compression code); has known-CWE-adjacent
  patterns (manual pointer arithmetic, manual length/bounds tracking, custom allocators); is in
  Tier B/C native-analysis coverage (i.e., IR/CSA/CodeQL substrate is weaker or absent here, per
  ADR-0001) so static tools are least likely to have already caught what fuzzing would find; has
  no or thin existing unit-test coverage of malformed/adversarial inputs; has a CVE history in this
  library or a structurally similar one (from 06's evidence)
- **Cost case** (what it would take to actually fuzz this), concretely: whether a harness can reuse
  an existing test/example entry point or needs new scaffolding; whether the function is reachable
  standalone or needs heavy setup/state to call meaningfully; build integration effort (does it fit
  the existing compile database, or does it need new build wiring); realistic seed-corpus
  availability (existing test vectors, sample files, structured-input needed); expected iteration
  speed (µs-scale pure-function fuzzing vs. slow end-to-end harnesses)
- **Recommendation**: `fuzz now` / `fuzz later` / `not worth it`, with the stated reasoning
  comparing benefit to cost -- not a bare label
- a "known coverage gaps" summary section, in the format `07-red-team-adversarial` expects to
  consume directly: the areas with the weakest current analysis coverage (static + dynamic +
  manual review combined), independent of whether they end up recommended for fuzzing -- this is
  the required-input handoff to lane 07, not just this lane's own fuzzing opinion

## Success Criteria

- every candidate has both a benefit case and a cost case, each citing real evidence (a DFD
  boundary, a coverage-tier fact, an existing CVE, an actual absence of test files -- not
  assertion)
- the ranking is defensible from the stated benefit/cost pairs, not just intuition
- the "known coverage gaps" output is present and usable by `07-red-team-adversarial` even if this
  lane recommends `not worth it` for every fuzz candidate in scope
- do not recommend fuzzing infrastructure choices (which fuzzer, sanitizer flags, corpus format) --
  that is out of scope for triage; a future fuzzing job makes that call once a target is selected
