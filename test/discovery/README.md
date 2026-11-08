# Build discovery cases

One folder per case: `cases/<NNN>-<slug>/tree/` is the folder under test (small, committed, no
binaries, no network inputs) and `cases/<NNN>-<slug>/expect.json` is its contract
(`appsec-review/discovery-case/1`, schema in `docs/schemas/discovery-case.schema.json`). The program,
the contract and the case matrix are in `docs/plans/build-discovery-test-program-2026-11-08.md`.

A case asserts the **total assignment** of every path in its tree — `evidence_of:<unit>[#<build
point>]`, `context:<unit>`, `source_only:<language>`, `orphaned:<reason>`, `inert`,
`excluded:<policy>` — plus the units (root, build system, family, profile, markers, build points,
facts), the look-alikes that must *not* be units (with the reason and the role they have instead),
the exact orphan list when it matters, and determinism. A check the runtime does not meet yet is
listed under `pending` with the registry sub-item that lands it; the runner treats it as a strict
xfail (it must fail, and the entry must be removed when it passes).

Run:

```
python -m pytest tests/test_discovery_cases.py -q                     # every check of every case
python -m appsec_review.acceptance.discovery check cases/001-cmake-targets
python -m appsec_review.acceptance.discovery assign <any folder>      # what discovery says about a real target
python -m appsec_review.acceptance.discovery new cases/0NN-new-case   # draft expect.json from current behaviour — correct it before committing
```

Adding a case: pick the matrix cell (plan §4), build the smallest tree that has the trigger, write
`expect.json` from the contract (not from the output), run `check`, and put every disagreement
either in `pending` with its sub-item or fix the code. Negative cases need the trigger present and
the conclusion absent. Numbers are allocated sequentially; slugs name the shape, not the target.
