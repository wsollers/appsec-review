# Subprompts — Independent Verification

## Threat Finding Verification

Verify one DFD/STRIDE or ASVS finding against source.

## Native Finding Verification

Verify one memory-safety finding against IR/source/tool artifacts.

## Focused Test Case Verification

Write and run the smallest practical test that confirms or refutes one specific source-level
hypothesis. Prefer ignored scratch locations over modifying target source.

For native C/C++ findings, run the authoritative test in the Docker/native image and compile
database environment that produced the engagement evidence (see environment.md's "Where the
authoritative container and toolchain actually are" for the image name, wrapper script, and
compiler path -- do not rediscover these by trial each dispatch). Prefer WSL + Docker for large
targets and copy/sync artifacts back into the repo-local `scratch/` and `targets/` layout. Host
compiler runs, including MinGW/MSVC/ad hoc Clang, are optional smoke checks only and must be
labeled `non-authoritative`.

### Reusing a previously compiled test binary (added 2026-09-18)

Rebuilding a fresh authoritative binary for every single claim is noisy and burns Docker/compile
time the budget model doesn't account for. Reuse an existing compiled probe for this exact test
case instead of rebuilding, subject to one rule:

**A previously compiled binary is stale, and must be rebuilt, if and only if any file that feeds
its build (the test harness source, and every target source/header file the build command actually
compiled or included) has a modification time strictly newer than the binary's own modification
time.** If every input's mtime is at or before the binary's mtime, the binary is current -- reuse
it and do not spend a rebuild on it. This is a real check, not a guess: read the actual mtimes
(e.g. `stat`/`Get-Item` on the binary and on each input path recorded in the testcase's own build
command) and record what you compared, not just "binary looked recent."

This mirrors the project's broader "never infer clean from an unscanned artifact" discipline in the
opposite direction: don't infer *stale* either, without checking. A real prior incident (session
8, `RT-FC04-002`) is the reason this needs a real check rather than blanket "always rebuild" or
blanket "always trust an existing binary": a stale binary in
`scratch/eastl-engagement/verification/rt-fc04-002/` gave the opposite verdict from a fresh build
against current source, because it predated a source change (or was a pre-patch artifact from a
different exercise) -- silently trusting it without a real mtime check would have produced a false
verdict. Silently rebuilding every time avoids that failure mode but wastes real time/cost once a
lane has many test cases. The mtime check gets both: cheap reuse when nothing changed, a real
rebuild when something did.

Record in the test-result output: which binary (if any) was considered for reuse, the mtimes
compared, and whether it was reused or rebuilt and why -- so a future lane/reviewer doesn't have to
re-derive the same staleness judgment blind.

The test must report the actual observed behavior, expected safe behavior, compile/run command,
container or compiler environment, exit code, and whether the claim is verified, refuted, or still
unresolved.

## Control Presence Verification

Confirm or refute the presence of a specific security control.

## Kill Chain Verification (added 2026-09-18)

Verify a multi-step kill-chain claim from `07-red-team-adversarial`'s `kill-chain` mode (see that
lane's config.md). A kill chain is a claim that several individually weak or unremarkable
weaknesses combine into an exploitable path -- do not verify it the way a single-step claim is
verified.

- Independently verify **each link in the chain separately**, using the same evidence discipline as
  any other claim (deterministic artifacts first, then source/config, then a focused test where
  practical). A link inherits no credibility from the chain narrative around it.
- For a tainted-data kill chain specifically: independently confirm the taint actually reaches each
  intermediate hop unmodified/unsanitized (or identify exactly where and how it is transformed),
  not just that the source and sink both exist. "Both ends are real" is not evidence the path
  between them is real.
- The chain's overall verdict is **not** an average of its links. Render it as:
  - `verified` only if every link is independently confirmed AND the composition itself is
    confirmed (i.e. an actual or faithfully simulated end-to-end trace was exercised, not just
    each link nodded through in isolation) -- a set of independently-true links does not by itself
    prove the composed path works, since a mitigation invisible at the single-link level (state
    reset between components, a boundary check that only fires on the full combined input shape,
    etc.) can still break the chain.
  - `refuted` if any single link is refuted -- name which link and why; a broken link breaks the
    whole chain regardless of how plausible the rest is.
  - `unresolved` if any link could not be checked within budget, or the composition itself could
    not be exercised even though every individual link held up.
- Report per-link verdicts in a table (link id, component, claim, verdict, evidence) plus one
  overall chain verdict with the reasoning above made explicit, not just the label.
