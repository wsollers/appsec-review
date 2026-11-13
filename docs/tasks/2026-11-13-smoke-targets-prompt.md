# Smoke targets: one minimal buildable repository per language, plus the guide

Session prompt. Start a fresh session on `wsollers/appsec-review` with this file, `AGENTS.md`,
`.claude/skills/multi-session-coordination/SKILL.md` and `docs/operations/test-targets.md` read in
that order. This document is the brief; it decides nothing that `AGENTS.md` decides. Stage 0
registered the T ids; the parent entry is T-134 (T-135 to T-145 are its parts).

## Goal

Create nine GitHub repositories under the `wsollers` account, `appsec-review-smoke-<language>`
for `cpp`, `java`, `javascript`, `python`, `ruby`, `go`, `csharp`, `rust` and `php`, and one
answer-key repository `appsec-review-smoke-guide`. Each smoke repository is a single build unit
of under four hundred lines that builds offline in its pinned build image in under a minute. It
carries a labelled inventory of planted items in four classes: **true positives** (several code
vulnerabilities with a source-to-sink path, and several vulnerable dependencies), **fixed**
items (a vulnerability and a dependency that were present in an earlier commit and are fixed at
the tagged head, so history analysis has something to find), **false positives** (code a
pattern scanner flags that a code-intelligence fact refutes: a dominating guard, a dominating
sanitizer, a constant operand, an unreachable function), and the known source, sink, sanitizer,
guard and dispatch cases the code-intelligence jobs must export. Each repository has a scripted,
backdated git history so source-history analysis sees a past. Clone the nine under `targets/`,
prove each builds with no network in its profile image, and document them in
`docs/operations/test-targets.md`.

The purpose is attribution: a review walk on a smoke target has one correct answer at topology,
discovery, build, SBOM, scanning, code intelligence, history and triage, so a failure anywhere
is a defect of the pipeline, not of the target. The false positives are the measure of whether
code intelligence corroborates and squelches rather than only adds. Smoke targets say nothing
about recall or scale; Freeciv and `appsec-multi-vuln` keep that role.

## Authority and constraints

1. `AGENTS.md` applies unchanged. Follow the multi-session skill before changes to this
   repository; the smoke repositories are new and uncontended.
2. The answer key is never cloned under `targets/` or anywhere a review can see it, and a job
   session never reads it to steer a run (walk charter, `test-targets.md`). Clone the guide to a
   sibling directory such as `~/projects/appsec-review-smoke-guide`.
3. Do not run a review, an integration test or a live test. "Build" in this brief means a
   `docker run --network none` of the language's build commands in its pinned build image as
   the non-root runtime user, nothing more. Running `appsec-review start` on a smoke target is
   the user's call, afterwards.
4. Do not edit `appsec-review.toml`, `containers/catalog.toml` or any image. If a build image
   lacks something a smoke target needs, change the target, not the image, and record the
   limit in the guide.
5. Repositories are public, like `appsec-multi-vuln`, unless the user says otherwise before
   Stage 2. Each carries a `LICENSE` (MIT) and a `README.md` that says it is a deliberately
   vulnerable smoke target and must not be deployed.
6. Commit in this repository only `docs/TODO.md`, `docs/operations/test-targets.md` and
   `targets/.gitignore` if a pattern is needed; do not push unless the user asks. Pushing the
   new repositories themselves is part of creating them.

## Stage 0: register the work

Fetch `origin/main`, read `docs/TODO.md` for the next free id (other sessions add entries daily),
and add: one parent entry for the program, one entry per language repository (nine), one for the
guide, one for the `test-targets.md` rows and clone lines. Each names its repository, its build
image and profile from `appsec-review.toml` `[jobs.job_project_build.settings.profiles.*]`, its
planted advisory, and its acceptance check. Run `tests/test_todo_registry.py`, commit
`docs/TODO.md` alone.

## Stage 1: the source

Start every smoke repository from the matching synthetic fixture source in this repository,
`tests/fixtures/graph/codeql_export/<language>-synthetic/source/` (C/C++ uses
`tests/fixtures/graph/codeql_export/synthetic/source/synthetic.cpp` plus the CMake layout of
`tests/fixtures/build_toolchains/native`; PHP has no fixture and is written new to the same
pattern). Those sources already contain, per language: a remote source reaching an SQL, command,
path, SSRF and deserialization sink; an argv and an environment source; one sanitized path; one
dominating and one non-dominating guard; virtual or interface dispatch; an unresolved indirect
call; a cross-function flow summary. `expected-facts.json` beside each is the code-intelligence
answer key and goes into the guide unchanged. Do not alter a case; add only what the build
manifest needs (an entry point, a project file) and keep the line numbers the expectations cite
stable, or regenerate the expectations against the moved lines and say so in the guide.

The JavaScript repository keeps one TypeScript file so the Node-dependent extractor path runs.
Swift is out of scope until a macOS executor exists.

### The planted inventory

On top of the fixture cases, each repository plants the following, each item under its own
function so the answer key can cite one span, and each labelled in a per-repository
`PLANTED.md` that the guide copies (the target may describe itself; the guide is the key):

- **True positives, code** (at least five per language): the fixture's remote-to-sink paths
  (SQL, command, path, SSRF, deserialization) plus two the fixture lacks where the language's
  CodeQL models support them, chosen from log injection, open redirect, XXE, regex injection,
  unsafe reflection, format string (C/C++), integer overflow into an allocation (C/C++, Rust, Go,
  C#), use after free (C/C++). Every path has an attacker-reachable source and an unguarded,
  unsanitized sink.
- **True positives, dependencies** (three per language): the one in the Stage 2 table plus two
  more from the same ecosystem with clean OSV records, one of them transitive where the
  ecosystem's lockfile records transitive pins.
- **Fixed, code** (two per language): a vulnerability introduced in an early commit and removed
  in a later commit whose message names it (for example "Fix command injection in
  run_tool (CWE-78)"), and one fixed by adding a sanitizer call rather than by removing the
  sink, so the fixed state is itself a guard or sanitizer fact.
- **Fixed, dependency** (one per language): a package pinned at a vulnerable version in an early
  commit and upgraded to the fixed version in a later commit, so the head lockfile is clean for
  it and only history shows the exposure.
- **False positives** (at least four per language), each a construct the Semgrep rules under
  `rules/semgrep/` or the language's common SAST rules flag, refuted by an exportable fact:
  a sink whose operand is a compile-time constant (`sql_query` with a literal string); a sink
  under a dominating guard that bounds the operand (`memcpy` with `n < sizeof(dst)` on the
  dominating edge, `strings.Repeat` under a bounded count); a sink reached only through a
  dominating sanitizer (`path.basename`, `realpath`, `getCanonicalPath`, `filepath.Clean`);
  a sink in a function with no callers and no entry point (dead code, so no `dataflow_path`
  reaches it); and, for C/C++, a banned function from `rules/semgrep/banned-functions.yml`
  used with a provably bounded length. Each false positive names, in `PLANTED.md`, the fact
  family that refutes it (`guard_fact`, `path_sanitizers`, `range_fact`, absence of
  `dataflow_path`).
- **One high-complexity function** per language, to trigger the complexity path of
  `job_review_prioritization`: cyclomatic complexity above 15 (the configured
  `cyclomatic_thresholds` are `[10, 15]`; `complexity.py` counts branches, loops, boolean
  operators and, where the language has them, error-propagation points), under about sixty
  lines so it is still readable, holding one of the code true positives so prioritization has
  a reason to rank it, and living in the file the history churns most, since the complexity
  pass runs over the highest-churn rank-eligible files. `PLANTED.md` records the intended
  cyclomatic count and the answer key expects the file in the top prioritization rank and the
  `cyclomatic_high_risk_share` metric above zero.

Keep the fixture cases' line numbers stable or regenerate `expected-facts.json` against the
moved lines and say so in the guide.

### The history

Each repository's history is produced by a committed, idempotent script `tools/make-history.sh`
that builds the commit graph from scratch on an empty branch, so the history is reproducible
and reviewable as code. Git takes author and committer dates from the environment, so the
script sets `GIT_AUTHOR_DATE`, `GIT_COMMITTER_DATE`, `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`,
`GIT_COMMITTER_NAME` and `GIT_COMMITTER_EMAIL` per commit (or passes `--date`), with dates
spread over roughly eighteen months ending before the tag, and two or three synthetic authors
with `example.com` addresses, never a real person. GitHub displays the given dates; a push of
backdated commits is ordinary. The graph has, in order: an initial commit; the build manifest;
the vulnerable dependency pins; the introduction of each fixed vulnerability (an ordinary
feature message, nothing that announces the flaw); feature commits touching the true-positive
functions and the high-complexity function's file (so churn concentrates there); the
dependency upgrade commit; the fix commits; one rename of a source file holding a true positive
(so history must follow renames); one revert and its re-apply; and a final commit that adds
`PLANTED.md`. At least thirty commits, none touching more than three files, no merge commits.

The history must discuss the fixed vulnerabilities, because source-history analysis reads
messages and documents, not only diffs:

- each fix commit has a subject naming the weakness and a body of three to six lines that
  says what the flaw was, how it was reached, what the fix does and why that is enough, and
  cites the CWE id and, for the dependency upgrade, the advisory id (for example
  `Fix command injection in run_tool (CWE-78)` with a body explaining that the tool name came
  from the request and now passes an allowlist);
- one later "hardening review" commit touches no vulnerable code but adds a `SECURITY.md`
  whose dated entries describe each fixed vulnerability and the dependency upgrade, so a
  document-reading job sees the same history the log shows;
- a `CHANGELOG.md` grows across the history with one dated line per fix and per upgrade, in
  the Keep a Changelog style, under `Security` headings;
- one commit body mentions a vulnerability that was investigated and found not exploitable
  (one of the planted false positives), stating why, so the history also carries a negative
  conclusion for the review to weigh.

The true positives that remain at the head are never mentioned in any message or document; the
history must not leak the answer key. Record each fix commit's SHA in the answer key after the
script runs, since SHAs change if the script changes.

## Stage 2: build manifest and the planted dependency

Each repository is one build unit with one manifest, no subprojects, no generated code, no
network at build time. The table names the primary planted dependency; the two further true
positives and the one fixed-in-history dependency per language follow the same offline rule.
A planted dependency must not be needed to compile: either it is
declared in the manifest and lockfile and never imported, so Syft, OSV-Scanner and Grype see it
in the lockfile while the build ignores it, or its vulnerable version is vendored into the tree.
Toolchain versions match the pinned images (`containers/catalog.toml` `probe_expect`): Node
22.23.3, .NET SDK 8.0.131, Rust 1.90.0, Go 1.23.1, Java 21 with Maven 3.9.9, Python 3.12.3, PHP
8.3.6 with Composer 2.7.1, gcc 13.3 with CMake 3.28.

| Language | Manifest and build | Planted dependency | How it is present offline |
|---|---|---|---|
| cpp | `CMakeLists.txt`, `cmake -S . -B build && cmake --build build` | zlib 1.2.11 | vendored under `third_party/zlib/` as a static library target the executable links |
| java | `pom.xml`, built with `javac` (direct compiler recipe); `mvn -o` must also succeed with an empty local repository because the code imports nothing outside the JDK | `org.apache.logging.log4j:log4j-core` 2.14.1 | declared in `pom.xml`, never imported |
| javascript | `package.json`, `package-lock.json`, `tsconfig.json`; build is `tsc` from a vendored `node_modules/typescript` or `node --check` if vendoring is too large; record which | `lodash` 4.17.15 | declared in `package.json` and lockfile, never required |
| python | `pyproject.toml`, `requirements.txt` with pins; build is `python -m compileall` | `urllib3` 1.24 | pinned in `requirements.txt`, never imported |
| ruby | `Gemfile`, `Gemfile.lock`; build is `ruby -c` over the sources | `rack` 2.0.0 | locked in `Gemfile.lock`, never required |
| go | `go.mod`, `go.sum`; `go build ./...` with `GOFLAGS=-mod=vendor` | `golang.org/x/text` v0.3.0 | listed in `go.mod` and `go.sum`, `vendor/modules.txt` present, never imported |
| csharp | `Smoke.csproj` (`net8.0`, Web SDK), `dotnet restore` then `dotnet build --no-restore`; keep the fixture's no-PackageReference restore working | `Newtonsoft.Json` 12.0.1 | declared in `packages.lock.json` with `RestorePackagesWithLockFile`; if restore then needs the package, vendor the `.nupkg` in a local feed under `nuget/` and point `nuget.config` at it |
| rust | `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml` with a vendored source replacement as the Rust fixture does | `time` 0.1.43 | vendored under `vendor/`, listed in `Cargo.lock`, never used |
| php | `composer.json`, `composer.lock`; build is `php -l` over the sources | `monolog/monolog` 1.23.0 | locked in `composer.lock`, never required |

If a chosen advisory turns out ambiguous in OSV (no clear fixed version, withdrawn, or
ecosystem mismatch), pick another and record the reason in the guide; do not keep an
advisory the matcher cannot be expected to find.

## Stage 3: create, verify, push

For each language, in the order cpp, javascript, csharp, java, python, go, rust, ruby, php:

1. Run `tools/make-history.sh` to produce the branch, then
   `gh repo create wsollers/appsec-review-smoke-<language> --public --description "appsec-review smoke target (<language>): deliberately vulnerable, do not deploy"`
   and push `main`. Check on GitHub that the commit dates shown are the scripted ones.
2. Prove the offline build on this host before pushing, as the runtime user, with the build
   image the profile names:

   ```text
   docker run --rm --network none --user 10001:10001 \
     -v "$PWD:/workspace:ro" -v "$(mktemp -d):/scratch" -w /workspace \
     <profile image tag> <build command>
   ```

   Use the `node`, `dotnet`, `rust`, `go`, `java`, `python`, `php` and `native` profile images
   from `appsec-review.toml`; the C/C++ build must also succeed with the `codeql-build` output
   directory the live tests use. Record the elapsed time; a build over sixty seconds is a defect
   of the target to fix, not a budget to raise.
3. Prove the planted dependencies are visible offline: `syft dir:. -o json` in the Syft tool
   image (`containers/tools/syft`) lists each true-positive package at its planted version and
   the fixed-in-history package at its fixed version; `osv-scanner --offline` is not required
   (it needs a database); record what Syft reported.
3a. Prove the false positives are flagged: run the Semgrep tool image over the repository with
   `rules/semgrep/*.yml` and `rules/sei-cert/` mounted, as the evidence-collection adapter does,
   and record which planted false positives a rule reported. A false positive no rule reports is
   not a false positive for this pipeline; replace it or record it as such in the guide.
3b. Prove the history reads: `git log --follow` on the renamed file shows its pre-rename
   commits, `git log --grep CWE-` lists every fix commit with its body, `SECURITY.md` and
   `CHANGELOG.md` name every fixed item and no live one, and `git log --format=%B | grep` for
   each live true positive's function name returns only feature messages.
3c. Prove the complexity: run `complexity.py`'s `_cyclomatic` over the high-complexity
   function through the Tree-sitter path the prioritization job uses (a short script against
   the checked-out file, no job run) and record the count; it must exceed 15.
4. Tag the verified commit `v1.0.0` and record the commit SHA in the guide.

## Stage 4: the guide

`gh repo create wsollers/appsec-review-smoke-guide --public`, with one directory per language
holding `answer-key.json` (`schema: appsec-review/smoke-answer-key/1`): the repository, the
verified commit and tag, the build profile and command, the expected build unit (one), and a
`planted` list with one record per item: `class` (`true_positive_code`,
`true_positive_dependency`, `fixed_code`, `fixed_dependency`, `false_positive`), `id`, the
weakness (CWE), the file and span at the tagged head (or, for fixed items, the introducing and
fixing commit SHAs and the span at the introducing commit), for dependencies the package,
version, ecosystem, OSV and CVE ids and fixed version, for false positives the rule id that
flags it and the fact family and location that refutes it, and the expected final disposition
(reported, reported-as-fixed, squelched). Beside it: the expected graph facts (the fixture's
`expected-facts.json` copied verbatim, with line numbers adjusted if Stage 1 moved any), the
expected language and tool matrix rows, the expected history signals (fix commits, the rename,
the revert, the churn concentration), and `expected_gaps` (for example `range_fact
not_applicable` for the languages without range analysis, the two Rust `known_gaps`). A root
`README.md` says what the guide is, that it is evaluation-only, and that it is never cloned
under `targets/`.

## Stage 5: clone and document

Clone each smoke repository to `targets/appsec-review-smoke-<language>` at its tag (this
directory is ignored by `targets/.gitignore`), and the guide to a sibling of the checkout, not
under it. Add to `docs/operations/test-targets.md`: one table row per smoke target (purpose,
build profile, planted advisory, the one build unit), the clone lines for Linux and Windows in
the existing style, the guide's clone line with the same never-under-`targets/` warning the
multi-vuln guide carries, and a paragraph stating what the smoke tier does and does not prove.
Run the docs link check if one exists by then (see `docs/tasks/2026-11-13-docs-program-prompt.md`
Stage 2); otherwise check links by hand.

## Acceptance

- Nine repositories and the guide exist on GitHub, each at a tagged commit recorded in the guide.
- Each smoke target built with `--network none` in its profile image as user 10001 in under
  sixty seconds on this host, with the command and elapsed time recorded in the guide.
- Syft reported every planted dependency at its planted or fixed version for each.
- Every planted false positive is reported by a mounted Semgrep rule, and every fix commit and
  the rename are visible in `git log`; the scripted history reproduces from `tools/make-history.sh`.
- `targets/` holds the nine clones; `git status` in this repository shows only `docs/TODO.md`
  and `docs/operations/test-targets.md` changed.
- `tests/test_todo_registry.py` passes; every T entry from Stage 0 is `done` or names what is
  left.

## Reporting

Report per language: repository URL, tag and commit, build command, elapsed time, Syft result,
the planted inventory counts per class, which false positives Semgrep flagged, the history
commit count and the fix commit SHAs, any case whose line numbers moved, and any advisory
substituted. Then report the guide URL, the
`test-targets.md` diff, and the commit in this repository, and stop for the user before pushing
this repository. The first review on a smoke target (`appsec-review start`) is the user's
request, not part of this brief.
