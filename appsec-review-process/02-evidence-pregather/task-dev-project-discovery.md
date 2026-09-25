# Developer Project Discovery

Run `02-dev-project-discovery` as a persona-dispatched pregather job. Its purpose is to determine,
for every developer-routed area of the repository, what buildable/testable project exists there and
**how to build and test it safely** -- not to build or test anything yourself. This is the first job
in the pipeline that decides *how the system under test wants to be built*, using both the target
repository's own files and the accepted `repository-partition-map.json` from
`02-repository-partition-discovery` as scope. Use the registry composition and output contract, and
write under `scratch/<project>-engagement/project-intel/`.

## Scope

Work only within the partitions the accepted partition map routed to `developer-engineer` as
primary or supporting reviewer (its `primary_persona_id`/`supporting_persona_ids` and
`include_paths`/`exclude_paths`). A partition dispositioned `deferred` or `unresolved` in that map
is out of scope here; note it in `coverage_gaps` rather than inventing a project for it. Do not
re-derive the partitioning -- that decision already happened and is upstream input, not something
to second-guess.

## Discovery

For each in-scope area, enumerate the manifests, lockfiles, workspace/solution files, and build
scripts that declare it as a project: `package.json`/`*.lock`, `pyproject.toml`/`poetry.lock`/
`requirements*.txt`, `pom.xml`/`build.gradle*`, `go.mod`/`go.sum`, `Cargo.toml`/`Cargo.lock`,
`*.csproj`/`*.sln`, `CMakeLists.txt`, `configure.ac`/`Makefile.am`, and the like -- this list is
illustrative, not exhaustive; read what the repository actually declares. Distinguish a real,
independently-buildable project root from a nested vendored dependency, a generated-code directory,
or an example/fixture that happens to contain its own manifest. A polyglot monorepo is several
projects, not one; do not collapse them. A single language does not imply a single project either.

For each project, determine: its language(s) and, where declared, version constraints; every
manifest and lockfile that defines it; which cataloged build-environment image (the "Build
Environment Catalog" section of this prompt) best matches its language and tooling, or that none
does and why; and the ordered commands that build and test it, grounded in what the repository's own
files actually declare (a `Makefile` target, a `package.json` script, a CI workflow step, an
autotools `configure.ac`) -- never a generic guess at what a project "usually" needs. Cite the exact
file each claim comes from.

## Safe Command Plan

For every command in a project's build/test sequence, decide and record: its exact argv; its
`authorization` -- `read-only` (nothing changes on disk or over the network), `network-required`
(needs external access, e.g. a package-manager restore against a live registry), or
`script-execution-required` (runs repository-controlled code: a configure script, a Makefile
recipe, a build tool's own scripts); and its concrete `side_effects` -- what it writes, generates,
or executes, named specifically (e.g. "writes `dist/`", "executes `tests/run.sh`"), not a vague
"builds the project." Order commands as they must actually run (generate before configure, configure
before build, build before test). Every command needs its own evidence citation to the file that
justified it. Never assume a dependency-restore step is safe or works offline; if a project's
restore step requires live network access, mark it `network-required` and say so in
`coverage_gaps` rather than silently planning around it. Never plan a command this job would itself
execute -- this job proposes the plan; nothing here runs a build.

## Output

Write `project-inventory.json` using `schemas/project-discovery.schema.json`
(`safe_command_plan` and `coverage_gaps` are top-level siblings of `projects` in that same file, not
separate documents) and a short `project-discovery-summary.md` describing the projects found, the
buildenv image chosen for each, and anything left uninspected. Give every project a stable
descriptive `project_id`. Report a coverage gap explicitly whenever a partition's build/test
approach could not be determined, needs network access this job cannot grant, or falls outside every
cataloged buildenv image -- never omit a project silently because its answer was unclear.

## Consumers

- The build-execution chain (`02-build-configure`, `02-native-build`, and further E-series jobs)
  reads `safe_command_plan` to actually run a build, under the pinned-container adapter (B13), never
  this job's own process.
- `01-component-characterization` and downstream review lanes read `projects` for language,
  location, and build-environment context.

Live-confirmed pattern to follow (D01, 2026-09-24): the persona has no tool access and no live
filesystem -- everything it can reason about is inlined into the prompt (the target repository's
files, exactly as `02-repository-partition-discovery` was shown them, plus the accepted partition
map as an additional readable input). `source_revision` and every `evidence_citations[].content_hash`
are orchestrator-owned provenance, not something this persona can compute reliably -- write your
best understanding of them if asked, but expect the orchestrator to overwrite both with its own
pinned values before publish, exactly as it does for partition discovery.
