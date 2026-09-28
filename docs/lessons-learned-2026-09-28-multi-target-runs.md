# Lessons learned: first multi-target runs (2026-09-27/28)

Status: **current, generalizable.** Written while hello-autotools, freeciv21 and doom3-bfg ran
`full_review` at the same time under [ADR-0013](decisions/ADR-0013-run-to-report-first.md). Each
breakage and its fix is one row in the `appsec-review-process/TODO.md` breakage log; this file
extracts what transfers. Continues
[`lessons-learned-2026-09-25-d02-d04-live-dispatch.md`](lessons-learned-2026-09-25-d02-d04-live-dispatch.md).
Its lesson 2 (keep structural checks strict, fix the wording) still holds for model output; lesson 5
below narrows it for checks on target data.

## 1. Give the model a query tool for structured data, not a pager

Model jobs in lookup mode read large upstream JSON (freeciv21's `build-index.json`, 3,500+ lines;
the repository partition map, 1,000+ lines) with `input_read` in 100-400-line windows, often
re-reading the same windows within one job. The retrieval audit made this visible: most of a
build-plan job's calls were line reads of JSON it only needed a few keys from.

The fix was `input_jq` in `input_mcp.py` (`c6f5a9ea`): the model sends a ref and a jq filter, and the
server runs the host's `jq` over the pinned bytes. On the same file, `keys` returned 203 bytes and
a unit count returned 2, where paging had returned tens of kilobytes. The model still gets no shell.
The input goes in on stdin only, with an empty environment, no module search path and an empty
working directory. Filters using `import`, `include`, `env`, `$ENV` or `input_filename` are refused
before jq runs. Each call returns up to 64 KB and flags truncation so the model narrows the filter;
that is a window per call, not a cap on the data. `prepare-host.sh` checks `jq` is installed.

**Rule:** when a model job's input is structured (JSON, and later SARIF, CycloneDX, SQLite),
expose a query over it rather than line windows. Name example filters in the tool description;
the model copies their shape.

## 2. Watch how the model reads, then change the tools

`input_mcp.py` audits every call under `runs/<run>/data/retrieval/`, tied to its job and attempt,
with hits, refs returned, bytes and time. `orchestrator/retrieval-report.py <run> --calls` groups
them per job and checks citation backing: of the paths a job's output cites, how many it actually
read or surfaced. Lesson 1 came straight from reading that report, and so did two other findings:

- Discovery and build jobs used `input_list`, `input_grep` and `input_read` and never the evidence
  index (`evidence_search`, `evidence_derived`). That suits structural jobs. Check the review jobs
  further downstream before concluding the index is well placed.
- In lookup mode the model can only see files through these tools, so the audit is a complete
  record of what it looked at. Freeciv21's discovery and build jobs backed 75 of 78 cited paths
  with a lookup. The report's first version showed 0% because it did not strip the
  `target-repository:` root prefix; a monitoring tool needs checking against a known case too.

## 3. Pasting inputs into the prompt does not scale; a limit was hiding that

Model jobs pasted every readable file into the prompt, and a 256-file limit stopped the job before
the size mattered. Once the limit was removed, hello-autotools' component characterization sent
9.3 MB (the Joern graph alone was 5 MB) and the CLI refused it. Above
`invocation.inline_input_bytes` (150 KB) the prompt now carries an inventory and the model looks
things up through `input_mcp.py`. The inventory itself was then too big for freeciv21: 6,100 files
listed one per line came to 895K characters and hit the $2 per-call spending cap before the model
did anything. Over 300 files it is now summarised by folder (about 6K characters), with
`input_list` for exact refs.

**Rule:** before raising or removing a limit, ask what it was protecting. Here it was protecting a
design that could not work at real sizes.

## 4. Log sizes instead of capping them

The count and byte limits (1,000 doc records, 256 inputs, 20,000 index records, 50,000 Joern
records, the build-discovery byte budget) were set for a 24-file fixture and stopped real targets
outright. William's call: do not cap, log. Each former limit now calls `size_log.observe` and the
job carries on; `orchestrator/size-report.py <run> --over` shows what went past an old limit.
Freeciv21's doc-intelligence ingest, for example, produced 1,220 records from 114 documents.

## 5. Real repositories are data a checker must accept

Most breakages were checks treating normal repository content as an error: a `+` in a folder name
(`data/graphics/logo+splash/`), 110 symlinks, lone-CR line endings, Joern naming headers that are
not in the checkout, a Windows-only MSBuild project, and our redactor masking text inside gitleaks'
own output. None of these makes the report wrong. The fix each time was to accept the data, or to
skip and count it, and record the effect as a coverage gap. A build that cannot run on Linux is a
gap in the report, not a failed run.

## 6. Several runs at once work; changing code under a running run does not

Runs are isolated by run id, so three targets ran on one host and one code location. The problem
was editing job code while runs were executing. A run picked up a changed `build_resolution.py`
mid-flight, and three downstream jobs then blocked on a fingerprint mismatch. Shared runtime
(`execution_state.SHARED_RUNTIME`, including `claude_cli_invoker.py` and `persona_invocation.py`)
is excluded from job fingerprints, so it can change at any time. Job-specific code should change
only between runs, or be held as a patch until the runs stop.

Intake's freshness check had the same weakness at the root of the graph: its definition hash
covered every schema and job template, so any unrelated edit re-ran the whole run. It now compares
only what intake actually read: the target snapshot, config, dependencies and tools.

## 7. The model's plans are good; guesses about the environment are not

The model correctly worked out that doom3-bfg's two projects are MSBuild/Win32-only and planned
no commands. It planned freeciv21 as one CMake/Ninja/Qt6 build. Its Ubuntu package names were
wrong, though (`libqt6core6-dev`, `libkf6archive-dev` do not exist on noble), and the image build
failed. The model had no way to check them. Follow-up: give the build plan an offline lookup against
the pinned package index, or feed apt's "unable to locate" list back to it for one repair round.

Repair rounds also start over: the model repeats every lookup, and in freeciv21 each retry cost
about $0.16-0.22. Values the orchestrator already knows (such as `source_revision`) should be
filled in before the schema check rather than costing a retry. A repair round should ideally
continue the same session rather than start a new one.
