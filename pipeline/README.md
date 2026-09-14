# pipeline — pregather → assemble → handoff → report

| Phase | Script | LLM? | Output |
|---|---|---|---|
| pregather | `pregather.sh` / `pregather.ps1` (twins; logic in container scripts) | no | compile DB, feasibility, IR, linked modules, ir-facts, CSA, CodeQL traced DB + mythos SARIF, `pregather-manifest.json` |
| assemble | `assemble.py` (Python, one impl) | no | `bundle.json` + `bundle.md`: verified / unresolved / refuted with IR evidence and `needs` |
| handoff | (prompts/, orchestrator — next) | yes | lane runs over the bundle only |
| report | (audit-report image — next) | no | executive + technical |

Tools live in the images (`images/*/Dockerfile`) — that is the catalog; digests are recorded in
every manifest. Run from WSL2 on Windows with sources on the WSL filesystem (fast); from a
Linux host identically. Host scripts have bash/PowerShell twins; anything with logic is Python.

Native Linux targets (EASTL, yquake2, Unreal): `--compile-db` with the cmake/bear/UBT
compile_commands.json, no `--msvc`; the gate and CodeQL replay detect the GNU driver.
Windows targets: converter + `--msvc`.
