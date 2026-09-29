# Ready-to-paste agent prompts

Each file here is the exact prompt to paste into a new Claude session. Every prompt tells the agent to read its brief in `docs/agent-briefs/`. Start order and where each runs:

| Prompt | Runs where | Start when | Branch |
|---|---|---|---|
| `B-hardening.md` | anywhere with the repo (local or cloud) | now | `hardening-b` |
| `D-kill-chains.md` | cloud session | now | `kill-chains` |
| `C-language-servers.md` | cloud (code) + you build images in WSL | now (independent of B/D) | `lang-servers` |
| `DOCS-sync.md` | cloud session | re-run after each branch merges to `main` | `docs-sync-<n>` |
| `E-dependency-reachability.md` | cloud | after `osv-feed` and `lang-servers` are merged | `dep-reachability` |
| `F-poc-and-fix.md` | cloud | after `kill-chains` merged | `poc-fix` |
| `G-per-language-codeql-reachability.md` | cloud | now (E, F, D, C, A, B are merged) | `codeql-reach` |
| `DOCS-sync-G.md` | cloud session | after `codeql-reach` is merged to `main` | `docs-sync-G` |
| `H-ghidra-x96dbg-images.md` | cloud (code) + you build images in WSL | now (independent) | `image-reverse-tools` |
| `I-dev-restart-and-executor.md` | cloud | now (wave 1) | `dev-executor` |
| `J-personas-roles-folder.md` | cloud | now (wave 1) | `personas-folder` |
| `M-report-completion.md` | cloud | now (wave 1) | `report-complete` |
| `K-registry-into-pipeline.md` | cloud | after `dev-executor` and `personas-folder` merge (wave 2) | `registry-move` |
| `L-formats-finish.md` | cloud | after `personas-folder` merges (wave 2) | `formats-2` |
| `N-caches-and-memo.md` | cloud | after `dev-executor` merges (wave 2) | `caches` |

Agent A (`osv-feed`) is finished; its branch is waiting for the controller to push and merge. Waves 1 and 2 (2026-09-29) run three agents at once because their file ownership is disjoint; wave 2 starts only after the merges named in its row. Each agent pushes ONLY its own branch; the controller merges.
