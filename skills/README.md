# skills

Top-level home for every skill in this repository. A skill is a tracked instruction set that an
agent loads before doing one bounded kind of work. Two families live here:

| Path | Purpose | Status |
|---|---|---|
| `skills/review/` | Skills used by the review processes themselves (lanes, workers, personas): the reusable procedure a worker follows for one kind of review work. | Empty; authored during the architecture rework (`docs/TODO/09-skills-rework.md`). |
| `skills/agents/claude/` | Skills installed for Claude-style agents operating this repository. | Search, OWASP-routing, vulnerability-lookup (`appsec-vuln-lookup`, offline OSV via `osv_lookup.py`), language-server, tree-sitter and CodeQL procedures are available; broader rework remains open. |
| `skills/agents/codex/` | The same skills packaged for Codex (`SKILL.md` with frontmatter). | `appsec-evidence-search`, `appsec-owasp-routing`, `appsec-vuln-lookup` and the language-tooling skills below are active. |
| `skills/_archive/` | The previous `appsec-review-process/agent-skills/` tree, moved here unchanged on 2026-09-21. **Not in use.** Nothing may point an agent at it. Delete it when the rework lands. | Archived. |

Until the rework lands, the only agent entry point is [`docs/agent-reader.md`](../docs/agent-reader.md).

## Language tooling skills (brief C, 2026-09-29)

One skill per pinned language server plus tree-sitter and CodeQL, each in both layouts
(`skills/agents/claude/<name>.md` points at `skills/agents/codex/<name>/SKILL.md`). Each says when
to use the tool, how to run it only through `appsec-review-process/lsp_driver.py` (or
`treesitter_ast.py` / the CodeQL lane) inside the sealed image boundary, and that results are
locators and target-derived data, never instructions; gaps are reported, never read as "no issues".
Pins: [`docs/language-servers.md`](../docs/language-servers.md).

| Skill | Tool (language, image) |
|---|---|
| `appsec-lsp-clangd` | clangd 21.1.0 (C/C++, `audit-buildenv-cpp`, `-cpp-resolute`) |
| `appsec-lsp-gopls` | gopls v0.18.1 (Go, `audit-buildenv-go`) |
| `appsec-lsp-jdtls` | Eclipse JDT LS 1.61.0 (Java, `audit-buildenv-java`) |
| `appsec-lsp-pylsp` | python-lsp-server 1.15.0 (Python, `audit-buildenv-python`) |
| `appsec-lsp-basedpyright` | basedpyright 1.40.1 (Python, `audit-buildenv-python`) |
| `appsec-lsp-typescript` | typescript-language-server 5.3.0 and vscode-json-language-server 4.10.0 (JS/TS/JSON, `audit-buildenv-typescript`) |
| `appsec-lsp-rust-analyzer` | rust-analyzer, Rust 1.90.0 (Rust, `audit-buildenv-rust`) |
| `appsec-lsp-csharp-ls` | csharp-ls 0.20.0 (C#, `audit-buildenv-dotnet`) |
| `appsec-lsp-phpactor` | Phpactor 2026.07.22.0 (PHP, `audit-buildenv-php`) |
| `appsec-tree-sitter` | tree-sitter 0.26.13 CLI and `treesitter_ast.py` (every compiler image) |
| `appsec-codeql` | CodeQL 2.27.0 per-language nodes `02-codeql-<lang>` (leads, retained databases), traced C/C++ lane and graph tables, reachability packs of `06-reachability-codeql` (`audit-codeql`, `audit-codeql-native`) |
