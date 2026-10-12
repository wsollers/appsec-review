---
id: generic
version: 1
covers: []
standards: ["cwe", "asvs5"]
max_tokens: 1500
---
## Runtime and framework model
A component whose language, framework, or deployment shape did not match a specific profile:
Ruby, Elixir, Scala, Perl, shell scripts, PowerShell, Lua, Swift on the server, mixed-language
glue, or an unrecognized framework. Establish the runtime model from the code itself: how the
process starts, which libraries handle input, and whether memory is managed.

## Trust and interface layer
- Identify entry points from how the component is invoked: listeners and routes, command-line
  arguments, environment variables, files read at startup or on request, message consumers,
  scheduled jobs, and exported library functions.
- Identify what the component is trusted to do: database credentials, cloud identity, filesystem
  write access, ability to spawn processes or call internal services.
- Note which party controls each input (anonymous internet user, authenticated user, operator,
  another service) since that sets the attacker model.
- When the runtime is unfamiliar, treat every parse, deserialization, interpreter call, and
  process spawn as a potential sink until its library semantics are established from source.

## Idiomatic security mechanisms
- Look for the framework's standard layers before assuming none exist: routing middleware, ORM or
  parameter binding, template autoescaping, built-in CSRF and session handling, permission
  decorators or before-filters (for example Rails `before_action`, Phoenix plugs).
- Shell scripts: quoting of every expansion (`"$var"`), `set -euo pipefail`, `--` before operands,
  `mktemp` for temporary files, no `eval`.
- PowerShell: parameter binding instead of `Invoke-Expression`, `-LiteralPath`, constrained
  language mode where configured.

## Stack-specific pitfalls
- Ruby: `send`/`public_send` with user method names, `Marshal.load`, `YAML.load` (pre-Psych 4),
  `constantize`, `open()` with a pipe prefix, `html_safe`, `permit!`.
- Shell: unquoted variables (word splitting and globbing), `eval`, command substitution of
  untrusted data, predictable `/tmp` files, `curl | sh`.
- PowerShell: `Invoke-Expression`, string-built `Start-Process` arguments.
- Perl: two-argument `open`, backticks, `system` with a single string.
- Elixir: `Code.eval_string`, `:erlang.binary_to_term` without `:safe`, atom exhaustion from
  `String.to_atom`.
- Lua (OpenResty, Redis scripting): `loadstring` on input, string patterns with catastrophic
  backtracking, `ngx.var` values trusted without decoding checks.

## Build and deployment facts to check
- How the component is built and launched (entry script, service unit, container command).
- Dependency manifests and lockfiles for the ecosystem in use.
- Runtime user, environment variables, and mounted secrets.
- Whether the absence of a specific profile hides a known framework; record the routing gap.
