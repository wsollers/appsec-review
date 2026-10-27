# Lua game-security review rules

An opt-in, repository-authored pack of 20 Lua rules for Semgrep CE and OpenGrep.
It identifies **review leads, not proven vulnerabilities**. It is registered for
offline compilation checks but is **not loaded by the application review pipeline**;
no runtime applicability, container pins, or existing default scans are changed.

The starting point is standard Lua/LuaJIT code, with selected API spellings from
LOVE, Garry's Mod, FiveM, LuaSocket/LuaSec, and Roblox-style remotes. This is not
complete support for any game engine or Lua dialect.

## Running a scan

Use the local rule file rather than a downloaded registry configuration. From the
repository root, with the relevant executable installed:

```powershell
semgrep scan --config .\rules\lua-game-security\game-security.yml --metrics off --disable-version-check --strict --json .\targets\your-game
opengrep scan --config .\rules\lua-game-security\game-security.yml --disable-version-check --strict --json .\targets\your-game
```

Replace the target with your game's script directory, not this repository's fixture
directory. Review JSON `errors`, `paths.scanned`, skipped files, and timeout messages
alongside results. Compare the scanned list to the intended Lua inventory. An exit
code of zero normally means the scan completed, **not** that it found no matches;
partial coverage is not a clean result. These commands do not execute Lua.

For an initial inventory, retain INFO and WARNING results. To make WARNING matches
fail a CI check, add `--severity WARNING --error`; establish and review a baseline
first. Suppress only documented, reviewed cases. INFO rules intentionally include
routine gameplay operations and should not be a blanket release gate.

Semgrep metrics and version checks are disabled above. The regression tests also
run with container networking disabled, non-root execution, a read-only rule mount,
and no target execution. Apply equivalent isolation when scanning untrusted mods;
do not execute their build scripts or install their dependencies just to run this pack.

### Using the repository's local Docker images

If the scanner is not installed on the host, run the existing pinned image instead.
This PowerShell example mounts only the rules and the selected game directory:

```powershell
$rules = (Resolve-Path .\rules\lua-game-security).Path
$target = (Resolve-Path .\targets\your-game).Path
docker run --rm --network none --read-only --user 10001:10001 `
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g --cpus 2 `
  --tmpfs /tmp:rw,size=256m -e HOME=/tmp -e XDG_CONFIG_HOME=/tmp `
  --mount "type=bind,source=$rules,target=/rules,readonly" `
  --mount "type=bind,source=$target,target=/target,readonly" `
  --entrypoint /opt/tool/bin/semgrep appsec-review/tool-semgrep:1.178.0 `
  scan --metrics off --disable-version-check --strict --json `
  --config /rules/game-security.yml /target
```

For OpenGrep, change the entrypoint to `/opt/tool/opengrep/opengrep.bin`, use
`appsec-review/tool-opengrep:1.30.2`, and remove `--metrics off`. These images must
already exist locally. Size/time limits can produce coverage gaps on large games;
review those gaps rather than treating the resource limit as a successful scan.

## Coverage

IDs below have the prefix `appsec-review.lua.`. WARNING means a dangerous capability,
dynamic sink, or insecure configuration to investigate; INFO is a broader audit lead.
Confidence describes the usefulness of the syntactic signal, not exploitability.

| Rule suffix | Level | Review boundary |
| --- | --- | --- |
| `dynamic-code` | WARNING | `load`, `loadstring`, GMod `RunString`, `RunStringEx`, `CompileString` |
| `file-code-loading` | WARNING | `dofile`, `loadfile`, LOVE file loading, GMod `CompileFile` |
| `shell-execution` | WARNING | `os.execute`, `io.popen` |
| `native-code` | WARNING | `package.loadlib`, `require("ffi")`, `ffi.load`, `ffi.cdef`, `ffi.C` calls |
| `debug-capability` | WARNING | Registry, local/upvalue/metatable access, debug console and instruction hooks |
| `environment-escape` | WARNING | `getfenv`, `setfenv`, `_ENV = _G`, `__index = _G` inheritance |
| `module-search-mutation` | WARNING | Replacing package paths/loaders/searchers or inserting search functions |
| `dynamic-module` | WARNING | Nonliteral `require` / GMod `include`, including numeric asset IDs |
| `global-dispatch` | WARNING | Calls through `_G[name]` / `_ENV[name]` |
| `dynamic-file-access` | WARNING | Nonliteral paths at selected `io`, `os`, LOVE and GMod file APIs |
| `file-rename` | WARNING | Both paths and overwrite semantics of `os.rename` |
| `sql-string-construction` | WARNING | Concatenation / `string.format` in GMod SQL, execute/exec/query methods and selected MySQL calls |
| `tls-verification-disabled` | WARNING | `verify = "none"` / `ssl_verify = false` fields and assignments |
| `cleartext-http` | WARNING | Literal `http://` URLs at selected LuaSocket, GMod and FiveM request APIs |
| `predictable-random` | INFO | `math` / LOVE RNG; only security-sensitive uses need replacement |
| `resource-amplification` | INFO | `string.rep`, GMod / LOVE decompression |
| `read-all` | INFO | Whole-stream reads and LuaSocket `receive("*a")` |
| `network-entrypoint` | INFO | GMod receivers, FiveM net events, Lua-compatible Roblox remote handlers |
| `game-command` | WARNING | GMod / FiveM console-command execution, distinct from OS shell execution |
| `process-exit` | WARNING | Host-process termination via `os.exit` |

For each match, establish who controls the input and which capabilities the host
actually exposes. Trace network messages, mod packages, save data and downloaded
assets to the sink. Check server-side authority for identity, inventory ownership,
currency, rewards, prices and administrative operations. Do not infer authorization
from a client-side check or a callback's registration.

Use data-only serialization instead of executable save files; private command
allowlists instead of global dispatch; bound parameters instead of SQL string
construction; and host-enforced filesystem containment instead of string-prefix
checks. Updates and mods need a provenance/signature policy. Untrusted code also
needs host-enforced memory, instruction/time and capability limits. Lua-level
environment tables alone are not a complete sandbox.

## Deliberate limitations

- **No source-to-sink or cross-file guarantee.** These are portable structural
  patterns, not a taint model. Aliased functions, wrappers, dynamically computed
  names, bracket-style library access and strings built elsewhere may be missed.
  Engine constant propagation can affect which expressions count as literals.
- **No dialect coverage claim.** Lua support is experimental in the pinned engines.
  Luau type annotations, `continue`, compound assignment, GMod syntax extensions
  and vendor grammar changes may fail parsing. The remote-handler fixtures use
  standard Lua syntax, not a representative Luau program. Do not rename files or
  force the Lua parser and then treat partial results as complete coverage.
- **Not all APIs are modeled.** Engine-specific native bindings, C/C++ host
  initialization, `luaL_openlibs`, native memory safety, custom serializers,
  encryption, dependency vulnerabilities and hardcoded secrets need other checks.
- **Bounds and authorization are manual review.** The pack does not prove missing
  checks, authenticate network peers, establish server/client execution context,
  or detect all loops, decompression bombs, races, replay and economic logic flaws.
  An authorized handler or bounded `string.rep` still produces an INFO lead.
- **Names are not types.** An `execute`/`query` receiver or a `verify` table field
  can be unrelated to SQL/TLS. Lua matching does not reliably distinguish dot and
  colon calls; the SQL rule explicitly excludes `os.execute`. Field assignments
  are used instead of table ellipses because the pinned Lua parsers do not match
  those ellipses reliably. Bare variables with these field names can also match.
- **Literal paths/modules are not certified safe.** The dynamic-path and module
  rules exclude ordinary quoted literals to reduce noise. Trusted-looking names
  can still resolve to attacker-writable files. Code-loading and shell rules
  deliberately flag even literal inputs. Cleartext HTTP detection is limited to
  quoted literal URL forms, not every HTTP request table or computed URL.

A scan with no matches is not evidence that Lua usage is secure.

## Regression checks

From a checkout with its own test environment and the locally built tool images:

```powershell
.\.venv\Scripts\python -m pytest tests\test_lua_game_rules.py --basetemp=test/tmp/lua-game-security -q
.\.venv\Scripts\python containers\build.py query-packs lua-game-security
```

The tests read the versions/executables from `containers/tools/*/tool.toml`
(Semgrep **1.178.0**, OpenGrep **1.30.2** at introduction). They compare the entire
set of rule IDs and start lines to the fixture annotations, assert a clean parse
and complete fixture scan, and preserve raw JSON/stderr beneath the pytest
temporary directory. Every rule has positive and negative fixtures, including
comments/strings that must not match. Missing images are explicit test skips, not
proof of engine compatibility; require **no skips** for a release check.

Use this harness rather than the engines' native `--test`: their pinned annotation
readers do not recognize Lua's `-- ruleid:` / `-- ok:` comments. A negative fixture
only means that the named rule should not match, not that the example is secure.
