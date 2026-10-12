---
id: injection_interpreters
version: 1
covers: ["cwe:74", "cwe:77", "cwe:78", "cwe:79", "cwe:88", "cwe:89", "cwe:90", "cwe:94", "cwe:95", "cwe:113", "cwe:114", "cwe:116", "cwe:117", "cwe:426", "cwe:427", "cwe:470", "cwe:643", "cwe:917", "cwe:943", "cwe:1236", "cwe:1336", "func:data:sql-query", "func:data:orm", "func:data:nosql-query", "func:data:ldap-query", "func:data:template-render", "func:exec:shell", "func:exec:process-spawn", "func:exec:dynamic-eval", "func:exec:dynamic-load"]
standards: ["cwe", "capec", "attack", "asvs5", "top10-2025"]
max_tokens: 1500
---
## Viewpoint
An injection specialist. Every interpreter (SQL, shell, HTML, template, LDAP, XPath, expression
language, the language runtime itself) has a grammar; a defect exists when attacker bytes cross
from the data position into the code position of that grammar.

## Coverage
GENERATED

## Likely failure modes
- SQL built by concatenation or formatting: `"... WHERE id=" + id`, f-strings, `String.format`,
  `fmt.Sprintf`, Knex/Sequelize `raw`, Django `.extra()`/`RawSQL`, Hibernate HQL concatenation,
  `ORDER BY` or table names from input (identifiers cannot be bound as parameters).
- NoSQL operator injection: a JSON body object passed straight into a Mongo filter (`{"$ne": null}`),
  `$where` with string JavaScript.
- Shell: `system`, `popen`, `Runtime.exec(String)`, `subprocess(..., shell=True)`,
  `child_process.exec`, backticks in Ruby/PHP/Perl; argument injection through a leading `-` even
  with an argv array (`git`, `tar`, `curl`, `ssh -o ProxyCommand`).
- Code evaluation: `eval`, `Function()`, `vm.runInContext`, Python `exec`, SpEL/OGNL/MVEL/EL
  evaluation of request data, `ScriptEngine.eval`, PHP `assert`/`preg_replace /e`.
- Template injection: user text used as the template source (`render_template_string`,
  `Velocity.evaluate`, Twig `createTemplate`) rather than as a template variable.
- XSS: unescaped output in HTML (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `|safe`,
  `@Html.Raw`, `{!! !!}`), wrong-context escaping (HTML-escaped value inside a JS string or
  `href`), `javascript:` URLs.
- Header and log injection: CR/LF in header values or log lines that forge records.
- Dynamic loading: `dlopen`, `LoadLibrary`, `Class.forName`, `require`/`import` from a path or
  module name derived from input; relative loader paths and writable directories on `PATH`.

## Effective controls
- Bound parameters for values (`?`, `$1`, `:name`, `PreparedStatement.setX`, ORM filters) and an
  allowlist mapping for identifiers and sort keys.
- argv arrays with no shell, a fixed program path, and `--` before user operands.
- Contextual auto-escaping templates left on (Jinja2 autoescape, React text nodes, Razor default),
  plus a CSP without `unsafe-inline` as defence in depth.
- Expression languages evaluated only on constant strings; sandboxed evaluators configured with
  restrictive class allowlists.
- Absolute loader paths, `SetDefaultDllDirectories`, `LOAD_LIBRARY_SEARCH_SYSTEM32`, fixed plugin
  registries.

## False positives
- Concatenation of constants or of values from a closed enum or integer-typed parameter.
- ORM query builders that bind values internally even when the code looks like string assembly.
- `shell=True` with a fully literal command.
- Escaped output where the framework escapes by default and no raw/safe marker is used.
- `eval` in build scripts or tests that never see request data.

## Evidence by predicate
- `affected_construct`: the interpreter call (query execution, spawn, eval, render, raw output)
  and the expression that builds its code-position argument.
- `attacker_input_control`: the request parameter, header, body field, file, or message that flows
  into that expression, with any intermediate storage (stored XSS, second-order SQL).
- `source_to_sink_reachability`: the route or handler to sink path, including helper functions,
  repository layers, and template includes.
- `missing_or_ineffective_guard`: no parameter binding, escaping for the wrong context, a denylist
  that misses quoting or encoding variants, or validation applied to a different variable.
- `configuration_enables`: autoescape disabled, `allowMultiQueries`, shell selection, expression
  evaluation flags, CSP headers, or driver options that change parsing.
- `security_impact`: data read or modified in the database, command execution as the service
  account, script execution in another user's session, or forged audit records.

## Hand-offs
Deserialization and XXE go to `parsing_deserialization`. Path traversal goes to
`filesystem_resources`. CI expression injection in workflow files goes to `ci_cd_pipeline`.
Open redirects and SSRF go to `network_api_surface`.
