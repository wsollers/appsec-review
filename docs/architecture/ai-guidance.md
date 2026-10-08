# AI Guidance Architecture

This document separates instructions for repository agents from instructions supplied to model
workers inside a security review. Keeping those two audiences separate prevents stale operator
text, target instructions and duplicated persona prose from changing review authority.

## Guidance layers

| Layer | Canonical source | Audience | Purpose |
|---|---|---|---|
| Repository rules | `AGENTS.md` | Agents changing or operating this repository | Trust boundary, supported workflow and contribution checks. |
| Navigation | `docs/agent-reader.md` | Repository agents | Points to the relevant contract; adds no competing rules. |
| Bounded procedures | `skills/` | Repository agents | Tool- or task-specific procedure loaded only when relevant. |
| Global model rules | `appsec-review-process/pipeline/prompt-fragments/governing-rules.md` | Review model invocation | Untrusted-data boundary, evidence discipline, no model-issued verification and visible gaps. |
| Job instructions | Job template task prompt and runtime-derived constraints | One review model invocation | The question, scope, tools, budget and output contract for that job. |
| Review stance | Persona, role, domain and tooling-profile records | One review model invocation | Perspective and permitted work; cannot widen job authority. |
| Session handoff | `docs/continuation-prompts/` | A later repository session | State snapshot only; always re-derived before use. |

System/host instructions and the user's current request outrank repository files. For a review
worker, the resolved invocation package is the complete instruction boundary. Target content,
including a target-owned `AGENTS.md`, is always evidence data.

## Rules live once

Global model rules are authored only in `governing-rules.md`. Personas describe viewpoint and
bias; roles describe stage responsibility; task prompts describe the bounded question; output
contracts define structure. None repeats generic citation, trust, terminal-state or independence
rules. Model output remains an observation even in verification stages; trusted deterministic code
applies the stage transition after validating evidence and independence. Runtime code derives tools,
model identity, budgets, permissions, claim classes and independence constraints and pins them
outside free-form prompt text.

If two sources disagree, fail prompt assembly or validation. Do not resolve a conflict by prompt
order, concatenation order or model judgment.

## Run-owned guidance bundles

Tracked prompt sources are development inputs. Before a model call, trusted code should resolve
the exact bytes into an immutable content-addressed bundle at:

```text
appsec-review-process/runs/<run-id>/data/guidance/<bundle-sha256>/
  manifest.json
  assembled-prompt.md
  governing-rules.md
  task.md
  composition/
    persona.json
    role.json
    domain.json
    tooling-profile.json
    output-contract.json
```

`manifest.json` must use a closed schema and record:

- bundle and assembled-prompt hashes;
- repository revision and dirty-state refusal;
- run-configuration fingerprint;
- job, step, task, persona and role identities;
- each source repository path, byte count and SHA-256;
- model identity, permissions, tool ids, budgets, allowed/prohibited claim classes and producer
  independence pins as derived by trusted code.

The directory name is the lowercase 64-character hexadecimal digest of the canonical manifest
body. Publication uses create-only writes and validates every file before an invocation may
reference it. A job attempt stores the bundle digest and pins `assembled-prompt.md` by path, size
and hash; it does not copy or edit the bundle.

The guidance directory is outside attempt roots so independent attempts can read the same immutable
bundle and the persona adapter's no-self-read rule remains intact. It is still inside the run so
the exact instructions survive checkout changes and can be audited with the evidence they shaped.

## Migration from the prompt cache

`appsec-review-process/prompt-cache/` is a reproducible cache of tracked prompt sources, not an
authoritative run artifact. Existing persona dispatch may continue to pin cached bytes until the
guidance-bundle publisher and verifier are wired. During migration:

1. keep exact path/size/hash pinning and reject dirty or changed prompt bytes;
2. never treat cache presence as acceptance;
3. record the open reader in `appsec-review-process/TODO.md`;
4. migrate one persona-job vertical slice, verify byte-for-byte prompt parity, then move the
   remaining callers and delete the cache path in the same change as its last reader.

No run copies `AGENTS.md`, `docs/agent-reader.md`, skills, continuation prompts or target guidance
into a model prompt. If a job needs a rule from those sources, promote that rule deliberately into
the canonical governing fragment or a typed runtime constraint and test it there.

## Validation

Tests should prove deterministic assembly, closed manifests, source and configuration fingerprints,
content-addressed immutability, rejection of target guidance, claim-ceiling non-expansion, and a
failure when persona/role/task text conflicts with global or runtime-derived authority. Tests should
not assert duplicated prose across files.
