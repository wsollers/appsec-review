# Security tag taxonomy

Status: proposed design. Nothing in this page is implemented yet. It defines a finite, versioned
vocabulary for tagging code subjects. The tags feed a tag cloud and faceted retrieval filters.

Flat keyword matching does not work for this. Implementation facts, assurance controls, weakness
classes, and adversary techniques sit at different levels of abstraction. They also differ in how
much a tag claims. "This file calls `pickle.loads`" is an observed fact. "This file has CWE-502" is
a security claim, and `AGENTS.md` requires a claim to resolve to source lines or to a run-owned
tool artifact. The taxonomy therefore has two axes:

1. **Namespace.** What kind of thing the tag names: a code fact, a control, a weakness, or a
   threat.
2. **Basis.** How the tag was assigned and how strong it is as evidence (see below).

A tag without a basis cannot be stored or rendered.

## Changes from the original draft

| Problem in the draft | Correction |
| --- | --- |
| The `asvs:v1`…`v14` chapters are ASVS 4.0.3 numbering. The repository pins ASVS 5.0.0, which renumbered every chapter. The draft's own example `asvs:v9-self-contained-tokens` is a 5.0 chapter, so the draft mixed both editions. | Use ASVS 5.0 chapters under an edition-qualified namespace, `asvs5:`. |
| The "CWE pillars" list contained no pillars. CWE-79, CWE-89, and CWE-78 are Base or Variant weaknesses. CWE-20, CWE-119, CWE-287, and CWE-862 are Classes. | Tag the exact CWE ID. Roll it up for display by walking the pinned CWE feed's `ChildOf` relations to a fixed view (see [Rollup](#rollup-and-rendering)). |
| Names were embedded in IDs (`cwe:cwe-89-sql-injection`). Upstream names change between catalog releases, which would change the tag ID. | IDs carry only the stable identifier (`cwe:89`). Labels come from the pinned catalog. |
| The example rule `func:sys:dynamic-eval` + `func:net:rest-endpoint` → `cwe-78` maps eval to OS command injection. | Eval maps to CWE-94/CWE-95 (code injection). CWE-78 belongs to process and shell spawning. |
| Crosswalk rules derived *weaknesses* from capabilities: a JWT library plus signing produced a CWE tag. That reports a flaw because a feature exists. | A derived tag means "relevant / applicable", never "present". Only scanner output (`reported`) or validated claims (`confirmed`) can carry weakness tags as findings. |
| Enterprise ATT&CK was mapped directly from code. ATT&CK mostly describes adversary behaviour after compromise, so links such as T1556 and T1048 from a JWT library are speculative. | CAPEC is the attack-pattern layer for code weaknesses. Both the CWE and CAPEC feeds publish CWE↔CAPEC links. ATT&CK tags are reached through CAPEC's ATT&CK mappings, or directly for entry-point techniques such as T1190. |
| `posture:red-target:*` and `posture:blue-defense:*` were tags. | A subject's role in a data flow (source, sink, sanitizer, guard) becomes an attribute on each `func:*` assignment. "Red" and "blue" become saved views over namespaces rather than tags. |
| The CERT/MISRA labels were paraphrases (`cert-c:pointer-subtraction`, `misra:type-conversions`) and covered only C. | Use real rule IDs (`cert-c:arr36-c`, `misra-c2012:rule-10.3`) with a coarse category for rollup. Add schemes for other languages through the namespace registry. |
| NIST 800-53 was tagged at family level only. The SC family alone has more than 50 controls, so family tags cannot discriminate. | Tag at control level (`nist53r5:si-10`) and roll up to the family. |
| The ~120-tag budget treated the display vocabulary and the assignment vocabulary as one set. | Assignment is open within each hash-pinned catalog (for example, any CWE in 4.20). Display is a bounded rollup set of about 150 nodes. |
| Missing tags were treated as meaningful. | Coverage gaps are first-class `gap:*` tags. A missing tag never shows that a property is absent. |
| Several capability areas were missing: outbound HTTP (SSRF), templates, archive extraction, regex, LDAP, file upload, secrets, AI/LLM, mobile, build/CI, FFI. AuthN and AuthZ were also merged. | The functional vocabulary below adds these areas and separates `authn`, `session`, and `authz`. |

## Tag grammar

```
tag       := namespace ":" segment [":" segment] [":" segment]
namespace := [a-z][a-z0-9-]*            ; registered; edition-qualified when IDs are edition-unstable
segment   := [a-z0-9][a-z0-9.\-]*        ; lowercase; "." allowed for ATT&CK sub-techniques, control enhancements
```

- Tags are at most three levels deep after the namespace. Every tag is lowercase, and IDs are
  normalized on ingest: `T1190.001` → `t1190.001`, `CWE-079` → `cwe:79`, `MEM30-C` → `mem30-c`.
- A namespace carries an edition when the same ID means different things in different editions.
  For example, `asvs5:v9` and a hypothetical `asvs4:v9` are different chapters. CWE, CAPEC, and
  ATT&CK IDs are stable across releases. Deprecated or revoked entries are resolved through the
  `revoked-by` and `deprecated` data in the pinned feed. They are never silently kept.
- Display labels, descriptions, and parent links come from the pinned catalog at render time.
  They are not part of the tag.

## Assignment record and basis

Every assignment is one record. A tag cloud, filter, or crosswalk consumes records, never bare
strings.

```json
{
  "tag": "func:data:deserialize-native",
  "subject": {"kind": "source_span", "logical_id": "…", "component_id": "…", "project_id": "…"},
  "basis": "invoked",
  "flow_role": "sink",
  "producer": {"name": "capability-rules", "rule_id": "py.pickle.loads", "version": "…"},
  "evidence": [{"ref": "…", "path": "svc/cache.py", "span": {"start_line": 41, "end_line": 41}}],
  "derived_from": [],
  "crosswalk_rule": null,
  "confidence": "high",
  "vocabulary_sha256": "…",
  "crosswalk_sha256": "…"
}
```

`subject` reuses the retrieval logical identities: source files and spans, symbols, components,
packages, build artifacts, and tool observations.

| Basis | Meaning | Valid namespaces |
| --- | --- | --- |
| `declared` | A manifest, SBOM entry, or import makes the capability available. No call site was resolved. | `func`, `data`, `surface`, `component`, `lang` |
| `invoked` | A resolved call site, route registration, decorator, or configuration key exercises the capability. | `func`, `data`, `surface` |
| `reported` | A scanner rule matched, through SARIF or another normalized observation. The match is unverified. | `cwe`, `cert-*`, `misra-*`, `func` (rule-defined capability matches) |
| `confirmed` | An adjudicated claim with resolving evidence, produced by the inference review or the workbench. | `cwe`, `cert-*`, `misra-*`, `capec`, `attack` |
| `derived` | A crosswalk produced this tag from other assignments. It means "applicable" or "relevant to review". | `asvs5`, `masvs2`, `nist53r5`, `ssdf`, `top10-2025`, `api-top10-2023`, `cwe`, `capec`, `attack` |

Validation rejects every namespace/basis pair outside this table. For example, a `cwe:*` tag with
basis `invoked` is invalid: calling a function cannot show that a weakness exists.

A derived control tag (`asvs5:*`, `nist53r5:*`) means the control is *applicable*. It never means
the control is satisfied. Satisfaction belongs to the control-assessment workbench's
`control-result` shards.

`flow_role` is one of `source`, `sink`, `sanitizer`, `guard`, or `none`. It is valid only on
`func:*` assignments. It replaces the draft's `posture:*` tags and matches how CodeQL and Semgrep
taint models describe code.

## Namespace registry

Every namespace is registered with the following fields: its pinned catalog (or `local` for
repository-defined vocabularies), the catalog's canonical SHA-256, an ID normalizer, a rollup
rule, and its allowed bases. An unregistered namespace fails validation. A registered namespace
whose upstream catalog is not yet pinned is `proposed`. It is visible in this design but rejected
at runtime.

| Family | Namespace | Catalog / authority | Pinned today |
| --- | --- | --- | --- |
| Code facts | `func`, `data`, `surface`, `component`, `lang`, `gap` | Local vocabulary file. `component` reuses the workbench `COMPONENT_ROLES`. | No (new local file) |
| Controls | `asvs5` | OWASP ASVS 5.0.0 | Yes (fixture only) |
| Controls | `masvs2` | OWASP MASVS 2.1.0 | Yes (fixture only) |
| Controls | `nist53r5` | NIST SP 800-53 Rev. 5 (OSCAL catalog) | Proposed |
| Controls | `ssdf` | NIST SP 800-218 SSDF 1.1 | Proposed |
| Routing | `top10-2025`, `api-top10-2023` | OWASP Top 10 2025, API Security Top 10 2023 | Yes (routing context only) |
| Weakness | `cwe` | MITRE CWE 4.20 | Yes (`mitre_sync`) |
| Weakness | `cert-c`, `cert-cpp` | SEI CERT C / C++ rule IDs | Partly (`rules/cpp-cert`) |
| Weakness | `misra-c2012`, `misra-cpp2023` | MISRA rule IDs only. The rule text is licensed and is never stored. | Proposed |
| Threat | `capec` | MITRE CAPEC 3.9 STIX | Yes (`mitre_sync`) |
| Threat | `attack` | MITRE ATT&CK Enterprise 19.2 (Mobile/ICS optional) | Yes (`mitre_sync`) |

The Top 10 namespaces are routing and display rollups. As in the workbench, they cannot satisfy or
replace a control.

## 1. Code facts (`func`, `data`, `surface`, `component`, `lang`)

These tags describe only what the code does or exposes. They are assigned with basis `declared` or
`invoked`, or with basis `reported` when a capability-detection rule matches.

### `func` — capabilities

| Domain | Leaf tags |
| --- | --- |
| `func:authn` | `password`, `mfa`, `webauthn`, `oauth2-client`, `oauth2-server`, `oidc`, `saml`, `jwt`, `api-key`, `mtls-client`, `credential-recovery` |
| `func:session` | `cookie`, `server-store`, `token-refresh`, `csrf-token` |
| `func:authz` | `rbac`, `abac`, `object-ownership`, `policy-engine`, `tenant-scope` |
| `func:net` | `http-route`, `http-client`, `graphql`, `grpc`, `websocket`, `tls-server`, `tls-client`, `redirect`, `cors`, `raw-socket`, `dns` |
| `func:crypto` | `symmetric`, `asymmetric-sign`, `asymmetric-encrypt`, `hash`, `password-hash`, `mac`, `rng`, `key-mgmt`, `cert-validation` |
| `func:data` | `parse-json`, `parse-xml`, `parse-yaml`, `deserialize-native`, `sql-query`, `orm`, `nosql-query`, `ldap-query`, `template-render`, `regex`, `archive-extract`, `file-upload` |
| `func:exec` | `process-spawn`, `shell`, `dynamic-eval`, `dynamic-load`, `ffi`, `unmanaged-memory`, `ipc`, `concurrency` |
| `func:fs` | `read`, `write`, `path-build`, `temp-file`, `permissions` |
| `func:secrets` | `env-read`, `config-read`, `vault-client` |
| `func:telemetry` | `audit-log`, `app-log`, `tracing`, `metrics`, `error-report` |
| `func:ai` | `llm-call`, `tool-execution`, `vector-store`, `model-load` |
| `func:mobile` | `webview`, `deeplink`, `intent-ipc`, `local-storage`, `keystore` |
| `func:build` | `ci-workflow`, `container-build`, `iac`, `dependency-manifest`, `code-signing` |

That is 13 domains and about 90 leaves. Some notes on the leaves:

- `http-client` is any outbound request built from data, which makes it a server-side request
  forgery (SSRF) precondition.
- `deserialize-native` covers pickle, Java serialization, .NET `BinaryFormatter`, PHP `unserialize`,
  and YAML full loaders.
- `ffi` covers JNI, ctypes/cffi, cgo, Rust `unsafe`, and P/Invoke.
- `model-load` covers deserializing model weights, which is often pickle-backed.

Capability detection is keyed by package URL plus symbol (for example, `pkg:pypi/pyjwt` +
`jwt.decode` → `func:authn:jwt`). A match on the package alone gives `declared`. A resolved call
gives `invoked`.

### `data` — sensitivity of handled data

`data:credential`, `data:key-material`, `data:session-token`, `data:pii`, `data:financial`,
`data:health`.

### `surface` — exposure and privilege

| Group | Tags |
| --- | --- |
| Entry points | `surface:entry:http-public`, `surface:entry:http-internal`, `surface:entry:rpc`, `surface:entry:message-consumer`, `surface:entry:cli`, `surface:entry:env-config`, `surface:entry:file-input`, `surface:entry:local-ipc`, `surface:entry:mobile-deeplink` |
| Privilege | `surface:priv:elevated` (root, setuid, admin, privileged container), `surface:priv:sandboxed` |
| Boundaries | `surface:boundary:tenant`, `surface:boundary:egress` |

### `component` and `lang`

`component:<role>` reuses the 13 roles in `owasp_workbench.engine.COMPONENT_ROLES` verbatim, so
the tag cloud and control applicability share one component vocabulary. `lang:<id>` uses the
language identifiers of the tree-sitter and build adapters.

## 2. Assurance controls (`asvs5`, `masvs2`, `nist53r5`, `ssdf`)

Control tags are always `derived` and always mean *applicable*.

**ASVS 5.0** (`asvs5:v<n>`; finer tags `asvs5:v<n>.<section>` are allowed):

| Tag | Chapter | Tag | Chapter |
| --- | --- | --- | --- |
| `asvs5:v1` | Encoding and Sanitization | `asvs5:v10` | OAuth and OIDC |
| `asvs5:v2` | Validation and Business Logic | `asvs5:v11` | Cryptography |
| `asvs5:v3` | Web Frontend Security | `asvs5:v12` | Secure Communication |
| `asvs5:v4` | API and Web Service | `asvs5:v13` | Configuration |
| `asvs5:v5` | File Handling | `asvs5:v14` | Data Protection |
| `asvs5:v6` | Authentication | `asvs5:v15` | Secure Coding and Architecture |
| `asvs5:v7` | Session Management | `asvs5:v16` | Security Logging and Error Handling |
| `asvs5:v8` | Authorization | `asvs5:v17` | WebRTC |
| `asvs5:v9` | Self-contained Tokens | | |

**MASVS 2.1** (only for `android_mobile` and `ios_mobile` components, as in the workbench routing):
`masvs2:storage`, `crypto`, `auth`, `network`, `platform`, `code`, `resilience`, `privacy`.

**NIST SP 800-53 Rev. 5.** Each tag names a control and rolls up to its family. The
software-relevant starting set:

| Family | Controls |
| --- | --- |
| AC | `ac-3` access enforcement, `ac-4` information flow, `ac-6` least privilege, `ac-12` session termination |
| AU | `au-2` event logging, `au-3` record content, `au-9` protection of audit information |
| CM | `cm-6` configuration settings, `cm-7` least functionality |
| IA | `ia-2` identification and authentication, `ia-5` authenticator management |
| SA | `sa-8` security engineering principles, `sa-11` developer testing, `sa-15` development process |
| SC | `sc-8` transmission protection, `sc-12` key management, `sc-13` cryptographic protection, `sc-17` PKI certificates, `sc-23` session authenticity, `sc-28` protection at rest |
| SI | `si-7` software integrity, `si-10` input validation, `si-11` error handling, `si-16` memory protection |
| SR | `sr-3` supply-chain controls, `sr-4` provenance, `sr-11` component authenticity |

**SSDF** (`ssdf:po`, `ssdf:ps`, `ssdf:pw`, `ssdf:rv`, with practice IDs such as `ssdf:ps.1`)
covers `func:build:*` and the CI configuration analysis lane. The 800-53 SA and SR families
describe the organisation more than the code.

## 3. Weaknesses and coding standards (`cwe`, `cert-*`, `misra-*`)

These tags are findings only with basis `reported` or `confirmed`. With basis `derived`, they are
review hypotheses and are rendered as hollow nodes.

**CWE.** Assign the exact ID the producer or adjudicator gives. Normalize CodeQL
`external/cwe/cwe-079` and Semgrep `CWE-79: …` to `cwe:79`. Commonly seen IDs, with their correct
abstraction levels:

| Tag | Weakness | Abstraction |
| --- | --- | --- |
| `cwe:20` | Improper Input Validation | Class |
| `cwe:22` | Path Traversal | Base |
| `cwe:78` | OS Command Injection | Base |
| `cwe:79` | Cross-site Scripting | Base |
| `cwe:89` | SQL Injection | Base |
| `cwe:94` / `cwe:95` | Code Injection / Eval Injection | Base / Variant |
| `cwe:119` | Memory Buffer Bounds | Class |
| `cwe:287` | Improper Authentication | Class |
| `cwe:327` | Broken or Risky Crypto Algorithm | Class |
| `cwe:347` | Improper Verification of Cryptographic Signature | Base |
| `cwe:352` | Cross-Site Request Forgery | Compound |
| `cwe:502` | Deserialization of Untrusted Data | Base |
| `cwe:611` | XML External Entity | Base |
| `cwe:639` | Authorization Bypass via User-Controlled Key (IDOR) | Base |
| `cwe:798` | Hard-coded Credentials | Base |
| `cwe:862` | Missing Authorization | Class |
| `cwe:918` | Server-Side Request Forgery | Base |
| `cwe:1333` | Inefficient Regular Expression (ReDoS) | Base |

The repository producers map onto this namespace as follows:

- Gitleaks hits map to `cwe:798` with basis `reported`.
- Checkov and CI configuration findings map to their declared CWE, or to `gap:crosswalk-unmapped`
  when they declare none.

**CERT and MISRA.** Use the real rule ID. Roll up by the CERT category prefix (`mem`, `int`, `arr`,
`str`, `exp`, `fio`, `con`, `env`, `err`, `msc`) or by the MISRA rule group.

| Tag | Rule |
| --- | --- |
| `cert-c:mem30-c` | Do not access freed memory |
| `cert-c:int32-c` | Ensure signed integer operations do not overflow |
| `cert-c:arr30-c` | Do not form or use out-of-bounds pointers or array subscripts |
| `cert-c:arr36-c` | Do not subtract or compare two pointers that do not refer to the same array |
| `cert-c:con43-c` | Do not allow data races in multithreaded code |
| `cert-c:fio30-c` | Exclude user input from format strings |
| `cert-c:env33-c` | Do not call `system()` |
| `cert-c:exp33-c` | Do not read uninitialized memory |
| `misra-c2012:rule-1.3` | No undefined or critical unspecified behaviour |
| `misra-c2012:rule-2.1` | No unreachable code |
| `misra-c2012:rule-10.1`…`10.8` | Essential type model (implicit and explicit conversions) |
| `misra-c2012:rule-21.3` | No `<stdlib.h>` dynamic memory allocation |

Other language standards (for example, CERT Oracle Java) are added as separate registered
namespaces. They are not folded into a generic `safety:` prefix.

## 4. Threat framing (`capec`, `attack`)

CAPEC is the bridge from weakness to adversary. Both pinned MITRE feeds publish CWE↔CAPEC links,
and CAPEC publishes ATT&CK taxonomy mappings. Use those official links before writing any curated
rule.

| CWE | CAPEC | ATT&CK (where justified) |
| --- | --- | --- |
| `cwe:89` | `capec:66` SQL Injection | `attack:t1190` |
| `cwe:78` | `capec:88` OS Command Injection | `attack:t1190`, `attack:t1059` |
| `cwe:94`/`cwe:95` | `capec:242` Code Injection | `attack:t1190`, `attack:t1059` |
| `cwe:79` | `capec:63` Cross-Site Scripting | `attack:t1189`, `attack:t1539` |
| `cwe:22` | `capec:126` Path Traversal | `attack:t1190` |
| `cwe:502` | `capec:586` Object Injection | `attack:t1190` |
| `cwe:611` | `capec:221` XML External Entities | `attack:t1190` |
| `cwe:918` | `capec:664` Server-Side Request Forgery | `attack:t1190`, `attack:t1552.005` |
| `cwe:352` | `capec:62` Cross-Site Request Forgery | — |
| `cwe:347` | `capec:196` Session Credential Falsification through Forging | `attack:t1606` |
| `cwe:798` | — | `attack:t1552.001` |

Techniques that can be attached to a code subject:

| Tag | Technique |
| --- | --- |
| `attack:t1190` | Exploit Public-Facing Application. Requires `surface:entry:http-public`. |
| `attack:t1059` | Command and Scripting Interpreter |
| `attack:t1068` | Exploitation for Privilege Escalation. Requires `surface:priv:elevated`. |
| `attack:t1189` | Drive-by Compromise |
| `attack:t1203` | Exploitation for Client Execution |
| `attack:t1212` | Exploitation for Credential Access |
| `attack:t1539` | Steal Web Session Cookie |
| `attack:t1550.001` | Application Access Token |
| `attack:t1552.001` / `.005` | Credentials In Files / Cloud Instance Metadata API |
| `attack:t1606.001` / `.002` | Forge Web Credentials: Web Cookies / SAML Tokens |
| `attack:t1195.001` / `.002` | Supply Chain Compromise: Dependencies and Development Tools / Software Supply Chain. Attached to `func:build:*`. |
| `attack:t1499.004` | Application or System Exploitation (denial of service). Attached to ReDoS and resource exhaustion. |
| `attack:t1505.003` | Web Shell. Attached to file upload with an executable storage path. |

Post-compromise techniques are excluded unless a confirmed claim chain reaches them. Examples are
T1048 (exfiltration over an alternative protocol), T1078 (valid accounts) used as a code tag, and
T1556 (modify authentication process).

**Red and blue lenses** are saved views, not tags:

- Red view: `surface`, `capec`, and `attack` assignments, together with `func` assignments whose
  flow role is `source` or `sink`.
- Blue view: `func` assignments whose flow role is `guard` or `sanitizer`, together with
  `func:telemetry:audit-log`, `asvs5`, `nist53r5`, and `ssdf`.

## 5. Coverage gaps (`gap`)

`gap:no-ast:<lang>`, `gap:no-build:<unit>`, `gap:no-sast:<tool>`, `gap:scope-failed`,
`gap:crosswalk-unmapped`, `gap:catalog-fixture`.

Gap tags are attached to the subject that lacks coverage. A tag cloud computed over subjects that
carry a gap shows the gap as a hatched node, so an empty region of the cloud is never read as
clean.

## Crosswalk

Crosswalk rules are versioned data. The rule file is hash-pinned in central TOML, like the OWASP
catalogs. Each rule declares the following:

- its conditions over assignments in one scope (same span, symbol, component, or project);
- the tags it emits;
- the source of the mapping: `upstream` (a feed relation such as CWE `Related_Attack_Patterns`),
  `published` (for example, the OWASP Top 10 2025 CWE lists or the CTID ATT&CK↔800-53 mappings),
  or `curated` (a reviewer and a rationale are required);
- the maximum basis it can emit, which is always `derived`.

```json
{
  "schema": "appsec-review/tag-crosswalk/1",
  "rules": [
    {
      "id": "jwt-signature-applicability",
      "scope": "component",
      "when": {"all": [
        {"tag": "func:authn:jwt", "basis_at_least": "invoked"},
        {"tag": "func:crypto:asymmetric-sign", "basis_at_least": "declared"}
      ]},
      "emit": ["asvs5:v9", "nist53r5:ia-5", "nist53r5:sc-13", "cwe:347", "capec:196"],
      "source": "curated",
      "rationale": "Self-contained token verification applies; signature verification is the review question.",
      "reviewer": "…"
    },
    {
      "id": "eval-reachable-from-public-entry",
      "scope": "taint_path",
      "when": {"all": [
        {"tag": "surface:entry:http-public", "flow_role": "source"},
        {"tag": "func:exec:dynamic-eval", "flow_role": "sink", "basis_at_least": "invoked"}
      ]},
      "emit": ["cwe:94", "cwe:95", "capec:242", "asvs5:v1", "nist53r5:si-10", "attack:t1190", "attack:t1059"],
      "source": "curated",
      "rationale": "A public input reaches an eval sink; code injection is the review question, not a finding.",
      "reviewer": "…"
    },
    {
      "id": "cwe-capec-upstream",
      "scope": "same_subject",
      "when": {"all": [{"namespace": "cwe", "basis_at_least": "reported"}]},
      "emit_from": "cwe.related_attack_patterns",
      "source": "upstream"
    }
  ]
}
```

Rules for crosswalk assembly and evaluation:

- **One hop.** Derived tags are not crosswalk inputs, apart from `upstream` CWE→CAPEC→ATT&CK
  chains, which preserve `derived_from`. This prevents runaway inference.
- **`taint_path` scope** requires a producer-reported path, from CodeQL or Semgrep taint mode. Two
  tags co-occurring in the same file is not a path.
- **Conflicts fail assembly.** Examples: two rules emitting the same tag with incompatible
  rationale, an unknown tag, or a cycle. Rule ordering never resolves a conflict.
- **Determinism.** The same assignments, vocabulary hash, and crosswalk hash always produce the
  same derived set.

## Rollup and rendering

The assignment vocabulary is open within each pinned catalog. The display vocabulary is bounded by
a deterministic rollup:

| Namespace | Rollup |
| --- | --- |
| `func` | Domain (13 nodes). Drill down to the leaf. |
| `cwe` | Nearest ancestor in view CWE-1003 (Simplified Mapping of Published Vulnerabilities), via `ChildOf` in the pinned feed. Optionally also `top10-2025:a01`…`a10`. |
| `cert-*`, `misra-*` | Rule category or group. |
| `capec` | Its CAPEC mechanism-of-attack category. |
| `attack` | Tactic. |
| `nist53r5` | Family. |
| `asvs5`, `masvs2` | Chapter or group. These are already coarse. |

Rendering rules:

- **Size** is the number of distinct subjects at the chosen grain (default: components), not raw
  hit counts. One file with 500 SQL calls must not dominate. Use a log scale.
- **Colour** is the namespace family: code facts, controls, weaknesses, threats, gaps. Do not merge
  nodes across namespaces.
- **Fill** is the strongest basis present:
  - solid: `confirmed`;
  - strong tint: `reported`;
  - light tint: `invoked`;
  - outline: `declared` or `derived`;
  - hatched: `gap`.
- **Drill-down** goes rollup → leaf tag → subjects → resolving evidence. Every node must be able to
  reach a source span or a run artifact.

| Display family | Rollup nodes (approximate) | Primary producers |
| --- | --- | --- |
| Code facts | 13 `func` domains, 6 `data`, ~13 `surface`, 13 `component` | Tree-sitter AST shards (syntactic call/decorator patterns), target catalog and Syft package URLs, CodeQL source/sink models |
| Controls | 17 ASVS, 8 MASVS, ~8 NIST families, 4 SSDF groups | Crosswalk only |
| Weaknesses | ~40 CWE-1003 nodes in practice, ~10 CERT categories | CodeQL/Semgrep SARIF, Gitleaks, Checkov, CI analysis, adjudicated claims |
| Threats | ~15 CAPEC categories, ~8 ATT&CK tactics | Crosswalk via upstream feed relations, attack-chain composition |
| Gaps | Per producer | Coverage shards |

## Placement in the pipeline

The proposed producer is a `job_security_tagging` stage. It consumes the accepted catalog,
evidence-collection, AST, and CodeQL handoffs, and publishes immutable `tags` retrieval shards. A
shard's fingerprint covers:

- its upstream manifests;
- the vocabulary hash;
- the crosswalk hash;
- the capability-rule identity;
- the pinned catalog hashes.

Assignments are queried through the existing bounded `search`, `find`, and `coverage` filters, so
no new MCP tool is needed. The vocabulary file and the crosswalk file live under
`data/reference/taxonomy/` and are hash-pinned in `appsec-review.toml`.

Before any `proposed` namespace can be emitted at runtime, its catalog must be pinned: NIST 800-53
OSCAL, SSDF, MISRA IDs, and the CTID mappings.
