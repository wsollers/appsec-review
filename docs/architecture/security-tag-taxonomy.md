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
| Cloud, containers, IaC, Kubernetes, CI/CD, and supply chain had only five generic `func:build` leaves. | Section 5 adds provider-neutral `infra` capabilities with a separate `platform` filter, declarative subject kinds, Pod Security Standards, SLSA, CI/CD and Kubernetes Top 10 routing, a bounded `vuln` namespace for advisory matches, and infrastructure coverage gaps. |
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
| `declared` | A manifest, SBOM entry, or import makes the capability available. No call site was resolved. | `func`, `infra`, `platform`, `data`, `surface`, `component`, `lang` |
| `invoked` | A resolved call site, route registration, decorator, or configuration key exercises the capability. For declarative configuration (IaC, manifests, Dockerfiles, workflows), the parsed key or resource is the resolved site. | `func`, `infra`, `data`, `surface` |
| `reported` | A scanner rule matched, through SARIF or another normalized observation. The match is unverified. | `cwe`, `cert-*`, `misra-*`, `vuln`, `scorecard`, `func`, `infra` (rule-defined capability matches) |
| `confirmed` | An adjudicated claim with resolving evidence, produced by the inference review or the workbench. | `cwe`, `cert-*`, `misra-*`, `vuln`, `capec`, `attack` |
| `derived` | A crosswalk produced this tag from other assignments. It means "applicable" or "relevant to review". | `surface` (boundary tags only), `asvs5`, `masvs2`, `nist53r5`, `ssdf`, `k8s-pss`, `slsa1`, `top10-2025`, `api-top10-2023`, `cicd-top10`, `k8s-top10-2022`, `scorecard`, `cwe`, `capec`, `attack` |

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
| Code facts | `func`, `infra`, `platform`, `data`, `surface`, `component`, `lang`, `gap` | Local vocabulary file. `component` reuses the workbench `COMPONENT_ROLES`. | No (new local file) |
| Controls | `asvs5` | OWASP ASVS 5.0.0 | Yes (fixture only) |
| Controls | `masvs2` | OWASP MASVS 2.1.0 | Yes (fixture only) |
| Controls | `nist53r5` | NIST SP 800-53 Rev. 5 (OSCAL catalog) | Proposed |
| Controls | `ssdf` | NIST SP 800-218 SSDF 1.1 | Proposed |
| Controls | `k8s-pss` | Kubernetes Pod Security Standards (baseline, restricted) | Proposed |
| Controls | `slsa1` | SLSA v1.0 Build track | Proposed |
| Routing | `top10-2025`, `api-top10-2023` | OWASP Top 10 2025, API Security Top 10 2023 | Yes (routing context only) |
| Routing | `cicd-top10`, `k8s-top10-2022` | OWASP Top 10 CI/CD Security Risks, OWASP Kubernetes Top 10 (2022) | Proposed (routing context only) |
| Checks | `scorecard` | OpenSSF Scorecard check names | Proposed |
| Weakness | `cwe` | MITRE CWE 4.20 | Yes (`mitre_sync`) |
| Weakness | `cert-c`, `cert-cpp` | SEI CERT C / C++ rule IDs | Partly (`rules/cpp-cert`) |
| Weakness | `misra-c2012`, `misra-cpp2023` | MISRA rule IDs only. The rule text is licensed and is never stored. | Proposed |
| Weakness | `vuln` | Fixed local set over Grype/OSV advisory matches. Advisory IDs stay in evidence, never in tags. | No (new local file) |
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

That is 12 domains and about 85 leaves. Build, delivery, and deployment configuration moved to the
separate `infra` namespace (section 5). Some notes on the leaves:

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
covers `infra:ci:*`, `infra:supply:*`, and the CI configuration analysis lane. The 800-53 SA and SR families
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
| `attack:t1195.001` / `.002` | Supply Chain Compromise: Dependencies and Development Tools / Software Supply Chain. Attached to `infra:supply:*` and `infra:ci:*`. |
| `attack:t1499.004` | Application or System Exploitation (denial of service). Attached to ReDoS and resource exhaustion. |
| `attack:t1505.003` | Web Shell. Attached to file upload with an executable storage path. |

Post-compromise techniques are excluded unless a confirmed claim chain reaches them. Examples are
T1048 (exfiltration over an alternative protocol), T1078 (valid accounts) used as a code tag, and
T1556 (modify authentication process).

**Red and blue lenses** are saved views, not tags:

- Red view: `surface`, `capec`, `attack`, and `vuln` assignments, together with `func` assignments
  whose flow role is `source` or `sink`.
- Blue view: `func` assignments whose flow role is `guard` or `sanitizer`, together with
  `func:telemetry:audit-log`, `infra:cloud:audit-log`, `asvs5`, `nist53r5`, `ssdf`, `k8s-pss`, and
  `slsa1`.

## 5. Infrastructure, delivery, and supply chain (`infra`, `platform`, `vuln`)

Cloud, container, IaC, Kubernetes, CI/CD, and dependency configuration is code too. It describes
what gets deployed and how software is built, not what the application does at runtime. It gets
its own namespaces so that application capabilities and deployment configuration do not collide in
one facet.

### Subjects

Assignments here bind to declarative subjects, not only to source spans. Each one keeps the file
hash and exact span of the defining block, and adds a producer-native address:

| Subject kind | Address example |
| --- | --- |
| `iac_resource` | Terraform `module.net.aws_security_group.web`, CloudFormation logical ID, Bicep symbolic name |
| `k8s_object` | `apps/v1/Deployment/<namespace>/<name>/container/<name>` |
| `container_stage` | Dockerfile path plus stage name or index |
| `ci_step` | Provider, workflow path, job ID, step index or ID |
| `package` | Package URL plus resolved version (existing retrieval kind) |

`iac_resource`, `k8s_object`, `container_stage`, and `ci_step` are new logical-identity kinds. Until
retrieval supports them, assignments fall back to the source span and record the address as the
producer-native identity. Crosswalk scope `ci_job` groups every `ci_step` of one job.

### `platform` — where the configuration applies

`platform:aws`, `platform:azure`, `platform:gcp`, `platform:oci`, `platform:kubernetes`,
`platform:docker`, `platform:github-actions`, `platform:gitlab-ci`, `platform:azure-pipelines`,
`platform:jenkins`.

`infra` capability tags are provider-neutral, and `platform` is a separate filter. A public AWS S3
bucket and a public GCS bucket both get `infra:cloud:object-storage` and
`surface:entry:cloud-public`; only the `platform` tag differs. This keeps the vocabulary from
growing with the number of providers. The vocabulary file holds a versioned table that maps native
resource types (`aws_s3_bucket`, `google_storage_bucket`, `Microsoft.Storage/storageAccounts`) to
capability tags.

### `infra` — configured capabilities

| Domain | Leaf tags |
| --- | --- |
| `infra:container` | `image-build`, `base-image`, `multi-stage`, `user-directive`, `remote-fetch`, `package-install`, `build-secret`, `exposed-port`, `healthcheck`, `runtime-socket-mount` |
| `infra:kube` | `workload`, `security-context`, `service-account`, `rbac-role`, `rbac-binding`, `network-policy`, `ingress`, `service-exposure`, `secret-object`, `host-namespace`, `host-path`, `capabilities`, `admission-policy`, `helm-chart`, `kustomization`, `crd-operator` |
| `infra:iac` | `terraform`, `cloudformation`, `bicep-arm`, `pulumi`, `cdk`, `ansible`, `serverless-framework`, `remote-module`, `state-backend` |
| `infra:cloud` | `iam-policy`, `iam-trust`, `workload-identity`, `object-storage`, `database`, `kms-key`, `secret-store`, `network-acl`, `load-balancer`, `compute`, `function`, `queue-topic`, `registry`, `managed-k8s`, `instance-metadata`, `audit-log`, `encryption-config` |
| `infra:ci` | `workflow`, `trigger-untrusted`, `permissions`, `secret-use`, `oidc-token`, `self-hosted-runner`, `third-party-action`, `script-step`, `cache`, `artifact-publish`, `deploy-step`, `environment-gate` |
| `infra:supply` | `dependency-manifest`, `lockfile`, `registry-config`, `install-script`, `vendored-code`, `git-dependency`, `submodule`, `checked-in-binary`, `sbom`, `signature`, `provenance`, `update-bot` |

That is 6 domains and about 75 leaves. Some notes on the leaves:

- `infra:container:remote-fetch` is `ADD <url>`, or `curl … | sh` in a build stage.
- `infra:container:runtime-socket-mount` is a mount of `docker.sock` or the containerd socket.
- `infra:kube:host-namespace` is `hostNetwork`, `hostPID`, or `hostIPC`.
- `infra:ci:trigger-untrusted` is a trigger that runs on content from untrusted contributors, such
  as `pull_request_target`, `issue_comment`, or `workflow_run` on GitHub.
- `infra:ci:oidc-token` is permission to mint a workload identity token, such as `id-token: write`.
- `infra:supply:install-script` is a hook that runs at install time, such as npm
  `preinstall`/`postinstall`, or `setup.py` run by pip.
- `infra:supply:registry-config` is `.npmrc`, `pip.conf`, `NuGet.config`, Maven `settings.xml`, or
  similar. It is the subject for dependency-confusion review.
- `infra:supply:signature` and `infra:supply:provenance` record that signing or attestation is
  configured, for example cosign, Sigstore, or SLSA generators. They do not claim that anything
  verifies the signature or attestation.

`infra` tags record what is configured, not whether it is safe. A Deployment with
`privileged: true` gets `infra:kube:security-context` and `surface:priv:host`. The weakness itself
is a separate `reported` tag from Checkov or Trivy.

### `surface` additions

| Group | Tags |
| --- | --- |
| Entry points | `surface:entry:cloud-public` (public bucket, function URL, internet-facing load balancer or ingress), `surface:entry:ci-untrusted` (pipeline input controlled by untrusted contributors) |
| Privilege | `surface:priv:host` (privileged container, host namespace, `hostPath`, runtime socket), `surface:priv:cluster-admin`, `surface:priv:cloud-admin` (wildcard actions or resources), `surface:priv:ci-write` (write-scoped repository or package token) |
| Boundaries | `surface:boundary:cluster`, `surface:boundary:cloud-account`, `surface:boundary:ci-trust` (an untrusted trigger reaching a privileged job) |

### Controls and routing

| Namespace | Tags | Applies to |
| --- | --- | --- |
| `k8s-pss` | `k8s-pss:baseline`, `k8s-pss:restricted`, plus control names such as `k8s-pss:privileged`, `host-namespaces`, `host-path-volumes`, `capabilities`, `privilege-escalation`, `run-as-non-root`, `seccomp` | `infra:kube:*` workloads |
| `slsa1` | `slsa1:build-l1`, `slsa1:build-l2`, `slsa1:build-l3` | `infra:ci:artifact-publish`, `infra:supply:provenance` |
| `ssdf` | `ssdf:po.3` toolchains, `ssdf:po.5` secure environments, `ssdf:ps.1` protect code, `ssdf:ps.2` release integrity, `ssdf:ps.3` archive releases and SBOM, `ssdf:pw.4` reuse well-secured software, `ssdf:pw.6` build tool configuration, `ssdf:rv.1` identify vulnerabilities | `infra:ci:*`, `infra:supply:*` |
| `nist53r5` | Adds `ac-2` account management, `au-12` audit record generation, `cm-2` baseline configuration, `cm-8` component inventory, `ra-5` vulnerability monitoring, `sa-10` developer configuration management, `sc-7` boundary protection, `sc-39` process isolation, `si-2` flaw remediation | `infra:*` |
| `asvs5` | Section granularity: `asvs5:v15.1` (inventory and remediation time frames), `asvs5:v15.2` (dependencies), `asvs5:v13` (configuration), `asvs5:v3.6` (external resource integrity) | Application components only, as in the workbench |
| `cicd-top10` | `cicd-sec-1` insufficient flow control, `-2` identity and access management, `-3` dependency chain abuse, `-4` poisoned pipeline execution, `-5` insufficient pipeline-based access control, `-6` credential hygiene, `-7` insecure system configuration, `-8` ungoverned third-party services, `-9` improper artifact integrity validation, `-10` insufficient logging and visibility | Routing for `infra:ci:*` and `infra:supply:*` |
| `k8s-top10-2022` | `k01` insecure workload configurations through `k10` outdated and vulnerable components | Routing for `infra:kube:*` |
| `scorecard` | `pinned-dependencies`, `token-permissions`, `dangerous-workflow`, `binary-artifacts`, `signed-releases`, `dependency-update-tool`, `sast`, `vulnerabilities`, `branch-protection`, `code-review` | Repository and CI configuration |

CIS Benchmarks (Docker, Kubernetes, cloud foundations) are left out. Their IDs change with every
benchmark version and their licence restricts redistribution, so they belong in scanner rule
metadata, not in a tag namespace.

Scorecard's `branch-protection` and `code-review` checks need the provider API, so an offline run
reports them as `gap:offline:<check>`. The checks that can be evaluated from files are
`pinned-dependencies`, `token-permissions`, `dangerous-workflow`, `binary-artifacts`, and
`dependency-update-tool`. They can be `reported` once a pinned Scorecard producer is added.

### Weaknesses

| Tag | Weakness | Typical producer |
| --- | --- | --- |
| `cwe:250` | Execution with Unnecessary Privileges | Checkov, Trivy, Hadolint (root user, privileged container) |
| `cwe:269` | Improper Privilege Management | IAM and RBAC wildcard checks |
| `cwe:276` / `cwe:732` | Incorrect Default Permissions / Incorrect Permission Assignment for Critical Resource | Checkov, Trivy |
| `cwe:284` | Improper Access Control | Public storage and endpoint checks |
| `cwe:306` | Missing Authentication for Critical Function | Unauthenticated dashboards and APIs |
| `cwe:311` / `cwe:319` | Missing Encryption of Sensitive Data / Cleartext Transmission | Encryption-at-rest and TLS checks |
| `cwe:668` | Exposure of Resource to Wrong Sphere | Public bucket, open security group |
| `cwe:778` | Insufficient Logging | Audit-log and flow-log checks |
| `cwe:798` | Hard-coded Credentials | Gitleaks, Trivy secret scanning, Checkov secrets |
| `cwe:494` | Download of Code Without Integrity Check | Hadolint, Zizmor `unpinned-uses`, `curl \| sh` |
| `cwe:829` | Inclusion of Functionality from Untrusted Control Sphere | Unpinned actions, remote modules, checkout of untrusted code |
| `cwe:94` / `cwe:78` | Code Injection / OS Command Injection | Zizmor `template-injection` in CI script steps |
| `cwe:1357` | Reliance on Insufficiently Trustworthy Component | Dependency-confusion and registry configuration review |
| `cwe:1104` | Use of Unmaintained Third-Party Components | Dependency metadata |
| `cwe:1395` | Dependency on Vulnerable Third-Party Component | Grype, OSV-Scanner |

`vuln` is a small fixed namespace for advisory matches. CVE and GHSA identifiers are unbounded, so
they stay in the assignment's evidence and never become tags.

| Tag | Meaning |
| --- | --- |
| `vuln:severity:critical` … `vuln:severity:low`, `vuln:severity:unknown` | Normalized severity of the matched advisory |
| `vuln:kev` | The advisory is in CISA's Known Exploited Vulnerabilities catalog. Requires a pinned KEV snapshot. |
| `vuln:fix-available` | The advisory names a fixed version |
| `vuln:reachable` | Allowed only with basis `confirmed`, when reachability analysis or adjudication cites the vulnerable call path |

A package match without reachability evidence is `reported` and is never shown as reachable.

### Threats

| Tag | Technique or pattern | Typical trigger |
| --- | --- | --- |
| `attack:t1610` | Deploy Container | `surface:priv:cluster-admin`, writable workloads |
| `attack:t1611` | Escape to Host | `surface:priv:host` |
| `attack:t1609` | Container Administration Command | Exposed runtime socket or kubelet |
| `attack:t1612` | Build Image on Host | `infra:container:runtime-socket-mount` |
| `attack:t1525` | Implant Internal Image | `infra:cloud:registry` with write access from CI |
| `attack:t1613` | Container and Resource Discovery | Over-broad `rbac-role` read access |
| `attack:t1552.005` / `.007` | Cloud Instance Metadata API / Container API | `infra:cloud:instance-metadata` without a hop limit, exposed container APIs |
| `attack:t1078.004` | Valid Accounts: Cloud Accounts | Long-lived cloud credentials in CI |
| `attack:t1098.001` | Additional Cloud Credentials | `surface:priv:cloud-admin` |
| `attack:t1530` | Data from Cloud Storage | `infra:cloud:object-storage` with `surface:entry:cloud-public` |
| `attack:t1537` | Transfer Data to Cloud Account | Cross-account trust in `iam-trust` |
| `attack:t1648` | Serverless Execution | Writable `infra:cloud:function` |
| `attack:t1496` | Resource Hijacking | Public compute, or CI runners with untrusted triggers |
| `attack:t1199` | Trusted Relationship | Third-party actions and remote modules |
| `attack:t1195.001` / `.002` | Supply Chain Compromise | `infra:supply:*`, `infra:ci:artifact-publish` |
| `capec:437` / `capec:538` / `capec:695` | Supply Chain / Open-Source Library Manipulation / Repo Jacking | `infra:supply:*`, `infra:ci:third-party-action` |

### Crosswalk examples

```json
[
  {
    "id": "poisoned-pipeline-execution",
    "scope": "ci_job",
    "when": {"all": [
      {"tag": "infra:ci:trigger-untrusted", "basis_at_least": "invoked"},
      {"any": [
        {"tag": "infra:ci:secret-use", "basis_at_least": "invoked"},
        {"tag": "infra:ci:oidc-token", "basis_at_least": "invoked"},
        {"tag": "surface:priv:ci-write", "basis_at_least": "invoked"}
      ]}
    ]},
    "emit": ["surface:boundary:ci-trust", "cicd-top10:cicd-sec-4", "ssdf:ps.1", "attack:t1195.002", "cwe:829"],
    "source": "curated",
    "rationale": "Untrusted input reaches a job that holds secrets or write scope; poisoned pipeline execution is the review question.",
    "reviewer": "…"
  },
  {
    "id": "workload-host-escape-applicability",
    "scope": "k8s_object",
    "when": {"all": [{"tag": "surface:priv:host", "basis_at_least": "invoked"}]},
    "emit": ["k8s-pss:baseline", "k8s-top10-2022:k01", "nist53r5:sc-39", "attack:t1611", "cwe:250"],
    "source": "curated",
    "rationale": "Host-level privilege violates the baseline profile; container escape is the review question.",
    "reviewer": "…"
  },
  {
    "id": "public-object-storage",
    "scope": "iac_resource",
    "when": {"all": [
      {"tag": "infra:cloud:object-storage", "basis_at_least": "invoked"},
      {"tag": "surface:entry:cloud-public", "basis_at_least": "invoked"}
    ]},
    "emit": ["nist53r5:ac-3", "nist53r5:sc-7", "cwe:668", "attack:t1530"],
    "source": "curated",
    "rationale": "Storage is reachable without authentication; data exposure is the review question.",
    "reviewer": "…"
  }
]
```

`surface:boundary:ci-trust` is a fact about the configuration, but here it is emitted by a
crosswalk rule, so it carries basis `derived` and is rendered as an outline node.

**Absence rules need proven coverage.** Some rules depend on a tag being missing, for example "a
dependency manifest without a lockfile". Such a rule fires only when the producer asserts complete
coverage of that component's manifests, and the rule records that assertion in `derived_from`.
Without the assertion, the rule emits `gap:crosswalk-unmapped` instead. Otherwise an unscanned
directory would look the same as a missing lockfile.

## 6. Coverage gaps (`gap`)

`gap:no-ast:<lang>`, `gap:no-build:<unit>`, `gap:no-sast:<tool>`, `gap:scope-failed`,
`gap:crosswalk-unmapped`, `gap:catalog-fixture`.

Infrastructure and supply-chain gaps:

- `gap:framework-disabled:<framework>`: a scanner framework the bounded adapter does not run. The
  Checkov adapter currently reports this for `kubernetes`, `helm`, `bicep`, `arm`, and
  `serverless`.
- `gap:unrendered:<helm|kustomize|jsonnet|cdk>`: templates or generators that the review never
  expands. Tags come only from literal manifests; values injected at render time are unknown.
- `gap:deployed-state`: IaC and manifests describe intended configuration. Live cloud or cluster
  state, drift, and admission-time mutation are never observed.
- `gap:offline:<check>`: a check that needs a provider API, for example branch protection, required
  reviews, registry signatures, or organisation-level IAM.
- `gap:no-lockfile-coverage`: dependency resolution could not be reproduced, so the transitive
  graph is incomplete.

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
| `func` | Domain (12 nodes). Drill down to the leaf. |
| `infra` | Domain (6 nodes), filterable by `platform`. Drill down to the leaf. |
| `vuln` | Severity, with `vuln:kev` shown separately. |
| `k8s-pss`, `slsa1`, `cicd-top10`, `k8s-top10-2022`, `scorecard` | Already coarse; shown as is. |
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
| Code facts | 12 `func` domains, 6 `infra` domains, ~10 `platform`, 6 `data`, ~20 `surface`, 13 `component` | Tree-sitter AST shards (syntactic call/decorator patterns), target catalog and Syft package URLs, CodeQL source/sink models, Checkov/Trivy parsed resources, CI hierarchy artifacts |
| Controls | 17 ASVS, 8 MASVS, ~10 NIST families, 4 SSDF groups, 2 PSS profiles, 3 SLSA levels | Crosswalk only |
| Routing / checks | 10 CI/CD Top 10, 10 Kubernetes Top 10, ~10 Scorecard checks | Crosswalk; Scorecard checks are `reported` only if a pinned Scorecard producer is added |
| Weaknesses | ~40 CWE-1003 nodes in practice, ~10 CERT categories, 8 `vuln` nodes | CodeQL/Semgrep SARIF, Gitleaks, Checkov, Hadolint, Trivy config, Zizmor, actionlint, Grype, OSV-Scanner, CI analysis, adjudicated claims |
| Threats | ~15 CAPEC categories, ~8 ATT&CK tactics | Crosswalk via upstream feed relations, attack-chain composition |
| Gaps | Per producer | Coverage shards |

## Placement in the pipeline

The proposed producer is a `job_security_tagging` stage. It consumes the accepted catalog,
evidence-collection, AST, CodeQL, CI-configuration, and artifact-security handoffs, and publishes immutable `tags` retrieval shards. A
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
