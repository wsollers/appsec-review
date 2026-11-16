---
title: "Collation pass: facet tags for first-party units before hunting"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_owasp_control_assessment", "job_security_tagging"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Collation pass: facet tags for first-party units before hunting

This page specifies T-5008 (`docs/TODO.md`): a deterministic collation pass that classifies every
first-party file and component of a target by closed *facet* tags before any hunt package is
assembled, and the consumers that route the review on those tags. The user's decision
(2026-11-14) is the contract: "a collation pass before hunting classifies code by tags; an
authentication endpoint is tagged like auth, client facing, user tainted, networked listener,
session management, rpc". The pass lands in stages (vocabulary and deterministic derivation,
consumers, optional model pass); each section below says what is implemented at which stage.

Tags are routing data, never evidence. A security claim still cites resolving source lines. A
wrong facet can only misroute a package, weight a unit differently or send a control family to the
wrong applicability bucket; it can never establish or refute a weakness, and it never reaches a
model worker as free text.

## 1. The problem

A review worker today receives a lead menu, a unit context (`package-unit-context/2`, introduced as <!-- historical:begin -->`package-unit-context/1`<!-- historical:end --> in T-5000) of
hotspots, tag assignments, history signals, dependency packages and precomputed facts, and the
retrieval tools. It never receives a statement of what the unit *is*: that `src/request.cpp` reads
one request line from a connected socket, parses a verb, opens a per-connection session and runs a
maintenance tool named by the client. Every red, blue and verifier cell re-infers that from a
slice, and on smoke-cpp run `2026-11-14-0003` mostly did not: the `tags` index held 55 `lang:*`
assignments and 1,131 gap tags, no `component:*`, `surface:*` or `func:*` tag was minted for a
C/C++ target with a `main()`, sockets and parsers, the `components` payload carried only `root`,
`manifest` and `component_id`, and the OWASP workbench classified the single component with no
roles at `low` confidence from inputs it could not see
(`docs/reviews/owasp-value-review-2026-11-14.md`, section 2).

After the pass a worker knows, for every first-party unit it hunts:

| Facet | Question it answers | Example for a login route |
| --- | --- | --- |
| `role` | What security-relevant job does this code do? | `role:auth`, `role:session`, `role:input-parsing` |
| `exposure` | Who can reach it? | `exposure:client-facing` |
| `trust` | Whose data flows through it? | `trust:user-tainted` |
| `mechanism` | Through which channel is it reached? | `mechanism:http`, `mechanism:networked-listener` |
| `asset` | What is at stake? | `asset:credentials`, `asset:session-tokens` |
| `state` | What does it keep between calls? | `state:session`, `state:stateful` |

and, per component, a `target` class (`target:web-api`, `target:cli`, `target:network-service`, ...) that gates whether a
control standard applies at all.

## 2. Facet vocabulary

Six facet namespaces and one target-class namespace join the closed vocabulary in
`data/reference/taxonomy/vocabulary.json` (family `code_facts`, rollup `self`, status `active`).
Every value is defined in one sentence with the evidence that may establish it. Tags are
`<facet>:<value>`; the grammar of `security-tag-taxonomy.md` applies, so multi-word values use `-`.

### `role` (bases `declared`, `invoked`, `derived`, `reported`)

| Value | Definition | Evidence that establishes it |
| --- | --- | --- |
| `role:auth` | The code establishes or checks who a caller is. | `func:authn:*` tags; lexical identifiers (`authenticate`, `login`, `verify_password`, `check_password`, `credential`, `Authorization` header use); model pass with a cited line |
| `role:session` | The code creates, reads, refreshes or destroys per-principal session state. | `func:session:*` tags; lexical identifiers (`session_open`, `session_touch`, `HttpSession`, `set_cookie`, session middleware); model pass |
| `role:authorization` | The code decides whether an authenticated principal may perform an action. | `func:authz:*` tags; lexical identifiers (`authorize`, `has_role`, `permission`, `is_admin`, `@login_required`); model pass |
| `role:input-parsing` | The code turns bytes from outside the process into structured values. | graph entry points of class `remote`, `argv`, `file`, `ipc`, `local_user`; lexical parsers (`strtol`, `atoi`, `sscanf`, `strtok`, `parse_*`, request body accessors); model pass |
| `role:serialization` | The code encodes or decodes a structured interchange format. | `func:data:parse-*` and `func:data:deserialize-native` tags; serialization library includes or imports (cJSON, json, yaml, pickle, protobuf, serde); model pass |
| `role:crypto` | The code performs cryptographic operations or manages keys. | `func:crypto:*` tags; crypto library includes or imports (`openssl/`, `EVP_`, `hashlib`, `Cipher`, `hmac`); model pass |
| `role:storage` | The code reads or writes a database, object store or persistent record. | `func:data:sql-query`, `func:data:orm`, `func:data:nosql-query`, `func:data:ldap-query` tags; lexical database clients; model pass |
| `role:logging` | The code writes operational or audit records. | `func:telemetry:*` tags; graph `log_output` sinks; lexical logging calls (`syslog`, `logging.`, `logger.`, `spdlog`, `log_message`); model pass |
| `role:config` | The code reads environment, flags or configuration files that change behaviour. | `surface:entry:env-config`, `func:secrets:env-read`, `func:secrets:config-read` tags; lexical `getenv`, `os.environ`, `process.env` |
| `role:build-glue` | The file drives a build, packaging, container or CI step rather than running in the product. | `infra:supply:*`, `infra:ci:*`, `infra:container:*` path tags; build-descriptor path rules (`CMakeLists.txt`, `Makefile`, `*.cmake`, `setup.py`, `build.gradle`, `Dockerfile`) |
| `role:test` | The first-party file exists to exercise other code. | test-framework includes or imports (`gtest`, `pytest`, `unittest`, `@Test`, `testing.T`) in a file the dispositions keep first-party |

### `exposure` (bases `declared`, `invoked`, `derived`)

| Value | Definition | Evidence |
| --- | --- | --- |
| `exposure:client-facing` | A caller outside the process can reach the code without operator action. | derived from `mechanism:networked-listener`, `mechanism:http` or `mechanism:rpc` on the same file |
| `exposure:internal` | The code is reached only by other code of the same process or deployment. | reserved for a build or deployment fact that names an internal-only interface (no deterministic rule today; assigned only by the model pass with a cited line) |
| `exposure:operator-only` | Only a local operator who starts the program or feeds it a file reaches the code. | derived from `mechanism:cli` or `mechanism:file` when the same file has no listener-class mechanism (`networked-listener`, `http`, `rpc`, `ipc`) |
| `exposure:build-time` | The code runs during build, packaging or CI, not in the product. | derived from `role:build-glue` |

### `trust` (bases `declared`, `invoked`, `derived`)

| Value | Definition | Evidence |
| --- | --- | --- |
| `trust:user-tainted` | Data from an anonymous or end-user caller flows into the code. | graph entry point `remote`, `argv`, `local_user`; derived from `mechanism:networked-listener`, `mechanism:http`, `mechanism:rpc`, `mechanism:cli`; lexical request-body or argv accessors |
| `trust:partner-tainted` | Data from an authenticated peer system flows into the code. | lexical outbound-client-with-response patterns are *not* enough; assigned only by the model pass with a cited line, or from `func:authn:mtls-client` plus a listener |
| `trust:trusted` | Only data produced by the same trust domain flows into the code. | graph entry point `internal` or `database` with no other entry class on the file |
| `trust:none` | No external data reaches the code. | reserved; never assigned deterministically (absence of a source is not evidence) |

### `mechanism` (bases `declared`, `invoked`, `derived`)

| Value | Definition | Evidence |
| --- | --- | --- |
| `mechanism:networked-listener` | The code accepts or reads from a network socket. | graph entry point `remote`; lexical `listen`, `accept`, `bind`, `recv`, `recvfrom` with a socket include; `func:net:http-route`, `func:net:tls-server`, `func:net:websocket` |
| `mechanism:rpc` | The code exposes or serves a remote-procedure interface. | `func:net:grpc` tag; lexical gRPC, Thrift, XML-RPC, JSON-RPC server patterns |
| `mechanism:http` | The code serves HTTP routes or handlers. | `func:net:http-route` tag; lexical route decorators, router registrations, `http.ListenAndServe`, `@GetMapping` |
| `mechanism:ipc` | The code reads a local interprocess channel (pipe, Unix socket, shared memory, D-Bus). | graph entry point `ipc`; `surface:entry:local-ipc`, `func:exec:ipc` tags; lexical `AF_UNIX`, `mkfifo`, `shm_open`, `dbus` |
| `mechanism:file` | The code reads files named at run time. | graph entry point `file`; `surface:entry:file-input`, `func:fs:read` tags; lexical `fopen`, `ifstream`, `open(`, `readFile`, `os.Open` |
| `mechanism:cli` | The code is started from a command line and reads its arguments. | graph entry point `argv`; `surface:entry:cli` tag; lexical `argv`, `getopt`, `argparse`, `sys.argv`, `os.Args`, `flag.Parse`, `clap` |

### `asset` (bases `declared`, `invoked`, `derived`, `reported`)

| Value | Definition | Evidence |
| --- | --- | --- |
| `asset:credentials` | Passwords, API keys or other secrets that authenticate a principal pass through the code. | `data:credential`, `func:authn:password`, `func:authn:api-key`, `func:secrets:*` tags; derived from `role:auth`; lexical `password`, `passwd`, `api_key`, `secret_key` |
| `asset:session-tokens` | Session identifiers, cookies or bearer tokens pass through the code. | `data:session-token`, `func:session:cookie`, `func:session:token-refresh`, `func:authn:jwt` tags; lexical `session_id`, `set_cookie`, `bearer` |
| `asset:pii` | Personal data of natural persons passes through the code. | `data:pii` tag; lexical `ssn`, `social_security`, `date_of_birth`, `passport_number`, `email_address`; model pass |
| `asset:keys` | Cryptographic key material passes through the code. | `data:key-material`, `func:crypto:key-mgmt`, `func:crypto:asymmetric-*` tags; lexical `private_key`, `PEM`, `KeyPair` |
| `asset:money` | Monetary value or payment instruments are handled. | `data:financial` tag; lexical `payment`, `invoice`, `balance`, `stripe`, `paypal`, `braintree`; model pass |

### `state` (bases `declared`, `invoked`, `derived`)

| Value | Definition | Evidence |
| --- | --- | --- |
| `state:session` | The code keeps per-principal or per-connection state across calls. | derived from `role:session`; `func:session:server-store`; lexical session structs or stores |
| `state:cache` | The code keeps a memoized or evicting copy of other data. | lexical `cache`, `lru_cache`, `memcache`, `redis` client use |
| `state:persistent-store` | The code writes state that survives the process. | derived from `role:storage`; `func:fs:write` tag |
| `state:stateful` | The code keeps any state between calls. | derived from any other `state:*` tag on the same file |

`state:session` reconciles the T-5008 Scope list (`stateful`, `cache`, `persistent-store`) with its
Done-when, which names `state:session` for the HTTP fixture.

### `target` (basis `derived` only; subject kind `component`)

| Value | Definition | Evidence |
| --- | --- | --- |
| `target:web-api` | The component serves HTTP or RPC to clients. | `mechanism:http` or `mechanism:rpc` on any first-party file of the component |
| `target:mobile` | The component is an Android or iOS application. | `component:android-mobile`, `component:ios-mobile` or `func:mobile:*` on the component |
| `target:cli` | The component is a program started from a command line. | `mechanism:cli` on a first-party file and no `web-api` class |
| `target:network-service` | The component accepts network input that is not HTTP or RPC (a raw-socket listener). | `mechanism:networked-listener` on a first-party file and no `mechanism:http` or `mechanism:rpc` (rests on absence, confidence `medium`) |
| `target:library` | The component is linked into other programs and has no entry mechanism of its own. | a build receipt that builds only libraries for the component, or no `mechanism:*` tag on any first-party file while the component has first-party code |
| `target:build-tooling` | Every first-party file of the component is build glue. | all first-party files carry `role:build-glue` |
| `target:test-only` | The component has no first-party file that is not test code. | dispositions and `role:test` leave no first-party product file |

A component may carry more than one class (a repository with a CLI and an HTTP service). When no
rule fires the component gets no `target:*` tag and the pass records the gap
`collation:target_class_unresolved` for it; it never guesses `library`.

A raw socket server that is not HTTP (the smoke-cpp request server) is `target:cli` and
`target:network-service` with `exposure:client-facing` and `trust:user-tainted` on its request
handler: ASVS admits the transport-agnostic chapters only (V1, V2, V5, V7, V16; the OWASP workbench
decides this per control), MASVS does not apply, and the memory-safety and injection hunts still
route on the facets.

## 3. Derivation

The pass runs inside `job_security_tagging` (section 4) and reads only the attempt's accepted
retrieval manifest and shards plus hash-verified source bytes of first-party files. It never walks
the target tree. Every assignment is a `tag-assignment/1` record (`taxonomy.assignment`): tag,
basis, subject (`source_file` or `component`), producer, resolving evidence with a span, and for
derived tags the rule id and the assignment ids it derives from. Bases follow the taxonomy table:
`declared` for an import, include, path or lexical reference; `invoked` for an accepted graph site;
`derived` for a facet implied by other assignments through a pinned rule; `reported` for the model
pass. A facet tag derived from another tag cites that tag's assignment id in `derived_from`, so
`trace` walks from `exposure:client-facing` to the `recv` line that established the listener.

### 3.1 First-party scope

The pass classifies every accepted `source_file` row with the T-165 dispositions
(`review/dispositions.py`): `vendored`, `sdk`, `generated` and `test` files receive no facet tags
and are counted in the collation artifact under `skipped_dispositions`. The globs are the
`[jobs.job_inference_security_review.settings.source_dispositions]` table; the configuration
loader resolves the same table into the tagging job's `collation` settings so there is one source
of truth, and a run records both in its resolved configuration. A file with no language (a build
descriptor) is first-party and still collated: it gets `role:build-glue` from the path rules.

### 3.2 Sources, in precedence order

| Source | What it yields | Basis | When it is missing |
| --- | --- | --- | --- |
| Capability tags already collected by the job (`lang:*`, `func:*`, `surface:*`, `data:*`, `infra:*`, `component:*`; `declared` from paths and packages, `invoked` from graph entry/sink sites, `reported` from tools) | facets through the tag-to-facet rules (section 3.3) | `derived`, citing the input assignment | the facets that need them are not assigned; the job's existing `graph-capability:missing_graph` gap already names an absent graph index, and the collation artifact adds `collation:no_graph_facts` |
| Lexical facts: include, import, identifier and path patterns matched line by line against the hash-verified bytes of each first-party file, from pinned `collation.lexical_rules` and `collation.path_rules` in `data/reference/taxonomy/capability-rules.json` | facets and the `func`/`surface` tags a rule names, with the matched line as the evidence span | `declared` (confidence `high` for includes, imports and paths; `medium` for identifier patterns) | a file over `max_source_bytes_per_file` or unreadable is skipped with gap `collation:source_unread:<path>`; a language with no lexical rules is skipped with `collation:no_lexical_rules:<lang>` |
| Build receipts (`build` index, `build_action` rows with build points) | `target:library` when a component's build points produce only libraries and no file has an entry mechanism | `derived` | no `build` shard: `collation:no_build_facts`; the library class then rests on the recorded absence of mechanisms (confidence `medium`) |
| Target documents (`documents` index, kinds `openapi`, `postman`, `graphql`, `protobuf`, `asyncapi`) | `mechanism:http` from an OpenAPI, Postman or GraphQL document, `mechanism:rpc` from a protobuf or AsyncAPI document, on the owning component | `declared` | empty or absent: `collation:no_documents` (the smoke-cpp run indexed none). README text is not read: the catalog does not index it and free text would not give a closed value |
| Model pass (section 6) | `role`, `asset`, purpose | `reported` | disabled: a payload fact (`model_pass: disabled`), not a gap; rejected output: `collation:model_pass_rejected:<component>` |

The rules are data, pinned by hash with the capability-rules file (`collation.lexical_rules`,
`collation.path_rules`, `collation.tag_rules`, `collation.facet_rules`, `collation.target_rules`), so a
vocabulary or rule change changes the pinned identity and every shard fingerprint. Three target
classes are structural and live in the collector (`jobs/job_security_tagging/collation.py`):
`target:build-tooling` (every first-party file is `role:build-glue`), `target:test-only` (every
non-glue first-party file is `role:test`) and `target:library` (section 2); the data rules decide
`web-api`, `mobile` and `cli`.

### 3.3 Tag-to-facet rules (`derived`)

| Input tag on a file | Facet tags on the same file |
| --- | --- |
| `func:authn:*` | `role:auth`, `asset:credentials` |
| `func:session:*` | `role:session`, `state:session`, `asset:session-tokens` |
| `func:authz:*` | `role:authorization` |
| `func:crypto:key-mgmt`, `func:crypto:asymmetric-sign`, `func:crypto:asymmetric-encrypt` | `role:crypto`, `asset:keys` |
| other `func:crypto:*` | `role:crypto` |
| `func:data:parse-json`, `parse-xml`, `parse-yaml`, `deserialize-native` | `role:serialization`, `role:input-parsing` |
| `func:data:sql-query`, `orm`, `nosql-query`, `ldap-query` | `role:storage`, `state:persistent-store` |
| `func:telemetry:*` | `role:logging` |
| `func:secrets:*` | `role:config`, `asset:credentials` |
| `func:net:http-route` | `mechanism:http`, `mechanism:networked-listener` |
| `func:net:grpc` | `mechanism:rpc` |
| `func:net:tls-server`, `func:net:websocket` | `mechanism:networked-listener` |
| `func:exec:ipc` | `mechanism:ipc` |
| `func:fs:read` | `mechanism:file` |
| `func:fs:write` | `state:persistent-store` |
| `surface:entry:remote-input` | `mechanism:networked-listener`, `trust:user-tainted`, `role:input-parsing` |
| `surface:entry:cli` | `mechanism:cli`, `trust:user-tainted`, `role:input-parsing` |
| `surface:entry:file-input` | `mechanism:file`, `role:input-parsing` |
| `surface:entry:local-ipc` | `mechanism:ipc`, `role:input-parsing` |
| `surface:entry:env-config` | `role:config` |
| `data:credential` / `data:session-token` / `data:pii` / `data:key-material` / `data:financial` | `asset:credentials` / `asset:session-tokens` / `asset:pii` / `asset:keys` / `asset:money` |
| `infra:supply:*`, `infra:ci:*`, `infra:container:*` | `role:build-glue` |
| `component:android-mobile`, `component:ios-mobile`, `func:mobile:*` (component) | contribute to `target:mobile` |

### 3.4 Facet-to-facet rules (`derived`, same file)

| Rule | Condition | Assigns |
| --- | --- | --- |
| `exposure-from-listener` | `mechanism:networked-listener` or `mechanism:http` or `mechanism:rpc` | `exposure:client-facing`, `trust:user-tainted` |
| `exposure-from-operator-channel` | `mechanism:cli` or `mechanism:file`, and no `mechanism:networked-listener`, `mechanism:http`, `mechanism:rpc` or `mechanism:ipc` on the file | `exposure:operator-only` |
| `trust-from-cli` | `mechanism:cli` | `trust:user-tainted` |
| `exposure-from-build-glue` | `role:build-glue` | `exposure:build-time` |
| `state-from-session` | `role:session` | `state:session` |
| `state-from-storage` | `role:storage` | `state:persistent-store` |
| `stateful` | any of `state:session`, `state:cache`, `state:persistent-store` | `state:stateful` |
| `asset-from-auth` | `role:auth` | `asset:credentials` |

A rule whose condition names an absent tag (`exposure-from-operator-channel`) records the
condition in the assignment's `evidence` so the reader sees that it rests on absence at the time of
collation; its confidence is `medium`. No other rule rests on absence.

### 3.5 Component roll-up and target class

Every facet tag on a first-party file of component `C` is also assigned to `C` (`derived`, citing
the file assignments, one record per tag). The target-class rules of section 2 then run over the
component's tags and its build points, producing `target:*` assignments that cite the facet
assignments and build-action rows they rest on. A component with no first-party file gets no
facet or target tag and the gap `collation:no_first_party_files:<component>`.

### 3.6 Determinism

Rules are applied in file order (sorted path), rule order (as pinned), then derivation rounds to a
fixed point (bounded by the rule count). Records are merged by content identity
(`merge_assignments`) and the collation artifact is canonical JSON, so the same accepted manifest,
pinned taxonomy and settings give byte-identical artifacts and shard fingerprints on any host.

## 4. Placement in the graph

The pass is a new step `collation` of `job_security_tagging`, after `collection` and before
`crosswalk`:

```
taxonomy -> scope -> collection{source_facts, observation_facts, coverage_gaps}
        -> collation{collate_facets[, model_pass]} -> crosswalk -> integrity -> publication
```

`collate_facets` is the deterministic pass; `model_pass` (stage 4) publishes a disabled record unless
`settings.collation.model_pass.enabled` is true.

Why a step rather than a job between tagging and package assembly:

- The facets are tag assignments of the same taxonomy, pinned by the same hashes, validated by the
  same `integrity.validate_assignments` unit and published in the same `tags` index, so every
  consumer that already reads tags (`packages.py` routing tags, `units.py` tag density, OWASP
  routing context, `find`/`search`/`trace`) sees them with no new contract. A separate job would
  need its own `JobContract`, datasets, registry and topology entries, Dagster asset, accepted
  manifest rewrite and handoff, and would publish a second `tags` producer that `routing_tags`
  would have to merge.
- The crosswalk can derive controls from facets (an `asvs5:v6` chapter from `role:auth` on a
  `target:web-api` component) in the existing `apply_crosswalk` unit because collation precedes it.
- The job already holds the hash-verified source reader used for graph sites; lexical facts reuse
  it.

Contract parity (`.claude/skills/add-a-job-contract/SKILL.md`): `TOPOLOGY` in
`jobs/job_security_tagging/job.py` gains the step and its task(s), and `appsec-review.toml` gains
the matching `[jobs.job_security_tagging.steps.collation]` tables, so `_validate_config` keeps
refusing a topology that differs from central configuration. No new dataset: the facet records are
`tag_assignments` rows in the declared `tags` index, and the collation artifacts
(`collation.json`, `unit-purposes.json`) fall under the declared
`artifacts/security-tagging/*.json` pattern. The job's `JobContract.inputs` already name every
producer the pass reads (`job_target_catalog` source files, symbols, components, documents and
build units; `job_code_graph_index`; `job_language_build` build actions). Dagster needs no change:
the job's asset boundary is unchanged.

Typed settings, all under `[jobs.job_security_tagging.settings.collation]`:

| Key | Default | Meaning |
| --- | --- | --- |
| `max_source_bytes_per_file` | 262144 | Largest first-party file the lexical rules read; a larger file is skipped with a named gap |
| `max_files_per_component` | 4096 | Files collated per component; the rest are skipped with a named gap |
| `source_dispositions` | resolved by the loader from `jobs.job_inference_security_review.settings.source_dispositions` | The T-165 globs; a literal table here must equal that one or configuration loading fails. The resolved table is written into the tagging job's frozen settings (`config/collation.py`, `config/loader.py`) |
| `model_pass.enabled` | `false` | Section 6; the deterministic pass never depends on it |
| `model_pass.max_components` | 64 | Components the model pass may describe per run |
| `model_pass.max_excerpt_lines` | 400 | Source lines sent per component, chosen from facet evidence spans |
| `model_pass.model` | required only when enabled | A complete model profile (`provider`, `model`, `reasoning`, `max_input_tokens`, `max_output_tokens`, `timeout_seconds`, `retries`) |

These are semantic settings: they change which tags exist, so they are part of the run's frozen
configuration identity.

## 5. The published shard and the consumers

### 5.1 Shard

Facet and target assignments are `tag-assignment/1` records of family `code_facts`, published in
the `tags` index under shard id `facets` (the existing code-facts shard keeps the capability tags;
a separate shard lets a consumer open only the facets). Each row carries `tag`, `namespace`,
`basis`, `subject` (`kind`, `logical_id`, `path`, `component_id`), `producer`
(`{"name": "collation", "rule_id": ..., "version": <capability-rules sha256>}`), `evidence`
(`ref`, `path`, `file_sha256`, `span {start_line, end_line}`, and for lexical facts the matched
`pattern` id; never the matched text), `derived_from` and `confidence`. The shard fingerprint covers
the upstream manifest, the three taxonomy hashes, the component topology and the record content.

The collation artifact `artifacts/security-tagging/collation.json`
(`appsec-review/collation-pass/1`) is the human view: per first-party file its facet tags with
assignment ids, per component its facets and target classes, the skipped files by disposition, the
gaps, and the rule identities.

### 5.2 Consumers and exactly what each reads

| Consumer | Reads | Uses it for |
| --- | --- | --- |
| Unit context (`review/packages.py`, `_Assembler.unit_context_document`, T-5000) | the `facets` shard rows whose subject is one of the unit's source files or its component | `package-unit-context/2` gains `facets` (`unit-facets/2`, evolving <!-- historical:begin -->`unit-facets/1`<!-- historical:end -->): the unit's facet tags (union over its files and component, each with its strongest basis, distinct-subject count, assignment ids and entity identities), its component's `target_classes`, and from stage 3 the derived hunt obligations and the model-pass purpose when accepted. The facet entity identities join `entity_ids`, so a worker may `trace` them. Every hunt partition of the unit references it once |
| Hunt obligations (`review/packages.py`, `FACET_OBLIGATIONS`) | the unit's facet tags | A closed table maps facets to named hunt obligations carried in the unit context beside the predicate `obligations`: `role:auth` → `authentication_enforced`; `role:session` or `state:session` → `session_lifecycle`; `trust:user-tainted` → `input_validation`; `role:authorization` → `authorization_checked`; `asset:credentials` or `asset:keys` → `secret_handling`; `role:serialization` → `deserialization_safety`; `role:storage` → `storage_query_safety`; `role:crypto` → `crypto_misuse`; `mechanism:file` → `path_and_file_handling`; `role:logging` → `logging_hygiene`. Each obligation names the tags it rests on. The package view renders them as bounded questions; the obligation vocabulary is closed (`hunt-facet-obligations/1`) |
| Stack routing (`guidance/routing.py`, `route_stack`) | `mechanism:*` and `exposure:*` tags of the package scope | `mechanism:rpc` joins the C-family RPC basis; a managed-language scope with `mechanism:http`, `mechanism:networked-listener` or `mechanism:rpc` selects its service stack even when no `component:*` tag exists (today a language alone never selects a service stack; the real run had no component tags) |
| Persona routing (`route_persona`, `rank_personas`) | facet namespaces join `LOCATION_NAMESPACES`, so a persona whose `covers` names `role:auth` or `asset:credentials` is ranked on them | personas may cover facets; the partition check stays over `cwe`/`func`/`infra`/`data` so no persona is forced to claim every facet |
| Hunt panel (`hunt_panel`) | `trust:user-tainted`, `exposure:client-facing` | a tainted or client-facing unit tries `entry_down` before `sink_up`; the panel records the facets that decided it under `strategy_basis` |
| Lead admission weighting (`review/units.py`, `RankWeights`) | `exposure:client-facing`, `trust:user-tainted` on the unit's files | the rank rule becomes `review-unit-rank/4`: a signal `facets` adds `ranking.facet_exposure` and `ranking.facet_trust` points (typed, default 50 each of 1000, `[jobs.job_inference_security_review.settings.ranking]`) so exposed, tainted units are hunted first; a unit with no facet record scores 0, not unknown, because collation is exhaustive over first-party files; an absent tagging producer is unknown |
| OWASP target class and applicability (`owasp_workbench/engine.py`) | the component's `target:*`, facet and `component:*` tags from `routing_context` | `classify_components` is replaced by a tag reader that records the target classes, the legacy control roles derived from facets (`role:auth` → `authentication_identity`, `role:storage` → `storage`, `role:crypto` → `cryptography_data_protection`, `mechanism:http`/`rpc`/`networked-listener` → `application_api_server` and `network`, `target:mobile` → the mobile roles, `role:build-glue` → `build_supply_chain`, `role:test` → `test_development_only`) and the assignment ids as citations. `build_applicability` first applies the class gate: ASVS needs `target:web-api` (or `target:network-service` for the transport-agnostic chapters V1, V2, V5, V7, V16), MASVS needs `target:mobile`; a component without the class gets one `not_applicable` row per selected control, each citing the target-class assignment, and a per-family ledger entry (`partially_applicable` for the network-service case). Such a component produces no batch, no `OWASP_WORKER_STARTED` event and no `control_evidence` fact, and the job ends `SUCCEEDED`. `_deterministic_roles`, `_CAPABILITY_TAG_ROLES` and `characterize_components` are deleted; `classify_components` (`component-classification/2`) and `target_class_ledger` (`target-class-ledger/1`, published as `target-class-ledger.json` and in the handoff) replace them. A component with no `target:*` tag is `cannot_determine` for every control and is not dispatched; the job's terminal status counts gaps only (catalog and result gaps), not method limitations |
| Threat-model seeding (`job_threat_model_generation`) | `mechanism:*`, `exposure:*`, `trust:*` per component | external entities and trust boundaries of the DFD; documented here, not wired by T-5008 |
| Report "what this code is" (`reporting`) | the component's `target` classes and facets, the model-pass purpose | one sentence per component in the developer report; documented here, not wired by T-5008 |
| Operators | `find index=tags shard=facets kind=tag_assignment` and `trace` from a facet to its evidence | answering "what is this target" from the run |

The resolved hunt body carries the unit's facets as `unit_facets` (merged from the unit context) and the
package view renders them under `facets` as closed tag ids, target classes and obligations only.
The unit context is the only place a worker sees facets, as closed tag ids, and the only free
text that can accompany them is the model-pass purpose paragraph, which is bounded, cited and
labelled as a model statement (section 6). Facet tags never enter the governing rules, a persona,
a role or a task prompt.

## 6. Optional model pass (stage 4; default off)

One bounded, recorded model call per first-party component fills what the deterministic rules
cannot: a `role` or `asset` that only reading the code reveals, and a one-paragraph statement of
purpose.

- **Runtime skill.** `pipeline/skills/unit-purpose-collation/SKILL.md`
  (`metadata.audience: runtime-worker`), registered in `pipeline/guidance/registry.json` under
  `runtime_skills` with `jobs: ["job_security_tagging"]`, loaded only through
  `guidance.skills.load_runtime_skill`. It tells the worker to name only vocabulary values, to cite
  a line of the supplied excerpts or a deterministic assignment id for every claim, and to answer
  `unknown` rather than guess.
- **Request.** A `ModelRequest` whose summary holds the component's deterministic facet tags with
  their assignment ids, the first-party file list, and at most `max_excerpt_lines` source lines
  chosen around the facet evidence spans (each line labelled `path:line`). The vocabulary values
  allowed for `role` and `asset` are listed in the request. No tool is granted.
- **Closed result schema** `appsec-review/unit-purpose-proposal/1`:
  `{component_id, role: [role values], asset: [asset values], purpose: string <= 600 chars,
  claims: [{tag, citations: [{path, line} | {assignment_id}]}], unknown: [facet names]}`.
  Unknown keys, a value outside the vocabulary, a citation that is not a supplied line or a
  deterministic assignment id, or a purpose over the bound reject the whole proposal.
- **Recording.** The call goes through `appsec_review.inference.infer`, so the run-owned recording
  layer records and replays it like every other model call; the proposal, its hash and the
  acceptance decision are written to `artifacts/security-tagging/unit-purposes.json`.
- **Acceptance.** Each accepted claim becomes a `reported` assignment with producer
  `collation-model-pass`, evidence the cited line (hash-verified span) or the cited assignment, and
  confidence `medium`. A rejected proposal leaves the deterministic tags untouched and records
  `collation:model_pass_rejected:<component>`; a provider failure records
  `collation:model_pass_failed:<component>`.
- **Setting.** `model_pass.enabled = false` by default in every shipped profile; when disabled the
  unit publishes an empty proposal set with `mode: disabled` and no gap.
- **Implementation.** `jobs/job_security_tagging/model_pass.py` (`run_model_pass`), the specialized
  worker `unit_purpose` (`guidance/workers.py`: role `unit_purpose_collator`, task
  `unit_purpose_collation`, skill `unit-purpose-collation`), the role fragment
  `pipeline/prompt-fragments/roles/unit_purpose_collator.md`. The request carries the component's
  deterministic facets with assignment ids, its first-party paths, the allowed `role` and `asset`
  values and the excerpts (the lines the facets cite, then each file's first 20 lines, within
  `max_excerpt_lines`), each line clipped to 200 characters. Accepted claims are `reported`
  assignments with producer `collation-model-pass`; the purpose paragraph is stored in
  `unit-purposes.json` beside the proposal hash and acceptance decision. Carrying the purpose into
  the unit context (section 5.2) needs an accepted-upstream read of that artifact by package assembly
  and is not wired by T-5008.

## 7. Invariants

1. Tags are routing data. No consumer treats a facet as evidence of a weakness, a control or
   their absence; a claim cites source lines.
2. Closed vocabulary. Every facet value is in the pinned vocabulary; the collector, the model-pass
   validator and the unit-context schema reject anything else.
3. No free text from tags reaches a model. A worker sees tag ids, assignment ids and the bounded
   purpose paragraph labelled as a model statement; never a matched source line, a rule's regex or
   a README sentence.
4. A missing source is a named gap, never a guessed tag. Absence of a tag is unknown, except where
   section 3.4 states a rule that rests on absence and records it.
5. First-party only. Vendored, SDK, generated and test files get no facets; a unit that reaches
   them is already refused by the T-165 gate.
6. Determinism. Same accepted manifest, taxonomy pins and settings give byte-identical artifacts
   and fingerprints.
7. Every assignment is traceable to its evidence through `trace`, and every derived assignment to
   the assignments it rests on.

## 8. Proving cases

Unit tests under `tests/unit/job_security_tagging/test_collation.py`, `tests/review/` and the
OWASP suites, each under ten seconds, over canned accepted indexes (the existing
`CannedIndexes` helper) and hash-verified fixture bytes:

1. **HTTP login route** (T-5008 Done-when (a)): a Python file with a Flask route that reads
   `request.get_json()`, calls `verify_password`, and stores `session["user"]` gets `role:auth`,
   `role:session`, `exposure:client-facing`, `trust:user-tainted`, `mechanism:http`,
   `mechanism:networked-listener`, `state:session`, `asset:credentials`, each with a basis and an
   evidence span; its component gets `target:web-api`.
2. **CLI main** (Done-when (a)): a C file whose `main(int argc, char **argv)` reads `argv[1]` gets
   `mechanism:cli`, `trust:user-tainted`, `exposure:operator-only`; its component gets `target:cli`.
3. **No graph index**: the same fixtures with no `graph` shard record `collation:no_graph_facts`
   and still assign the mechanism and exposure facets the lexical rules prove.
4. **Determinism**: two runs over the same canned inputs (rows supplied in different orders) give
   byte-identical `collation.json` and identical shard fingerprints.
5. **Hunt package and unit context** (Done-when (b)): assembling packages over fixture 1 yields a
   unit context carrying the facets, `target:web-api`, and the obligations `authentication_enforced`,
   `session_lifecycle`, `input_validation`, `secret_handling`, and every hunt partition references
   it; the lead lane body is unchanged.
6. **Routing**: `route_stack` with `lang:python` and `mechanism:http` selects `python_service`;
   `hunt_panel` with `trust:user-tainted` orders `entry_down` first; `rank_personas` ranks a persona
   covering `role:auth` above an uncovered one.
7. **OWASP target class** (Done-when (c)): a component with `lang:cpp` and `mechanism:cli` yields
   one `not_applicable` row per selected ASVS and MASVS control citing the `target:cli` assignment,
   zero batches, zero `OWASP_WORKER_STARTED` events, zero `control_evidence` facts and a
   `SUCCEEDED` handoff; the HTTP component is `target:web-api` and keeps its ASVS matrix; the
   workbench no longer exports `characterize_components`' keyword classifier.
8. **Vocabulary and separation** (Done-when (d)): the pinned hashes in `appsec-review.toml` match
   the vocabulary and rules files; `tests/test_security_tagging.py` and
   `tests/test_skill_separation.py` pass.
9. **Model pass** (stage 4): a scripted transport returning a valid proposal adds `reported`
   `role`/`asset` assignments and a purpose; a proposal with an uncited claim or a value outside the
   vocabulary is rejected, the deterministic tags are unchanged and the gap is recorded; with
   `enabled = false` no transport call happens.

### 8.1 Expected facets for the smoke-cpp first-party files

Written from reading `targets/appsec-review-smoke-cpp/src/` (not the answer key). The user checks
the live run against this table (the live run is not part of this change).

| File | Expected facets (file level) | Established by |
| --- | --- | --- |
| `src/main.cpp` | `mechanism:cli`, `trust:user-tainted`, `exposure:operator-only`, `role:input-parsing` | `argv[1]`, `argv[2]` and `atoi` in `main`; no socket call in this file |
| `src/request.h` | none | declaration only |
| `src/request.cpp` | `mechanism:networked-listener`, `trust:user-tainted`, `exposure:client-facing`, `role:input-parsing`, `role:session`, `state:session`, `state:stateful`, `role:serialization`, `mechanism:file`, `role:logging` | `<sys/socket.h>`, `recv`/`send`; `strtol`/`strchr` request parsing; `session_open`/`session_touch`/`session_close`; `<cJSON.h>`; `fopen`/`fread` in `serve_file`/`read_asset`; `log_message` |
| `src/session.cpp` | `role:session`, `state:session`, `state:stateful` | `session_open`/`session_touch`/`session_close` definitions |
| `src/cache.h` | `role:session`, `state:session`, `state:stateful` | `struct Session` and the `session_*` declarations |
| `src/synthetic.cpp` | `mechanism:cli`, `trust:user-tainted`, `exposure:operator-only`, `role:input-parsing`, `role:config` | `argv[1]`, `atoi` in `main`; `getenv("INPUT_LEN")`; `send` without a receive is not a listener |
| `src/util.h` | none | declarations only |
| `src/util.c` | none | `system("/bin/true")`, `memcpy`, `sprintf` are capability facts (`func:exec:process-spawn`, `func:exec:unmanaged-memory` from graph sinks), not facets |
| `CMakeLists.txt` | `role:build-glue`, `exposure:build-time` | build-descriptor path rule |
| component | facets above rolled up; `target:cli`, `target:network-service` | `mechanism:cli` on `main.cpp`, `mechanism:networked-listener` on `request.cpp`, no `mechanism:http` or `mechanism:rpc` |

The expected outcome for the OWASP job on that target is therefore: `target:cli` and
`target:network-service`; ASVS `partially_applicable` (the transport-agnostic chapters V1, V2, V5,
V7, V16 are `unsupported_missing_evidence` because no recogniser reads C/C++ until T-5011/T-5013,
the other chapters `not_applicable` citing the class); MASVS not applicable with the class
citation; no batch and no model call (run `2026-11-16-0005` instead read no tag at all because a
graph shard exhausted the shared routing scan; tag discovery is now separate); and the hunt for
`request.cpp` carrying `input_validation`, `session_lifecycle`, `path_and_file_handling` and
`logging_hygiene` obligations beside the predicate obligations.

## 9. Implementation state

| Stage | Content | State |
| --- | --- | --- |
| 1 | This document and the pointers in the three operations pages | this change |
| 2 | Vocabulary, pinned rules, `collation.collate_facets`, unit context `facets` | implemented (`tests/unit/job_security_tagging/test_collation.py`, `tests/review/test_unit_facets.py`) |
| 3 | Hunt obligations, routing, rank signal, OWASP target class, classifier deletion | implemented (`tests/unit/job_owasp_control_assessment/test_target_class.py`, `test_target_class_job.py`, `tests/review/test_unit_facets.py`, `tests/review/test_units.py`, `tests/test_guidance_routing.py`) |
| 4 | Model pass, runtime skill, typed setting | implemented, off by default (`tests/unit/job_security_tagging/test_model_pass.py`); the purpose paragraph is recorded in `unit-purposes.json` and is not yet carried into the unit context (see section 6) |

Not covered by T-5008: threat-model seeding and the report sentence (section 5.2), catalog-fact
dispositions (T-165 remainder), catalog symbols as a facet source (lexical facts cover the names), and
any live-run measurement.
