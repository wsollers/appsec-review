# Bounded static deployment inventory

`appsec_review.deployment` is the F05 **leaf domain**, not a job, registry, store,
collector, model loop or threat-model authority. It accepts already-admitted bytes and
returns conservative static declarations with resolving evidence. It never opens target
paths, follows includes, renders templates, installs target packages, executes target
code, contacts clouds or scans sockets.

F02 owns the authoritative job contracts. F06 must wire admission, central typed settings,
accepted inputs, dataset publication, registry/topology/test-map registration and retrieval
to those contracts. None of those integration surfaces is implemented by this domain.

## Public contracts

| API | Contract |
| --- | --- |
| `SourceDocument(path, data, sha256, format, deployment, scope="target", variant=None, service=None)` | Exact UTF-8 source bytes and accepted SHA-256; canonical target-relative POSIX logical path. `deployment`, `scope`, `variant` and configuration attachment `service` are adapter-owned context, never target assertions. |
| `Selection(deployment, variant, paths)` | One explicitly selected, already-rendered variant per deployment, naming exact supplied paths. It is not evidence that the variant is running. Unsupported/dynamic descriptors and unresolved overlays cannot select a service. |
| `Limits(...)` | Frozen, positive, bounded parser limits. F06 should supply these from its typed configuration, not prompts. |
| `extract_inventory(documents, *, target_snapshot, selections=(), limits=Limits()) -> Inventory` | Pure deterministic extraction. `Inventory.to_dict()` is the JSON publication value; `validate_inventory(value)` validates its closed shape and internal references. |
| `resolve_evidence(evidence, source) -> bytes` | Verify path, exact SHA-256, byte span and line span against the supplied source. No file read or newline normalization. |
| `inventory_schema()`, `observations_schema()`, `catalog_schema()` | Fresh closed JSON Schema 2020-12 objects, generated from domain records. Unknown fields are rejected, including nested records. These are not shared job or retrieval schemas. |
| `catalog()` | Versioned signatures, registered evidence-rule IDs/classes, precise supported syntax and an explicit unsupported-family inventory. The inventory records its canonical SHA-256. |
| `import_observations(document, *, target_snapshot, environment, as_of, limits=Limits())` | Parse a closed imported JSON snapshot against caller-supplied target/environment/time. Never collect observations. |
| `compare_observations(inventory, imported)` | Compare only explicitly bound service IDs, environment, endpoint role, port and transport. Does not bind an endpoint by port, banner or product name. |

Wire identifiers are `appsec-review/deployment-inventory/1`,
`appsec-review/deployment-evidence/1`, `appsec-review/deployment-signatures/1` and
`appsec-review/deployment-observations/1`. Python modules hold the authoritative schemas
and catalog, so installed packages need no new package-data registration. Schema views
are generated; do not hand-edit generated copies.

Service IDs hash the target snapshot, adapter deployment, variant and logical key.
Source IDs additionally bind path, exact source hash, format, scope and attachment.
Evidence records carry source ID, original path/hash, inclusive one-based line range,
half-open byte range, versioned extraction rule and authority. IDs and JSON output are
independent of input order. No full source document or secret setting value is copied into
the inventory; extracted image/address/identity literals remain data. Consumers resolve
excerpts through the accepted source boundary.
Construction and resolution share exact full-line byte boundaries; trailing blank lines
and LF/CRLF terminators are retained, not stripped before line-span verification.

Service keys are:

- `compose:<service-name>`
- `kubernetes:<namespace>:<Pod|Deployment|StatefulSet|DaemonSet>:<resource>:<container>`
- `kubernetes:<namespace>:Service:<resource>`
- `configuration:<logical-path>` for unbound configuration

An Nginx/Redis/PostgreSQL document may explicitly attach to a descriptor key using
`SourceDocument.service`; it must have the same deployment and variant. The core does
not guess mount associations from basenames or scan configuration directories.
A missing attachment target remains an explicit `binding_unresolved` gap. F06 must
establish the source-to-service attachment from accepted mounting/selection evidence.

## Meaning and authority

| Evidence class | Meaning here |
| --- | --- |
| `dependency_installed` | Reserved for a future accepted dependency producer; never emitted by static deployment extraction. An image declaration is not installation evidence. |
| `product_hint` | A recognized image repository or compatible configuration syntax. Product identity is declared, not runtime-verified. A port or banner cannot identify a product. |
| `deployment_declaration` | Non-runtime facts such as a Service type, configured policy directive or process worker identity. Policy directive presence does not prove enforcement. |
| `configured_listener` | Literal Compose port/expose, Kubernetes port or supported configuration declaration. Container, published, Service, node and configuration roles stay separate. `effective` is always `unknown`. |
| `selected_deployment` | Adapter-selected supplied variant only. Does not prove rollout, running containers, effective overlays or reachability. |
| `observed_listener` | Separate imported endpoint assertions, with authority `imported_observation`, an exact source and a bounded validity window. Never inserted into static inventory facts. |
| `proven_reachability` | Reserved; neither static extraction nor importing a claimed successful measurement can emit this. Future verification must establish the measurement's provenance, vantage and applicability. |

Static evidence authority is `target_declaration`. Target labels, annotations, comments,
documents and configuration cannot change scope, suppress findings, select a variant or
authorize collectors. `analysis_platform` input is separately accounted as excluded and
cannot supply target evidence. Never classify a customer's Redis as platform infrastructure
merely because the analysis platform also uses Redis/Garnet.

`Service.product` is populated only by exact supported image-repository signatures:
official `nginx`, `redis` and `postgres`, including their `library/` and
`docker.io/library/` spellings. Arbitrary registries with those basenames do not match.
Configuration syntax is only a product hint; it does not establish a product/version.
Image tags yield **declared** major/minor/patch precision, not running binary versions.
Missing tags, `latest`, release channels and unsupported/pre-release suffixes leave the
version unknown. Known Alpine and Debian packaging suffixes retain the declared numeric
version; the original tag remains in `image`. A digest alone cannot supply a version.

All listeners keep unknown effective runtime state and reachability. A missing bind,
runtime-assigned published port, absent configuration port, implicit product default,
unrendered interpolation, include or overlay is not filled using a default.
TLS flags describe supplied declarations/capability, not proof of enforced encrypted access.
Nginx worker identity and container user identity are distinct declarations.

## Supported extraction and explicit gaps

| Format | Implemented slice | Important omissions |
| --- | --- | --- |
| Compose YAML/JSON | Literal services, image, short/long ports, expose, depends_on, user. Explicit host bind and TCP/UDP/SCTP are retained. | No profiles, interpolation, extension expansion, anchors, merge keys, ranges, mounts, build, networking, command/entrypoint overrides or effective multi-file merge. Unhandled fields are named gaps. |
| Kubernetes YAML/JSON streams | `v1` Pod/Service and `apps/v1` Deployment/StatefulSet/DaemonSet; container images/ports, Service selectors and numeric/named target ports, explicit service account and UID. | No Helm/Kustomize rendering, List expansion, CRDs, Jobs/CronJobs, ingress, NetworkPolicy, RBAC, secret contents, init/ephemeral containers, cloud metadata, effective defaults or observed rollout. Unknown kinds/versions and fields are gaps. |
| Nginx | Literal HTTP server listeners, upstream server groups, proxy targets and location path, main worker user. Proxy evidence includes the target declarations. | Includes, variables, nonliteral locations, stream/module blocks, unhandled directives/options, effective virtual-host precedence, header trust and enforced TLS/auth remain unresolved. Duplicate upstream names are ambiguous. |
| Redis-compatible configuration | Explicit bind, port, tls-port; presence of requirepass/aclfile/protected-mode. Port zero is retained as an explicit disable declaration, not a listener. | No default-port inference, include expansion, ACL file parsing, version inference, runtime protection or authentication proof. Secret values are not emitted. |
| PostgreSQL configuration | Explicit listen_addresses, port, ssl and password_encryption presence. Quoted values and inline comments are parsed inertly. | No defaults, includes, pg_hba.conf evaluation, role catalog, TLS/auth enforcement or server-version inference. |

The catalog explicitly inventories unsupported software/cloud families (other proxies,
databases, cache/search engines, messaging, storage, compute/platform, identity/secrets,
admin/observability) and unsupported IaC/build/source formats. A name in that inventory
is **not detection coverage**. New signatures need implemented evidence rules, tests,
explicit limitations and an updated catalog identity; not just another vendor name.

Repeated declarations retain conflicts and source evidence. Multiple descriptor sources
for a service are **not merged**: product/image/version/identity and selected variant stay
unknown until the adapter supplies an actual selected/rendered result. Repeated differing
configuration values are conflicting declarations, not a guessed last-value-wins result.
Cross-variant services have distinct IDs; cross-deployment names never join.
Duplicate Kubernetes resources in one stream retain every declaration's evidence, labels
and listeners, but their services are marked `duplicate_declaration`. Selectors cannot
combine one declaration's labels with another declaration's ports, or resolve through an
ambiguous resource; unrelated unambiguous matches remain available.

Outcome semantics:

- `complete`: all supplied target input was parsed within the supported static slice,
  with no extraction gap. This does not mean complete target discovery or a secure target.
- `partial`: usable declarations plus named gaps, bounds, missing configuration or
  unresolved relationships; also an empty/no-target input set.
- `unsupported`: all analyzed input was outside the implemented syntax/format catalog.
- `malformed`: all analyzed input was invalid; duplicate input source identities also
  reject the request. Invalid API/admission metadata raises `ValueError`.

Each source has its own outcome, disposition and rules. A malformed document publishes
no partial service/evidence facts. Good documents can survive an independently malformed
document, producing overall `partial`. Syntax/output bounds are explicit, never silent
truncation. Unknown target fields remain gaps; unknown wire-contract fields are rejected.

Defaults: 64 documents, 512 KiB/document, 4 MiB total, depth 32, 20,000 syntax events/tokens
and 10,000 extracted records. Hard safety ceilings are 256 documents, 2 MiB/document,
16 MiB total, depth 64, 100,000 syntax events/tokens and 50,000 records.
Scalar declarations are additionally bounded to 4,096 characters (Nginx tokens to 1,024)
so extracted records cannot exceed the closed wire schema's literal bounds.
Constructed identities, claims and fact descriptions are checked against the same wire
bound. Nonempty Kubernetes service-account names must be DNS subdomains of at most 253 characters;
invalid identifiers yield a valid `malformed` outcome, and oversized constructed values
yield a valid `partial` outcome without truncation.
An empty service-account name is treated like an omitted name: the Pod and its evidence
are preserved, and the effective/default runtime account remains unknown.

## Imported observations and drift

An observation document has exactly `schema`, `target_snapshot`, `environment` and
`endpoints`. Each endpoint requires all fields (unknowns use JSON `null`):

```json
{
  "id": "measurement-1",
  "service_id": null,
  "address": "127.0.0.1",
  "port": 6379,
  "transport": "tcp",
  "role": "container",
  "observed_at": "2026-11-06T11:00:00Z",
  "expires_at": "2026-11-06T13:00:00Z",
  "owner": "container:cache",
  "banner": null,
  "reachability": "not_tested",
  "vantage_point": null
}
```

`service_id` must be an exact inventory ID or null. The address must be an IP literal;
no DNS is resolved. Roles are container/published/service/node/configuration.
Reachability is `not_tested`, `succeeded` or `failed`; reported tests require their
vantage point. This records an assertion, not independently established proof.
Duplicate keys/IDs, unknown fields, invalid numbers/times and foreign snapshots/environments
reject the entire import. Validity is positive and at most seven days. Expired and future
records are retained with explicit gaps, never treated as current. An empty snapshot is a
`no_observations` gap, not evidence of an environment with no listeners.

Drift states are `matched_declaration`, `port_matches_bind_unknown`, `bind_differs`,
`observed_only`, `static_only`, `unbound` and `stale`. Missing observations do not prove
closed ports, removed services or lack of exposure. Wildcard/hostname/unknown static binds
cannot become exact IP matches. Different endpoint roles do not match. Even a match does
not prove product, patch level, effective policy or vulnerability. Multi-instance routing,
network namespaces and collector/proof authenticity remain future integration work.

## Focused verification and manual scenarios

Unit selectors: `tests/test_deployment_inventory.py`,
`tests/test_deployment_contracts.py`, `tests/test_deployment_observations.py`.
Fixtures under `tests/fixtures/deployment/` are inert, synthetic customer declarations,
not a runnable deployment or target. Run these units with bounded parallelism,
reproducible shuffle seed and a unique `test/tmp/fleet-f05-*` base temp.

The following are **manual and not executed by F05**. F06/F02 integration and explicit
user authorization are prerequisites; no scenario authorizes a collector or customer run.

| Scenario | Prerequisites / budget | Expected evidence |
| --- | --- | --- |
| Accepted-input-to-publication | F02/F06 adapters; isolated synthetic run; 60 s | Pass the four Compose/config fixtures through accepted catalog admission, extract, publish with existing immutable dataset machinery, validate inventory and resolve every evidence span from exact accepted bytes. Alter one source byte and verify rejection rather than rehashing/normalizing. |
| Retrieval and consumer boundary | F06 registered capability and dataset; synthetic run; 60 s | Retrieve bounded services, listeners, edges, conflicts and gaps; reject foreign snapshot, platform evidence and unknown fields; preserve source identities and distinguish retrieved from used/cited evidence. |
| Rendered variant / overlay | Operator supplies separately rendered inert prod/dev manifests; 30 s | Select one variant through the adapter. Confirm raw unresolved overlays/profiles never infer an effective value or selected service; record excluded/missing coverage. |
| Imported observation drift | Inert operator-created snapshot only; 30 s | Import a bound endpoint and compare matched/custom-port/bind-mismatch/expired cases. A same-port banner with no service ID stays unbound. No network or cloud call occurs. |
| Scope and threat-model context | Synthetic platform Garnet/Redis plus customer Redis; 30 s | Only adapter-scoped customer declarations enter inventory; a target annotation claiming exclusion does not suppress it. Consumers do not promote declarations, TLS flags or imported success to proven reachability. |

No integration, acceptance, live Dagster, deployment, cloud collector, socket scan or
customer target execution has been performed to establish these scenarios.
