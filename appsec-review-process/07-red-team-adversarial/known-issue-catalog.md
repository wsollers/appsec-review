# Known Attack And Security Issue Catalog

Use this catalog as hypothesis fuel for the red-team lane. These are not findings. A catalog item
becomes a candidate only when it is grounded in target-specific evidence, source locations, scanner
output, or an explicit coverage gap.

For each applicable component, the red-team output should cite:

- component id or component-cloud group
- attack/security issue class
- concrete target location or missing-evidence gap
- why the existing pipeline might miss it
- minimum check needed to confirm, refute, or route it

## identity-access

Applies to authentication, authorization, accounts, profiles, sessions, entitlements, platform
identity bridges, moderation roles, parental controls, and age gates.

- broken authentication or account takeover through weak login/session validation
- authorization bypass between player, admin, support, moderator, and service roles
- insecure direct object reference for user profile, inventory, save data, or records
- trust in client-supplied user ids, platform ids, device ids, or entitlement state
- token confusion across JWT/OAuth/platform tokens, environments, or audiences
- missing token expiry, replay protection, revocation, issuer validation, or nonce binding
- account linking abuse between Steam/Epic/Xbox/PSN/Nintendo/mobile identities
- privilege escalation through feature flags, roles, debug claims, or test accounts
- age gate or parental-control bypass across platform/mobile/web surfaces
- ban/block/report/moderation bypass or inconsistent enforcement across services
- account enumeration, password reset abuse, MFA bypass, or insecure recovery flows
- unsafe user deletion, merge, migration, or support impersonation workflows

Useful searches: `auth`, `login`, `signin`, `session`, `token`, `jwt`, `oauth`, `account`, `user`,
`profile`, `entitlement`, `permission`, `role`, `admin`, `moderator`, `ban`, `block`, `report`,
`parental`, `age`, `xuid`, `psn`, `nintendo`, `steam`.

## network-rpc-transport

Applies to REST APIs, microservices, gateways, RPC/gRPC/protobuf, custom protocols, WebSockets,
UDP/TCP gameplay networking, packet codecs, dispatchers, matchmaking protocols, and service
discovery.

- unauthenticated or under-authorized endpoint, route, RPC method, or message handler
- request smuggling, header confusion, method override, CORS, CSRF, or origin trust issues
- insecure service-to-service trust based only on network location, headers, or service names
- missing rate limits on login, matchmaking, inventory, chat, or expensive search endpoints
- packet parser memory corruption, integer overflow, truncation, or unchecked length fields
- message type confusion, version downgrade, replay, reordering, or desync in custom protocols
- trust in client-authoritative gameplay state, position, inventory, currency, or match results
- WebSocket/session hijack, missing origin checks, stale connection authorization, or room escape
- RPC/protobuf unknown-field, oneof, default-value, or optional-field authorization mistakes
- reflection/debug endpoint exposure or management route reachable from untrusted networks
- inconsistent auth checks between REST, RPC, internal service, and admin versions of an operation
- denial of service through compression bombs, oversized messages, queue flooding, or fanout abuse

Useful searches: `http`, `route`, `controller`, `endpoint`, `grpc`, `proto`, `rpc`, `websocket`,
`socket`, `udp`, `tcp`, `packet`, `frame`, `message`, `handler`, `dispatch`, `gateway`, `proxy`,
`listener`, `matchmaking`, `lobby`, `replication`, `rate_limit`.

## crypto-secrets-trust

Applies to TLS/mTLS, certificate handling, signing, encryption, token validation, secret storage,
secure randomness, platform keystores, and anti-cheat/integrity trust.

- disabled TLS validation, accept-all certificates, hostname mismatch, or weak pinning
- mTLS configured for transport but not bound to service identity or authorization
- hardcoded secrets, keys, tokens, certificates, passwords, or signing material
- secrets logged, copied into crash dumps, sent in telemetry, or embedded in client builds
- weak random number generation for tokens, matchmaking secrets, keys, or nonces
- encryption without authentication, fixed IV/nonce reuse, ECB mode, or homegrown crypto
- JWT/signature validation bugs: missing issuer/audience/algorithm/key id checks
- key rotation, environment separation, or test/prod secret confusion
- client-side trust in signatures, anti-cheat attestations, or purchase receipts without server validation
- local secure-storage misuse on Android/iOS/consoles/PC
- downgrade from secure to insecure transport, update channel, or content manifest

Useful searches: `tls`, `ssl`, `cert`, `certificate`, `pin`, `mtls`, `crypto`, `encrypt`, `decrypt`,
`sign`, `verify`, `hmac`, `hash`, `random`, `secret`, `vault`, `key`, `keystore`, `token`,
`attest`, `integrity`.

## player-social-game-services

Applies to player state, inventory, economy, wallet, progression, achievements, leaderboard,
matchmaking, lobby, friends, chat, voice, presence, guilds, telemetry, records, game server
orchestration, and anti-cheat services.

- client-authoritative currency, inventory, achievements, rank, skill, or match results
- race conditions or replay attacks in purchase, inventory, reward, crafting, or trade flows
- duplicate grant, refund, rollback, idempotency, or transaction boundary failures
- matchmaking manipulation, lobby hopping, team abuse, hidden rating disclosure, or queue flooding
- leaderboard tampering, score injection, stale signature acceptance, or anti-cheat bypass
- chat/voice/message abuse: spam, impersonation, unsafe links, moderation bypass, injection
- privacy leaks in presence, friends, party, guild, recent players, or blocked-user flows
- replay/session record tampering, unsafe import/export, or exposure of private match data
- server orchestration trust issues: joining unauthorized sessions or controlling game-server lifecycle
- telemetry/event injection that influences economy, moderation, matchmaking, or analytics decisions
- insufficient abuse controls for reporting, blocking, invite, friend request, or group creation

Useful searches: `player`, `inventory`, `wallet`, `currency`, `progression`, `achievement`,
`leaderboard`, `rank`, `match`, `lobby`, `party`, `friend`, `presence`, `chat`, `voice`, `guild`,
`telemetry`, `event`, `record`, `replay`, `session`, `anti_cheat`.

## data-storage-records

Applies to databases, caches, queues, blob storage, save-game storage, audit records, import/export,
migrations, search indexes, analytics pipelines, and PII storage.

- SQL/NoSQL/LDAP/search injection or unsafe query construction
- tenant/player/object authorization gaps in repositories, DAOs, GraphQL resolvers, or data loaders
- sensitive data stored without encryption, retention controls, access logging, or minimization
- PII/secrets in logs, telemetry, crash dumps, analytics events, queues, or dead-letter topics
- cache key confusion, stale authorization, cross-user cache poisoning, or shared cache leakage
- unsafe deserialization/import/export of saves, records, configs, telemetry, or analytics batches
- migration or backfill scripts that bypass auth, overwrite security fields, or mishandle prod data
- queue replay, duplicate processing, missing idempotency, or poison-message denial of service
- object storage path traversal, predictable object ids, public buckets, or unsigned upload/download abuse
- data deletion/export/privacy workflows incomplete across caches, queues, analytics, and backups

Useful searches: `sql`, `query`, `db`, `database`, `repository`, `dao`, `record`, `save`, `storage`,
`blob`, `cache`, `redis`, `queue`, `kafka`, `stream`, `migration`, `analytics`, `pii`, `personal`.

## admin-operations-management

Applies to admin web UIs, operations consoles, customer support tooling, moderation systems,
feature flags, live-ops, deployment controllers, observability, debug endpoints, and privileged jobs.

- admin or support endpoint exposed to public networks or protected by weaker auth than player APIs
- horizontal/vertical privilege escalation across support, moderator, live-ops, and engineering roles
- unsafe impersonation, account mutation, grants, refunds, bans, or inventory edits
- feature flag or remote-config abuse to unlock hidden functionality, disable controls, or route traffic
- debug, health, metrics, profiling, trace, or diagnostic endpoints leaking secrets or PII
- command execution, template injection, SSRF, path traversal, or file read through admin tools
- missing audit logs, tamperable logs, or incomplete approval flow for privileged actions
- batch jobs or maintenance scripts with broad production credentials and weak input validation
- live-ops content/config path that bypasses code review, signing, or staged rollout controls
- over-permissive cloud IAM, service account, deployment token, or break-glass workflow

Useful searches: `admin`, `ops`, `operator`, `console`, `support`, `moderation`, `liveops`,
`feature_flag`, `remote_config`, `debug`, `diagnostic`, `metrics`, `health`, `maintenance`,
`backoffice`, `dashboard`, `privileged`.

## client-platform-ui

Applies to PC, console, mobile/tablet clients, platform bridge code, store/purchase integration,
push notifications, deep links, local storage, crash reporting, and UI flows.

- client-side enforcement of security, entitlement, price, currency, matchmaking, or anti-cheat decisions
- insecure local storage of tokens, refresh tokens, secrets, save data, or PII
- Android exported activity/service/receiver/provider, intent injection, WebView misuse, or backup leakage
- iOS URL scheme/deep link hijack, pasteboard/keychain misuse, ATS exceptions, or jailbreak assumptions
- console platform identity/purchase trust without server-side receipt or entitlement validation
- PC launcher/update/plugin path trust, DLL search order, file permission, or local privilege issues
- unsafe deep links, push notification payloads, clipboard import, QR codes, or external URL handling
- UI redress, account confusion, logout/session persistence, or cross-account cached state
- crash reporting/telemetry leaking tokens, usernames, device ids, chat content, or PII
- platform-specific privacy/consent gaps for children, voice/chat, contacts, location, or ads

Useful searches: `android`, `ios`, `iphone`, `ipad`, `mobile`, `xbox`, `xbl`, `playstation`, `psn`,
`switch`, `nintendo`, `steam`, `epic`, `activity`, `viewcontroller`, `store`, `purchase`, `iap`,
`push`, `deeplink`, `webview`, `keychain`, `keystore`, `crash`.

## content-update-assets

Applies to content pipelines, asset loaders, patch/update clients, DLC/content entitlements,
mod/plugin systems, scripting runtimes, file import/export, archive parsers, localization, and CDN
downloads.

- unsigned or weakly signed update, patch, DLC, mod, plugin, or content manifest
- path traversal, zip slip, symlink abuse, absolute-path writes, or unsafe extraction
- archive/compression bomb, malformed asset parser crash, or native memory corruption
- script/mod/plugin sandbox escape, excessive permissions, or untrusted code execution
- CDN or manifest downgrade, replay, cache poisoning, or environment confusion
- local file overwrite or DLL/library load through asset/update paths
- entitlement bypass for DLC/content unlocks or client-side content gating
- localization/string format injection, markup/script injection, or unsafe rich text handling
- importer/exporter SSRF, file disclosure, or unsafe temporary file handling

Useful searches: `asset`, `content`, `pak`, `bundle`, `patch`, `update`, `dlc`, `mod`, `plugin`,
`script`, `lua`, `archive`, `zip`, `compress`, `decompress`, `localization`, `cdn`, `download`,
`manifest`.

## native-runtime-memory

Applies to C/C++/Rust/native runtimes, allocators, arenas, pools, ring buffers, packet buffers,
serialization buffers, parser/deserializers, containers, strings, threading, jobs, IPC, and file/path
handling.

- out-of-bounds read/write from length, capacity, stride, offset, index, or signedness errors
- integer overflow/underflow in allocation, resize, packet, string, image, archive, or asset sizes
- allocation/deallocation family mismatch, double free, use-after-free, invalid free, or lifetime escape
- type confusion, unsafe cast, object slicing, variant/union misuse, or invalid downcast
- uninitialized memory exposure in packets, saves, logs, telemetry, or IPC
- parser state machine desync, malformed packet handling, or incomplete bounds checks
- ring buffer wraparound, producer/consumer race, queue overflow, or stale pointer reuse
- data race, lock inversion, TOCTOU, atomic/non-atomic mixing, or weak memory-order assumptions
- path traversal, symlink race, unsafe temp files, or platform path normalization mistakes
- FFI boundary mismatch, ABI mismatch, ownership transfer confusion, or unsafe callback lifetime

Useful searches: `alloc`, `allocator`, `arena`, `pool`, `bump`, `ring`, `queue`, `buffer`, `packet`,
`serialize`, `deserialize`, `parse`, `string`, `utf`, `thread`, `mutex`, `atomic`, `job`, `ipc`,
`path`, `file`, `memcpy`, `memmove`, `size`, `capacity`.

## build-deploy-infrastructure

Applies to build systems, CI workflows, deployment manifests, Kubernetes/Helm/Terraform, Docker
images, secrets injection, service mesh, ingress, environment config, release signing, and artifact
publishing.

- secret leakage in CI logs, artifacts, Docker layers, mobile packages, symbols, or crash uploads
- unpinned actions/images/dependencies, supply-chain compromise, or untrusted build inputs
- CI privilege escalation through pull requests, forks, path filters, cache poisoning, or artifact reuse
- over-permissive cloud IAM, Kubernetes RBAC, service accounts, ingress, or network policies
- missing image hardening, root containers, writable filesystems, dangerous Linux capabilities
- deployment config exposing debug/admin ports, metrics, traces, databases, queues, or dashboards
- environment mix-up between dev/stage/prod secrets, endpoints, signing keys, or feature flags
- unsigned releases, weak artifact provenance, missing SBOM/signature verification, or update-chain gaps
- IaC drift, manually modified production resources, or missing policy checks

Useful searches: `docker`, `k8s`, `kubernetes`, `helm`, `terraform`, `cloudformation`, `workflow`,
`github`, `jenkins`, `build`, `deploy`, `release`, `sign`, `artifact`, `secret`, `env`, `ingress`,
`mesh`, `sidecar`, `rbac`, `iam`.

