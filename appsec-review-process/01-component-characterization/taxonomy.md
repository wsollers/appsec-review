# Functional Component Taxonomy

Use this taxonomy as a search and classification vocabulary. It is not exhaustive; add
target-specific components when the evidence supports them.

The output should behave like a component word cloud: broad enough to orient the review, but able to
point to fine-grained files, symbols, routes, handlers, schemas, or build targets.

## Output Shape

Each functional component should include:

- `component_id`
- `name`
- `coarse_group`
- `component_type`
- `aliases`
- `search_terms`
- `representative_locations`
- `evidence`
- `trust_boundaries`
- `data_classes`
- `security_control_relevance`
- `downstream_lanes`
- `parallel_review_group`
- `confidence`

Representative locations may be directories, files, functions, classes, routes, service names,
protobuf/RPC definitions, config keys, manifests, or build targets.

## Coarse Groups

### Identity, Accounts, And Access

- authentication
- authorization / policy
- account service
- user profile / user manager
- session management
- entitlement / ownership
- roles / permissions / moderation roles
- parental controls / age gates
- ban / block / report systems
- account linking / SSO / OAuth
- device identity
- platform identity bridge

Search terms: `auth`, `login`, `signin`, `session`, `token`, `jwt`, `oauth`, `account`, `user`,
`profile`, `entitlement`, `permission`, `role`, `ban`, `block`, `report`, `moderation`,
`parental`, `age`, `device_id`, `xuid`, `psn`, `nintendo`, `steam`.

### Network, Protocol, RPC, And Transport

- REST API service
- GraphQL endpoint
- gRPC/protobuf service
- custom RPC protocol
- matchmaking protocol
- lobby/session protocol
- realtime gameplay protocol
- WebSocket service
- UDP/TCP socket service
- packet codec / frame parser
- message router / dispatcher
- service discovery
- load balancer / gateway / edge proxy
- rate limiting / throttling

Search terms: `http`, `rest`, `route`, `controller`, `endpoint`, `graphql`, `grpc`, `proto`,
`rpc`, `websocket`, `socket`, `udp`, `tcp`, `packet`, `frame`, `message`, `handler`, `dispatch`,
`gateway`, `proxy`, `listener`, `matchmaking`, `lobby`, `session`, `replication`, `netcode`,
`rate_limit`, `throttle`.

### TLS, Crypto, Secrets, And Trust

- TLS/mTLS setup
- certificate validation / pinning
- crypto primitives
- key management
- signing / verification
- token minting / validation
- password hashing
- secret storage
- secure random
- platform secure enclave / keystore
- anti-cheat attestation trust

Search terms: `tls`, `ssl`, `cert`, `certificate`, `pin`, `mtls`, `crypto`, `encrypt`, `decrypt`,
`sign`, `verify`, `hmac`, `hash`, `bcrypt`, `argon`, `random`, `rng`, `secret`, `vault`, `key`,
`keystore`, `token`, `attest`, `integrity`.

### Player, Social, Match, And Game Services

- player state service
- inventory / economy / wallet
- progression / achievements
- leaderboard / ranking
- matchmaking
- lobby / party / squad
- friends / presence
- chat / voice / messaging
- guild / clan / team
- telemetry / events
- record / replay / session history
- game-server orchestration
- anti-cheat service

Search terms: `player`, `inventory`, `wallet`, `currency`, `progression`, `achievement`,
`leaderboard`, `rank`, `match`, `matchmaking`, `lobby`, `party`, `squad`, `friend`, `presence`,
`chat`, `voice`, `message`, `guild`, `clan`, `team`, `telemetry`, `event`, `record`, `replay`,
`session`, `game_server`, `dedicated`, `anti_cheat`.

### Data, Storage, Persistence, And Records

- database access layer
- object storage / blob service
- cache / Redis / memcache
- durable queue / stream
- save-game storage
- records / audit history
- import/export
- migrations
- search indexing
- analytics pipeline
- PII storage

Search terms: `sql`, `query`, `db`, `database`, `repository`, `dao`, `record`, `save`, `persist`,
`storage`, `blob`, `s3`, `cache`, `redis`, `memcache`, `queue`, `kafka`, `stream`, `migration`,
`index`, `analytics`, `pii`, `personal`.

### Admin, Operations, And Management Plane

- admin web UI
- operations console
- customer support tool
- moderation console
- feature flags / remote config
- live-ops tooling
- deployment controller
- observability / metrics
- incident/debug endpoint
- privileged batch job
- maintenance endpoint

Search terms: `admin`, `ops`, `operator`, `console`, `support`, `moderation`, `liveops`,
`feature_flag`, `remote_config`, `debug`, `diagnostic`, `metrics`, `health`, `maintenance`,
`backoffice`, `dashboard`, `privileged`.

### Client UI And Platform Integration

- PC client UI
- console UI
- mobile UI
- Android platform bridge
- iOS platform bridge
- Xbox platform bridge
- PlayStation platform bridge
- Nintendo/Switch platform bridge
- Steam/Epic platform bridge
- store / purchase bridge
- push notifications
- deep links
- local secure storage
- crash reporting

Search terms: `android`, `ios`, `iphone`, `ipad`, `mobile`, `xbox`, `xbl`, `playstation`, `psn`,
`switch`, `nintendo`, `steam`, `epic`, `console`, `ui`, `view`, `screen`, `activity`,
`viewcontroller`, `store`, `purchase`, `iap`, `push`, `deeplink`, `crash`.

### Content, Assets, Mods, And Update

- content pipeline
- asset loader
- patch/update client
- DLC/entitlement content
- mod/plugin system
- scripting runtime
- file import/export
- compression/archive parser
- localization
- CDN/download client

Search terms: `asset`, `content`, `pak`, `bundle`, `patch`, `update`, `dlc`, `mod`, `plugin`,
`script`, `lua`, `python`, `archive`, `zip`, `compress`, `decompress`, `localization`, `cdn`,
`download`, `manifest`.

### Native Runtime, Memory, And Concurrency

- memory allocator
- arena / pool / bump allocator
- ring buffer / queue
- packet buffer
- serialization buffer
- container primitives
- string/encoding
- parser/deserializer
- threading / atomics
- job system
- process / IPC
- file/path handling

Search terms: `alloc`, `allocator`, `arena`, `pool`, `bump`, `ring`, `queue`, `buffer`, `packet`,
`serialize`, `deserialize`, `parse`, `string`, `utf`, `thread`, `mutex`, `atomic`, `job`, `ipc`,
`process`, `path`, `file`, `memcpy`, `memmove`, `size`, `capacity`.

### Build, CI/CD, Infrastructure, And Deployment

- build system
- CI workflow
- deployment manifests
- Kubernetes/Helm/Terraform
- Docker images
- secrets injection
- service mesh
- ingress
- environment config
- release signing
- artifact publishing

Search terms: `docker`, `k8s`, `kubernetes`, `helm`, `terraform`, `cloudformation`, `workflow`,
`github`, `jenkins`, `build`, `deploy`, `release`, `sign`, `artifact`, `secret`, `env`, `ingress`,
`mesh`, `sidecar`.

## Parallel Review Groups

Use these group names when routing components for parallel review:

- `identity-access`
- `network-rpc-transport`
- `crypto-secrets-trust`
- `player-social-game-services`
- `data-storage-records`
- `admin-operations-management`
- `client-platform-ui`
- `content-update-assets`
- `native-runtime-memory`
- `build-deploy-infrastructure`

