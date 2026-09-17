# Config — Component Characterization

## Required Inputs

- `ENGAGEMENT_LLM_INPUT.md`
- `coverage-ledger.json`
- symbol index
- semantic index, if available
- repo profile/static summary
- target source tree
- `taxonomy.md`

## Required Outputs

- `component-purpose-map.json`
- `component-purpose-map.md`
- explicit code-scope exclusions for test/sample, benchmarks, vendored dependencies, generated code,
  and documentation where applicable
- functional/security components suitable for ASVS/MASVS/threat/native routing
- component-cloud entries with coarse groups, aliases, search terms, and fine-grained locations
- parallel review groups for independent lane execution
- classification gaps and rescope triggers

## Code-Scope Classifications

Use these categories for physical source buckets and add target-specific categories as needed:

- production service
- client
- server/core
- library
- management plane
- infrastructure
- build tooling
- test/sample
- generated code
- vendored third-party
- documentation

## Functional/Security Component Types

Use functional/security component types when building the review model. Add target-specific types as
needed.

- memory management / allocator
- container / collection primitive
- buffer / ring buffer / queue
- string / encoding / Unicode
- parser / serializer / deserializer
- crypto / key management
- authentication / identity / user
- authorization / policy
- network service / protocol
- record / data service
- storage / persistence
- concurrency / threading / atomics
- process / IPC boundary
- logging / telemetry
- update / plugin / extension mechanism
- platform integration
- build / deployment control plane
- REST API / HTTP service
- RPC / gRPC / protobuf service
- WebSocket / realtime transport
- UDP/TCP gameplay networking
- TLS / mTLS / certificate validation
- account / profile / user manager
- entitlement / inventory / economy
- matchmaking / lobby / session
- chat / voice / messaging
- friends / presence / social graph
- leaderboard / ranking
- telemetry / analytics
- admin / moderation / support console
- live operations / feature flags / remote config
- Android platform integration
- iOS platform integration
- console platform integration
- PC platform integration
- content / asset / patch update pipeline

## Component Cloud Requirements

Build the functional map like a component word cloud backed by code locations:

- start with coarse groups from `taxonomy.md`
- expand into target-specific components when evidence supports them
- attach aliases and search terms that can drive `rg`, semantic-index, CodeQL, or manual source review
- attach representative locations from coarse directories down to specific files, symbols, handlers,
  routes, protobuf/RPC definitions, manifests, or build targets
- include `parallel_review_group` so identity, network, crypto, data, admin, client/platform,
  native-runtime, and infrastructure work can run independently
- include `negative_evidence` when a category was searched or considered and not found

## Exclusion Rules

Tests, benchmarks, generated outputs, and vendored dependencies should be excluded from deeper
inference by default, but still recorded in `analysis_exclusions` with:

- path pattern
- reason
- evidence
- rescope trigger

Do not exclude a bucket when evidence shows it is shipped, linked into production, customer
modifiable in production, or security-critical to build/deployment.
