# Prompt — L0A Component And Purpose Identification

You are building the component-purpose map for an appsec review. Use deterministic artifacts first,
then direct source inspection. Do not infer vulnerability conclusions in this lane.

The goal is not merely to restate the directory tree. Build a functional/security component model
that can drive threat modeling, ASVS/MASVS applicability, native-memory review, dependency
reachability, and verification routing.

Treat this lane as building a component word cloud backed by evidence. The map should range from
coarse groups such as identity, network, admin, client platform, data, crypto, and native runtime
down to fine-grained code locations such as files, symbols, handlers, routes, schemas, protobuf/RPC
definitions, manifests, or build targets.

## Required Analysis Layers

Produce two separate layers:

1. **Code-scope classification**
   - classify physical source buckets as production/live, test/sample, benchmark, vendored
     dependency, generated, build tooling, documentation, or unknown
   - emit explicit `analysis_exclusions` for buckets that should be excluded from deeper inference by
     default, such as tests, benchmarks, generated outputs, and vendored dependencies
   - include rescope triggers that would bring an excluded bucket back into scope, such as shipped
     test utilities, linked vendored code, or customer-modifiable scripts

2. **Functional/security components**
   - infer semantic components from symbols, filenames, build targets, call relationships,
     scanner clusters, semantic index hits, and direct source inspection
   - avoid using only top-level directories as components unless the directory itself is a meaningful
     product/runtime boundary
   - examples of useful components include memory management, allocation arenas, bump allocators,
     ring buffers, string/encoding handling, parser/deserializer, crypto, auth, user management,
     network services, record services, storage/persistence, policy/authorization, IPC, logging,
     update mechanisms, mobile platform glue, or build/deployment control planes
   - for game or multi-platform targets, actively look for REST services, microservices, network
     services, TLS/certificate handling, RPC/gRPC/protobuf, WebSockets, UDP/TCP gameplay networking,
     accounts, user/profile managers, entitlement/inventory/economy, matchmaking/lobby/session,
     chat/voice/social graph, admin/moderation/support consoles, live-ops tooling, Android/iOS
     clients, console platforms, PC platform glue, content/update pipelines, and telemetry

For each functional/security component:

- assign `component_id`
- give a short `name`
- identify `coarse_group`
- identify representative path(s), files, symbols, or build targets
- classify component type
- include aliases and search terms useful for full-text search, semantic retrieval, and CodeQL review
- state observed purpose
- assign confidence
- cite evidence
- identify trust-boundary relevance
- identify data classes handled, if known
- identify ASVS/MASVS/security-control relevance, or state `none/low` with rationale
- note deployability/liveness if known
- identify downstream lanes that should inspect it
- assign a `parallel_review_group` so related components can be reviewed independently from other
  groups

When a major expected category is absent, record that as `negative_evidence` rather than silently
omitting it. For example, a C++ library may have no REST services or accounts; a multiplayer game
backend likely should have identity, network/RPC, data, admin, and telemetry components.

## Output Requirements

Output both JSON and markdown. The JSON must include:

- `code_scope_classification`
- `analysis_exclusions`
- `component_cloud`
- `functional_components`
- `parallel_review_groups`
- `negative_evidence`
- `classification_gaps`
- `rescope_triggers`

Mark unknowns explicitly. Do not treat vendored, sample, test, benchmark, or generated code as
production unless evidence supports that classification.
