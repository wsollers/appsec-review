# Subprompts — Component Characterization

## Top-Level Partition

Partition the repo into top-level components using manifests, build files, directory layout, compile
database entries, symbols, package files, deployment configs, and static summary evidence.

This is only the scope-control layer. Do not stop at physical directory buckets.

## Functional Component Inference

Infer functional/security components from names, symbols, call relationships, build targets, semantic
index hits, risky files, and scanner clusters. Prefer components that help later review lanes answer
security questions, such as memory management, allocation strategy, string/encoding handling,
network-facing services, identity/user management, record services, crypto, authorization, storage,
IPC, update mechanisms, and build/deployment control planes.

For library-only targets, infer reusable primitives rather than services. For service/app targets,
infer runtime subsystems and trust boundaries rather than just folders.

Read `taxonomy.md` and use it as the vocabulary for the initial component cloud. The taxonomy is a
starting point, not a limit.

## Component Cloud Pass

Build a component cloud with coarse-to-fine location evidence:

1. Start from taxonomy coarse groups.
2. Generate target-specific aliases and search terms.
3. Search deterministic artifacts first: LLM input, retrieval plan, symbol index, semantic index,
   compile database, manifest files, and scanner clusters.
4. Search source with full-text patterns where useful.
5. Record representative locations at the finest reliable granularity: directory, file, class,
   function, route, RPC method, protobuf/message type, config key, manifest, or build target.
6. Record negative evidence for important absent categories.

For multiplayer game targets, explicitly probe for:

- REST/microservices/API gateway
- RPC/gRPC/protobuf/custom message protocols
- TLS/mTLS/certificates/secrets
- accounts/users/profiles/sessions/entitlements
- matchmaking/lobby/party/game-session services
- realtime gameplay network code, packet codecs, replication, UDP/TCP sockets
- player inventory/economy/progression/leaderboards
- chat/voice/friends/presence/social graph
- admin/support/moderation/live-ops/feature flags
- telemetry/analytics/events/crash reporting
- Android/iOS mobile code, tablet UI, console platform glue, PC platform glue
- content/assets/mods/plugins/update/patch/download flows
- storage/cache/queues/search/indexing/data migrations

## Parallel Grouping

Assign every functional component to one `parallel_review_group`:

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

The orchestrator can then launch independent ASVS/MASVS/threat/native lanes per group.

## Liveness Review

For each component, determine whether it appears production/live, test/sample, vendored, generated, or
unknown. Cite evidence and list what would change the classification.

## Exclusion Plan

Emit `analysis_exclusions` for tests, benchmarks, generated outputs, and vendored dependencies that
should not consume deeper inference budget by default. Each exclusion must include the path pattern,
reason, evidence, and rescope trigger.

## Routing Map

For each component, list which lanes apply: ASVS/MASVS, native memory, dependency reachability,
threat modeling, red-team, verification, synthesis.
