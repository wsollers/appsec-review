---
id: cpp_rpc_service
version: 1
covers: []
standards: ["cwe", "cert-cpp", "asvs5"]
max_tokens: 1500
---
## Runtime and framework model
A C or C++ server exposing gRPC (`grpc::Server`, callback or completion-queue API), protobuf over a
custom transport, Thrift (`TThreadedServer`, `TNonblockingServer`), Cap'n Proto, or another IDL.
Generated stubs (`*.pb.h`, `*.grpc.pb.h`, `gen-cpp/`) are produced from `.proto`/`.thrift`
files and are not hand-reviewed code; the service implementation subclasses `Service` or
`CallbackService` and overrides one method per RPC. Object lifetime is governed by the framework:
request and response messages may live in a `google::protobuf::Arena` owned by the call, and the
`ServerContext`/`CallbackServerContext` dies when the RPC finishes.

## Trust and interface layer
- Every RPC method is an entry point; the `.proto`/`.thrift` service definition is the route
  table. Field values, repeated-field counts, `bytes` and `string` lengths, `oneof` choice,
  `Any` payloads, and metadata headers are attacker-controlled.
- Unknown fields are preserved by proto3 and re-serialized; a proxy may forward fields it did not
  validate.
- Authentication is usually an `AuthMetadataProcessor`, a server interceptor
  (`experimental::Interceptor`), or channel credentials; authorization is per method and is easy
  to omit on one method.
- Reflection (`grpc::reflection::InitProtoReflectionServerBuilderPlugin`), health, channelz, and
  admin services expose method lists and internals when registered on the public port.

## Idiomatic security mechanisms
- `ServerBuilder::SetMaxReceiveMessageSize`/`SetMaxSendMessageSize`; protobuf
  `CodedInputStream::SetRecursionLimit` and total-bytes limits for custom parsing; Thrift
  `TConfiguration` max message size, container limits, and recursion depth.
- `SslServerCredentials` with `GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY` for
  mTLS; peer identity from `context->auth_context()` rather than from metadata strings.
- Per-method authorization checked in the interceptor against the full method name, or at the top
  of each handler, defaulting to deny for unknown methods.
- Deadlines: clients set `set_deadline`; servers check `context->IsCancelled()` and propagate the
  deadline to downstream calls.
- Resource quotas (`grpc::ResourceQuota`, `SetMaxThreads`) and the HTTP/2 concurrent-streams setting.

## Stack-specific pitfalls
- `InsecureServerCredentials()` on a non-loopback address; TLS without client verification where
  peers are assumed authenticated.
- Repeated-field counts or `bytes` lengths used directly for native buffers (`memcpy(buf,
  req.data().data(), req.size_hint())`); `int` truncation of `size()`.
- Arena lifetime: pointers to arena-allocated submessages kept beyond the call, or messages from
  one arena `Swap`ped into another; `release_*()` without ownership transfer.
- Async callback lifetime: reactors or completion-queue tags capturing `this`, `request`, or
  `ServerContext` after `Finish()` or cancellation; `OnDone` races with outstanding writes.
- Streaming: server writes without waiting for `OnWriteDone` (unbounded buffering), client
  streams read into memory with no per-stream message cap, no backpressure on bidirectional
  streams.
- Missing deadlines leaving handlers and threads pinned; cancellation not checked in loops.
- Metadata header values (`x-user-id`) trusted as identity when set by the caller.
- `Any` or `google.protobuf.Struct` unpacked into types chosen by the sender.

## Build and deployment facts to check
- Port binds and credential type passed to `AddListeningPort`; which services are registered on
  which port, including reflection, health, and admin.
- gRPC, protobuf, and Thrift library versions against advisories; whether generated code matches
  the checked-in `.proto` sources.
- Configured message size, recursion, concurrency, and keepalive limits, and environment overrides.
- Certificate and CA paths, client-certificate requirement, and service-mesh mTLS that may supply
  or replace transport security.
- Sanitizer and fortify flags in release builds; whether fuzz targets exist for message handlers.
