# clangd-indexer runtime closure: license and security review

Reviewed 2026-10-10 for clangd `23.1.0` (`clangd_indexing_tools-linux-23.1.0.zip`, SHA-256
`48259f33a0684760fdb363be036eb5c6f707fbeb0877e5fff58d1e6cc308a763`). The archive is not committed.

## License

The LLVM Project is licensed under Apache-2.0 with LLVM Exceptions. The archive's `LICENSE.TXT`
(SHA-256 `8d85c105…afee`) is installed in the image beside the binary. The builtin headers in
`lib/clang/23/include` are covered by the same license. The statically linked zlib uses the
permissive zlib license.

No other third-party components were identified in the installed closure. The excluded
`clangd-index-server` is the only shipped binary that links gRPC and protobuf; `clangd-indexer`
contains no gRPC symbols.

## Provenance

**Release.** The asset is a GitHub release asset of `clangd/clangd` tag `23.1.0`. That repository
holds only release automation, and the tag is a lightweight tag on commit `0d73b70d…`. Its
`autobuild.yaml` workflow builds the `llvm-project` ref supplied when the workflow is dispatched,
on `ubuntu:20.04` with clang-10.

**Open item: the LLVM source ref is unverified.** It is expected to be `llvmorg-23.1.0` (commit
`ea7d852a…`). The binary doesn't embed a VCS revision (`--version` prints only
`LLVM version 23.1.0`), and the release description that names the ref couldn't be retrieved
during review.

**Signatures.** No checksum file, detached signature, sigstore bundle, attestation or
reproducible-build record is published. Integrity therefore rests on the reviewer-recorded SHA-256
and SHA-512, and signature status is `not-published`.

## Known advisories in the installed closure

| Component | Advisories | Exposure in this runtime |
| --- | --- | --- |
| zlib 1.2.11 (statically linked) | CVE-2018-25032 (deflate memory corruption with some inputs, fixed in 1.2.12); CVE-2022-37434 (`inflateGetHeader` heap overflow, fixed in 1.2.13) | zlib compresses the indexer's own output, not target data. Target sources are never decompressed by it, and the indexer doesn't call `inflateGetHeader`. Not reachable from target input under current use, but recorded as unresolved upstream. |
| LLVM/Clang 23.1.0 | No OSV/NVD bulk match was run against the LLVM binary itself | Clang parses untrusted target source, so crashes and resource exhaustion are possible. Any of them is bounded by the container's non-root, read-only, no-network, PID, memory, CPU and timeout limits. Recorded as an open item. |

## Runtime notes for integration

- **Resource profile.** The central policy caps every tool at 1 GiB and 600 seconds. Real
  Unreal-scale compilation databases need per-TU batching and a reviewed per-tool resource
  profile; the policy is not weakened here.
- **MSVC headers.** clang-cl commands need the MSVC and Windows SDK headers. They are licensed
  operator inputs, mounted read-only, and never committed.
- **Index format.** The binary RIFF index is clangd's internal, version-coupled format. Integration
  should normalize the YAML output or a pinned-version conversion, never depend on the binary
  layout across versions.

The integration files in this directory (`Dockerfile` and the TOML/JSON contracts) belong to this
repository and do not redistribute LLVM.
