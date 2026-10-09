# CodeQL runtime notice

CodeQL is a GitHub product distributed under GitHub's CodeQL terms. The licensed CLI, extractor,
query-pack, and library payloads are operator-provided runtime assets and are deliberately not
stored in this repository. `assets.lock.json` records the reviewed version, immutable image
identity, license-file hash, extractor tree hashes, and query-pack hashes required by the runtime.

The C++ custom-query layer uses the official
`github/codeql-coding-standards@v2.62.0` `coding-standards-codeql-packs.zip` release asset. The
archive is not committed. `Dockerfile.custom-source` verifies its SHA-256 before extracting only
the self-contained `cert-cpp-coding-standards.tgz` member into the operator-provided licensed
source image. Runtime analysis remains offline.

The small launcher and integration code in this directory are part of this repository and do not
grant or redistribute a CodeQL license.
