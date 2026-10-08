# CodeQL C/C++ runtime notice

This directory contains only the reviewed integration, identities, and acquisition metadata.
It does not redistribute the CodeQL CLI or query packs. The runtime validates a separately
provided, locally licensed `audit-codeql:local` image against `assets.lock.json`, then copies
its pinned `/opt/codeql` payload into an image derived from the already accepted project build
image. That preserves the exact project toolchain and keeps network access disabled.

Use of the CodeQL payload remains subject to the license shipped at `/opt/codeql/LICENSE.md` in
the source image. If the pinned local asset is absent or its identity changes, capability
validation fails before any coverage is claimed.
