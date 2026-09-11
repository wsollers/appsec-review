# ADR-0003: Source of MSVC headers/libs for clang-cl on Linux

Status: Accepted 2026-09-11 (default: option 1, xwin) — option 2 remains available

## Context

clang-cl on Linux needs the MSVC CRT headers/libs and a Windows SDK to compile Windows
targets. The vendor code targets VS2013 (toolset v120, `_MSC_VER` 1800).

## Options

1. **xwin / msvc-wine** — fetches the current MSVC CRT + Windows SDK from Microsoft's
   manifests at image-build or run time. Easy and reproducible (pin the manifest version),
   but it is the 14.x toolset. VS2013 code will hit `_MSC_VER` guards and CRT differences;
   compile with `-fms-compatibility-version=19.x` and patch 2013-isms. Analysis semantics
   diverge from what shipped (design §22.4).
2. **Real v120 headers/libs** lifted from a VS2013 installation. Faithful to release
   semantics; clang may reject some of the old headers; obtaining them requires a Visual
   Studio subscription.

## Constraints regardless of option

- Microsoft headers/libs are never baked into an image layer. They are mounted as a
  licensed input volume, hashed, and recorded in `build-isolation-manifest.json`.
- The mount point is identical for both options so the Dockerfile does not change.
- The chosen option and its hash are recorded in `run-manifest.json`.

## Decision

Default to **option 1 (xwin, manifest 17)**: obtainable without a subscription, pinnable, reproducible. The image, converter, and smoke test detect the mounted layout and emit `-imsvc` flags for xwin's `crt/`+`sdk/` tree or `/winsysroot` for a real VS tree, so switching to option 2 changes only what is mounted at `/msvc`. Revisit if the feasibility gate shows the modern CRT rejecting VS2013 code at a rate that pushes L3 below Tier B.
