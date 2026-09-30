# ADR-0033: Build images once on hal5000, pull them elsewhere through a private registry

Status: **Accepted** (2026-09-30, William: "store the docker images in github and just maintain them once";
publishing host hal5000).

## Context

Every host built all 34 images the B13 registry needs (`orchestrator/prepare-host.sh` step 3). The operator
switches between zarathustra and hal5000 often, and a week of image changes meant hours of rebuilds on each.
The B16 records already pin a local image id and jobs never pull (`--pull never`), so a pulled image works
as long as the build state that the records are generated from is right.

Two things made a pulled image fail the fingerprint check:

- A dependent image's fingerprint named its base images by local image id. Docker Engine (zarathustra) and
  Docker Desktop's containerd image store (hal5000) give the same pulled bytes different ids.
- `scancode-toolkit` clones its source at build time without a pinned commit, and the fingerprint names
  the clone's HEAD. A host that pulls has no clone.

## Decision

1. hal5000 (WSL) is the publishing host. `images/image_build.py publish <id>... | --all` pushes a current
   successful build to `ghcr.io/wsollers/appsec-review/<id>` (private; `APPSEC_IMAGE_REGISTRY` overrides)
   and records the manifest digest, fingerprint, attempt id, completion time and clone commits in the
   committed `images/published.lock.json`.
2. `image_build.py pull <id>... | --all` pulls `repository@manifest_digest` only when the lock's fingerprint
   equals this checkout's. It tags the image with its local tag and writes `latest.json` with the
   publisher's fingerprint and attempt id and this host's image id. The B16 records, the container adapter
   and every job are unchanged. A lock older than the sources is `STALE` and the host builds locally.
3. A fingerprint names each required image by its build identity (fingerprint and attempt id from
   `latest.json`), not its local image id. A rebuilt base still changes its attempt id, so its dependents
   rebuild as before. A host with no clone takes the clone commit from the lock.
4. `prepare-host.sh` step 3 pulls before it builds. `image_build.py rekey` (run by step 3) moves builds that
   are current under the old fingerprint to the new one without rebuilding; remove it once both hosts ran it.

## Consequences

- An image is maintained once: change it, build on hal5000, `publish`, commit the lock. Other hosts pull.
- Each host needs `docker login ghcr.io` with a classic token: `read:packages` to pull, `write:packages`
  on hal5000. Without it a pull fails and step 3 falls back to building, as before.
- Private package storage is billed beyond GitHub's free allowance; the images are tens of GB. The CodeQL
  bundle's licence is the reason the packages stay private.
- The dependent images' fingerprints change once, so their B16 records change and jobs that use them rerun
  once (as after brief K).
- A pulled image is not reproduced locally; its provenance is the publisher's attempt, named in the lock and
  in the B16 record's `build_attempt_id`.
- Build state is no longer strictly per host: the lock carries hal5000's build identity to every host
  ([host layouts](../processes/host-layouts.md)).
