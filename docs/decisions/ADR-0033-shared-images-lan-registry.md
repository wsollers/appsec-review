# ADR-0033: Build images once on hal5000, pull them elsewhere from a LAN registry

Status: **Accepted** (2026-09-30, William: build and maintain the images once; publishing host hal5000;
registry on zarathustra's LAN, not GitHub's container registry, whose private storage is billed).

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

1. zarathustra runs Docker's `registry` image (`orchestrator/image-registry/compose.yaml`) at
   `192.168.1.228:5000`: plain HTTP on the LAN, no auth, data in a named volume. Every host lists it under
   Docker's `insecure-registries`.
2. hal5000 (WSL) is the publishing host. `images/image_build.py publish <id>... | --all` pushes a current
   successful build to `192.168.1.228:5000/appsec-review/<id>` (`APPSEC_IMAGE_REGISTRY` overrides) and
   records the manifest digest, fingerprint, attempt id, completion time and clone commits in the committed
   `images/published.lock.json`.
3. `image_build.py pull <id>... | --all` pulls `repository@manifest_digest` only when the lock's fingerprint
   equals this checkout's and the repository is under the configured registry. It tags the image with its
   local tag and writes `latest.json` with the publisher's fingerprint and attempt id and this host's image
   id. The B16 records, the container adapter and every job are unchanged. A lock older than the sources is
   `STALE` and the host builds locally.
4. A fingerprint names each required image by its build identity (fingerprint and attempt id from
   `latest.json`), not its local image id. A rebuilt base still changes its attempt id, so its dependents
   rebuild as before. A host with no clone takes the clone commit from the lock.
5. `prepare-host.sh` step 3 pulls before it builds. `image_build.py rekey` (run by step 3) moves builds that
   are current under the old fingerprint to the new one without rebuilding; remove it once both hosts ran it.

## Consequences

- An image is maintained once: change it, build on hal5000, `publish`, commit the lock. Other hosts pull.
- No cost and no account. Pulls need zarathustra up; when it is not, step 3 falls back to building.
- The registry has no authentication. Anyone on the LAN can push to it, but a host pulls only the manifest
  digest committed in the lock, and Docker verifies content by digest, so a foreign push cannot change what
  a host runs. It can fill the disk; the registry is not exposed beyond the LAN.
- The dependent images' fingerprints change once, so their B16 records change and jobs that use them rerun
  once (as after brief K).
- A pulled image is not reproduced locally; its provenance is the publisher's attempt, named in the lock and
  in the B16 record's `build_attempt_id`.
- Build state is no longer strictly per host: the lock carries hal5000's build identity to every host
  ([host layouts](../processes/host-layouts.md)).
- If zarathustra's LAN address changes, set `APPSEC_IMAGE_REGISTRY` and republish; the lock records full
  repository names.
