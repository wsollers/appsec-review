# ADR-0033: Build images once on hal5000, share them through Google Drive

Status: **Accepted** (2026-09-30, William: build and maintain the images once; publishing host hal5000;
store them in his Google Drive (2 TB plan), not GitHub's container registry, whose private storage is
billed, and not a LAN registry).

## Context

Every host built all 34 images the B13 registry needs (`orchestrator/prepare-host.sh` step 3). The operator
switches between zarathustra and hal5000 often, and a week of image changes meant hours of rebuilds on each.
The B16 records already pin a local image id and jobs never pull (`--pull never`), so a loaded image works
as long as the build state that the records are generated from is right.

Two things made a shared image fail the fingerprint check:

- A dependent image's fingerprint named its base images by local image id. Docker Engine (zarathustra) and
  Docker Desktop's containerd image store (hal5000) give the same loaded bytes different ids.
- `scancode-toolkit` clones its source at build time without a pinned commit, and the fingerprint names
  the clone's HEAD. A host that loads the image has no clone.

## Decision

1. The image store is a Google Drive folder, named per host by `APPSEC_IMAGE_STORE`: an rclone remote
   (`gdrive:appsec-review/images`, the default setup on both hosts) or an absolute folder (a synced or
   mounted Drive folder).
2. hal5000 (WSL) is the publishing host. `images/image_build.py publish <id>... | --all` writes
   `docker save <tag> | zstd` to `<id>-<sha256 prefix>.tar.zst` in the store and records the archive name,
   its sha256, the fingerprint, attempt id, completion time and clone commits in the committed
   `images/published.lock.json`.
3. `image_build.py pull <id>... | --all` acts only when the lock's fingerprint equals this checkout's. It copies
   the archive to local staging, checks its sha256 against the lock, `zstd -d | docker load`s it, and writes
   `latest.json` with the publisher's fingerprint and attempt id and this host's image id. The B16 records,
   the container adapter and every job are unchanged. A lock older than the sources is `STALE` and the host
   builds locally.
4. A fingerprint names each required image by its build identity (fingerprint and attempt id from
   `latest.json`), not its local image id. A rebuilt base still changes its attempt id, so its dependents
   rebuild as before. A host with no clone takes the clone commit from the lock.
5. `prepare-host.sh` step 3 pulls before it builds when `APPSEC_IMAGE_STORE` is set. `image_build.py rekey`
   (run by step 3) moves builds that are current under the old fingerprint to the new one without
   rebuilding; remove it once both hosts ran it.

## Consequences

- An image is maintained once: change it, build on hal5000, `publish`, commit the lock. Other hosts pull.
- Works from any network; nothing has to stay on. Every change uploads the whole image (archives do not
  share layers the way a registry does), so a publish is bound by upload bandwidth.
- The lock's sha256 is the integrity check: an archive that is still syncing, truncated or replaced is
  refused and never loaded. Anyone with write access to the Drive folder can replace an archive, but not
  what a host loads.
- Old archives stay in the folder until deleted by hand; the lock names the current ones.
- The dependent images' fingerprints change once, so their B16 records change and jobs that use them rerun
  once (as after brief K).
- A loaded image is not reproduced locally; its provenance is the publisher's attempt, named in the lock and
  in the B16 record's `build_attempt_id`.
- Build state is no longer strictly per host: the lock carries hal5000's build identity to every host
  ([host layouts](../processes/host-layouts.md)).
