---
title: "Image-pin verification and host bindings"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_image_pin_verification", "job_model_connectivity"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Image-pin verification and host bindings

The operator builds and smokes images on each review host's declared Docker daemon. Committed
configuration describes recipes: tags, versions and asset payload hashes. Observed Docker IDs and
CodeQL preinstalled runtime declarations live only in ignored `deploy/dagster/host-pins.toml`.
They are not portable between daemons or hosts, and pinning never edits tracked recipes.

<a id="host-procedure-rebuild-re-pin-reload"></a>

## Host procedure

Do not rebuild or move tags while a review uses them. After an explicitly authorized image build
and smoke, inspect and publish the local bindings:

```bash
.venv/bin/appsec-review update-image-pins
.venv/bin/appsec-review update-image-pins --write
.venv/bin/appsec-review signing sign-image --all-pinned --private-key ~/.config/appsec-review/signing/private/operator.pem
```

The updater inspects each distinct recipe tag once. It includes enabled catalog images and
configured job/reporting image references. Missing or uninspectable images refuse the entire
update. The complete candidate configuration must pass the real typed loader before the host file
is atomically replaced; configuration/catalog bytes never change. An unchanged update is idempotent.
`run-readiness pin` runs these commands without a Git add or commit.

The host file has a closed schema:

```toml
schema = "appsec-review/host-pins/1"
preinstalled_runtimes = []

[images]
"audit-buildenv-cpp:local" = "sha256:<64 lowercase hex digits>"
"audit-codeql:custom-2.27.0" = "sha256:<64 lowercase hex digits>"
```

The example is illustrative, not a complete or loadable inventory. Use the updater for the complete
set. `APPSEC_REVIEW_HOST_PINS` may select another explicit file; the default is relative to the
configuration's directory. The loader's `host_pins=` argument takes precedence over that variable.
No missing binding falls back to another host's committed ID.

Declare a preinstalled CodeQL runtime only after verifying its actual source/build/runtime IDs,
effective numeric user, CodeQL/runner releases and runner source. Entries use the existing typed
CodeQL declaration fields under `[[preinstalled_runtimes]]`. A moved source does not relabel an
old runtime: conflicting declarations refuse the update. Missing declared build/runtime images
also refuse it. Remove or correct the declaration explicitly. An empty set retains the configured
`preinstalled_undeclared = "derive"` policy; it is not evidence that a runtime is installed.

Signing policy is unchanged. Image launch enforcement remains configured by
`[signing].image_enforcement`; signing images does not enable enforcement. Key provisioning and
explicit signature verification read signing policy without requiring image inventory first.
The host bindings are identity inputs, not signatures or authorization to trust an image.

## Frozen configuration

The loader applies host bindings after the runtime profile and capacity overlay, before typed
validation. Build profiles, CodeQL, dossier rendering and telemetry rendering all receive the
same tag-to-ID binding. The resolved JSON includes the host document and its hash. The runner
copies its exact bytes to `runs/<run-id>/data/configuration/host-pins.toml` and records the layer
in the configuration manifest. Intake verifies that copy against the resolved record.

Changing bindings changes the resolved configuration identity. Existing run files are never
rewritten to follow the host. A source-only repair cannot admit a configuration change; start a
fresh authorized run. This applies to the T-051 cutover itself. Preserve old run evidence rather
than importing acceptance into a differently configured run.

## The gate

`job_image_pin_verification` follows `job_model_connectivity`, before target acquisition/intake.
It always executes and does not propagate its handoff into downstream semantic identity.
Its `enabled` setting remains the existing typed Boolean.

The job reads the catalog and **frozen resolved configuration**, verifies the frozen host-pins
hash, and checks every enabled non-manual catalog image, enabled job image reference and enabled
telemetry PDF image against its bound ID. A manual catalog image is still checked when an enabled
job/report references it. It runs only `docker image inspect`, through the injectable runner.

`image-pin-plan/2` records catalog, resolved-configuration and host-pins hashes plus the selected
pins. `image-pin-verification.json` and the handoff record every expected/observed ID and status.
Success requires every selected binding to match. Missing, moved or uninspectable images fail
with `ImagePinVerificationFailed`, retained diagnostic artifacts and one retryable
`producer-gap/1` record per failing reference. Failed attempts publish no accepted handoff.
Started/completed/failed events retain pin counts or detailed failures.

## Deploying changed application code

Compose mounts the existing host-pins file read-only into each application service and refuses
to create a directory when that file is missing. Generate bindings before starting the stack.
For source/configuration changes, use `scripts/stack-restart.sh --code-location-only` (the source
reload/signing path), not an application-image rebuild. Build images only for actual tooling or
dependency changes. A CodeQL image/release or query-source change still requires the bounded
query-pack compilation documented in [CodeQL operations](codeql-analysis.md).
