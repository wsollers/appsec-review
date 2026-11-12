# Unity discovery, inventory and builds

Unity is an engine identity on a language build unit, not a replacement language. A validated
project has `family = "dotnet"`, `build_system = "unity"` and an `engine` declaration with the
source's Editor stamp/revision. C# and native source remain available to their analysis lanes.
The source declaration is not evidence that an Editor is installed or that a player was built.

## Discovery and inventory

Discovery reads only accepted, bounded catalog descriptors. `ProjectSettings/ProjectVersion.txt`
must contain a valid Editor declaration with supporting project settings or a package manifest
in the same project root. An ordinary `Assets` directory or `.unity` scene is insufficient.
Generated IDE projects under an accepted Unity root do not authorize a generic .NET/MSBuild build.
Descriptor-first retention preserves the existing ordinary-content quotas, exclusions, path and
symlink safeguards; unread, incomplete and competing observations remain explicit.

Manifest requests and lock-recorded versions/edges are distinct observations. A requested
dependency version differing from a locked version is not, by itself, a resolution failure.
Builtin package versions remain their own versions and have engine-qualified identities.
Assembly definitions describe module scope and platform filters, not authenticated plugin
packages. Editor-only and mixed modules remain source inventory. Default Android/iOS settings
do not establish selected targets or shipment; opaque backend/architecture/SDK numbers remain raw.
Missing or uninspected native/plugin/package contents are coverage gaps, not evidence of absence.

Dependency intelligence enriches its existing SPDX 2.3 publication, not a second SBOM format.
Metadata-only packages have `filesAnalyzed = false`, unresolved downloads/licenses use
`NOASSERTION`, and unknown versions remain omitted. Descriptor evidence hashes are not package
checksums. Project-to-dependency `DEPENDS_ON` edges retain requested-version evidence; supported
build/test/development/runtime relationships have dependency-to-dependent direction.
Versioned application metadata is carried in SPDX comments, not nonstandard package fields.
No hypothetical APK/IPA, contained file, shipped-runtime or package verification assertions are
created from source metadata.

Configuration fingerprints are versioned canonical input identities with explicit unknowns and
partial status. They bind the source/root, declared engine, recorded settings/dependencies and
known build inputs; they do not prove reproducibility, execution, or shipped content.

The catalog now captures bounded settings and plugin `.meta` documents into the same descriptor
bundle used by graph/2. Raw backend/platform/CPU declarations remain source-scoped partial facts,
not generic .NET recipes, mobile selection or a reason to provision an Editor. Shared ancestor
Dockerfile context uses the same deterministic compiler; unrelated descendant Dockerfiles cannot
grant a Unity or native unit context. Sensitive container declarations are withheld with a gap.
These V2 source additions are not yet executed or accepted.

## Execution boundary

`jobs.job_project_build.settings.unity` defaults to:

```toml
[jobs.job_project_build.settings.unity]
enabled = false
```

An operator must explicitly configure a provisioned, immutable non-root container capability
matching the project's exact Editor stamp and requested platform/backend/architecture. Existing
container execution, cancellation, timeout, working-directory and output boundaries apply.
The review never installs an Editor, obtains a license, configures credentials or provisions
SDKs/modules/images. Source/dependency analysis continues when preflight cannot establish build
capability. Linux-container availability does not imply iOS/macOS build-host support.

The flat typed settings describe one operator-selected capability per run. Set `tag` to an
explicit non-`latest` local tag, `image_id` to its immutable `sha256:...`, `user` to numeric
non-root `uid:gid`, `editor_executable` to its absolute in-container path, and the exact
`editor_version`/`editor_revision` declared by source. Set `target`, `architecture`,
`scripting_backend`, `modules` (target enum names), `license_ready`, and a canonical
`output_path` under a dedicated build directory. `execute_method` is an optional qualified
static entrypoint; otherwise the reviewed run-owned `BuildPipeline` bridge is used.
`timeout_seconds`, `output_bytes` and `artifact_count_limit` bound execution/log retention/output
inventory; existing job/unit and container resource limits may be stricter and are not raised.
Unknown fields, arbitrary command arrays, environment overrides and credentials are
rejected. The configured image and license/module declarations are preflight claims until actual
Editor/version/module/backend checks succeed. An exact declared revision must match both
configuration and observed Editor full-version evidence.

For `case-095`, select `target = "StandaloneLinux64"`, `architecture = "x86_64"`,
`scripting_backend = "Mono"`, `modules = ["StandaloneLinux64"]`,
`execute_method = "AppSecCorpus.Editor.CorpusBuild.Build"` and
`output_path = "build/Case095.x86_64"`, with `timeout_seconds = 900` and the operator's real
image/Editor identity. Do not copy placeholder image IDs or license material into configuration.
The source pin `2022.3.62f1` alone is not that provisioned identity.

Unity actions bypass model recipe inference and generic project-image repair. A build operates
only on a run-owned source copy. Successful execution requires a successful actual build command
and verified, newly produced outputs; detection, a plan, or successful capability preflight is
insufficient. Command/output receipts are independent from configuration fingerprints.
The language-build publication forwards the accepted Unity receipt without a second build, so
artifact indexing, dependency consumers and receipt-backed telemetry observe the same result.

`review.build_units.discovered_by_engine`, `by_engine` and `engine_discovery` in run metrics
expose detection, execution outcomes and coverage separately. The telemetry report includes an
engine-build coverage table; failed or not-requested engine work is never represented as success.
Compiler capture and platform-specific packaging limitations remain named gaps.

### Original corpus fixture contract

The separately maintained `wsollers/appsec-multi-vuln` fixture root is
`projects/unity/case-095`. Its agreed capability is exact Editor `2022.3.62f1`,
Mono / `StandaloneLinux64` / `x86_64`, with the Linux player module already provisioned.
The Unity command-line target is `Linux64`; the C# `BuildTarget` enum is
`StandaloneLinux64`. Its configured entrypoint is
`AppSecCorpus.Editor.CorpusBuild.Build` with `output_path = "build/Case095.x86_64"`.
The executor supplies `APPSEC_UNITY_OUTPUT` as an absolute output filename inside the copied
project; the standalone corpus wrapper alternatively supplies `-corpusBuildOutput`.
Expected products include a nonempty player and
`Case095_Data/Managed/Assembly-CSharp.dll`. The corpus does not fabricate compiler artifacts
or application receipts. The appsec executor owns preflight, command and output evidence.

The [exact published release](https://unity.com/releases/editor/whats-new/2022.3.62f1),
[2022.3 Editor command-line reference](https://docs.unity3d.com/2022.3/Documentation/Manual/EditorCommandLineArguments.html)
and [license management](https://docs.unity3d.com/2022.3/Documentation/Manual/ManagingYourUnityLicense.html)
are the applicable upstream references. Original/MIT-licensed fixture source does not remove
Unity Editor licensing or activation requirements. Engine-independent .NET unit checks are not
Editor-build evidence. Evaluator answer keys are outside target/review inputs and are not part
of this executor contract.

## Validation boundaries

Synthetic fixtures live under `tests/fixtures/unity_workflow/` and
`tests/fixtures/unity_inventory/`. Focused unit checks use fake external execution boundaries;
they are not Unity Editor compilation or activation evidence.

Unit command (Linux checkout with its own installed test environment):

```bash
.venv/bin/python -m pytest -q tests/test_unity_inventory.py tests/test_unity_build.py \
  tests/test_unity_workflow.py --basetemp=test/tmp/unity-unit
```

Manual commands below are **not unit checks**. They require an explicit execution request and
`APPSEC_UNITY_INTEGRATION_CONFIG` naming a central TOML file with an already licensed,
provisioned exact-version Linux64/Mono Unity capability and the reviewed default build bridge:

```bash
.venv/bin/python -m pytest -q tests/acceptance/job_project_build/test_unity_project_builds.py \
  --basetemp=test/tmp/unity-project-acceptance
.venv/bin/python -m pytest -q tests/acceptance/test_unity_workflow.py \
  --basetemp=test/tmp/unity-acceptance
```

These suites perform real Editor/container execution only when explicitly selected; they are
excluded from implicit collection. They do not skip missing provisioning: they fail with the
named prerequisite instead of claiming acceptance. They were authored but **not run** for this
implementation. No existing live review, target clone, deployed process or container pin is
updated by this implementation.
