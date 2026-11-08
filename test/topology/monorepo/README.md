# Build-topology fixture monorepo

A small, deterministic repository whose directory shapes stand in for a real multi-platform
monorepo (native server, engine client, mobile clients, a website) so the build-discovery ->
topology -> plan layer can be exercised in seconds. Every compiled part builds with stock
cmake/make/gcc, cargo, go and node; nothing needs a network. The tree is byte-pinned by
`MANIFEST.json` (SHA-256 of every file; regenerate with
`python -m appsec_review.acceptance.topology manifest --write`). The behaviour expected of the
tooling over this tree lives outside the tree in `../monorepo.expectations.json`.

| Shape | Directory | What it contains | Why it is here |
| --- | --- | --- | --- |
| A | `server/` | A CMake application that `add_subdirectory(third_party/tinylib)`; the vendored library has its own `CMakeLists.txt`, a legacy standalone `Makefile`, and a `test/Makefile` whose sources are `../src/*.c`. | A nested Makefile under a parent driver must be owned by the parent, not built on its own. |
| B | `tools/packer/`, `common/` | A Makefile that compiles `main.c` together with `../../common/src/util.c` and includes `../../common/include/util.h`. | The build needs more of the tree than the unit's own directory. |
| C | `rust/`, `go/`, `web/` | A Cargo workspace (two crates, `cli` depends on `core` by path), a `go.work` workspace (two modules), and an npm workspace (two packages, root `build` script runs `node build.js`). | Workspace members belong to the workspace root, where the build runs. |
| D | `client-unity/` | `ProjectSettings/ProjectVersion.txt`, `Packages/manifest.json`, one script. | An engine project whose build is a policy decision, not a Linux image. |
| E | `client-ios/` | `App.xcodeproj/project.pbxproj` and one Swift file. | A platform no pinned image can build; source analysis only. |
| F | `client-android/` | `settings.gradle` including `:app` and `:lib`, each with a `build.gradle` (no root `build.gradle`, no wrapper jar), one Kotlin file each. | One project rooted at the settings file, never two independent roots. |
| G | `website/` | `public/index.php` with no `composer.json`; `lib/composer.json` with `src/Foo.php`. | An interpreted tree without a build beside a package-only unit. |
| H | `server/examples/hello/` | A `CMakeLists.txt` without `project()`, included by the parent only under `option(SERVER_BUILD_EXAMPLES ... OFF)`. | A nested root that can never build alone and is not even built by default. |
| I | `tools/sign/` | A self-contained CMake project nothing references. | The control: a genuine second native root. |

## Building the compiled shapes by hand

Work on a copy, never inside this directory:

```text
cmake -S server -B /tmp/build-server && cmake --build /tmp/build-server
cmake -S tools/sign -B /tmp/build-sign && cmake --build /tmp/build-sign
make -C tools/packer                      # succeeds only with common/ present
make -C server/third_party/tinylib/test   # succeeds only with ../src and ../include present
(cd rust && cargo build --workspace --offline)
(cd go && go build ./shared/... ./svc/...)
(cd web && npm run build)
```

The Unity, Xcode, Gradle and PHP shapes are not built; they exist to be classified.
