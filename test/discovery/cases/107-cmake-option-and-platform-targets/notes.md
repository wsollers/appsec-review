# 107 — CMake option() and platform-gated targets (E1, positive)

The contract (plan §4 E) says build points carry condition facts and discovery never drops a
conditional build point nor claims it unconditionally. The case schema has no `condition` field on
a build point, so the E cases (107–114) state conditions on the unit:

- `conditions`: `{<build point name>: <condition expression in the build system's own words>}`,
  present on every unit and `{}` when nothing is conditional.
- `options`: `{<option>: <default>}` for CMake `option()` declarations.
- `source_conditions` (E3, E4): `{<path>: <condition>}` for a source compiled only under a
  configuration, platform or build tag (`ExcludedFromBuild`, `//go:build`, `_windows.go`).
- `includes` (E2): the `include $(VAR).mk` directives and the files they can resolve to.
- `configurations`, `configuration_mapping` (E3): MSBuild solution configurations and which of
  them build each project.

The plan (T-036) decides what to do with a conditional build point; discovery only records it.
`app/tools/CMakeLists.txt` is reached through `add_subdirectory` inside `if(APP_BUILD_TOOLS)`: not
a unit of its own (T-056.5), its target a conditional build point of `app`.
