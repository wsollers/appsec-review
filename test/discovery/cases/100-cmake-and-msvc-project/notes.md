# 100 — CMake and a hand-maintained MSVC project at one root (C1, positive)

Two build systems describe the same two sources from the same directory. The contract (plan §4 C)
wants one unit per system at that root, `parallel_with` on each naming the other, and a recorded
capture authority. Vocabulary used by the C cases (100–106):

- `parallel_with`: labels (`root|system`) of the other units at the same root that build the same
  sources.
- `capture_authority`: `primary` on the unit whose build is captured, `secondary` on the others.
  Policy: the system the review's native lane can run and that emits a compilation database
  natively wins — CMake and meson over make and autotools, any of those over MSBuild (not in the
  native profile). The secondary's descriptors stay evidence of its own unit; the shared sources
  are bound to the primary's build points.
- `generated_by` (case 101): the system whose generator wrote this unit's descriptors.

The `.sln` here is not a .NET build: it lists one `.vcxproj`. Today it is concluded as a
`dotnet` unit at the same root, and the MSBuild context files (`.filters`, `.user`,
`Directory.Build.props`) attach to that look-alike (matrix A4, T-056.4).
