# Host

The host project builds two in-tree dependencies through CMake itself: `external/tinylib` as an
ExternalProject (its own configure and build, run by the host build) and `external/fmtlite` through
FetchContent, which adds it as a subdirectory of the host configure.
