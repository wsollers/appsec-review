# Packer

An autotools project. `src/` is an automake SUBDIR; the vendored `third_party/zlite` is a CMake
project the top-level Makefile.am configures and builds before the packer links against it.
