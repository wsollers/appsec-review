# Packer

An autotools project whose `src/` is an automake SUBDIR. `third_party/zlite` is a CMake project that
must be built beforehand by whoever builds the packer; nothing in the autotools build runs it.
