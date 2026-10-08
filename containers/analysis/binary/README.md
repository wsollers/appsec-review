# Binary-analysis replacements

The omnibus reverse-engineering image is replaced by enabled narrow tools where coverage overlaps:
BLint for hardening properties, Syft for inventory, and Grype/Trivy for matching and configuration.
Any future disassembler, parser, or debugger image must be one bounded capability with an explicit
output/failure contract, a fixed artifact closure, and a representative binary fixture.
