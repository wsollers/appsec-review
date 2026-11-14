---
title: "Binary-analysis replacements"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Binary-analysis replacements

The omnibus reverse-engineering image is replaced by enabled narrow tools where coverage overlaps:
BLint for hardening properties, Syft for inventory, and Grype/Trivy for matching and configuration.
Any future disassembler, parser, or debugger image must be one bounded capability with an explicit
output/failure contract, a fixed artifact closure, and a representative binary fixture.

`tool-ghidra` (`containers/tools/ghidra/`) is the first such image: headless disassembly and
decompilation of one binary, with the export and failure contract in its README, the closure in
its `inventory.json`, and the case-083 fixture under `containers/fixtures/ghidra/`. The fixture is
source only; its binaries are compiled on demand and never committed.
