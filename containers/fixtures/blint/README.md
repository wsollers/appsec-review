---
title: "BLint fixture"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# BLint fixture

Functional acceptance compiles `vulnerable.c` into a run-owned ELF artifact before cataloging it.
The scanner receives only that accepted artifact and never compiles or executes target code.
