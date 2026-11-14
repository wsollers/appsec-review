---
title: "BLint fixture"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# BLint fixture

Functional acceptance compiles `vulnerable.c` into a run-owned ELF artifact before cataloging it.
The scanner receives only that accepted artifact and never compiles or executes target code.
