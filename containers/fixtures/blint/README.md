---
title: "BLint fixture"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# BLint fixture

Functional acceptance compiles `vulnerable.c` into a run-owned ELF artifact before cataloging it.
The scanner receives only that accepted artifact and never compiles or executes target code.
