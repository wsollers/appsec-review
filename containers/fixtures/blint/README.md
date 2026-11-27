---
title: "BLint fixture"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "ea03df9695991eafe37065717624278af845a74c"
---
# BLint fixture

Functional acceptance compiles `vulnerable.c` into a run-owned ELF artifact before cataloging it.
The scanner receives only that accepted artifact and never compiles or executes target code.
