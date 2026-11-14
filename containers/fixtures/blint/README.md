---
title: "BLint fixture"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# BLint fixture

Functional acceptance compiles `vulnerable.c` into a run-owned ELF artifact before cataloging it.
The scanner receives only that accepted artifact and never compiles or executes target code.
