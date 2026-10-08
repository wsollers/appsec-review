# BLint fixture

Functional acceptance compiles `vulnerable.c` into a run-owned ELF artifact before cataloging it.
The scanner receives only that accepted artifact and never compiles or executes target code.
