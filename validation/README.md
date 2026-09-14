# validation

Ground-truth corpus (design §19). First target: Notepad++ v8.5.6 (CVE-2023-40031/40036/40164/40166, Utf8_16_Read::convert) → v8.5.7 before/after. Second VS2013-era target: open.


Records:
- `notepad-plus-plus-8.5.6.md` — first CVE rediscovery run (2026-09-12): CSA found 1 of 4 with all 4 in scope (346 TUs); the three misses are the SVF lane's acceptance test.
