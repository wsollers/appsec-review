# Entry-export smoke fixture (brief Q3)

`libentry.cpp` is built as a shared library with `-fvisibility=hidden` by `scripts/smoke_entry_exports.sh`:

| Function | Linkage / visibility | Expected |
|---|---|---|
| `entry_parse` | external, `visibility("default")` | exported-symbol root; the `strcpy` in `sink_copy` (line 9) is REACHABLE through it |
| `helper_static`, `sink_copy` | `static` | not in `.dynsym`, never a root |
| `helper_hidden`, `only_from_hidden` | `visibility("hidden")` | not in `.dynsym`, never a root; line 19 is not REACHABLE |
| `fx::overload(int)`, `fx::overload(const char*)` | exported overloads | one qualified name, two CPG methods: `ambiguous-export`, no entry |

`cpg-records.jsonl` is a hand-written CPG for this file in the Joern exporter's record shape (the smoke
test checks the export side live: build, `binary-summary`, join). It is canned, not a Joern run.
