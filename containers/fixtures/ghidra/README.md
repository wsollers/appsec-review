# Ghidra known-binary fixture

`case-083/main.c` is a byte-identical copy of `projects/native/case-083/src/main.c` from
[`wsollers/appsec-multi-vuln`](https://github.com/wsollers/appsec-multi-vuln) at commit
`7c10536389c3cfb20a27d7a6a78943267ea43b3f` (Git blob `fa0fdffc66f50213e8921d349630762de492fe42`, SHA-256
`6d4a19d1bcd41dec9ec9d763c324f53f1523090f44b7bd938a79e917be58e5cc`). It is a synthetic CWE-120:
`print_label` copies `argv[1]` into a 32-byte stack buffer with `strcpy`. Do not reuse it.

No binary is committed. `python -m appsec_review.binary_decompilation.efficacy` compiles the
source offline with the pinned `tool-native-cpp` image into the variants declared in
`expectations.json`, decompiles each with `tool-ghidra`, and scores the publication against the
checks listed there. Because the source is known, every check has a ground-truth answer.

| Variant | Flags | What it measures |
| --- | --- | --- |
| `symbols` | `-O0 -g -fno-inline` | Best case: names, types, and the buffer size survive. |
| `stripped` | `-O2 -s` | Realistic third-party case: names are gone and the helper is inlined. |

`expectations.json` is the answer key for this fixture. It is repository-development material and
must never be copied into a review target or a review-worker prompt.

See [`docs/operations/binary-decompilation.md`](../../../docs/operations/binary-decompilation.md)
for the commands and
[`docs/architecture/binary-decompilation.md`](../../../docs/architecture/binary-decompilation.md)
for the design.
