# svf-taint — whole-program taint over SVF's value-flow graph

Status 2026-09-12: **written against SVF-3.3 headers (API names verified), not yet
compiled.** First build happens inside the image via `build.sh`; expect a round of
compile fixes.

## Why it exists

CSA + CTU + a Win32 taint config catches the 40036/40164 shape when the index and the
table are one or two calls apart (verified on a synthetic case). It is still per-path,
per-entry-point exploration with a budget. SVF gives the other view: a whole-program,
flow-insensitive value-flow graph where "does an input byte reach this index" is a graph
reachability question with no path budget. The two disagree in useful ways: what CSA
misses for budget reasons SVF still reports; what SVF over-approximates CSA (or a human)
refutes. That pairing is the L3 memory-safety lane.

## What it reports

Candidates, not proofs. Each has source (call, arg, location, function), sink (statement,
location, function), and — where the base is resolvable — the object, its kind
(global/heap/stack) and its declared byte/element size.

| kind | meaning |
|---|---|
| `TAINTED_INDEX` | tainted value used as a GEP index into a global / constant array |
| `TAINTED_HEAP_OFFSET` | tainted value used as a GEP offset on a heap object |
| `TAINTED_SIZE_ARG` | tainted value is the size argument of a copy/alloc call |

## Acceptance test

The three Notepad++ v8.5.6 CVEs CSA missed: 40166 (`Buffer.cpp`,
`detectLanguageFromTextBegining`), 40036 (`CharDistribution.cpp`, `HandleOneChar`), 40164
(`nsCodingStateMachine.h`, `NextStateImpl`). Source for all of them is `ReadFile` in
`Buffer.cpp`. Passing = each site appears as a candidate in v8.5.6. The 40031 site should
appear too (`TAINTED_HEAP_OFFSET` on `m_pNewBuf` writes), and its disappearance in v8.5.7
is not expected — the bound was fixed, the taint flow is the same; that is exactly the
case where the candidate is correct and the *refutation* is what changes between
versions.

## Build and run (inside audit-native)

```
# build (repo mounted as /workspace, output to /scratch)
images/audit-native/run.sh . - ./scratch -- bash /workspace/images/audit-native/svf-taint/build.sh /scratch/svf-taint-build

# run on the linked notepadPlus module from link_ir.py
images/audit-native/run.sh . - ./scratch-npp -- /scratch/svf-taint-build/svf-taint \
    -sources=ReadFile:1,MapViewOfFile:-1 -out=/scratch/svf-taint.json \
    /scratch/linked/PowerEditor__visual.net__notepadPlus.bc
```

Note the first command mounts the *repo* as `/workspace` (to read the source) and the
second mounts nothing there; the binary and module live under scratch dirs. Once the
build is clean, add it to the Dockerfile after the SVF layer so it ships at `/opt/svf-taint`.

## Known limitations of this first version

- Flow- and context-insensitive (Andersen). Expect false positives wherever a bound check
  exists; they are the refutation lane's input, not noise to suppress here.
- Source attribution is first-wins; a value tainted by two sources reports one.
- Integer arithmetic propagates through SVF's BinaryOP nodes; bit-tricks that SVF models
  as unknown break the chain (under-report).
- `-sources` names match by substring for C++ symbols; tighten once mangled-name
  matching is needed for vendor-specific deserializers.
