# ir-facts + verify_candidate — the mechanical half of L7

`ir-facts` (LLVM tool) dumps from the linked bitcode the numbers a memory-safety claim
rests on: global array element counts, constants stored into fields by constructors,
non-constant GEP indices with their width/provenance, size arguments of copy/alloc calls,
stack arrays. `verify_candidate.py` matches findings (CodeQL SARIF, CSA) to those facts by
source location and emits VERIFIED_PRIMITIVE / REFUTED / UNRESOLVED with the evidence.

Design §23.1: VERIFIED_PRIMITIVE confirms the *local mechanism*; each result also states
what would resolve the remaining dependency (range analysis, witness) — those are the
`VERIFICATION_DEPENDENCY_REGISTERED` events for the orchestrator.

Status 2026-09-13: ir-facts not yet compiled. Expected on Notepad++ v8.5.6 with the
mythos pack results:
- table-size (40036): VERIFIED_PRIMITIVE — IR global `[5376 x i16]`, ctor stores 8102.
- constant-length-read (40166): VERIFIED_PRIMITIVE, needs bound check.
- unchecked-index at nsCodingStateMachine.h (40164): VERIFIED_PRIMITIVE, needs range.
- the ~16 `UTF8BytesOfLead[ch]`-style hits: REFUTED by type (zext i8 into ≥256 entries).
- undersized buffer (40031): VERIFIED_PRIMITIVE, needs witness.

```
images/audit-native/run.sh . - ./scratch -- bash /workspace/images/audit-native/ir-facts/build.sh /scratch/ir-facts-build
cp scratch/ir-facts-build/ir-facts scratch-npp/ir-facts
images/audit-native/run.sh . - ./scratch-npp -- /scratch/ir-facts /scratch/linked/PowerEditor__visual.net__notepadPlus.bc -o /scratch/ir-facts.json
python3 images/audit-native/scripts/verify_candidate.py --ir-facts scratch-npp/ir-facts.json \
    --sarif scratch-codeql/codeql/mythos.sarif --csa scratch-npp/csa-cve/findings-csa.json --out scratch-npp/verified.json
```
