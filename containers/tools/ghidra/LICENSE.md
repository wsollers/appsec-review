# Ghidra runtime closure: license and security review

Reviewed 2026-10-12 for Ghidra `12.1.4` (`ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`). The archive is not committed.
The repository holds only the lock, the inventory, and integration code.

## Ghidra

Ghidra is Apache-2.0 (`LICENSE` in the archive, SHA-256 `c71d239d...`, recorded as
`license_sha256`).

**Provenance.** The archive is an immutable GitHub release asset of tag `Ghidra_12.1.4_build`,
published by the National Security Agency's `NationalSecurityAgency/ghidra` repository on
2026-09-21. `Ghidra/application.properties` inside the verified archive names source revision
`8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`.

**Integrity.** The SHA-256 calculated from the download equals the digest GitHub reports for the
release asset. The SHA-512 in the lock was calculated from the same download; upstream publishes
none.

**Signatures.** No detached signature, sigstore bundle, SLSA attestation, or reproducible-build
record is published for the asset. Signature status is therefore `not-published`. The checksum
comes from the same release channel and is an integrity check, not a signature.

## Installed closure

`inventory.json` lists the 2,799 installed files (603.5 MB): 180 JARs, 6 ELF executables or
libraries, and 5 scripts. The debugger modules (`Ghidra/Debug`), `Extensions`, `server`, `docs`,
`GPL/DMG`, `GPL/Icons`, and the GUI launchers are not installed.

Native code that can run in the image:

| File | Role | License |
| --- | --- | --- |
| `Ghidra/Features/Decompiler/os/linux_x86_64/decompile` | Decompiler engine, one process per analysis thread | Apache-2.0 (Ghidra) |
| `Ghidra/Features/Decompiler/os/linux_x86_64/sleigh` | Processor specification compiler | Apache-2.0 (Ghidra) |
| `GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_24`, `demangler_gnu_v2_41` | GNU C++ demangler, run as a separate process | GPL 3, as declared in `GPL/DemanglerGnu/LICENSE.txt` |
| `Ghidra/Features/FileFormats/os/linux_x86_64/lzfse` | LZFSE decompression helper | BSD-3-APPLE, as declared in the `FileFormats` `Module.manifest` |
| `Ghidra/Features/FileFormats/data/sevenzipnativelibs/Linux-amd64/lib7-Zip-JBinding.so` | 7-Zip binding for container file formats | LGPL 2.1, as declared in the `FileFormats` `Module.manifest` |

Five JARs embed native libraries for several platforms (`sevenzipjbinding-all-platforms`, two
`jna` versions, `sigar-lib`, `flatlaf`). A headless export does not use the GUI look-and-feel or
SIGAR.

The archive ships its own license texts under `licenses/` and `GPL/licenses/`, both installed. They
cover Apache-2.0, BSD variants, MIT, LGPL-2.1, LGPL-3.0, MPL-2.0, GPL-2.0 with the Classpath
exception, GPL-3.0, the Jython and PSF licenses, and public-domain dedications.

The GPL-licensed demanglers are separate executables that Ghidra invokes over a pipe. Nothing in
this repository links against them, and the image is used internally and not redistributed.

Conclusion: acceptable for internal, unmodified execution inside this repository's runtime.

## JDK

Ghidra's launcher requires a JDK, and Ghidra compiles `AppsecExportProgram.java` at run time. The
image copies Eclipse Temurin 21 from
`eclipse-temurin:21-jdk-noble@sha256:b468c3fc688b14450571494f588bd939378e7fd542ed5a73f8efc13f17872a87`
(GPL-2.0 with the Classpath exception) into `/opt/jdk`. The JRE that `base-jre` already carries
stays in place, so the image holds two Java runtimes.

## Open items

These were **not** done in this review and are named gaps, not clean results:

- **No complete per-component license review.** Each Ghidra module's `Module.manifest` declares a
  license for every bundled third-party file. Those declarations were read for `FileFormats` and
  `DemanglerGnu` only, not for all modules. The bundled `bom.json` (CycloneDX 1.4, 203 components)
  carries no license fields, so it cannot substitute. The summary above otherwise rests on the
  license texts upstream ships.
- **No advisory match.** Neither the installed JARs nor the two Java runtimes were matched against
  a vulnerability database. Run Syft and Grype or Trivy over the built image and record the result
  here.
- **Ghidra parses hostile input.** Loaders and analyzers read attacker-controlled binaries, and
  Ghidra has had memory-safety and deserialization advisories. The mitigation is the runtime
  boundary (no network, non-root, read-only root, dropped capabilities, bounded resources), not a
  claim that this version has no such defect.
- **Unused modules are still installed.** PyGhidra, BSim, GhidraServer, and the GUI feature modules
  ship inside `Ghidra/Features` and were kept to avoid breaking module resolution. Trimming them
  needs a functional regression run.
- **Duplicate Java runtime.** Replace the JRE-plus-JDK arrangement with a single reviewed
  `base-jdk` image.
