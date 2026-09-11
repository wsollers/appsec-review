# New toolbox scripts — 2026-09-09 — usage quick-reference

Both scripts are saved individually in this project under `claude/toolbox/` (`fingerprint_native_binaries.py`, `check_mobile_source.py`) — each file's own docstring is the authoritative usage doc. This note is a short pointer to both, kept alongside them so a future session doesn't have to open each file to know what it's for.

Built in response to the goal-conformance review (`claude/goal-conformance-review-2026-09-09.md`) — specifically the 46%-unscanned-binary coverage gap and the still-open `sast-mobile` no-op confirmation for `fsh-server`.

## `fingerprint_native_binaries.py`

**Purpose:** closes the coverage gap where 46% of the SBOM (1,531 of 3,311 components) was never checked for anything at all, because `syft`/`osv-scanner` can't resolve a raw native binary to a package identity. For every `.dll`/`.exe`/`.so`/`.dylib`/`.a`/`.lib`/`.pdb` found, it now does five distinct things:

1. **Hashes it** (SHA256 — tamper/identity detection).
2. **Extracts embedded version metadata** — PE VersionInfo (FileVersion, ProductVersion, CompanyName, ProductName, OriginalFilename) via `pefile`; ELF header architecture/type via stdlib, plus SONAME if `pyelftools` is installed.
3. **Flags filename/embedded-name mismatches** (a file claiming to be `foo.dll` whose own OriginalFilename says otherwise).
4. **Flags writable+executable (W^X) sections/segments** — PE section Characteristics, or ELF `PT_LOAD` program-header flags via a dependency-free stdlib parse of the raw program header table. This is the highest-value signal the script produces: legitimate compiler output essentially never emits a section that's both writable and executable at once, so this is the real packer/self-modifying-code/hand-rolled-loader tell, not just a heuristic.
5. **Flags high-entropy sections** (PE only, ≥7.2 bits/byte — possible packing/encryption/compression) and **reports debug-stripped status and Authenticode signature presence** (PE: debug directory + embedded PDB path if present; ELF: `.symtab` presence via `pyelftools`). Signature detection is presence-only — it does not validate the certificate chain; that needs `signtool verify /pa` or equivalent against a real trust store, which a static file read can't do.

**Setup:** `pip install pefile --break-system-packages` (required). Optional, for deeper detail: `pip install pyelftools --break-system-packages` (ELF SONAME + stripped-symbol detection) and `pip install cryptography --break-system-packages` (extracts the Authenticode signer's certificate subject once a signature is already known to be present).

**Smoke-test before the real run** (confirms the version-extraction path works before trusting it at scale):
```powershell
python fingerprint_native_binaries.py C:\Windows\System32\kernel32.dll -o smoke-test
```
Check `smoke-test\binary-fingerprints.csv` — `product_version` populated, `company_name` = `Microsoft Corporation`, and (kernel32.dll is signed) `signature_status` should say `SIGNED`.

**Real run — RECOMMENDED: the whole confirmed-real `fsh-server` tree in one pass**, not just the two/three components the CVE triage originally named — the 46% gap is repo-wide, not specific to those paths:
```powershell
python fingerprint_native_binaries.py "F:\Barracuda\fsh-server" -o F:\Barracuda\evidence-server\native-binaries
```
A narrower re-run of just the two originally-named components is still supported if you want a quick re-check after a partial fix:
```powershell
python fingerprint_native_binaries.py `
    "F:\Barracuda\fsh-server\Server\www\gdip\tools\php-7.3.19-nts-Win32-VC15-x64" `
    "F:\Barracuda\fsh-server\GM\gaiya\WOD" `
    "F:\Barracuda\fsh-server\GM\gaiya\文件上传接口\ApiUpload" `
    -o F:\Barracuda\evidence-server\native-binaries
```
Writes `binary-fingerprints.csv`/`.md` (full detail, with W^X/entropy/signature/debug findings surfaced at the top of the `.md` in priority order) and appends new rows into `native-dependencies.csv` — the same schema `build_layered_sbom.py native-template` already uses, without overwriting anything hand-seeded there.

**Tested this session:** hashing, PE/ELF/ar-archive/Mach-O/unknown format detection, non-PE-file handling, real-PE-without-version-resource handling, the CSV merge-without-clobber logic, and — for the new hardening checks — a crafted ELF with a deliberate `PT_LOAD` RWX segment (correctly flagged) against a real, unmodified `/bin/ls` (correctly NOT flagged), plus a real unsigned PE (correctly flagged `UNSIGNED`, and incidentally surfaced a real embedded PDB path pointing to a developer's local machine — a live demonstration of exactly the kind of leak this check is for). All confirmed correct. The "real PE *with* both a populated version resource AND a valid Authenticode signature" combination had no single test file available in the build sandbox that carried both — the two code paths were verified independently (version resource against a real signed system DLL is what the smoke-test step above checks for you; signature-presence logic against a real unsigned PE). Worth confirming once against a real signed binary if one is handy before fully trusting the `signer_cn` extraction specifically.

## `check_mobile_source.py`

**Purpose:** a five-minute, dependency-free way to confirm the open punch-list item — "is `fsh-server` really mobile-source-free, or did `sast-mobile` just never launch" — without spending a full Docker/mobsfscan cycle just to check a presumed no-op. Walks a tree for Android markers (`.java`/`.kt`/`.kts`, `AndroidManifest.xml`, an Android-Gradle-Plugin `build.gradle`) and iOS markers (`.swift`/`.m`/`.mm`, `Info.plist`, `.xcodeproj`/`.xcworkspace`, `Podfile`), reports every match by path, and exits 0 only if zero strong signals were found for both platforms.

**No install needed — pure stdlib.**

**Primary use — confirm the fsh-server punch-list item:**
```powershell
python check_mobile_source.py "F:\Barracuda\fsh-server" -o F:\Barracuda\evidence-server\sast-mobile
```
Writes `mobile-source-check.json`/`.md` plus `android-coverage.txt`/`ios-coverage.txt` in the same format the real `sast-mobile-android`/`-ios` Docker steps already write, so it drops into the same evidence directory as a corroborating, independently-derived check.

**Secondary use — pre-flight before running the real mobsfscan pass against the client** (confirms the target path actually has source before spending the Docker cycle):
```powershell
python check_mobile_source.py "F:\Barracuda\fsh-client" -o F:\Barracuda\evidence-client\sast-mobile-preflight
```

**Tested this session:** both the confirmed-clean-tree path (exit 0, correct warning text) and the found-Android-source path (exit 1, correct file listing) were run against synthetic fixtures and verified correct, including the iOS-display-name fix (`"ios".capitalize()` → `"Ios"` was caught and corrected to `"iOS"`).

## Next step for both

Run them against the real `F:\Barracuda` tree and paste back: for the fingerprinting script, the console summary line plus any mismatch rows; for the mobile-source check, the console summary and exit code. Both feed directly into closing out `session-status-2026-09-03-server-analysis.md`'s open punch-list items.
