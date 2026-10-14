# Deferred container acceptance work

- Build environments: split dependency resolution from offline analysis; pin each language closure;
  share only explicit LSP payload layers; add per-language compile and language-server fixtures.
- Native analysis: compiler tracing and C/C++ build/AST/IR/ELF evidence (`tool-native-cpp`), Infer
  (`tool-infer`), C/C++ symbol indexing (`tool-clangd-indexer`), and CPG production (`tool-joern`)
  are enabled narrow images, and CodeQL images are packaged outside the catalog
  (`containers/tools/codeql/README.md`). Remaining: decide whether the other archived `audit-native`
  capabilities (SVF, CodeChecker) earn a bounded image (Ghidra is now `tool-ghidra`), then retire or replace the deferred
  `audit-native`, `audit-codeql`, and `audit-lsp-vendor` catalog entries.
- Binary analysis: add a specialized capability only when BLint/Syft/Grype/Trivy do not satisfy a
  job contract; prohibit curl-to-shell installers and duplicated scanners.
- Ghidra (`tool-ghidra`): close the open items in `containers/tools/ghidra/LICENSE.md` (advisory
  match, full per-module license read, unused-module trim), replace the JRE-plus-JDK arrangement
  with one reviewed `base-jdk`, pin `image_id` in the catalog, lint the Dockerfile, and add a PE
  fixture.
- ScanCode: evaluate a fixed official release artifact or image, verify its license database and
  output schema, and compare its incremental value with Syft before enabling.
- Microsoft SBOM Tool and SBOM Assembly: keep replaced by Syft unless a concrete job contract proves
  a missing format or merge feature.
- Document conversion: resolve a complete hashed `.deb` closure for pandoc/poppler and add PDF/DOCX
  functional fixtures.
- Report rendering: resolve a minimal hashed TeX closure and add deterministic render verification.
- Dagster: orchestration is an application deployment concern; do not restore its archived image.
