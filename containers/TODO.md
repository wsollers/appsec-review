# Deferred container acceptance work

- Build environments: split dependency resolution from offline analysis; pin each language closure;
  share only explicit LSP payload layers; add per-language compile and language-server fixtures.
- Native analysis: split compiler tracing, CodeQL, and language-server extraction; remove the
  archived omnibus inheritance; define independent output and failure contracts.
- Binary analysis: add a specialized capability only when BLint/Syft/Grype/Trivy do not satisfy a
  job contract; prohibit curl-to-shell installers and duplicated scanners.
- ScanCode: evaluate a fixed official release artifact or image, verify its license database and
  output schema, and compare its incremental value with Syft before enabling.
- Microsoft SBOM Tool and SBOM Assembly: keep replaced by Syft unless a concrete job contract proves
  a missing format or merge feature.
- Document conversion: resolve a complete hashed `.deb` closure for pandoc/poppler and add PDF/DOCX
  functional fixtures.
- Report rendering: resolve a minimal hashed TeX closure and add deterministic render verification.
- Dagster: orchestration is an application deployment concern; do not restore its archived image.
