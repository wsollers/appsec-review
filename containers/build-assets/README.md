---
title: "Build assets"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Build assets

Build assets are inputs that support review jobs but are not scanner images. `audit-doc-convert` is
ported as a design but remains disabled until pandoc and poppler have a complete, hash-locked offline
`.deb` closure, including transitive packages and license data. Acceptance requires PDF and DOCX
fixtures, deterministic output checks, and the standard runtime boundary.
