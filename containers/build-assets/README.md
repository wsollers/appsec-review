---
title: "Build assets"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Build assets

Build assets are inputs that support review jobs but are not scanner images. `audit-doc-convert` is
ported as a design but remains disabled until pandoc and poppler have a complete, hash-locked offline
`.deb` closure, including transitive packages and license data. Acceptance requires PDF and DOCX
fixtures, deterministic output checks, and the standard runtime boundary.
