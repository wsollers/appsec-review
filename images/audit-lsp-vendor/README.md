# audit-lsp-vendor

Build-only image: the vendored, checksum-verified tree-sitter CLI (0.26.13), py-tree-sitter 0.26.0
with 13 grammar wheels, and clangd 21.1.0 wheels that every compiler image installs offline with a
BuildKit bind mount. Never run against a target; no B16 record. Pins, licences and the vendoring
model: [`docs/language-servers.md`](../../docs/language-servers.md).

```
python3 -B images/image_build.py build audit-lsp-vendor
```

Build it before any `audit-buildenv-*` or `audit-codeql*` image (their `image.json` lists it in
`requires_images`).
