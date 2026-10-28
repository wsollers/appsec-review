# SPDX 2.3 schema resource

`spdx-2.3.schema.json` is an unmodified copy of the official SPDX specification
v2.3 release's `schemas/spdx-schema.json`.

- Source: https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json
- Download: https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json
- SHA-256: `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`
- Schema identifier: `http://spdx.org/rdf/terms/2.3`
- Dialect: JSON Schema draft-07
- Attribution: SPDX specification contributors, SPDX Workgroup, Linux Foundation.
- License: Creative Commons Attribution 3.0 Unported (CC-BY-3.0).
  https://creativecommons.org/licenses/by/3.0/
- Unmodified upstream license: `SPDX-LICENSE.txt`, obtained from
  https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/LICENSE
  (SHA-256 `017e38491cccbd2bdb6da0a32a33db9ec245b5dab30fdcd09f2c742c975e5b35`).

The schema has no `$ref` dependencies. Validation loads this package resource
with `importlib.resources`, checks its pinned digest, and uses a closed registry
which refuses external retrieval. No schema or license network request is made
at runtime.
