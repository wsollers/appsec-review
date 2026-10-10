# SQLite utility image

`tool-sqlite` provides bounded, read-only inspection of SQLite databases. The application mounts
the selected database directory at `/target` read-only and supplies the command arguments.

```text
sqlite-tool version
sqlite-tool inspect /target/index.sqlite
sqlite-tool integrity /target/index.sqlite
sqlite-tool query /target/index.sqlite --sql "SELECT name FROM sqlite_master WHERE type = ?" --parameters '["table"]'
```

Database paths must resolve beneath `/target`. Connections use `mode=ro`, `immutable=1`, and
`PRAGMA query_only=ON`. The query command accepts one parameterized, read-only statement; an SQLite
authorizer rejects writes, transaction control, `ATTACH`, `DETACH`, and caller-supplied pragmas.
Rows, cell size, execution time, and virtual-machine work are bounded.

This image is an operator and controlled-pipeline utility. It is not a generic MCP SQL endpoint.
The retrieval MCP continues to verify accepted manifests and expose only its bounded application
queries.
