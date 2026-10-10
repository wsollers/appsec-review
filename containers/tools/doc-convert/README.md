# tool-doc-convert

Offline text extraction for design documents that the target catalog identifies by name but cannot
store as text: PDFs (pypdf) and DOCX/ODT/RTF/EPUB (static pandoc, always run with `--sandbox`).
`job_document_conversion` is the only caller. It mounts the target read-only, writes only to a
run-owned scratch directory, and runs the image with no network as uid 10001.

| File | Purpose |
| --- | --- |
| `Dockerfile` | Two-stage, network-free build: installs the hash-locked wheel and unpacks pandoc, then copies both onto `base-python`. |
| `doc_convert.py` | The converter installed as `/opt/tool/bin/doc-convert`, the image's only command surface. |
| `requirements.txt` | `pypdf` pin with its SHA-256 for `pip --require-hashes`. |
| `assets.lock.json` | HTTPS URL, byte size, SHA-256, license, and provenance for every downloaded asset. |
| `tool.toml` | Runtime contract: executable, limits, user, and the smoke-test version probe. |

Downloaded assets land in `downloads/`, which is ignored and never committed.

## Build

Run these from the repository root. The build engine downloads each asset in `assets.lock.json` over
HTTPS, checks its byte size and SHA-256, then runs `docker build --network=none`.

1. Make sure the shared Python base exists. `tool-doc-convert` depends on it:

   ```bash
   containers/build-all.sh build base-python
   ```

2. Validate the catalog and asset locks without building:

   ```bash
   containers/build-all.sh --validate-only
   ```

3. Fetch, verify, and build the image:

   ```bash
   containers/build-all.sh build tool-doc-convert
   ```

   On Windows, use `containers/build-all.ps1` with the same arguments.

4. Smoke-test it under the repository runtime policy. This runs `doc-convert --version` with no
   network, a read-only root filesystem, and uid 10001:

   ```bash
   containers/build-all.sh smoke tool-doc-convert
   containers/build-all.sh security tool-doc-convert
   ```

5. Optionally, record the built image id in `containers/catalog.toml` as `image_id`. The executor then
   refuses any other local image with the same tag:

   ```bash
   docker image inspect appsec-review/tool-doc-convert:1.0.0 --format '{{.Id}}'
   ```

Build logs and a machine-readable summary are written under `runs/container-builds/<run-id>/`.

### Manual build (debugging only)

The engine above is authoritative. To reproduce a build by hand, place the verified assets at the
paths named in `assets.lock.json`, then run:

```bash
docker build --network=none --pull=false \
  --build-arg TOOL_VERSION=1.0.0 --build-arg PYPDF_VERSION=6.19.0 --build-arg PANDOC_VERSION=3.9.0.2 \
  --tag appsec-review/tool-doc-convert:1.0.0 containers/tools/doc-convert
```

## Updating pins

1. Choose pypdf and pandoc releases that are at least two weeks old.
2. Update `requirements.txt`, then update every URL, `sha256`, `bytes`, and `version` in
   `assets.lock.json`.
3. Update the `build_args` in the `tool-doc-convert` entry of `containers/catalog.toml`.
4. If the converter changes, bump `VERSION` in `doc_convert.py` together with `version` in
   `tool.toml` and the catalog `version`/`tag`.
5. Re-run validate, build, smoke, and security.

A changed image changes the conversion job's runtime identity, so earlier conversions are not reused.

## Manual conversion check

```bash
docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
  -v "$PWD/path/to/docs:/target:ro" -v "$PWD/test/tmp/doc-convert:/scratch" \
  appsec-review/tool-doc-convert:1.0.0 /opt/tool/bin/doc-convert \
  --input /target/design.pdf --format pdf --output-dir /scratch/out
```

The output is `out/text.txt` plus `out/manifest.json`. The manifest holds the input SHA-256, the
per-page character ranges, the status, and any gaps. Possible statuses are `SUCCEEDED`, `NO_TEXT`,
`ENCRYPTED`, `TIMEOUT`, `FAILED`, and `UNSUPPORTED`.
