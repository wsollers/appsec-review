---
title: "Garnet result cache: Windows Nano Server image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_inference_security_review"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Garnet result cache: Windows Nano Server image

The inference security review caches pointers to completed blue-role cell results in
[Microsoft Garnet](https://github.com/microsoft/garnet), a Redis-compatible server with per-key TTL.
The cache is optional and fail-open: if it is unreachable, reviews run uncached and only cost more.

## Why two images

| Host | Image | Where it is defined |
| --- | --- | --- |
| Linux, WSL, and Docker Desktop in Linux-containers mode (including the native Windows Compose stack) | Upstream `ghcr.io/microsoft/garnet:2.2.5`, pinned by digest | `result-cache` service in [`deploy/dagster/compose.yaml`](../../../deploy/dagster/compose.yaml) |
| Docker in Windows-containers mode, which cannot run the Linux image | `appsec-review/garnet:2.2.5-nanoserver-ltsc2022`, built locally | [`Dockerfile.nanoserver`](Dockerfile.nanoserver) and [`build-windows.ps1`](build-windows.ps1) here |

Upstream publishes no Nano Server image, so this one is built from Garnet's own
`Dockerfile.nanoserver` at tag `v2.2.5` (commit `8d007138208ce030eb10a50c80e636b1678b83e4`), with both
.NET 10.0.14 `nanoserver-ltsc2022` base images pinned by digest. It is not in
[`containers/catalog.toml`](../../catalog.toml): that catalog holds linux/amd64 review-tool images that
`containers/build.py` builds, and this is a Windows service image that the review never launches.

## Build

On a Windows Server 2022-compatible host with Docker switched to Windows containers, run:

```powershell
pwsh -File containers/services/garnet/build-windows.ps1
```

The script refuses a Linux-containers engine and refuses to build if the `v2.2.5` tag no longer
names the pinned commit. It fetches that exact commit into
`%LOCALAPPDATA%\appsec-review\garnet-src\<commit>` (override with `-SourceDirectory`), verifies the
checkout, builds it as the context, and prints the local image ID. NuGet packages are restored at
build time at the versions Garnet's sources declare at that commit. Nothing is pushed.

## Run

Keep the password out of the command line, where `docker inspect` would show it, by writing a Garnet
config file. Publish the port only on loopback:

```powershell
$conf = "$env:LOCALAPPDATA\appsec-review\garnet-conf"
New-Item -ItemType Directory -Force -Path $conf | Out-Null
$json = @{ AuthenticationMode = "Password"; Password = $env:APPSEC_RESULT_CACHE_PASSWORD } | ConvertTo-Json
[System.IO.File]::WriteAllText("$conf\garnet.conf", $json)
docker run -d --name appsec-result-cache --restart unless-stopped -p 127.0.0.1:6379:6379 `
    -v "${conf}:C:\garnet-conf:ro" appsec-review/garnet:2.2.5-nanoserver-ltsc2022 `
    --config-import-path C:\garnet-conf\garnet.conf --port 6379 --memory 128m --index 16m --page 4m --segment 32m
```

`--config-import-path`, `--port`, `--memory`, `--index`, `--page` and `--segment` are Garnet 2.2.5
options (`libs/host/Configuration/Options.cs`). Values on the command line override the file. Restrict
the config directory to the operator's account, because the file holds the password.

## Point a review at it

The review process must have `APPSEC_RESULT_CACHE_PASSWORD` set to the same value. Set the endpoint
with a configuration overlay passed through `APPSEC_REVIEW_CONFIG_OVERLAY`:

```toml
[jobs.job_inference_security_review.settings.result_cache]
endpoint = "redis://<host>:6379/0"
```

`<host>` is the address at which the review process reaches the published port: `127.0.0.1` for a
process on the same host. The Compose stack uses its own `result-cache` service at
`redis://result-cache:6379/0` and needs no overlay.
