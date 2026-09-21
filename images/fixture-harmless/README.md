# fixture-harmless

The harmless pinned fixture container for the pinned-container argv adapter (backlog batch B13).
It runs no review tool. It exists so the live adapter tests can exercise the boundary with busybox
applets: echo, write into scratch, fail to write the read-only target, find no network, time out.

There is no Dockerfile on purpose. A locally built image has no registry digest, and its image id
is not reproducible across docker versions, so it could only be named by tag. The fixture is an
upstream image named **only by digest**:

| Field | Value |
|---|---|
| Registry record | `appsec-review-process/registry/container-images/fixture-harmless.json` |
| Repository | `docker.io/library/alpine` |
| Digest (image index) | `sha256:f71a5f071694a785e064f05fed657bf8277f1b2113a8ed70c90ad486d6ee54dc` |
| Upstream release | Docker Official Image `alpine` 3.17 (3.17.5) |

Provision it once, by digest, never by tag:

```bash
docker pull docker.io/library/alpine@sha256:f71a5f071694a785e064f05fed657bf8277f1b2113a8ed70c90ad486d6ee54dc
```

The adapter always passes `--pull never`, so it never provisions an image itself. The live test
class pulls this exact digest once if it is absent; on a host that already holds it, nothing is
downloaded. To rotate the fixture, change the registry record's digest and this table together;
the record hash is part of every container result and of the fingerprint material.
