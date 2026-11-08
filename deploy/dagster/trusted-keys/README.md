# Committed trust anchors

Public Ed25519 keys of the operators whose signatures the review host trusts, one
`<key id hex>.pem` per key (the name is the SHA-256 of the key's DER SubjectPublicKeyInfo and every
verifier recomputes it, so a renamed or swapped file is refused). Only public keys live here; the
private key stays in `~/.config/appsec-review/signing/private/` on the host that signs and never
enters the repository, an image, a build context, `runs/` or a fixture.

This directory is **not** a trust directory. Verifiers read `[signing] trusted_keys_dir`
(`/etc/appsec-review/signing/trusted-keys`, root-owned; `%ProgramData%\appsec-review\signing\trusted-keys`
on Windows) and would refuse a checkout as an anchor directory anyway (writable by the developer, and
by anyone whose change is merged). Committing an anchor here makes the public key available; a
host trusts it only after an operator installs it:

```sh
appsec-review signing export-trust-anchor --into deploy/dagster/trusted-keys    # after keygen, commit the .pem
sudo appsec-review signing install-trust-anchors                                  # on each review host
```

`install-trust-anchors` copies every anchor here into the trusted-keys directory, checks that each
name matches its key ID and is Ed25519, refuses to replace a differing file of the same name, and
loads the result the way the verifiers do. Removing a `.pem` here does not revoke anything: delete
the installed anchor on each host as well. See `docs/operations/signing.md`, "Key custody".
