---
title: "SSH from Windows into the WSL checkout"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# SSH from Windows into the WSL checkout

Development, builds, tests and walks run inside WSL ([`AGENTS.md`](../../AGENTS.md), "Workspace
hygiene"). An agent session that lives on the Windows side and drives the WSL checkout through
`wsl -d <distro> -e bash -c '...'` pays for every call with a process spawn and breaks on shell
quoting: a heredoc or a Python snippet inside the single-quoted `bash -c` string dies on the first
apostrophe, writes over `\\wsl.localhost\...` need a prior read, and background commands die with
the shell. The fix is to run the session **inside** WSL, for example through a saved SSH connection
in a supporting desktop client. This page describes host setup; client UI and authentication
features are separate from this repository's implementation.

The testing protocol requires the connectivity check in [section 4](#4-verify-before-a-session-relies-on-it)
before a session that drives WSL starts work
([testing architecture](../architecture/testing.md#1-establish-scope-and-the-criterion)). When
the check fails, the session stops and asks the user to run the steps below; it does not fall back
to `wsl -e bash -c` for the walk and does not install or change anything itself.

Host facts that differ per machine (user name, distro name, port, key path, folder) are the
user's; nothing here is committed with real values.

## 1. SSH server in the distro (once)

Systemd must be enabled in the distro (`/etc/wsl.conf` with `[boot] systemd=true`), otherwise the
service does not persist. Port 2222 avoids a Windows OpenSSH server that may own port 22. Run from
PowerShell as the distro's root:

```powershell
wsl -d <distro> -u root -e bash -c "apt-get update && apt-get install -y openssh-server && sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config && systemctl enable --now ssh && systemctl is-active ssh"
```

Expected last line: `active`.

## 2. Key pair on Windows (once)

PowerShell swallows an empty `""` argument, so `-N ""` fails with `option requires an argument`.
Either quote it the PowerShell way or omit `-N` and press Enter at both passphrase prompts:

```powershell
ssh-keygen -t ed25519 -f C:/Users/<user>/.ssh/id_ed25519 -N '""'
```

Passphrase and SSH-agent support depend on the client. Choose the user's intended key/agent
setup and verify that the client can use it; this example is not a requirement to remove an
existing key's passphrase. Keep the private key on its owning machine.

## 3. Authorize the key in the distro and name the connection

```powershell
wsl -d <distro> -e bash -c "mkdir -p ~/.ssh && cat /mnt/c/Users/<user>/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
```

Give the connection a name in `~/.ssh/config` so every tool uses the same values:

```powershell
Add-Content -Path "$env:USERPROFILE\.ssh\config" -Value @"

Host wsl-<hostname>
    HostName localhost
    Port 2222
    User <wsl user>
    IdentityFile C:/Users/<user>/.ssh/id_ed25519
    IdentitiesOnly yes
"@
```

## 4. Verify before a session relies on it

This is the check the testing protocol runs first. It must print the checkout's `HEAD`:

```powershell
ssh wsl-<hostname> "cd ~/projects/appsec-review && git rev-parse --short HEAD"
```

Failure modes, in the order to look:

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Connection refused` | the distro is down (WSL stops after idle) or `ssh` is not active | `wsl -d <distro> -e true` wakes it; then `wsl -d <distro> -e systemctl is-active ssh` |
| `Permission denied (publickey)` | the public key is not in `~/.ssh/authorized_keys`, or permissions are wider than 700/600 | repeat step 3 |
| `Could not resolve hostname wsl-<hostname>` | no `Host` entry in `~/.ssh/config` | repeat the `Add-Content` block in step 3 |
| prompts for a passphrase | the key has one | generate a key without one for the app, or add the key to an agent |

The Dagster stack keeps the distro up while it runs; a host with no stack running needs the wake
command before the check.

## 5. Register the connection in the desktop app

Register or import the connection using the client's documented UI; the existence of
`~/.ssh/config` alone does not prove the client uses it. Use the same host `localhost`, port
`2222`, WSL user, key/agent and checkout folder (`/home/<wsl user>/projects/appsec-review`).
Name it `wsl-<hostname>` so the alias and client agree, then verify the new session's Linux
working directory and checkout identity.

The interactive coding client and the provider executable used by Dagster model jobs are
separate installations/selections. For a Claude deployment,
`APPSEC_CLAUDE_BINARY` in `deploy/dagster/.env` identifies the configured host executable;
upgrading an interactive client does not establish which executable the stack mounts.
