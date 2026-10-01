#!/bin/bash
# run-sast-php.sh — the sast-php orchestrator step's actual logic, baked
# into the image at build time instead of being assembled at runtime as a
# PowerShell "+"-concatenated string passed to `bash -lc "<one big
# string>"`. That shape (compound string built via PowerShell concatenation,
# crossing the -File/array-splat boundary to docker.exe) has already caused
# two separate, hard-to-reproduce failures elsewhere in this toolbox
# (joern-parse and ast-grep-scan — see Invoke-VendorAuditPrePass.ps1's own
# in-file history and process-review-2026-09-03-semgrep-manual-run-lessons.md
# Addendum 4) and was fixed there by eliminating the runtime-constructed
# string entirely. This file applies the same fix to sast-php: the
# orchestrator's Cmd is now just @("bash", "/opt/scripts/run-sast-php.sh") —
# two static literal array elements, nothing built by PowerShell string
# concatenation, nothing to marshal incorrectly.
#
# 2026-09-08: also fixes the REAL bug that was actually breaking this step
# (found via the container's real stderr log, not guessed): psalm hard-
# requires a psalm.xml config file in the project root and refuses to run
# without one ("Could not locate a config XML file in path /workspace. Have
# you run 'psalm --init' ?") — and /workspace is bind-mounted read-only, so
# `psalm --init` could never write one there even if we ran it first. Fixed
# by shipping a minimal static psalm.xml baked into the image (see the
# Dockerfile's COPY of psalm.xml to /opt/config/psalm.xml) and pointing
# psalm at it explicitly with --config, instead of relying on it to find a
# config next to the (read-only, config-less) target tree.
#
# Each tool's own failure is swallowed by `|| true`, same as the original
# inline command — one sub-tool crashing should not stop the other two from
# still writing whatever they can.
psalm --config=/opt/config/psalm.xml --root=/workspace --report=/evidence/sast-php/psalm.json || true
phpstan analyse /workspace --level=5 --error-format=json > /evidence/sast-php/phpstan.json || true
phpcs --standard=PSR12 --report=json --report-file=/evidence/sast-php/phpcs.json /workspace || true
