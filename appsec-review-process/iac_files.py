#!/usr/bin/env python3
"""IaC and container-definition file-name rules, shared by the full-review assembly (which decides
whether ``02-iac-config-scan`` launches) and the vendor IaC probe and hadolint inputs (which decide
what that scan covers). One rule, so the assembly never launches a scan whose probe then reports the
same file as not applicable (P38: ``*.Dockerfile`` and ``Containerfile``)."""
from __future__ import annotations

from pathlib import PurePosixPath

IAC_SUFFIXES = {".tf", ".tfvars"}
IAC_YAML_TOKENS = ("deploy", "k8s", "helm", "terraform")
CONTAINERFILES = {"dockerfile", "containerfile"}


def containerfile(relative: str) -> bool:
    """``Dockerfile``, ``Containerfile``, ``Dockerfile.*`` or ``*.Dockerfile``, in any case."""
    path = PurePosixPath(relative.lower())
    return path.name in CONTAINERFILES or path.name.startswith("dockerfile.") or path.suffix == ".dockerfile"


def github_workflow(relative: str) -> bool:
    path = PurePosixPath(relative.lower())
    return path.parts[:2] == (".github", "workflows") and path.suffix in {".yaml", ".yml"}


def iac_input(relative: str) -> bool:
    """A checkout-relative path the IaC/config scan has something to say about."""
    path = PurePosixPath(relative.lower())
    return (path.suffix in IAC_SUFFIXES or
            (path.suffix in {".yaml", ".yml"} and any(token in path.as_posix() for token in IAC_YAML_TOKENS)) or
            containerfile(relative) or github_workflow(relative))
