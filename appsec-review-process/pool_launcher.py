#!/usr/bin/env python3
"""Lifecycle launcher for C01 pool expansion and C02 wait-all rendezvous.

This is the single composition boundary that turns a validated pool specification into launched
B13/B14 instances and a verified terminal manifest.  It delegates execution and verification to
the existing adapters; it does not interpret worker output or decide quorum.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from execution_state import Blocked
import pool_rendezvous as rendezvous
import pool_specification as specification


@dataclass(frozen=True)
class LaunchedPool:
    pool_root: Path
    pool_directory: str
    expansion_sha256: str
    terminal_manifest_sha256: str
    outcome: str
    instance_count: int


def launch(spec: Any, *, context: specification.PoolContext,
           runtime: rendezvous.RendezvousRuntime) -> LaunchedPool:
    """Expand once, launch every expected instance, wait-all, and reverify from disk."""
    plan = specification.expand_pool(spec, context=context)
    pool_root = plan.pool_root(context)
    rendezvous.run_rendezvous(pool_root, expected_spec=spec, context=context, runtime=runtime)
    verified = rendezvous.load_verified_manifest(pool_root, expected_spec=spec, context=context,
                                                 rendezvous_parent=runtime.rendezvous_parent)
    manifest = verified.manifest
    if len(verified.instances) != len(plan.instances):
        raise Blocked("pool launcher: verified terminal population differs from expansion")
    return LaunchedPool(pool_root=pool_root, pool_directory=plan.pool_directory,
        expansion_sha256=plan.manifest["expansion_sha256"],
        terminal_manifest_sha256=manifest["manifest_sha256"], outcome=manifest["outcome"],
        instance_count=len(verified.instances))
