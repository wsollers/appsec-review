"""Deployment-only release assembly, kept outside imported computation dependencies."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Sequence

from appsec_review.runtime.release import (
    MANIFEST_ENV, MANIFEST_NAME, build_release, manifest_path, read_document,
)
from appsec_review.storage import atomic_bytes, canonical_json


def verify_deployment_assets() -> None:
    """Check mounted assets and graph definitions before starting the code server."""
    from appsec_review.application_paths import application_root, verify_runtime_assets
    verify_runtime_assets()
    from appsec_review.container_runtime.catalog import load_catalog as load_container_catalog
    load_container_catalog(application_root("containers/catalog.toml"))
    from appsec_review.graph.catalog import load_catalog as load_graph_catalog
    load_graph_catalog()
    from appsec_review.orchestration.dagster.definitions import defs
    defs.get_job_def("wave1_review")


def main(argv: Sequence[str] | None = None, *, execvp=os.execvp) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=None,
                        help="dependency manifest; defaults to release-dependencies.json under --root")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"manifest to write; defaults to ${MANIFEST_ENV} or {MANIFEST_NAME} under --root")
    parser.add_argument("--verify-assets", action="store_true",
                        help="also verify the mounted runtime assets and catalogs (the former image-build checks)")
    parser.add_argument("--exec", dest="then", nargs=argparse.REMAINDER, default=None,
                        help="after writing the manifest, replace this process with the given command")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    manifest = args.manifest if args.manifest is not None else root / "release-dependencies.json"
    output = args.output if args.output is not None else manifest_path(root)
    if args.then is not None and not args.then:
        parser.error("--exec requires a command")
    if args.verify_assets:
        verify_deployment_assets()
    from appsec_review.runtime.registry import builtin_registry
    release = build_release(root, read_document(manifest), builtin_registry().job_ids())
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(output, canonical_json(release))
    print(release["sha256"], flush=True)
    if args.then is not None:
        execvp(args.then[0], list(args.then))
    return 0
