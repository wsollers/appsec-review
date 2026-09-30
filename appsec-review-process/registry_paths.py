#!/usr/bin/env python3
"""Where the job definition records live (brief K): one ``pipeline/`` folder beside this module.

    pipeline/job-graph.json               lifecycle nodes, lanes, dependencies
    pipeline/tunables.json                shared tunables
    pipeline/job-templates/<id>.json      compositions a lane dispatches
    pipeline/output-contracts/<id>.json   required files, status fields, claim classes
    pipeline/domains/<id>.json            reviewed surfaces
    pipeline/tooling-profiles/<id>.json   evidence and action boundaries
    pipeline/permission-capabilities/     capability definitions
    pipeline/container-images/<id>.json   pinned tool images
    pipeline/prompt-fragments/            shared prompt text
    pipeline/prompt-fragments/tool-guides/  one guide per model lookup tool or family (brief U4)

``appsec-review-process/pipeline/`` is not the repository-root ``pipeline/`` (the Layer 1 evidence
scripts). Personas and roles live in ``personas/`` beside it; ``persona_registry`` owns those paths.

Every reader takes its paths from here. ``REGISTRY`` is the directory callers pass around as
``registry_dir``; ``rel`` gives the process-relative name a lifecycle uses as the key of a file in
its implementation hash map.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIRNAME = "pipeline"
REGISTRY = ROOT / DIRNAME

JOB_TEMPLATES = "job-templates"
OUTPUT_CONTRACTS = "output-contracts"
DOMAINS = "domains"
TOOLING_PROFILES = "tooling-profiles"
PERMISSION_CAPABILITIES = "permission-capabilities"
CONTAINER_IMAGES = "container-images"
PROMPT_FRAGMENTS = "prompt-fragments"

GRAPH_NAME = "job-graph.json"
TUNABLES_NAME = "tunables.json"
JOB_GRAPH = REGISTRY / GRAPH_NAME
TUNABLES = REGISTRY / TUNABLES_NAME
JOB_TEMPLATES_DIR = REGISTRY / JOB_TEMPLATES
OUTPUT_CONTRACTS_DIR = REGISTRY / OUTPUT_CONTRACTS
DOMAINS_DIR = REGISTRY / DOMAINS
TOOLING_PROFILES_DIR = REGISTRY / TOOLING_PROFILES
PERMISSION_CAPABILITIES_DIR = REGISTRY / PERMISSION_CAPABILITIES
CONTAINER_IMAGES_DIR = REGISTRY / CONTAINER_IMAGES
PROMPT_FRAGMENTS_DIR = REGISTRY / PROMPT_FRAGMENTS
TOOL_GUIDES_DIR = PROMPT_FRAGMENTS_DIR / "tool-guides"


def record(kind: str, record_id: str, registry_dir: Path = REGISTRY) -> Path:
    """``<registry_dir>/<kind>/<record_id>.json`` for a registry record kind named above."""
    return Path(registry_dir) / kind / (record_id + ".json")


def template(job_id: str, registry_dir: Path = REGISTRY) -> Path:
    return record(JOB_TEMPLATES, job_id, registry_dir)


def contract(contract_id: str, registry_dir: Path = REGISTRY) -> Path:
    return record(OUTPUT_CONTRACTS, contract_id, registry_dir)


def rel(kind: str, record_id: str | None = None) -> str:
    """Process-relative name: ``rel(kind, id)`` for a record, ``rel(name)`` for a top-level file."""
    return f"{DIRNAME}/{kind}" + ("" if record_id is None else f"/{record_id}.json")


GRAPH_REL = rel(GRAPH_NAME)
TUNABLES_REL = rel(TUNABLES_NAME)


def template_rel(job_id: str) -> str:
    return rel(JOB_TEMPLATES, job_id)


def contract_rel(contract_id: str) -> str:
    return rel(OUTPUT_CONTRACTS, contract_id)


def repo_rel(relative: str) -> str:
    """Repository-relative name of a process-relative one (``appsec-review-process/<relative>``)."""
    return f"{ROOT.name}/{relative}"
