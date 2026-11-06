"""Tiny source releases for offline runtime-contract tests."""
from pathlib import Path

from appsec_review.runtime.release import build_release, MANIFEST_NAME
from appsec_review.storage import atomic_json


def write_release(root: Path, job_ids, *, version: int = 1):
    job_ids = tuple(job_ids)
    root.mkdir(parents=True, exist_ok=True)
    source = root / "release-src"
    source.mkdir(exist_ok=True)
    for job_id in job_ids:
        directory = source / job_id
        directory.mkdir(exist_ok=True)
        path = directory / "job.py"
        if not path.exists():
            path.write_text(f"VERSION = {version}\n")
    for name, content in (("shared.py", "VERSION = 1\n"), ("validator.json", "{}\n"),
                          ("mounted.sh", "echo fixture\n")):
        path = source / name
        if not path.exists():
            path.write_text(content)
    manifest = {"schema": "appsec-review/release-dependencies/1",
                "common": ["release-src/shared.py"], "validators": ["release-src/validator.json"],
                "scripts": ["release-src/mounted.sh"], "job_pattern": "release-src/{job_id}/*.py",
                "environment_requirements": ["APPSEC_REVIEW_TARGET", "MODEL_TOKEN"]}
    value = build_release(root, manifest, tuple(job_ids))
    atomic_json(root / MANIFEST_NAME, value)
    return value
