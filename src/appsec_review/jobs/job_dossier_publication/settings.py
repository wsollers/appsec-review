"""Central, typed bounds for protected dossier publication."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

from appsec_review.storage import canonical_json
import hashlib


@dataclass(frozen=True, slots=True)
class DossierPublicationSettings:
    enabled: bool
    render_pdf: bool
    max_packages: int
    max_dossiers: int
    max_artifact_bytes: int
    max_source_excerpts: int
    max_evidence_rows: int
    max_text_chars: int
    max_code_lines: int
    max_code_chars: int
    image_tag: str
    image_id: str
    render_timeout_seconds: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> DossierPublicationSettings:
        keys = set(cls.__dataclass_fields__)
        if not isinstance(value, Mapping) or set(value) != keys:
            raise ValueError("dossier settings must define exactly: " + ", ".join(sorted(keys)))
        for key in ("enabled", "render_pdf"):
            if type(value[key]) is not bool:
                raise ValueError(f"dossier {key} must be a boolean")
        for key, maximum in {
            "max_packages": 10000, "max_dossiers": 20000, "max_artifact_bytes": 67108864,
            "max_source_excerpts": 32, "max_evidence_rows": 256, "max_text_chars": 16000,
            "max_code_lines": 200, "max_code_chars": 32000, "render_timeout_seconds": 600,
        }.items():
            if type(value[key]) is not int or not 1 <= value[key] <= maximum:
                raise ValueError(f"dossier {key} must be an integer in [1, {maximum}]")
        if (not isinstance(value["image_id"], str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"])):
            raise ValueError("dossier image_id must be an immutable sha256 image identity")
        tag = value["image_tag"]
        if not isinstance(tag, str) or not tag or any(c.isspace() for c in tag) or tag.startswith("-"):
            raise ValueError("dossier image_tag must be a nonempty image tag")
        return cls(**dict(value))

    def identity(self) -> dict[str, Any]:
        return asdict(self)

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.identity())).hexdigest()
