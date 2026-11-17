"""Job definition wrapper for ``job_sarif_export``."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import JOB_ID
from .datasets import CONSUMES, CONTRACT, DATASETS
from .exporter import export_sarif_bundle


@dataclass(frozen=True)
class SarifExportJob:
    job_id: str = JOB_ID
    contract: Any = CONTRACT
    consumes: tuple[str, ...] = CONSUMES
    datasets: tuple[Any, ...] = DATASETS
    strict_gaps: bool = True


def build_job(*_args: Any, **_kwargs: Any) -> SarifExportJob:
    return SarifExportJob()


__all__ = ["SarifExportJob", "build_job", "export_sarif_bundle"]
