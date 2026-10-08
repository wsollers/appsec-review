from __future__ import annotations

from datetime import datetime
from pathlib import Path


class RunStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def create(self, instant: datetime) -> tuple[str, Path]:
        self.root.mkdir(parents=True, exist_ok=True)
        prefix = instant.date().isoformat()
        for serial in range(1, 10_000):
            run_id = f"{prefix}-{serial:04d}"
            path = self.root / run_id
            try:
                path.mkdir()
            except FileExistsError:
                continue
            (path / "data" / "jobs").mkdir(parents=True)
            return run_id, path
        raise RuntimeError(f"daily run id space exhausted for {prefix}")

    def resolve(self, run_id: str) -> Path:
        if len(run_id) != 15 or run_id[4] != "-" or run_id[7] != "-" or run_id[10] != "-":
            raise ValueError(f"invalid run id: {run_id}")
        path = (self.root / run_id).resolve()
        root = self.root.resolve()
        if path.parent != root or not path.is_dir():
            raise FileNotFoundError(f"run does not exist: {run_id}")
        return path
