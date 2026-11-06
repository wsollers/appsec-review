from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import tomllib


class GateError(RuntimeError):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(f"{category}: {message}")


def table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GateError("configuration", f"{label} must be a table")
    return dict(value)


def strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise GateError("configuration", f"{label} must be a nonempty string list")
    result = tuple(str(item) for item in value)
    if len(set(result)) != len(result):
        raise GateError("configuration", f"{label} contains duplicates")
    return result


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or "\\" in value
            or ":" in value or any(ord(char) < 32 for char in value)
            or path.as_posix() != value or value.startswith("-")):
        raise GateError("configuration", f"not a canonical repository-relative path: {value!r}")
    return value


def checked_file(root: Path, value: str) -> Path:
    path = root / relative_path(value)
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise GateError("missing-input", f"required in-repository file is unavailable: {value}")
    return path


def unit_selector(value: str) -> str:
    relative_path(value)
    path = PurePosixPath(value)
    blocked = {"integration", "acceptance", "live"}
    if (path.parts[0] != "tests" or path.suffix != ".py" or not path.name.startswith("test_")
            or blocked.intersection(path.parts)
            or any(word in path.stem.lower() for word in ("live", "integration", "acceptance", "image_build", "real_model"))):
        raise GateError("unsafe-selector", f"only explicitly reviewed offline unit files are allowed: {value}")
    return value


@dataclass(frozen=True)
class Config:
    source_roots: tuple[str, ...]
    baseline: str
    timeout_seconds: int
    sast_rules: tuple[str, ...]
    unit_tests: tuple[str, ...]
    contract_tests: tuple[str, ...]
    quality_prefixes: tuple[str, ...]
    documentation_prefixes: tuple[str, ...]
    shared_paths: tuple[str, ...]
    bootstrap_modules: tuple[str, ...]
    public_contracts: tuple[str, ...]
    type_files: tuple[str, ...]


def load_config(root: Path) -> Config:
    try:
        document = tomllib.loads(checked_file(root, "pyproject.toml").read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeError) as error:
        raise GateError("configuration", str(error)) from error
    tools = table(document.get("tool"), "tool")
    raw = table(tools.get("appsec-quality"), "tool.appsec-quality")
    expected = set(Config.__dataclass_fields__) - {"type_files"}
    if set(raw) != expected | {"version"} or type(raw["version"]) is not int or raw["version"] != 1:
        raise GateError("configuration", "quality configuration has unknown/missing keys or unsupported version")
    timeout = raw["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise GateError("configuration", "timeout_seconds must be an integer between 1 and 600")
    baseline = raw["baseline"]
    if not isinstance(baseline, str):
        raise GateError("configuration", "baseline must be a path")
    relative_path(baseline)
    lists = {name: strings(raw[name], name) for name in expected - {"baseline", "timeout_seconds"}}
    for name in ("source_roots", "shared_paths", "unit_tests", "contract_tests"):
        for value in lists[name]:
            relative_path(value)
    for name in ("quality_prefixes", "documentation_prefixes"):
        for value in lists[name]:
            if not value.endswith("/"):
                raise GateError("configuration", f"{name} must contain directory prefixes")
            relative_path(value[:-1])
    if not set(lists["sast_rules"]) <= {"B102", "B301", "B307", "B506", "B602"}:
        raise GateError("configuration", "SAST rule is outside the reviewed rule set")
    for value in (*lists["unit_tests"], *lists["contract_tests"]):
        unit_selector(value)
        checked_file(root, value)
    if set(lists["unit_tests"]) & set(lists["contract_tests"]):
        raise GateError("configuration", "unit and contract selectors overlap")
    mypy = table(tools.get("mypy"), "tool.mypy")
    type_files = strings(mypy.get("files"), "mypy.files")
    for value in (*type_files, *lists["source_roots"]):
        relative_path(value)
        path = root / value
        if not path.exists() or not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise GateError("missing-input", f"required source scope is unavailable: {value}")
    return Config(
        source_roots=lists["source_roots"], baseline=baseline, timeout_seconds=timeout,
        sast_rules=lists["sast_rules"], unit_tests=lists["unit_tests"],
        contract_tests=lists["contract_tests"], quality_prefixes=lists["quality_prefixes"],
        documentation_prefixes=lists["documentation_prefixes"], shared_paths=lists["shared_paths"],
        bootstrap_modules=lists["bootstrap_modules"], public_contracts=lists["public_contracts"],
        type_files=type_files,
    )
