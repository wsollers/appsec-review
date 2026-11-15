"""Typed ``[jobs.job_evidence_collection.steps.source_sast.tasks.cppcheck_scan.settings]`` (T-5018).

cppcheck's ``--enable`` classes decide what the scanner looks for. ``style``, ``performance``,
``portability`` and ``information`` are readability and maintainability checks (``unusedStructMember``,
``variableScope``, ``constVariablePointer``, ...) with no security signal; the shipped profile enables
``warning`` only. The adapter builds its argv from this frozen setting, keeps the output format and
output path fixed, and the container-execution receipt records the effective argv. Operators widen the
profile per host or per target only through the configuration layers (``profiles/<profile>.toml`` or
the target's recipe), never through free-form flags: ``extra_args`` admits only the allow-listed
option names below, each with a bounded value. The review-side
``[[jobs.job_inference_security_review.settings.lead_filters.stylistic]]`` rule class (T-167) stays as
the second line of defence for any class that an operator does widen.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any


JOB_ID = "job_evidence_collection"
STEP_ID = "source_sast"
TASK_ID = "cppcheck_scan"
PREFIX = f"jobs.{JOB_ID}.steps.{STEP_ID}.tasks.{TASK_ID}.settings"
SETTING_KEYS = frozenset({"enable", "suppressions", "extra_args"})

# cppcheck --enable classes (``cppcheck --help``). ``all`` is deliberately absent: a profile names
# what it turns on.
ENABLE_CLASSES = frozenset({"warning", "style", "performance", "portability", "information",
                            "unusedFunction", "missingInclude"})
DEFAULT_ENABLE = ("warning",)
# cppcheck message ids are identifiers (``unusedStructMember``, ``nullPointer``); the optional
# ``:<file>`` or ``:<file>:<line>`` suffixes are not admitted, so a suppression never names a path.
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
# Allow-listed ``extra_args`` options and the shape their value must take (``None``: a bare flag).
# Anything that reads or writes outside the sandbox or changes what is scanned (``--project``,
# ``--output-file``, ``--plist-output``, ``--cppcheck-build-dir``, ``--addon``, ``--file-list``,
# ``--include``, ``-D``, ``-U``, ``-I``) is deliberately not on the list.
EXTRA_ARG_VALUES: Mapping[str, re.Pattern[str] | None] = {
    "--check-level": re.compile(r"normal|exhaustive"),
    "--std": re.compile(r"c(89|99|11|17|23)|c\+\+(03|11|14|17|20|23|26)"),
    "--platform": re.compile(r"unix32|unix64|win32A|win32W|win64|avr8|elbrus-e1cp|pic8|pic8-enhanced"
                             r"|pic16|mips32|native|unspecified"),
    "--library": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"),
    "--max-ctu-depth": re.compile(r"[1-9][0-9]?"),
    "--max-configs": re.compile(r"[1-9][0-9]{0,2}"),
    "--inconclusive": None,
}
MAX_LIST_ITEMS = 64


def _identifier_list(value: object, field: str, *, what: str,
                     allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"{field} must be a list of at most {MAX_LIST_ITEMS} {what}s")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _IDENTIFIER.fullmatch(item):
            raise ValueError(f"{field} contains an invalid {what}: {item!r}")
        if allowed is not None and item not in allowed:
            raise ValueError(f"{field} names an unknown {what} {item!r}; allowed: "
                             + ", ".join(sorted(allowed)))
        if item in items:
            raise ValueError(f"{field} repeats {what} {item!r}")
        items.append(item)
    return tuple(items)


def _extra_args(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"{field} must be a list of at most {MAX_LIST_ITEMS} allow-listed cppcheck flags")
    seen: set[str] = set()
    args: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} contains a non-string flag: {item!r}")
        name, separator, argument = item.partition("=")
        if name not in EXTRA_ARG_VALUES:
            raise ValueError(f"{field} contains a flag outside the allow-list: {item!r}; allowed: "
                             + ", ".join(sorted(EXTRA_ARG_VALUES)))
        shape = EXTRA_ARG_VALUES[name]
        if shape is None:
            if separator:
                raise ValueError(f"{field} flag {name} takes no value: {item!r}")
        elif not separator or not shape.fullmatch(argument):
            raise ValueError(f"{field} flag {name} has an unsupported value: {item!r}")
        if name in seen:
            raise ValueError(f"{field} repeats flag {name}")
        seen.add(name)
        args.append(item)
    return tuple(args)


@dataclass(frozen=True, slots=True)
class CppcheckProfile:
    """The frozen cppcheck scan profile; ``argv_fragment`` is what the adapter inserts after the executable."""

    enable: tuple[str, ...] = DEFAULT_ENABLE
    suppressions: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "enable", _identifier_list(
            self.enable, f"{PREFIX}.enable", what="cppcheck check class", allowed=ENABLE_CLASSES))
        if not self.enable:
            raise ValueError(f"{PREFIX}.enable must name at least one cppcheck check class")
        object.__setattr__(self, "suppressions", _identifier_list(
            self.suppressions, f"{PREFIX}.suppressions", what="cppcheck message id"))
        object.__setattr__(self, "extra_args", _extra_args(self.extra_args, f"{PREFIX}.extra_args"))

    @property
    def argv_fragment(self) -> tuple[str, ...]:
        """``--enable=...``, the suppressions and the allow-listed extra flags, in configuration order."""
        return ("--enable=" + ",".join(self.enable),
                *(f"--suppress={message_id}" for message_id in self.suppressions),
                *self.extra_args)

    def view(self) -> dict[str, Any]:
        return {"enable": list(self.enable), "suppressions": list(self.suppressions),
                "extra_args": list(self.extra_args)}


def parse_cppcheck_profile(settings: Mapping[str, Any] | None) -> CppcheckProfile:
    """Validate the task settings table; every message names the offending key."""
    settings = {} if settings is None else settings
    if not isinstance(settings, Mapping):
        raise ValueError(f"{PREFIX} must be a table")
    unknown = set(settings) - SETTING_KEYS
    if unknown:
        raise ValueError(f"{PREFIX} has unknown settings: " + ", ".join(sorted(unknown)))
    values: dict[str, Any] = {}
    for key in sorted(SETTING_KEYS):
        if key in settings:
            if not isinstance(settings[key], list):
                raise ValueError(f"{PREFIX}.{key} must be a list")
            values[key] = tuple(settings[key])
    return CppcheckProfile(**values)
