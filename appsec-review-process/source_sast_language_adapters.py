"""Pinned/offline Go, Java, and PHP source-SAST execution plans.

This module declares real container invocations only.  A tool is either bound to a pinned B16
image and marked READY, or marked UNAVAILABLE with an explicit gap; it is never represented as
executed by planning code.
"""
from __future__ import annotations
from typing import Any

LANGUAGE_TOOLS = {
    "go": {"tool_id":"gosec","image_id":"tool-gosec","version":"2.22.8",
           "argv":["/opt/tool/bin/gosec","-fmt=json","-out=/scratch/gosec.json","./..."]},
    "java": {"tool_id":"spotbugs","image_id":"tool-spotbugs","version":"4.9.3",
             "argv":["/opt/tool/bin/spotbugs","-textui","-xml:withMessages","-output","/scratch/spotbugs.xml","/workspace"]},
    "php": {"tool_id":"phpstan","image_id":"tool-phpstan","version":"2.1.22",
            "argv":["/opt/tool/bin/phpstan","analyse","--no-progress","--error-format=json","--memory-limit=1G","/workspace"]},
}
SUFFIXES = {".go":"go", ".java":"java", ".php":"php"}


def detected_languages(paths: list[str]) -> list[str]:
    return sorted({SUFFIXES[suffix] for path in paths for suffix in SUFFIXES if path.lower().endswith(suffix)})


def build_plan(languages: list[str], registry: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if len(languages) != len(set(languages)) or any(language not in LANGUAGE_TOOLS for language in languages):
        raise ValueError("source SAST language selection is invalid")
    plan = []
    for language in sorted(languages):
        spec = LANGUAGE_TOOLS[language]
        image = registry.get(spec["image_id"])
        digest = image.get("digest") if isinstance(image, dict) else None
        ready = isinstance(digest, str) and digest.startswith("sha256:") and len(digest) == 71
        plan.append({"language":language, "tool_id":spec["tool_id"], "version":spec["version"],
            "image_id":spec["image_id"], "image_digest":digest if ready else None,
            "status":"READY" if ready else "UNAVAILABLE", "executed":False,
            "network":{"mode":"none","destinations":[]}, "target_read_only":True,
            "argv":spec["argv"] if ready else [],
            "gap":None if ready else f"{language} SAST unavailable: pinned image {spec['image_id']} is absent or invalid."})
    return plan


def execution_gaps(plan: list[dict[str, Any]]) -> list[str]:
    gaps=[]
    for item in plan:
        gaps.append(item["gap"] if item["status"] == "UNAVAILABLE" else
                    f"{item['language']} SAST is pinned and planned but no accepted offline tool receipt was supplied.")
    return gaps
