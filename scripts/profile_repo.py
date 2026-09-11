#!/usr/bin/env python3
"""
profile_repo.py — recursive filesystem fingerprinter for the Vendor Code
Audit Playbook. Run this FIRST, before anything else in the pipeline
(before Build-AuditToolbox.ps1, before Phase 0 scope decisions are even
final) — it's the answer to "what am I actually looking at" for a vendor
drop you haven't reviewed yet.

Pure standard library, no pip installs, no Docker. Point it at one or more
root folders (e.g. fsh-client, fsh-infra, fsh-server) and it reports, per
root and combined:
  - languages present, by file count / bytes (skips generated/cache dirs)
  - build systems / package managers detected (package.json, *.csproj,
    go.mod, requirements.txt/pyproject.toml, composer.json, Cargo.toml,
    pom.xml/build.gradle, Gemfile, CMakeLists.txt/Makefile)
  - Unity project detection + exact engine version, if present
  - containerization & IaC artifacts: Dockerfiles (with parsed FROM base
    images), docker-compose files, Kubernetes manifests, Helm charts,
    Terraform (+ parsed provider blocks), Packer templates, Vagrantfiles,
    Ansible playbooks, CI/CD pipeline configs
  - database artifacts: *.sql files, MySQL/my.cnf-style config, ORM
    migration folders
  - native/opaque binaries shipped in-tree (.dll/.so/.dylib/.a/.lib) —
    feeds the playbook's vendor-trust workstream (Phase 1B)
  - env/secrets-adjacent files by name only (.env*, appsettings*.json,
    web.config, id_rsa*, *.pem, *.pfx) — presence and location, never
    content; this is a map for Phase A's real secrets scanner, not a
    secrets scanner itself
  - git repo detection (.git present, submodule file present)
  - a "Needs follow-up" list: things that look important but this script
    can't fully characterize (large unrecognized extensions, an unreadable
    directory, a Dockerfile with no image tag, etc.)

Output: one JSON file per invocation (full detail) plus a Markdown summary
suitable for pasting straight into the Phase 0 scope worksheet or Phase 1
discovery prompt as evidence.

Usage:
    python3 profile_repo.py fsh-client fsh-infra fsh-server -o profile
    # -> profile/repo_profile.json, profile/repo_profile.md

    python3 profile_repo.py "F:\\Barracuda\\fsh-server" -o profile --lines
    # --lines also counts lines of code per language (slower — reads every
    # matched text file instead of just stat()-ing it)

    # Exclude confirmed-out-of-scope paths (bundled tooling, stale reference
    # projects, etc.) from the next run, once you've decided what to skip:
    python3 profile_repo.py "F:\\Barracuda\\fsh-client" -o profile2 \\
        --exclude-file fsh-client-exclude.txt --exclude-dir 官方版本
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Directories we never want to descend into: VCS internals, package caches,
# build output, IDE state, and (critically for a Unity project) the
# multi-gigabyte generated Library/Temp/Obj folders that dwarf the actual
# source and mean nothing about what the vendor wrote.
# ---------------------------------------------------------------------------
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "bower_components",
    "bin", "obj", "Library", "Temp", "Logs", "UserSettings", "MemoryCaptures",
    "build", "dist", "target", "out", ".gradle", ".idea", ".vs", ".vscode",
    ".terraform", ".terragrunt-cache", ".packer_cache",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv", "env",
}

# extension -> language label. Deliberately includes Unity-authored asset
# types (.shader/.cginc/.compute) as their own bucket so they don't get
# miscounted as "unknown," and .meta separately since a Unity project can be
# 50%+ .meta files by count and that's worth knowing, not hiding.
EXT_LANGUAGE: dict[str, str] = {
    ".cs": "C#", ".csx": "C#",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".hxx": "C++",
    ".c": "C", ".h": "C/C++ header",
    ".py": "Python", ".pyi": "Python",
    ".go": "Go",
    ".php": "PHP", ".phtml": "PHP",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".tf": "Terraform/HCL", ".tfvars": "Terraform/HCL",
    ".pkr.hcl": "Packer/HCL",
    ".sh": "Shell", ".bash": "Shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell",
    ".bat": "Batch", ".cmd": "Batch",
    ".sql": "SQL",
    ".yml": "YAML", ".yaml": "YAML",
    ".json": "JSON", ".xml": "XML", ".ini": "INI/Config", ".cfg": "INI/Config", ".conf": "INI/Config",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "SCSS",
    ".md": "Markdown", ".txt": "Text",
    ".shader": "Unity Shader", ".cginc": "Unity Shader", ".compute": "Unity Compute Shader",
    ".asset": "Unity Asset", ".prefab": "Unity Prefab", ".unity": "Unity Scene",
    ".mat": "Unity Material", ".anim": "Unity Animation", ".controller": "Unity Animator",
    ".meta": "Unity Meta",
}

BINARY_NATIVE_EXTS = {".dll", ".so", ".dylib", ".a", ".lib", ".pdb", ".exe"}
SECRET_ADJACENT_PATTERNS = [
    re.compile(r"^\.env(\..+)?$", re.IGNORECASE),
    re.compile(r"^appsettings(\..+)?\.json$", re.IGNORECASE),
    re.compile(r"^web\.config$", re.IGNORECASE),
    re.compile(r"^id_rsa\w*$", re.IGNORECASE),
    re.compile(r".*\.pem$", re.IGNORECASE),
    re.compile(r".*\.pfx$", re.IGNORECASE),
    re.compile(r".*\.p12$", re.IGNORECASE),
    re.compile(r"^\.npmrc$", re.IGNORECASE),
    re.compile(r"^credentials(\.json)?$", re.IGNORECASE),
    re.compile(r"^secrets\.\w+$", re.IGNORECASE),
]

BUILD_MARKERS: dict[str, str] = {
    "package.json": "Node.js/npm",
    "package-lock.json": "npm (lockfile)",
    "yarn.lock": "Yarn",
    "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "Python/pip",
    "pyproject.toml": "Python (pyproject)",
    "Pipfile": "Python/pipenv",
    "setup.py": "Python (setuptools)",
    "go.mod": "Go modules",
    "go.sum": "Go modules (sum)",
    "composer.json": "PHP/Composer",
    "composer.lock": "PHP/Composer (lockfile)",
    "Gemfile": "Ruby/Bundler",
    "Cargo.toml": "Rust/Cargo",
    "pom.xml": "Java/Maven",
    "build.gradle": "Java-Kotlin/Gradle",
    "build.gradle.kts": "Kotlin/Gradle",
    "CMakeLists.txt": "C/C++ (CMake)",
    "Makefile": "C/C++ (Make)",
    # .sln / .csproj are matched by suffix below, not exact name — not listed here.
}

CONTAINER_IAC_MARKERS = {
    "dockerfile_exact": {"Dockerfile"},        # matched case-sensitively by exact name
    "dockerfile_suffix": ".dockerfile",         # e.g. api.dockerfile
    "compose": {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
    "helm_chart": {"Chart.yaml", "Chart.yml"},
    "vagrant": {"Vagrantfile"},
    "jenkins": {"Jenkinsfile"},
    "gitlab_ci": {".gitlab-ci.yml"},
    "azure_pipelines": {"azure-pipelines.yml"},
    "ansible_cfg": {"ansible.cfg"},
}

FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)
TF_PROVIDER_RE = re.compile(r'provider\s+"([a-zA-Z0-9_-]+)"')
TF_RESOURCE_RE = re.compile(r'resource\s+"([a-zA-Z0-9_-]+)"')
K8S_KIND_RE = re.compile(r'^\s*kind:\s*([A-Za-z]+)', re.MULTILINE)
K8S_APIVERSION_RE = re.compile(r'^\s*apiVersion:\s*(\S+)', re.MULTILINE)
UNITY_VERSION_RE = re.compile(r"m_EditorVersion:\s*(\S+)")

MAX_SNIFF_BYTES = 200_000  # cap on how much of a text file we read to sniff its content (Dockerfile/tf/k8s parsing)


@dataclass
class RootProfile:
    root: str
    total_files: int = 0
    total_bytes: int = 0
    scanned_dirs: int = 0
    skipped_dirs: list[str] = field(default_factory=list)
    languages: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: {"files": 0, "bytes": 0, "lines": 0}))
    build_systems: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    dockerfiles: list[dict[str, Any]] = field(default_factory=list)
    compose_files: list[str] = field(default_factory=list)
    k8s_manifests: list[dict[str, Any]] = field(default_factory=list)
    helm_charts: list[str] = field(default_factory=list)
    terraform_files: list[dict[str, Any]] = field(default_factory=list)
    packer_files: list[str] = field(default_factory=list)
    other_iac: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    unity_projects: list[dict[str, Any]] = field(default_factory=list)
    sql_files: list[str] = field(default_factory=list)
    native_binaries: list[dict[str, Any]] = field(default_factory=list)
    secret_adjacent_files: list[str] = field(default_factory=list)
    git_repos: list[str] = field(default_factory=list)
    follow_up: list[str] = field(default_factory=list)


def safe_read_text(path: Path, max_bytes: int = MAX_SNIFF_BYTES) -> str | None:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def classify_language(path: Path) -> str | None:
    # .pkr.hcl needs special-casing since Path.suffix only gives the last
    # dot-segment ('.hcl'), not the compound extension.
    name = path.name.lower()
    if name.endswith(".pkr.hcl"):
        return "Packer/HCL"
    return EXT_LANGUAGE.get(path.suffix.lower())


def count_lines(path: Path) -> int:
    try:
        with path.open("rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def normalize_exclude_prefix(raw: str) -> str:
    """Turn a user-supplied exclude path (possibly Windows-style, possibly
    with a trailing slash) into a normalized posix-style relative prefix for
    matching against rel-path-from-root strings."""
    p = raw.strip().replace("\\", "/").strip("/")
    return p


def load_exclude_paths(exclude_paths: list[str], exclude_file: Path | None) -> list[str]:
    prefixes = [normalize_exclude_prefix(p) for p in exclude_paths if p.strip()]
    if exclude_file:
        for line in exclude_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            prefixes.append(normalize_exclude_prefix(line))
    return [p for p in prefixes if p]


def is_path_excluded(rel_posix: str, prefixes: list[str]) -> bool:
    """True if rel_posix is the excluded path itself or lives under it —
    a segment-boundary prefix match, not a bare substring match, so
    excluding 'foo/bar' doesn't also catch 'foo/barbaz'."""
    for prefix in prefixes:
        if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
            return True
    return False


def profile_root(root: Path, exclude_dirs: set[str], count_lines_flag: bool, exclude_paths: list[str] | None = None) -> RootProfile:
    profile = RootProfile(root=str(root))
    exclude_paths = exclude_paths or []

    for dirpath, dirnames, filenames in _walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        rel_dir_posix = str(rel_dir).replace("\\", "/")
        if rel_dir_posix == ".":
            rel_dir_posix = ""

        pruned = [d for d in dirnames if d in exclude_dirs]
        kept_after_name_prune = [d for d in dirnames if d not in exclude_dirs]

        path_pruned = []
        for d in list(kept_after_name_prune):
            candidate = f"{rel_dir_posix}/{d}" if rel_dir_posix else d
            if is_path_excluded(candidate, exclude_paths):
                path_pruned.append(d)
        kept_after_name_prune = [d for d in kept_after_name_prune if d not in path_pruned]

        for d in pruned:
            profile.skipped_dirs.append(str((rel_dir / d)).replace("\\", "/") + "  [name-excluded]")
        for d in path_pruned:
            profile.skipped_dirs.append((f"{rel_dir_posix}/{d}" if rel_dir_posix else d) + "  [path-excluded]")

        dirnames[:] = kept_after_name_prune
        profile.scanned_dirs += 1

        if ".git" in filenames or (Path(dirpath) / ".git").is_dir():
            profile.git_repos.append(str(rel_dir).replace("\\", "/") or ".")

        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_path = str(fpath.relative_to(root)).replace("\\", "/")

            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            profile.total_files += 1
            profile.total_bytes += size

            # --- language classification ---
            lang = classify_language(fpath)
            if lang:
                bucket = profile.languages[lang]
                bucket["files"] += 1
                bucket["bytes"] += size
                if count_lines_flag and lang not in ("Unity Meta", "Unity Asset", "Unity Prefab", "Unity Scene", "Unity Material", "Unity Animation", "Unity Animator"):
                    bucket["lines"] += count_lines(fpath)

            # --- build system markers ---
            if fname in BUILD_MARKERS:
                profile.build_systems[BUILD_MARKERS[fname]].append(rel_path)
            elif fname.endswith(".sln"):
                profile.build_systems[".NET Solution"].append(rel_path)
            elif fname.endswith(".csproj"):
                profile.build_systems[".NET Project"].append(rel_path)

            # --- containers / IaC ---
            if fname == "Dockerfile" or fname.endswith(".dockerfile"):
                text = safe_read_text(fpath) or ""
                froms = FROM_RE.findall(text)
                profile.dockerfiles.append({"path": rel_path, "from_images": froms or None})
                if not froms:
                    profile.follow_up.append(f"{rel_path}: Dockerfile with no parseable FROM line — check manually")
            elif fname in CONTAINER_IAC_MARKERS["compose"]:
                profile.compose_files.append(rel_path)
            elif fname in CONTAINER_IAC_MARKERS["helm_chart"]:
                profile.helm_charts.append(rel_path)
            elif fname in CONTAINER_IAC_MARKERS["vagrant"]:
                profile.other_iac["Vagrant"].append(rel_path)
            elif fname in CONTAINER_IAC_MARKERS["jenkins"]:
                profile.other_iac["Jenkins"].append(rel_path)
            elif fname in CONTAINER_IAC_MARKERS["gitlab_ci"]:
                profile.other_iac["GitLab CI"].append(rel_path)
            elif fname in CONTAINER_IAC_MARKERS["azure_pipelines"]:
                profile.other_iac["Azure Pipelines"].append(rel_path)
            elif fname in CONTAINER_IAC_MARKERS["ansible_cfg"]:
                profile.other_iac["Ansible"].append(rel_path)
            elif rel_path.replace("\\", "/").startswith(".github/workflows/") and fname.endswith((".yml", ".yaml")):
                profile.other_iac["GitHub Actions"].append(rel_path)

            if fname.endswith((".tf", ".tfvars")):
                text = safe_read_text(fpath) or ""
                providers = sorted(set(TF_PROVIDER_RE.findall(text)))
                resources = sorted(set(TF_RESOURCE_RE.findall(text)))
                profile.terraform_files.append({"path": rel_path, "providers": providers or None, "resource_types": resources or None})
            elif fname.endswith(".pkr.hcl") or fname == "packer.json" or fname.endswith(".pkr.json"):
                profile.packer_files.append(rel_path)

            if fname.endswith((".yml", ".yaml")) and rel_path not in profile.compose_files:
                text = safe_read_text(fpath)
                if text and K8S_KIND_RE.search(text) and K8S_APIVERSION_RE.search(text):
                    kind = K8S_KIND_RE.search(text).group(1)
                    api_version = K8S_APIVERSION_RE.search(text).group(1)
                    if kind not in ("Chart",):  # avoid false positives on unrelated yaml
                        profile.k8s_manifests.append({"path": rel_path, "kind": kind, "apiVersion": api_version})

            # --- database ---
            if fname.endswith(".sql"):
                profile.sql_files.append(rel_path)

            # --- native / opaque binaries ---
            if fpath.suffix.lower() in BINARY_NATIVE_EXTS:
                profile.native_binaries.append({"path": rel_path, "bytes": size})

            # --- secrets-adjacent filenames (presence only, never content) ---
            if any(pat.match(fname) for pat in SECRET_ADJACENT_PATTERNS):
                profile.secret_adjacent_files.append(rel_path)

            # --- Unity project root detection ---
            if fname == "ProjectVersion.txt" and rel_dir.name == "ProjectSettings":
                text = safe_read_text(fpath) or ""
                m = UNITY_VERSION_RE.search(text)
                profile.unity_projects.append({
                    "path": str(rel_dir.parent).replace("\\", "/") or ".",
                    "editor_version": m.group(1) if m else "unknown — could not parse ProjectVersion.txt",
                })

    return profile


def _walk(root: Path):
    """Thin wrapper around os.walk that tolerates permission errors on
    individual subdirectories instead of aborting the whole scan."""
    import os
    yield from os.walk(root, topdown=True, onerror=lambda e: None)


def summarize_languages(profile: RootProfile, top_n: int = 12) -> list[tuple[str, dict[str, int]]]:
    return sorted(profile.languages.items(), key=lambda kv: kv[1]["files"], reverse=True)[:top_n]


def to_jsonable(profile: RootProfile) -> dict[str, Any]:
    d = {
        "root": profile.root,
        "total_files": profile.total_files,
        "total_bytes": profile.total_bytes,
        "scanned_dirs": profile.scanned_dirs,
        "skipped_dirs": profile.skipped_dirs,
        "languages": {k: v for k, v in sorted(profile.languages.items(), key=lambda kv: kv[1]["files"], reverse=True)},
        "build_systems": dict(profile.build_systems),
        "dockerfiles": profile.dockerfiles,
        "compose_files": profile.compose_files,
        "k8s_manifests": profile.k8s_manifests,
        "helm_charts": profile.helm_charts,
        "terraform_files": profile.terraform_files,
        "packer_files": profile.packer_files,
        "other_iac": dict(profile.other_iac),
        "unity_projects": profile.unity_projects,
        "sql_files": profile.sql_files,
        "native_binaries": profile.native_binaries,
        "secret_adjacent_files": profile.secret_adjacent_files,
        "git_repos": profile.git_repos,
        "follow_up": profile.follow_up,
    }
    return d


def render_markdown(profiles: list[RootProfile]) -> str:
    lines: list[str] = ["# Repository profile\n"]
    combined_langs: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "bytes": 0, "lines": 0})

    for p in profiles:
        lines.append(f"## `{p.root}`\n")
        lines.append(f"- {p.total_files:,} files, {p.total_bytes / 1_048_576:.1f} MB scanned, {p.scanned_dirs:,} directories descended")
        if p.skipped_dirs:
            lines.append(f"- {len(p.skipped_dirs)} directory/directories skipped (build/cache/VCS — see JSON for the list)")
        if p.git_repos:
            lines.append(f"- git repo root(s) detected at: {', '.join('`' + g + '`' for g in p.git_repos)}")
        lines.append("")

        lines.append("**Languages (by file count):**\n")
        lines.append("| Language | Files | Size |" + (" Lines |" if any(v["lines"] for v in p.languages.values()) else ""))
        lines.append("|---|---|---|" + ("---|" if any(v["lines"] for v in p.languages.values()) else ""))
        has_lines = any(v["lines"] for v in p.languages.values())
        for lang, stats in summarize_languages(p):
            combined_langs[lang]["files"] += stats["files"]
            combined_langs[lang]["bytes"] += stats["bytes"]
            combined_langs[lang]["lines"] += stats["lines"]
            size_str = f"{stats['bytes']/1024:.0f} KB" if stats["bytes"] < 1_048_576 else f"{stats['bytes']/1_048_576:.1f} MB"
            row = f"| {lang} | {stats['files']:,} | {size_str} |"
            if has_lines:
                row += f" {stats['lines']:,} |"
            lines.append(row)
        lines.append("")

        if p.unity_projects:
            lines.append("**Unity project(s):**\n")
            for u in p.unity_projects:
                lines.append(f"- `{u['path']}` — editor version `{u['editor_version']}`")
            lines.append("")

        if p.build_systems:
            lines.append("**Build systems / package managers detected:**\n")
            for name, files in p.build_systems.items():
                sample = ", ".join(f"`{f}`" for f in files[:3])
                more = f" (+{len(files)-3} more)" if len(files) > 3 else ""
                lines.append(f"- {name}: {sample}{more}")
            lines.append("")

        if p.dockerfiles:
            lines.append("**Dockerfiles:**\n")
            for d in p.dockerfiles:
                imgs = ", ".join(f"`{i}`" for i in (d["from_images"] or [])) or "*(no FROM parsed)*"
                lines.append(f"- `{d['path']}` — base image(s): {imgs}")
            lines.append("")

        if p.compose_files or p.k8s_manifests or p.helm_charts or p.other_iac:
            lines.append("**Other container/orchestration artifacts:**\n")
            for f in p.compose_files:
                lines.append(f"- docker-compose: `{f}`")
            for k in p.k8s_manifests:
                lines.append(f"- Kubernetes {k['kind']} ({k['apiVersion']}): `{k['path']}`")
            for h in p.helm_charts:
                lines.append(f"- Helm chart: `{h}`")
            for name, files in p.other_iac.items():
                sample = ", ".join(f"`{f}`" for f in files[:3])
                more = f" (+{len(files)-3} more)" if len(files) > 3 else ""
                lines.append(f"- {name}: {sample}{more}")
            lines.append("")

        if p.terraform_files:
            all_providers = sorted({pr for tf in p.terraform_files for pr in (tf["providers"] or [])})
            lines.append(f"**Terraform:** {len(p.terraform_files)} file(s); provider(s): {', '.join(all_providers) or 'none parsed'}\n")

        if p.packer_files:
            lines.append(f"**Packer:** {len(p.packer_files)} template file(s): {', '.join('`'+f+'`' for f in p.packer_files[:5])}\n")

        if p.sql_files:
            lines.append(f"**SQL/database files:** {len(p.sql_files)} — e.g. {', '.join('`'+f+'`' for f in p.sql_files[:5])}\n")

        if p.native_binaries:
            total_mb = sum(b["bytes"] for b in p.native_binaries) / 1_048_576
            lines.append(f"**Native/opaque binaries shipped in-tree:** {len(p.native_binaries)} file(s), {total_mb:.1f} MB total — route to Phase 1B vendor-trust triage\n")

        if p.secret_adjacent_files:
            lines.append("**Secrets-adjacent filenames found (presence only — not scanned for content here, feed to Phase A's real secrets scanner):**\n")
            for f in p.secret_adjacent_files[:20]:
                lines.append(f"- `{f}`")
            if len(p.secret_adjacent_files) > 20:
                lines.append(f"- ... (+{len(p.secret_adjacent_files) - 20} more)")
            lines.append("")

        if p.follow_up:
            lines.append("**Needs follow-up:**\n")
            for f in p.follow_up:
                lines.append(f"- {f}")
            lines.append("")

        lines.append("---\n")

    if len(profiles) > 1:
        lines.append("## Combined language totals (all roots)\n")
        lines.append("| Language | Files | Size |")
        lines.append("|---|---|---|")
        for lang, stats in sorted(combined_langs.items(), key=lambda kv: kv[1]["files"], reverse=True)[:15]:
            size_str = f"{stats['bytes']/1024:.0f} KB" if stats["bytes"] < 1_048_576 else f"{stats['bytes']/1_048_576:.1f} MB"
            lines.append(f"| {lang} | {stats['files']:,} | {size_str} |")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", type=Path, help="One or more root folders to profile (e.g. fsh-client fsh-infra fsh-server)")
    ap.add_argument("-o", "--output", type=Path, default=Path("."), help="Output directory for repo_profile.json / .md (default: current directory)")
    ap.add_argument("--lines", action="store_true", help="Also count lines of code per language (slower — reads every matched text file)")
    ap.add_argument("--exclude-dir", action="append", default=[],
                     help="Additional directory NAME to skip wherever it appears (repeatable) — e.g. --exclude-dir 官方版本")
    ap.add_argument("--exclude-path", action="append", default=[],
                     help="Additional relative PATH (from a scanned root) to skip, and everything under it (repeatable). "
                          "Matched independently per root, so a path that doesn't exist under a given root is simply ignored for it.")
    ap.add_argument("--exclude-file", type=Path, default=None,
                     help="Text file with one --exclude-path entry per line (blank lines and #comments ignored) — "
                          "the practical way to hand a long list of confirmed-out-of-scope paths, especially ones with "
                          "non-ASCII names that are painful to retype on a command line.")
    args = ap.parse_args()

    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    exclude_paths = load_exclude_paths(args.exclude_path, args.exclude_file)
    args.output.mkdir(parents=True, exist_ok=True)

    profiles: list[RootProfile] = []
    for root in args.roots:
        if not root.exists():
            print(f"WARNING: {root} does not exist — skipping", file=sys.stderr)
            continue
        print(f"Scanning {root} ...", file=sys.stderr)
        profiles.append(profile_root(root.resolve(), exclude_dirs, args.lines, exclude_paths))

    if not profiles:
        sys.exit("No valid root folders to scan.")

    json_out = {"roots": [to_jsonable(p) for p in profiles]}
    (args.output / "repo_profile.json").write_text(json.dumps(json_out, indent=2), encoding="utf-8")
    (args.output / "repo_profile.md").write_text(render_markdown(profiles), encoding="utf-8")

    print(f"\nWrote {args.output / 'repo_profile.json'}", file=sys.stderr)
    print(f"Wrote {args.output / 'repo_profile.md'}", file=sys.stderr)
    for p in profiles:
        print(f"  {p.root}: {p.total_files:,} files, {len(p.languages)} language(s) detected, "
              f"{len(p.dockerfiles)} Dockerfile(s), {len(p.terraform_files)} Terraform file(s), "
              f"{len(p.unity_projects)} Unity project(s), {len(p.native_binaries)} native binarie(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
