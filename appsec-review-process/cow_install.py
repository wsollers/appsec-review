"""Copy-on-write install sessions for build resolution.

Our buildenv images are sealed: nothing here writes to them. A build unit gets a thin writable
layer on top (a container from the sealed image by digest), packages are installed into that layer
with network to the declared Ubuntu mirror only, and the layer is committed as a disposable image
labelled with the run. Later rounds stack another thin layer on the previous commit, so nothing is
ever copied and nothing is rebuilt from scratch.

The packages come from three places, and the lock records which:

- ``plan``: the build plan's apt list, after checking each name exists (unknown names are dropped
  and reported rather than failing the image);
- ``resolved``: files the failed trial said were missing (CMake package configs, pkg-config
  modules, headers, programs), mapped to packages with apt-file in a cached resolver layer;
- nothing else: no package is installed that neither source named.

``cleanup(run_id)`` removes a run's disposable containers and images by label.
"""
from __future__ import annotations

import tunables
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

LABEL_DISPOSABLE = "appsec.review.disposable"
LABEL_RUN = "appsec.review.run_id"
LABEL_ROLE = "appsec.review.role"
RESOLVER_MAX_AGE_SECONDS = tunables.shared("cow_resolver_max_age_days") * 86400
# One mirror per distribution: Ubuntu buildenvs (cpp, java) use archive.ubuntu.com, the Debian ones
# (go, php, python, rust, typescript, dotnet) deb.debian.org (William, 2026-10-01, D-28; the Ubuntu
# sources failed with exit 100 on bookworm).
APT_SOURCES = (". /etc/os-release && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && "
               'if [ "$ID" = debian ]; then '
               "printf 'Types: deb\\nURIs: http://deb.debian.org/debian\\nSuites: %s %s-updates\\n"
               "Components: main\\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\\n' "
               '"$VERSION_CODENAME" "$VERSION_CODENAME" > /etc/apt/sources.list.d/debian.sources; '
               "else printf 'Types: deb\\nURIs: http://archive.ubuntu.com/ubuntu\\nSuites: %s %s-updates\\n"
               "Components: main universe\\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\\n' "
               '"$VERSION_CODENAME" "$VERSION_CODENAME" > /etc/apt/sources.list.d/ubuntu.sources; fi')


class InstallFailed(RuntimeError):
    pass


def docker() -> str:
    value = os.environ.get("APPSEC_DOCKER_BIN") or shutil.which("docker")
    if not value:
        raise InstallFailed("Docker CLI is unavailable")
    return str(Path(value).resolve())


def _run(argv, *, timeout, log: Path | None = None, input_text: str | None = None) -> subprocess.CompletedProcess:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input_text, check=False)
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as out:
            out.write(f"$ {' '.join(argv[:6])} ...\n{done.stdout[-20000:]}\n{done.stderr[-20000:]}\n[exit {done.returncode}]\n")
    return done


def image_id_of(reference: str) -> str | None:
    done = _run([docker(), "image", "inspect", "--format", "{{.Id}}", reference], timeout=60)
    value = done.stdout.strip()
    return value if done.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", value) else None


def _created_epoch(reference: str) -> float | None:
    done = _run([docker(), "image", "inspect", "--format", "{{.Created}}", reference], timeout=60)
    if done.returncode:
        return None
    text = done.stdout.strip()[:19]
    try:
        return time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except ValueError:
        return None


# ---- resolver layer: apt index + apt-file Contents, cached per sealed base ------------------------

def resolver_image(base_digest: str, *, log: Path, timeout: int = 1800) -> str:
    """A cached layer over the sealed base with the apt lists and apt-file Contents index, used only
    to answer package questions. Rebuilt when older than the 14-day ceiling."""
    tag = f"appsec-build/resolver-{base_digest.split(':', 1)[1][:12]}:local"
    created = _created_epoch(tag)
    if created is not None and time.time() - created < RESOLVER_MAX_AGE_SECONDS:
        return tag
    name = f"appsec-resolver-{uuid.uuid4().hex[:10]}"
    script = (f"{APT_SOURCES} && apt-get update -qq && "
              "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends apt-file >/dev/null && "
              "apt-file update >/dev/null")
    done = _run([docker(), "run", "--name", name, "--user", "root", "--network", "bridge",
                 "--label", f"{LABEL_ROLE}=resolver", base_digest, "sh", "-c", script], timeout=timeout, log=log)
    try:
        if done.returncode:
            raise InstallFailed(f"resolver layer build exited {done.returncode}")
        commit = _run([docker(), "commit", "--change", f"LABEL {LABEL_ROLE}=resolver", name, tag], timeout=600, log=log)
        if commit.returncode:
            raise InstallFailed("resolver layer commit failed")
    finally:
        _run([docker(), "rm", "-f", name], timeout=120)
    return tag


def _resolver_query(resolver: str, script: str, *, log: Path, timeout: int = 600) -> str:
    done = _run([docker(), "run", "--rm", "--network", "none", "--user", "root", resolver, "sh", "-c", script],
                timeout=timeout, log=log)
    return done.stdout


def check_names(resolver: str, names: list[str], *, log: Path) -> tuple[list[str], list[str]]:
    """Split apt names into (known, unknown) against the resolver's package lists."""
    if not names:
        return [], []
    safe = [n for n in names if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", n)]
    script = "for p in " + " ".join(safe) + "; do if apt-cache show --no-all-versions \"$p\" >/dev/null 2>&1; " \
             "then echo \"OK $p\"; else echo \"NO $p\"; fi; done"
    out = _resolver_query(resolver, script, log=log)
    known = sorted({line[3:] for line in out.splitlines() if line.startswith("OK ")})
    return known, sorted(set(names) - set(known))


# ---- what did the failed build say it was missing? ------------------------------------------------

_PATTERNS = [
    # CMake find_package in config mode lists the file names it looked for.
    ("cmake-config", re.compile(r"Could not find a package configuration file provided by\s+\"([^\"]+)\"(.*?)(?:\n\s*\n\s*Add|\Z)", re.S)),
    ("cmake-module", re.compile(r"Could NOT find (\w+)")),
    ("pkg-config", re.compile(r"No package '([^']+)' found")),
    ("pkg-config", re.compile(r"Package '([^']+)',? required by '[^']*', not found")),
    ("pkg-config-list", re.compile(r"The following required packages were not found:\s*\n((?:\s*-\s*\S+\s*\n)+)")),
    ("header", re.compile(r"fatal error: ([\w./+-]+\.(?:h|hh|hpp|hxx)): No such file")),
    ("program", re.compile(r"(?:^|\n)(?:/bin/sh: \d+: |sh: \d+: |bash: line \d+: )?([\w.+-]+): (?:command )?not found")),
    ("program", re.compile(r"Could not find (?:program|executable) ['\"]?([\w.+-]+)")),
]


def missing_from_logs(text: str) -> list[dict]:
    """Missing build inputs named in configure/build output, each with apt-file regexes to try."""
    needs: list[dict] = []

    def add(kind, name, regexes):
        if name and not any(n["kind"] == kind and n["name"] == name for n in needs):
            needs.append({"kind": kind, "name": name, "regexes": regexes})

    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            name = match.group(1).strip()
            if kind == "cmake-config":
                files = re.findall(r"([\w.+-]+(?:Config|-config)\.cmake)", match.group(2) or "")
                files = files or [f"{name}Config.cmake", f"{name.lower()}-config.cmake"]
                add(kind, name, [r"/" + re.escape(f) + r"$" for f in sorted(set(files))])
            elif kind == "cmake-module":
                low = name.lower()
                add(kind, name, [rf"/pkgconfig/{re.escape(low)}[0-9.]*\.pc$", rf"/include/(?:[^/]+/)?{re.escape(low)}\.h$",
                                 rf"/lib[^/]*/lib{re.escape(low)}[0-9.]*\.so$"])
            elif kind == "pkg-config":
                module = re.split(r"[<>= ]", name)[0]
                add(kind, module, [rf"/pkgconfig/{re.escape(module)}\.pc$"])
            elif kind == "pkg-config-list":
                for module in re.findall(r"-\s*([\w.+-]+)", name):
                    module = re.split(r"[<>=]", module)[0]
                    add("pkg-config", module, [rf"/pkgconfig/{re.escape(module)}\.pc$"])
            elif kind == "header":
                add(kind, name, [r"/include/(?:.*/)?" + re.escape(name) + r"$"])
            elif kind == "program":
                if name in ("sh", "bash", "make", "cmake") or len(name) < 2:
                    continue
                add(kind, name, [rf"^/usr/(?:s?bin|lib/[^/]+/bin)/{re.escape(name)}$"])
    return needs


_DOWNLOAD_FAILED = re.compile(r"(?:error: )?downloading '([^']+)' failed")


def offline_downloads(text: str) -> list[str]:
    """URLs the build tried to fetch (CMake ExternalProject/FetchContent). The trial is offline, so
    no package fixes these (freeciv21: the Libertinus font zip, guarded by FREECIV_DOWNLOAD_FONTS)."""
    return sorted(set(_DOWNLOAD_FAILED.findall(text)))


_DOWNLOAD_GUARD = re.compile(r"\b([A-Z][A-Z0-9_]*DOWNLOAD[A-Z0-9_]*)\b")


def download_guards(source_root: Path, limit: int = 2000) -> list[str]:
    """CMake options that gate build-time downloads (freeciv21: FREECIV_DOWNLOAD_FONTS guards the
    Libertinus ExternalProject). Read from if()/option() lines of the unit's CMake files."""
    names: set[str] = set()
    files = [p for p in [source_root / "CMakeLists.txt", *sorted(source_root.rglob("*.cmake"))]
             if p.is_file() and not p.is_symlink()][:limit]
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith(("if(", "if (", "elseif(", "option(", "option (", "cmake_dependent_option(")):
                names.update(_DOWNLOAD_GUARD.findall(line))
    return sorted(names)


def with_options_off(commands: list[dict], names: list[str]) -> list[dict]:
    """The plan's configure commands with -D<name>=OFF added where the name is not already set."""
    out = []
    for command in commands:
        argv = list(command.get("argv") or [])
        if command.get("phase") == "configure" and argv and argv[0].rsplit("/", 1)[-1] == "cmake" \
                and "--build" not in argv:
            for name in names:
                if not any(a.startswith(f"-D{name}=") or a.startswith(f"-D{name}:") for a in argv):
                    argv.append(f"-D{name}=OFF")
        out.append({**command, "argv": argv})
    return out


_VERSION_CONFLICT = re.compile(
    r'Could not find a configuration file for package "([^"]+)" that is compatible\s+with requested version\s+"([^"]+)"(.*?)(?:Call Stack|\n\s*\n\S|\Z)', re.S)


def version_conflicts(text: str) -> list[str]:
    """Dependencies that are installed but too old (freeciv21: Qt 6.6 required, noble has 6.4.2).
    apt cannot fix these from the pinned mirror; they become a named coverage gap."""
    out = []
    for name, wanted, rest in _VERSION_CONFLICT.findall(text):
        found = sorted(set(re.findall(r"version: ([0-9][\w.+-]*)", rest)))
        entry = f"{name} >= {wanted} required; available: {', '.join(found) or 'none'}"
        if entry not in out:
            out.append(entry)
    return out


def packages_for(resolver: str, needs: list[dict], *, log: Path, prefer: set[str] | None = None) -> dict[str, str | None]:
    """Map each need to one apt package with apt-file, all lookups in one resolver container.

    Ranking: a package the plan already named; then one whose name contains the missing thing's
    stem (lua.h -> liblua*); then the shallowest matching path; then -dev; then the shortest name."""
    prefer = prefer or set()
    script = []
    for i, need in enumerate(needs):
        for j, regex in enumerate(need["regexes"]):
            script.append(f"echo '@@ {i} {j}'; apt-file search -x {json.dumps(regex)} 2>/dev/null | head -300")
    out = _resolver_query(resolver, "; ".join(script), log=log, timeout=1800) if script else ""
    hits: dict[tuple[int, int], list[tuple[str, str]]] = {}
    key = None
    for line in out.splitlines():
        if line.startswith("@@ "):
            _, i, j = line.split(); key = (int(i), int(j)); hits[key] = []
        elif key is not None and ": " in line:
            package, path = line.split(": ", 1)
            hits[key].append((package.strip(), path.strip()))
    result: dict[str, str | None] = {}
    for i, need in enumerate(needs):
        stem = re.sub(r"[^a-z0-9]", "", re.sub(r"\.(h|hh|hpp|hxx|pc)$|config\.cmake$|-config\.cmake$", "",
                                           need["name"].split("/")[-1].lower()))
        chosen = None
        for j, _regex in enumerate(need["regexes"]):
            candidates = hits.get((i, j), [])
            if not candidates:
                continue
            def rank(item):
                package, path = item
                flat = re.sub(r"[^a-z0-9]", "", package)
                return (package not in prefer, not (stem and stem in flat), path.count("/"),
                        not package.endswith("-dev"), "dbg" in package, len(package), package)
            chosen = min(candidates, key=rank)[0]
            break
        result[f"{need['kind']}:{need['name']}"] = chosen
    return result


# ---- the copy-on-write layer ---------------------------------------------------------------------

def install_layer(from_image: str, packages: list[str], *, repository: str, run_id: str, unit: str,
                  round_no: int, log: Path, timeout: int = 1800) -> str:
    """Install packages into a fresh writable layer over from_image and commit it. Returns the
    committed image id. from_image is never modified."""
    name = f"appsec-cow-{uuid.uuid4().hex[:12]}"
    safe = [p for p in packages if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", p)]
    script = (f"{APT_SOURCES} && apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
              f"apt-get install -y --no-install-recommends {' '.join(safe)} && rm -rf /var/lib/apt/lists/*")
    labels = [f"{LABEL_DISPOSABLE}=true", f"{LABEL_RUN}={run_id}", f"{LABEL_ROLE}=build-unit"]
    argv = [docker(), "run", "--name", name, "--user", "root", "--network", "bridge"]
    for label in labels:
        argv += ["--label", label]
    done = _run(argv + [from_image, "sh", "-c", script], timeout=timeout, log=log)
    try:
        if done.returncode:
            raise InstallFailed(f"install round {round_no} exited {done.returncode}")
        tag = f"{repository}:r{round_no}-{uuid.uuid4().hex[:6]}"
        commit_argv = [docker(), "commit"]
        for label in labels + [f"appsec.review.unit={unit}", f"appsec.review.round={round_no}"]:
            commit_argv += ["--change", f"LABEL {label}"]
        commit = _run(commit_argv + [name, tag], timeout=600, log=log)
        if commit.returncode:
            raise InstallFailed(f"install round {round_no} commit failed")
    finally:
        _run([docker(), "rm", "-f", name], timeout=120)
    image = image_id_of(tag)
    if image is None:
        raise InstallFailed("committed layer has no image id")
    return image


def cleanup(run_id: str | None = None, *, dry_run: bool = False) -> dict:
    """Remove disposable containers and images (one run's, or all). Sealed images carry no
    disposable label and are never touched."""
    selector = [f"label={LABEL_DISPOSABLE}=true"] + ([f"label={LABEL_RUN}={run_id}"] if run_id else [])
    filters = sum((["--filter", f] for f in selector), [])
    containers = _run([docker(), "ps", "-aq", *filters], timeout=60).stdout.split()
    images = _run([docker(), "images", "-q", *filters], timeout=60).stdout.split()
    if not dry_run:
        if containers:
            _run([docker(), "rm", "-f", *containers], timeout=300)
        if images:
            _run([docker(), "rmi", "-f", *sorted(set(images))], timeout=600)
    return {"containers": len(containers), "images": len(set(images)), "dry_run": dry_run}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Remove disposable build-unit layers.")
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.run_id and not args.all:
        parser.error("give a run id or --all")
    print(json.dumps(cleanup(None if args.all else args.run_id, dry_run=args.dry_run)))
