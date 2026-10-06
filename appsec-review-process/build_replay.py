"""Shared happy-path lock replay for 02-build-configure and 02-native-build.

Both jobs consume the accepted stage-13 lock and execute only its recorded argv through B13.  The
target remains read-only, the trusted runner copies it to /scratch, and network is disabled.  This
module deliberately contains the common mechanics; the two public worker modules bind distinct
job identities and output contracts.
"""
from __future__ import annotations

import tunables

from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import threading
from typing import Any
import zlib

import build_resolution
import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import permission_capabilities as pc
import registry_paths
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

CONTROL_SCHEMA = "appsec-review/build-replay-input/1"
CONTROL_FILE = "build-replay.json"
RUNNER_VERSION = "build-lock-replay/2"
RECEIPTS = "b13-receipts.json"
# P35: configure-generated headers (config.h, gnulib replacements) exist only in the build copy.
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".inc")
HEADER_LIMIT, HEADER_MAX_BYTES = 256, 1 << 20
HEADERS_DIR = "generated-headers"
# P36: build-dependency capture bounds (counts, hashed bytes per file, wall clock); beyond them = gaps.
DEPENDENCY_LIMITS = {"files": 8192, "translation_units": 8192, "link_commands": 1024, "edges": 1 << 20,
                     "hash_max_bytes": 256 << 20, "seconds": 1800}
DEPENDENCIES_FILE, DEPENDENCIES_SCHEMA = "build-dependencies.json", "build-dependencies.schema.json"
DEPENDENCIES_MAX_BYTES = 64 << 20

SPECS: dict[str, dict[str, Any]] = {
    "02-build-configure": {
        "dagster_job": "build_configure",
        "contract": "configured-build",
        "result": "configured-build.json",
        "schema": "configured-build.schema.json",
        "summary": "configured-build-summary.md",
        "profile": "build-configure-v1",
        "phases": ("configure",),
    },
    "02-native-build": {
        "dagster_job": "native_build",
        "contract": "native-build",
        "result": "native-build.json",
        "schema": "native-build.schema.json",
        "summary": "native-build-summary.md",
        "profile": "native-build-v1",
        "phases": ("configure", "build"),
    },
}


def spec(job: str) -> dict[str, Any]:
    try:
        return SPECS[job]
    except KeyError as exc:  # pragma: no cover - internal call set is closed
        raise ValueError(job) from exc


def root(run_id: str, job: str) -> Path:
    return data_path(run_id, "jobs", job)


def control_path(run_id: str) -> Path:
    return data_path(run_id, "controls", CONTROL_FILE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _source_snapshot(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file():
        raise Blocked("build replay: staged artifact-manifest.json is required")
    return "sha256:" + file_hash(path)


def source_tree_sha256(target: Path) -> str:
    """Bind the exact checkout bytes replayed by E02, excluding Git administration data."""
    target = target.resolve()
    records: dict[str, dict[str, str]] = {}
    for current, dirs, files in os.walk(target, topdown=True, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(files):
            path = Path(current, name)
            relative = path.relative_to(target).as_posix()
            if path.is_symlink():
                records[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                records[relative] = {"kind": "file", "sha256": "sha256:" + file_hash(path)}
            else:
                raise Blocked(f"build replay: checkout contains a special file: {relative}")
    return "sha256:" + digest(records)


def _cap(job: str) -> dict[str, Any]:
    params = {name: None for name in pc.PARAMETER_NAMES}
    params.update(command_profile_id=spec(job)["profile"], target_path=".")
    return {"kind": "target-execution", "version": "1.0", "parameters": params,
            "origin": "staged-run-config"}


def stage_control(run_id: str, *, authority: str = "Task-authorized engagement owner") -> Path:
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    source = _source_snapshot(run_id)
    target = _target(run_id)
    grants = []
    requirements = {}
    for job in SPECS:
        capability = _cap(job)
        requirements[job] = {"schema": "appsec-review/permission-requirement/1.0",
                             "job_id": job, "capabilities": [capability]}
        grants.append({
            "schema": "appsec-review/permission-grant/1.0",
            "grant_id": "happy-path-" + job,
            "effect": "ALLOW",
            "authority": {"name": authority, "role": "engagement-owner"},
            "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (issued + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "binding": {"run_id": run_id, "source_snapshot_sha256": source, "job_id": job},
            "justification": f"Happy-path {job} replay of the accepted build lock through B13.",
            "capabilities": [capability],
        })
    # D-28 (William, 2026-10-01): replayed builds reach their package managers like the trial did.
    value = {"schema": CONTROL_SCHEMA, "mode": "success", "requirements": requirements,
             "grants": grants, "timeout_seconds": tunables.value(job, "container_timeout_seconds"),
             "build_network": "unrestricted"}
    errors = validate_document(value, "build-replay-input.schema.json")
    if errors:
        raise ValueError("invalid build-replay control: " + "; ".join(errors))
    atomic_json(control_path(run_id), value)
    return control_path(run_id)


def _rebind(grants, run_id, source):
    """Bind staged grants to the current manifest hash.

    Intake rewrites artifact-manifest.json every time it re-runs, so a grant staged against an
    earlier manifest would otherwise go stale mid-run (ADR-0013: a check that blocks runs without
    protecting the report is relaxed). Grants stay bound to this run and job.
    """
    return [{**g, "binding": {**g["binding"], "source_snapshot_sha256": source}}
            if isinstance(g, dict) and g.get("binding", {}).get("run_id") == run_id else g
            for g in grants]


def _permission(control: dict[str, Any], job: str, run_id: str, source: str, at: str) -> dict[str, Any]:
    requirement = control["requirements"][job]
    grants = _rebind([g for g in control["grants"] if g["binding"]["job_id"] == job], run_id, source)
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": None}
    decision = pc.evaluate(requirement, grants, context)
    capabilities = pc.require_granted(decision, requirement=requirement, grants=grants,
                                      context=context)
    granted = {(item["kind"], json.dumps(item["parameters"], sort_keys=True))
               for item in capabilities}
    expected_capability = _cap(job)
    expected = {(expected_capability["kind"],
                 json.dumps(expected_capability["parameters"], sort_keys=True))}
    if granted != expected:
        raise Blocked(f"{job}: permission decision is not the exact target-execution capability")
    return {"requirement": requirement, "grants": grants, "decision": decision}


def _target(run_id: str) -> Path:
    manifest = read_json(run_path(run_id) / "inputs" / "artifact-manifest.json")
    value = manifest.get("target", {}).get("repo_path")
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked("build replay: target.repo_path must be an absolute real checkout directory")
    return path


def _code_hashes(job: str) -> dict[str, str]:
    wrapper = "build_configure.py" if job == "02-build-configure" else "native_build.py"
    names = ("build_replay.py", wrapper, "container_execution.py", "permission_capabilities.py",
             "publish_job_output.py", "validate_job_output.py",
             registry_paths.contract_rel(spec(job)["contract"]))
    result = {name: file_hash(ROOT / name) for name in names}
    for name in ("build-replay-input.schema.json", spec(job)["schema"],
                 "container-image.schema.json", "pinned-container-result.schema.json"):
        result["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    if job == "02-native-build":
        result["schemas/" + DEPENDENCIES_SCHEMA] = file_hash(ROOT.parent / "schemas" / DEPENDENCIES_SCHEMA)
    return result


def _upstream(run_id: str, job: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    resolution = build_resolution.validate(run_id)
    lock_path = resolution / build_resolution.LOCK_FILE
    lock_set = read_json(lock_path)
    pointer = read_json(build_resolution.root(run_id) / "accepted.json")
    resolution_binding = {"job": build_resolution.JOB,
        "attempt_id": pointer["attempt_id"], "lock_sha256": "sha256:" + file_hash(lock_path)}
    if job == "02-native-build":
        import build_configure
        configured = build_configure.validate(run_id)
        configured_pointer = read_json(build_configure.root(run_id) / "accepted.json")
        return resolution, lock_set, {"resolution": resolution_binding, "configured": {
            "job": build_configure.JOB, "attempt_id": configured_pointer["attempt_id"],
            "result_sha256": "sha256:" + file_hash(configured / build_configure.RESULT),
            "envelope_sha256": "sha256:" + file_hash(configured / "result.json"),
        }}
    return resolution, lock_set, resolution_binding


def current_inputs(run_id: str, job: str, at: str | None = None) -> dict[str, Any]:
    """``at``: when the permission gate is evaluated: now for new work, the accepted attempt's own
    start when validate() re-checks it (build_resolution.accepted_started_at)."""
    cpath = control_path(run_id)
    if not cpath.is_file():
        raise Blocked(f"{job}: missing data/controls/{CONTROL_FILE}; explicit grants were not staged")
    control = read_json(cpath)
    errors = validate_document(control, "build-replay-input.schema.json")
    if errors:
        raise Blocked(f"{job}: control fails its closed schema ({len(errors)} errors)")
    source = _source_snapshot(run_id)
    target = _target(run_id)
    permission = _permission(control, job, run_id, source, at or _utc_now())
    _resolution, lock_set, upstream = _upstream(run_id, job)
    records = {}
    for lock in lock_set["locks"]:
        image_id = lock["image"]["image_id"]
        record_path = build_resolution.catalog_root() / "container-images" / f"{image_id}.json"
        if not record_path.is_file():
            raise Blocked(f"{job}: host-local image record is missing for {image_id}")
        record = read_json(record_path)
        if validate_document(record, "container-image.schema.json"):
            raise Blocked(f"{job}: host-local image record is invalid for {image_id}")
        if record["digest"] != lock["image"]["digest"]:
            raise Blocked(f"{job}: lock/image digest mismatch for {image_id}")
        records[image_id] = {"value": record, "sha256": "sha256:" + file_hash(record_path)}
    return {"run_id": run_id, "job": job, "source_snapshot_sha256": source,
        "source_tree_sha256": source_tree_sha256(target),
        "source_revision": lock_set["source_revision"], "target_path": str(target),
        "control": {"path": f"data/controls/{CONTROL_FILE}", "sha256": file_hash(cpath),
                    "value": control}, "upstream": upstream, "lock_set": lock_set,
        "image_records": records,
        "permission_fingerprint_sha256": pc.input_fingerprint_component(permission["decision"]),
        "boundary_sha256": ce.boundary_sha256(), "code": _code_hashes(job)}


HEADER_COLLECTOR = r'''import hashlib,os,pathlib
def generated_headers(src,pristine,limit,max_bytes,suffixes):
 found=[]; omitted=0
 for cur,dirs,files in os.walk(src):
  dirs[:]=sorted(d for d in dirs if d not in ('.git','CMakeFiles'))
  for name in sorted(files):
   p=pathlib.Path(cur,name); rel=p.relative_to(src).as_posix()
   if p.suffix.lower() not in suffixes or p.is_symlink() or not p.is_file() or os.path.lexists(os.path.join(pristine,rel)): continue
   size=p.stat().st_size
   if size>max_bytes or len(found)>=limit: omitted+=1; continue
   found.append({'path':rel,'sha256':'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest(),'size_bytes':size})
 return found,omitted
'''

# P36: what the build consumed, captured in the build image after a successful replay. Link lines come
# from the clang driver's own job log (CC_PRINT_OPTIONS_FILE, set for build-phase commands): every job
# the driver runs is logged with its full argv, including the linker job with the driver's resolved -L
# dirs, -l, -rpath and crt objects. That is independent of PATH (CC is absolute in the buildenv images),
# of bear (cmake units have no bear) and of make recursion, and needs no ptrace; bear 3 only emits
# compile entries and `make -n` misses recursive and generated rules. A link the clang driver did not run
# (a bare `ld`) is not logged: a built binary with no link line is a gap. Headers per TU come from the
# compiler itself (-M over each compile-DB entry's own argv, output to a pipe, never the tree); DT_NEEDED
# and RUNPATH from binutils readelf (installed in audit-buildenv-cpp); ownership from dpkg-query -S/-W.
DEPENDENCY_COLLECTOR = r'''import re,shlex,shutil,subprocess,time
VENDOR_DIRS={'vendor','vendored','third_party','third-party','thirdparty','3rdparty','external','externals','extern','deps'}
LINKER=re.compile(r'(?:.*/)?(?:[A-Za-z0-9_.+-]*-)?(?:ld|ld\.bfd|ld\.gold|ld\.lld|lld|mold)\Z')
DROP_ARG={'-o','-MF','-MT','-MQ','-MJ','--serialize-diagnostics','-Xclang'}
DROP={'-c','-S','-E','-M','-MM','-MD','-MMD','-MP','-MG','-fsyntax-only'}
INCLUDE_FLAGS=('-isystem','-iquote','-idirafter','-I')
LINK_VALUE_OPTIONS={'-dynamic-linker','--dynamic-linker','-soname','-h','-plugin','-plugin-opt','-T','--version-script','-m','-z','-e','--sysroot','-y'}
def _run(argv,cwd=None,timeout=120):
 try:
  p=subprocess.run(argv,cwd=cwd,capture_output=True,text=True,errors='replace',timeout=timeout,check=False)
  return p.returncode,p.stdout,p.stderr
 except (OSError,subprocess.SubprocessError) as e: return None,'',type(e).__name__
def link_commands(text):
 """Linker argvs in a clang driver job log, and the count of job lines that did not parse."""
 found=[]; bad=0
 for line in text.splitlines():
  if not line.startswith(' "'): continue
  try: argv=shlex.split(line)
  except ValueError: bad+=1; continue
  if argv and LINKER.match(argv[0]): found.append(argv)
 return found,bad
def parse_link(argv):
 out=None; dirs=[]; libs=[]; rpath=[]; static=False; i=1
 while i<len(argv):
  a=argv[i]; nxt=argv[i+1] if i+1<len(argv) else None
  if a=='-o' and nxt is not None: out=nxt; i+=2; continue
  if a in ('-L','--library-path') and nxt is not None: dirs.append(nxt); i+=2; continue
  if a in ('-l','--library') and nxt is not None: libs.append({'spec':'-l'+nxt,'static':static}); i+=2; continue
  if a in ('-rpath','-R','--rpath') and nxt is not None: rpath.extend(x for x in nxt.split(':') if x); i+=2; continue
  if a in LINK_VALUE_OPTIONS: i+=2; continue  # -dynamic-linker /lib64/ld-linux-x86-64.so.2 is no input
  if a.startswith(('-rpath=','--rpath=')): rpath.extend(x for x in a.split('=',1)[1].split(':') if x)
  elif a.startswith('--library-path='): dirs.append(a.split('=',1)[1])
  elif a.startswith('-L') and len(a)>2: dirs.append(a[2:])
  elif a.startswith('-l') and len(a)>2: libs.append({'spec':a,'static':static})
  elif a in ('-Bstatic','-static','-dn','-non_shared','--Bstatic'): static=True
  elif a in ('-Bdynamic','-dy','-call_shared','--Bdynamic'): static=False
  elif not a.startswith('-') and (a.endswith('.a') or re.search(r'\.so(\.[0-9]+)*\Z',a)): libs.append({'spec':a,'static':a.endswith('.a')})
  i+=1
 return {'output':out,'libraries':libs,'library_dirs':dirs,'rpath':rpath}
def _deps_argv(words):
 out=[]; skip=False
 for w in words:
  if skip: skip=False; continue
  if w in DROP_ARG: skip=True; continue
  if w in DROP or w.startswith(('-MF','-MT','-MQ','-MJ','-Wp,-M')): continue
  out.append(w)
 return out+['-M','-w']
def _deps(text):
 body=text.replace('\\\n',' ').split(':',1)
 if len(body)<2: return []
 return [t.replace('\\ ',' ').replace('$$','$') for t in re.findall(r'(?:\\ |\S)+',body[1])]
def _elf_id(path):
 try:
  with open(path,'rb') as f: head=f.read(20)
 except OSError: return None
 return (head[4],head[5],head[18:20]) if head[:4]==b'\x7fELF' and len(head)==20 else None
def _dynamic(readelf,path):
 rc,out,_=_run([readelf,'-d','--wide',path],timeout=60)
 if rc!=0: return None
 needed=re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]',out)
 field=lambda tag:[x for m in re.findall(r'\('+tag+r'\)\s+Library \w+: \[([^\]]*)\]',out) for x in m.split(':') if x]
 return needed,field('RUNPATH'),field('RPATH')
def _os_release(path):
 values={}
 try:
  for line in open(path,encoding='utf-8',errors='replace'):
   k,_,v=line.strip().partition('=')
   if k: values[k]=v.strip().strip('"').strip("'")
 except OSError: return None
 ident=values.get('ID','').lower()
 return {'id':ident,'version_id':values.get('VERSION_ID') or None,'codename':values.get('VERSION_CODENAME') or None} if re.fullmatch(r'[a-z0-9._-]{1,64}',ident) else None
def _usrmerge(path):
 for a,b in (('/usr/lib/','/lib/'),('/usr/lib64/','/lib64/'),('/usr/bin/','/bin/'),('/usr/sbin/','/sbin/')):
  if path.startswith(a): return b+path[len(a):]
  if path.startswith(b): return a+path[len(b):]
 return None
def build_dependencies(cfg):
 src,pristine=os.path.normpath(cfg['src']),os.path.normpath(cfg['pristine']); lim=cfg['limits']; tools=cfg['tools']
 deadline=time.monotonic()+lim['seconds']; gaps=[]
 omitted={'files':0,'translation_units':0,'link_commands':0,'edges':0,'hashes':0}
 files=[]; index={}; resources=set()
 def classify(path):
  path=os.path.normpath(path)
  for root in (src,pristine):
   if path==root: return '.','checkout'
   if path.startswith(root+'/'):
    rel=path[len(root)+1:]
    if not os.path.lexists(os.path.join(pristine,rel)): return rel,'generated'
    return rel,('third-party-in-checkout' if VENDOR_DIRS & {p.lower() for p in rel.split('/')[:-1]} else 'checkout')
  if any(path.startswith(r+'/') for r in resources): return path,'toolchain'
  return path,None
 def add(path,kind):
  key,cls=classify(path)
  if key in index:
   item=files[index[key]]
   if kind not in item['kinds']: item['kinds'].append(kind)
   return index[key]
  if len(files)>=lim['files']: omitted['files']+=1; return None
  real=os.path.join(src,key) if cls in ('checkout','generated','third-party-in-checkout') else path
  sha=size=None
  try:
   size=os.stat(real).st_size
   if size<=lim['hash_max_bytes']:
    h=hashlib.sha256()
    with open(real,'rb') as f:
     for chunk in iter(lambda:f.read(1<<20),b''): h.update(chunk)
    sha='sha256:'+h.hexdigest()
  except OSError: pass
  if sha is None: omitted['hashes']+=1
  index[key]=len(files); files.append({'path':key,'class':cls,'kinds':[kind],'sha256':sha,'size_bytes':size,'packages':[]})
  return index[key]
 def located(cwd,p): return os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd,p))
 # Compiler defaults: the resource dir (toolchain), the default include list and library search dirs.
 entries=[e for e in cfg['entries'] if isinstance(e,dict) and (e.get('arguments') or shlex.split(e.get('command','')))[1:2]!=['-cc1']]
 include_dirs=[]; library_dirs=[]; probed=set()
 def note(seq,value):
  if value not in seq and len(seq)<1024: seq.append(value)
 for e in entries:
  words=e.get('arguments') or shlex.split(e.get('command','')); lang='c++' if re.search(r'\.(cc|cpp|cxx|c\+\+|C)\Z',e.get('file','')) else 'c'
  if (words[0],lang) in probed: continue
  probed.add((words[0],lang))
  rc,out,_=_run([words[0],'-print-resource-dir'],timeout=30)
  if rc==0 and out.strip().startswith('/'): resources.add(os.path.normpath(out.strip()))
  rc,_,err=_run([words[0],'-E','-v','-x',lang,os.devnull],timeout=30)
  inside=False
  for line in err.splitlines():
   if line.startswith('#include'): inside=True; continue
   if line.startswith('End of search list'): inside=False
   elif inside and line.startswith(' /'): note(include_dirs,os.path.normpath(line.split(' (')[0].strip()))
  rc,out,_=_run([words[0],'-print-search-dirs'],timeout=30)
  for line in out.splitlines():
   if line.startswith('libraries:'):
    for d in line.split('=',1)[-1].split(':'):
     if d.startswith('/'): note(library_dirs,os.path.normpath(d))
 # (1) headers per translation unit.
 units=[]; failed=0; edges=0
 for e in entries:
  if len(units)>=lim['translation_units'] or time.monotonic()>deadline: omitted['translation_units']+=1; continue
  words=e.get('arguments') or shlex.split(e.get('command','')); cwd=e.get('directory') or src
  flag=None
  for w in words:
   if flag: note(include_dirs,classify(located(cwd,w))[0]); flag=None; continue
   if w in INCLUDE_FLAGS: flag=w; continue
   for f in INCLUDE_FLAGS:
    if w.startswith(f) and len(w)>len(f): note(include_dirs,classify(located(cwd,w[len(f):]))[0]); break
  rc,out,_=_run(_deps_argv(words),cwd=cwd)
  tu=located(cwd,e.get('file',''))
  headers=[]
  if rc!=0: failed+=1
  else:
   for p in _deps(out):
    p=located(cwd,p)
    if p==tu: continue
    if edges>=lim['edges']: omitted['edges']+=1; continue
    i=add(p,'header')
    if i is not None and i not in headers: headers.append(i); edges+=1
  units.append({'file':classify(tu)[0],'exit_code':rc,'headers':sorted(headers)})
 if failed: gaps.append(f'dependency-listing-failed:{failed} translation unit(s)')
 # (2) link lines from the driver job log.
 try: text=open(cfg['clang_log'],encoding='utf-8',errors='replace').read() if cfg.get('clang_log') else ''
 except OSError: text=''
 argvs,bad=link_commands(text)
 if bad: gaps.append(f'link-log-unparsed:{bad} job line(s)')
 binaries=list(cfg['binaries']); links=[]
 def library(spec,static,dirs):
  if not spec.startswith('-l'): return spec if os.path.isabs(spec) and os.path.isfile(spec) else None
  name=spec[2:]; names=[name[1:]] if name.startswith(':') else (['lib'+name+'.a'] if static else ['lib'+name+'.so','lib'+name+'.a'])
  for d in dirs:
   for n in names:
    if os.path.isabs(d) and os.path.isfile(os.path.join(d,n)): return os.path.join(d,n)
  return None
 for argv in argvs:
  if len(links)>=lim['link_commands']: omitted['link_commands']+=1; continue
  parsed=parse_link(argv); out=parsed['output']; binary=None
  if out:
   o=os.path.normpath(out)
   if o.startswith(src+'/'): o=o[len(src)+1:]
   match=[b for b in binaries if b==o or b.endswith('/'+o)]
   binary=match[0] if len(match)==1 else None
  for lib in parsed['libraries']:
   path=library(lib['spec'],lib['static'],parsed['library_dirs'])
   lib['file']=add(path,'static-library' if path.endswith('.a') else 'shared-library') if path else None
   # a relative direct input (.libs/libx.so) is a build-tree product; an -l nothing resolves is a gap
   if path is None and lib['spec'].startswith('-l'): gaps.append(f"library-unresolved:{lib['spec']}"+(f':{binary}' if binary else ''))
  for d in parsed['library_dirs']:
   if d.startswith('/'): note(library_dirs,classify(d)[0])
  links.append({'output':out,'binary':binary,'argv':argv[:8192],**parsed})
 for b in binaries:
  if not any(l['binary']==b for l in links): gaps.append(f'link-command-not-captured:{b}')
 # (3) DT_NEEDED and RUNPATH of each built binary, resolved like the loader would, then transitively.
 records=[]; cache={}
 rc,out,_=_run([tools['ldconfig'],'-p'],timeout=60)
 for m in re.finditer(r'^\s+(\S+) \(([^)]*)\) => (\S+)$',out,re.M): cache.setdefault(m.group(1),[]).append(m.group(3))
 defaults=sorted(d for d in os.listdir('/usr/lib') if d.endswith('-linux-gnu')) if os.path.isdir('/usr/lib') else []
 defaults=[p for d in defaults for p in ('/lib/'+d,'/usr/lib/'+d)]+['/lib64','/usr/lib64','/lib','/usr/lib']
 env_dirs=[d for d in os.environ.get('LD_LIBRARY_PATH','').split(':') if d.startswith('/')]
 def resolve(soname,origin,runpath,rpath,elf):
  if '/' in soname: return (soname,None) if _elf_id(soname)==elf else (None,None)
  expand=lambda d:d.replace('${ORIGIN}',origin).replace('$ORIGIN',origin)
  for via,dirs in (('rpath',[] if runpath else rpath),('ld-library-path',env_dirs),('runpath',runpath),('cache',None),('default',defaults)):
   for p in (cache.get(soname,[]) if dirs is None else [os.path.join(expand(d),soname) for d in dirs]):
    if _elf_id(p)==elf: return os.path.normpath(p),via
  return None,None
 if shutil.which(tools['readelf']) is None and binaries: gaps.append('readelf-unavailable: DT_NEEDED not recorded')
 else:
  queue=[(os.path.join(src,b),b) for b in binaries]; seen=set()
  while queue:
   path,label=queue.pop(0)
   if time.monotonic()>deadline: gaps.append(f'needed-walk-stopped:{len(queue)+1} object(s) beyond the time bound'); break
   if path in seen: continue
   seen.add(path); dyn=_dynamic(tools['readelf'],path); elf=_elf_id(path)
   if dyn is None: gaps.append(f'dynamic-section-unreadable:{label}'); continue
   needed,runpath,rpath=dyn; resolved=[]
   for soname in needed:
    p,via=resolve(soname,os.path.dirname(path),runpath,rpath,elf)
    i=add(p,'needed') if p else None
    if p is None: gaps.append(f'needed-unresolved:{label}:{soname}')
    else: queue.append((p,files[i]['path'] if i is not None else p))  # what the loaded library loads, too
    resolved.append({'soname':soname,'file':i,'via':via})
   if label in binaries: records.append({'path':label,'needed':resolved,'runpath':runpath,'rpath':rpath})
 # (4) OS package ownership of every out-of-checkout file.
 distro=_os_release(cfg['os_release']); manager=None
 outside=[f for f in files if f['class'] is None]
 if shutil.which(tools['dpkg_query']) is None or not os.path.isdir('/var/lib/dpkg'):
  gaps.append(f"package-manager-unavailable:{(distro or {}).get('id') or 'unknown'}: no dpkg; out-of-checkout files are unattributed")
 else:
  manager='dpkg'; spell={}
  for f in outside:
   p=f['path']; real=os.path.realpath(p)
   spell[f['path']]=[s for s in dict.fromkeys([p,_usrmerge(p),real,_usrmerge(real)]) if s and not re.search(r'[*?\[\]\\]',s)]
  owners={}; names=sorted({s for v in spell.values() for s in v})
  for k in range(0,len(names),256):
   _,out,_=_run([tools['dpkg_query'],'-S',*names[k:k+256]],timeout=300)
   for line in out.splitlines():
    if line.startswith('diversion '): continue
    pkgs,sep,path=line.partition(': /')
    if sep: owners['/'+path]=sorted(x.strip() for x in pkgs.split(','))
  for f in outside: f['packages']=next((owners[s] for s in spell[f['path']] if s in owners),[])[:16]
  wanted=sorted({p for f in outside for p in f['packages']}); packages={}
  fmt='${binary:Package}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n'
  for k in range(0,len(wanted),256):
   _,out,_=_run([tools['dpkg_query'],'-W','-f',fmt,*wanted[k:k+256]],timeout=300)
   for line in out.splitlines():
    v=line.split('\t')
    if len(v)==6 and v[3]: packages[v[0]]={'package':v[0],'name':v[1],'arch':v[2],'version':v[3],'source':v[4] or None,'source_version':v[5] or None}
  for f in outside:
   f['packages']=[p for p in f['packages'] if p in packages or p.split(':')[0] in packages]
 for f in files:
  if f['class'] is None: f['class']='system-package' if f['packages'] else 'unattributed'
 unattributed=[f['path'] for f in files if f['class']=='unattributed']
 if unattributed: gaps.append(f"unattributed-files:{len(unattributed)}: "+', '.join(unattributed[:5])+(' ...' if len(unattributed)>5 else ''))
 owned={p for f in files for p in f['packages']}
 table=[packages[p] if p in packages else packages[p.split(':')[0]] for p in sorted(owned)] if manager else []
 for key,n in omitted.items():
  if n: gaps.append(f'{key}-omitted:{n} beyond the capture bound')
 return {'schema':'appsec-review/build-dependencies/1','distro':distro,'package_manager':manager,
  'limits':{k:lim[k] for k in ('files','translation_units','link_commands','edges','hash_max_bytes','seconds')},
  'search_dirs':{'include':include_dirs,'library':library_dirs},'files':files,'packages':table,
  'translation_units':units,'link_commands':links,'binaries':records,'omitted':omitted,'coverage_gaps':gaps[:256]}
def empty_dependencies(lim,gap):
 return {'schema':'appsec-review/build-dependencies/1','distro':None,'package_manager':None,
  'limits':{k:lim[k] for k in ('files','translation_units','link_commands','edges','hash_max_bytes','seconds')},
  'search_dirs':{'include':[],'library':[]},'files':[],'packages':[],'translation_units':[],'link_commands':[],
  'binaries':[],'omitted':{'files':0,'translation_units':0,'link_commands':0,'edges':0,'hashes':0},'coverage_gaps':[gap]}
'''

RUNNER = HEADER_COLLECTOR + DEPENDENCY_COLLECTOR + r'''import json,shutil,stat,sys
cfg=json.loads(sys.argv[1]); roots=cfg.get('roots',{'workspace':'/workspace','scratch':'/scratch'})
work,scratch=roots['workspace'],pathlib.Path(roots['scratch']); src=scratch/'src'; deps=cfg.get('dependencies')
shutil.copytree(work,src,symlinks=False,ignore_dangling_symlinks=True)
log=scratch/'build-deps'/'clang-jobs.log'
if deps: log.parent.mkdir(parents=True,exist_ok=True)
def executables():
 out={}
 for p in src.rglob('*'):
  if 'CMakeFiles' in p.relative_to(src).parts: continue  # CMake compiler probes, not target binaries
  try:
   if p.is_file() and p.stat().st_mode & 0o111 and p.read_bytes()[:4]==b'\x7fELF':
    out[p.relative_to(src).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
  except OSError: pass
 return out
before=executables(); records=[]
for item in cfg['commands']:
 argv=list(item['argv']); cwd=src/item['cwd']
 if item['phase']=='build' and cfg['compile_database']=='bear':
  argv=['bear','--output',str(src/'compile_commands.json'),'--',*argv]
 env=dict(os.environ,CC_PRINT_OPTIONS='1',CC_PRINT_OPTIONS_FILE=str(log)) if deps and item['phase']=='build' else None
 p=subprocess.run(argv,cwd=cwd,check=False,env=env)
 records.append({'phase':item['phase'],'argv':argv,'cwd':str(cwd),'exit_code':p.returncode})
 if p.returncode: break
after=executables(); binaries=[]; headers=[]; omitted=0
if cfg['mode']=='native':
 for rel,sha in sorted(after.items()):
  if before.get(rel)!=sha:
   p=src/rel; binaries.append({'path':rel,'sha256':'sha256:'+sha,'size_bytes':p.stat().st_size})
 h=cfg['headers']; headers,omitted=generated_headers(str(src),work,h['limit'],h['max_bytes'],h['suffixes'])
 if deps and not any(x['exit_code'] for x in records):
  try:
   entries=json.loads((src/'compile_commands.json').read_text()) if (src/'compile_commands.json').is_file() else []
   record=build_dependencies({'src':str(src),'pristine':work,'entries':entries,'clang_log':str(log),
    'binaries':[b['path'] for b in binaries],'limits':deps['limits'],'os_release':'/etc/os-release',
    'tools':{'readelf':'readelf','dpkg_query':'dpkg-query','ldconfig':'ldconfig'}})
  except Exception as exc:  # the capture never fails a build that succeeded; its failure is a gap
   record=empty_dependencies(deps['limits'],f'capture-failed:{type(exc).__name__}')
  (scratch/deps['record']).write_text(json.dumps(record,sort_keys=True)+'\n')
(scratch/'replay-result.json').write_text(json.dumps({'runner':cfg['runner'],'commands':records,'binaries':binaries,'generated_headers':headers,'generated_headers_omitted':omitted},sort_keys=True)+'\n')
sys.exit(next((x['exit_code'] for x in records if x['exit_code']),0))'''


def _runtime(source: str, images_dir: Path) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked("build replay: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=images_dir, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=None, clock=_utc_now, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}



# The runner travels in argv, compressed and split into members under the container's per-member limit
# (container_argv_member_chars_max); the bootstrap joins them back. sys.argv[1] stays the config.
RUNNER_BOOTSTRAP = "import base64,sys,zlib;exec(zlib.decompress(base64.b64decode(''.join(sys.argv[2:]))))"


def runner_argv(cfg: dict) -> list[str]:
    packed = base64.b64encode(zlib.compress(RUNNER.encode("utf-8"), 9)).decode("ascii")
    size = ce.MAX_ARGV_MEMBER_CHARS
    return ["/usr/bin/python3", "-c", RUNNER_BOOTSTRAP, json.dumps(cfg, sort_keys=True),
            *(packed[i:i + size] for i in range(0, len(packed), size))]

def _request(run_id: str, job: str, adapter_id: str, record: dict[str, Any], lock: dict[str, Any],
             inputs: dict[str, Any]) -> dict[str, Any]:
    control = inputs["control"]["value"]
    permission = _permission(control, job, run_id, inputs["source_snapshot_sha256"], _utc_now())
    phases = spec(job)["phases"]
    commands = [item for phase in phases for item in lock[phase]]
    cfg = {"runner": RUNNER_VERSION, "mode": "native" if job == "02-native-build" else "configure",
           "compile_database": lock["compile_database"]["method"], "commands": commands,
           "headers": {"limit": HEADER_LIMIT, "max_bytes": HEADER_MAX_BYTES, "suffixes": list(HEADER_SUFFIXES)}}
    if job == "02-native-build":
        cfg["dependencies"] = {"limits": DEPENDENCY_LIMITS, "record": DEPENDENCIES_FILE}
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": job, "attempt_id": adapter_id,
        "image": {"image_id": record["image_id"], "digest": record["digest"]},
        "argv": runner_argv(cfg),
        "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"}],
        "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"}],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "unrestricted-build" if control.get("build_network") == "unrestricted" else "none",
                    "destinations": []}, "permission": permission,
        "limits": {**tunables.container_limits(job), "timeout_seconds": control["timeout_seconds"]}}


def _compile_db(path: Path, allowed: list[str]) -> list[dict[str, Any]]:
    try:
        value = read_json(path)
    except Exception as exc:
        raise RuntimeError("02-native-build: compile_commands.json is missing or invalid") from exc
    if not isinstance(value, list) or not value:
        raise RuntimeError("02-native-build: compile_commands.json is empty")
    # bear also records clang's internal frontend re-exec (`clang-21 -cc1 ...`, multi-vuln); it
    # duplicates the driver entry and is not a compile command. Drop it and keep the file in step.
    kept = [e for e in value if isinstance(e, dict) and
            (e.get("arguments") or shlex.split(e.get("command", "")))[1:2] != ["-cc1"]]
    if len(kept) != len(value):
        value = kept
        atomic_json(path, value)
        if not value:
            raise RuntimeError("02-native-build: compile_commands.json is empty")
    for index, entry in enumerate(value):
        words = entry.get("arguments") or shlex.split(entry.get("command", ""))
        if not words or words[0] not in set(allowed):
            raise RuntimeError(f"02-native-build: compile_commands[{index}] is not fixed clang")
        if not isinstance(entry.get("file"), str) or not entry["file"].startswith("/scratch/src/"):
            raise RuntimeError(f"02-native-build: compile_commands[{index}] escapes /scratch/src")
    return value


def _header_path(rel: Any) -> str:
    pure = PurePosixPath(rel) if isinstance(rel, str) else PurePosixPath("..")
    if (pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts) or
            pure.suffix.lower() not in HEADER_SUFFIXES):
        raise RuntimeError("02-native-build: generated header path is not a normalized header path")
    return pure.as_posix()


def _publish_headers(replay: dict[str, Any], built: Path, out: Path, attempt: Path) -> dict[str, Any]:
    """P35: copy the runner-declared configure-generated headers out of the build copy, hash-bound."""
    declared, omitted = replay.get("generated_headers", []), replay.get("generated_headers_omitted", 0)
    if not isinstance(declared, list) or len(declared) > HEADER_LIMIT or not isinstance(omitted, int) or omitted < 0:
        raise RuntimeError("02-native-build: generated header listing exceeds its bound")
    headers = []
    for item in declared:
        rel = _header_path(item.get("path") if isinstance(item, dict) else None)
        source = built / rel
        if source.is_symlink() or not source.is_file() or source.stat().st_size > HEADER_MAX_BYTES:
            raise RuntimeError(f"02-native-build: declared generated header is missing: {rel}")
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
        sha = "sha256:" + file_hash(target)
        if sha != item.get("sha256"):
            raise RuntimeError(f"02-native-build: generated header changed after the build: {rel}")
        headers.append({"path": rel, "sha256": sha, "size_bytes": target.stat().st_size})
    return {"root": out.relative_to(attempt).as_posix(), "headers": headers, "omitted": omitted}


def _dependency_record(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > DEPENDENCIES_MAX_BYTES:
        raise RuntimeError(f"02-native-build: {DEPENDENCIES_FILE} is missing or over its byte bound")
    record = read_json(path)
    if validate_document(record, DEPENDENCIES_SCHEMA):
        raise RuntimeError(f"02-native-build: {DEPENDENCIES_FILE} fails its closed schema")
    count = len(record["files"])
    if (count > record["limits"]["files"] or len(record["translation_units"]) > record["limits"]["translation_units"] or
            any(i >= count for unit in record["translation_units"] for i in unit["headers"]) or
            any(item["file"] is not None and item["file"] >= count for link in record["link_commands"] for item in link["libraries"]) or
            any(item["file"] is not None and item["file"] >= count for binary in record["binaries"] for item in binary["needed"])):
        raise RuntimeError(f"02-native-build: {DEPENDENCIES_FILE} exceeds its bound or indexes outside its file table")
    return record


def _publish_dependencies(scratch: Path, out: Path, attempt: Path) -> dict[str, str]:
    """P36: copy the runner's build-dependencies.json out of the trial, hash-bound. In-tree files it hashed
    are re-hashed from the trial's build copy; a record that disagrees with the bytes is refused."""
    record = _dependency_record(scratch / DEPENDENCIES_FILE)
    for item in record["files"]:
        if item["class"] in ("checkout", "generated", "third-party-in-checkout") and item["sha256"]:
            built = scratch / "src" / _tree_path(item["path"])
            if built.is_symlink() or not built.is_file() or "sha256:" + file_hash(built) != item["sha256"]:
                raise RuntimeError(f"02-native-build: build-dependency file differs from the build copy: {item['path']}")
    target = out / DEPENDENCIES_FILE
    target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(scratch / DEPENDENCIES_FILE, target)
    return {"path": target.relative_to(attempt).as_posix(), "sha256": "sha256:" + file_hash(target)}


def _verify_dependencies(attempt: Path, unit: dict[str, Any]) -> None:
    descriptor = unit.get("build_dependencies")
    if descriptor is None:
        return
    path = attempt / _tree_path(descriptor["path"])
    if path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != descriptor["sha256"]:
        raise Blocked("02-native-build: build-dependencies artifact changed")
    try:
        _dependency_record(path)
    except RuntimeError as exc:
        raise Blocked(str(exc)) from None


def _tree_path(rel: Any) -> str:
    pure = PurePosixPath(rel) if isinstance(rel, str) else PurePosixPath("..")
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise RuntimeError("02-native-build: build-dependency path is not a normalized relative path")
    return pure.as_posix()


def fingerprint_view(inputs: dict[str, Any]) -> dict[str, Any]:
    """The inputs as the fingerprint sees them: each B16 image record by its image identity (id,
    repository, digest), not its file bytes. A re-key or cached rebuild with the same image digest
    rewrites build_attempt_id/build_fingerprint_sha256 and must not re-run the native build and every
    consumer (ADR-0013). The full record stays in inputs.json and is what the replay mounts."""
    records = inputs.get("image_records")
    if not isinstance(records, dict):
        return inputs
    return {**inputs, "image_records": {image_id: {"identity_sha256": ce.image_identity_sha256(entry["value"])}
                                        for image_id, entry in sorted(records.items())}}


def fingerprint(inputs: dict[str, Any]) -> str:
    return "sha256:" + digest(fingerprint_view(inputs))


def _validate_attempt(run_id: str, job: str, attempt: Path, inputs: dict[str, Any]) -> None:
    stored = read_json(attempt / "inputs.json")
    if fingerprint_view(stored) != fingerprint_view(inputs):
        raise Blocked(f"{job}: immutable attempt inputs changed")
    inputs = stored          # the attempt is verified against exactly what it ran with
    result = read_json(attempt / spec(job)["result"])
    if validate_document(result, spec(job)["schema"]):
        raise Blocked(f"{job}: result schema validation failed")
    receipts = read_json(attempt / RECEIPTS)
    for receipt in receipts:
        trial = attempt / receipt["trial_path"]
        registry = attempt / receipt["registry_path"]
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        runtime = _runtime(inputs["source_snapshot_sha256"], registry)
        errors = ce.verify_container_result(trial, run_id=run_id, job_id=job,
            attempt_id=receipt["adapter_attempt_id"], request=request, images_dir=registry,
            expected_result_sha256=receipt["expected_result_sha256"], **_host(runtime))
        if errors:
            raise Blocked(f"{job}: B13 evidence failed re-verification ({len(errors)} errors)")
    if job == "02-native-build":
        locks = {item["unit_id"]: item for item in inputs["lock_set"]["locks"]}
        for unit in result["units"]:
            lock = locks.get(unit["unit_id"])
            if lock is None:
                raise Blocked(f"{job}: result names a unit absent from the accepted lock")
            db = attempt / unit["compile_database"]["path"]
            entries = _compile_db(db, lock["compile_database"]["compiler_allowlist"])
            if len(entries) != unit["compile_database"]["entries"]:
                raise Blocked(f"{job}: compile database entry count changed")
            if len(entries) != lock["compile_database"]["entries"]:
                raise Blocked(f"{job}: compile database is incomplete relative to the accepted lock")
            for binary in unit["binaries"]:
                path = attempt / binary["artifact_path"]
                if not path.is_file() or "sha256:" + file_hash(path) != binary["sha256"]:
                    raise Blocked(f"{job}: binary artifact changed")
                if path.read_bytes()[:4] != b"\x7fELF":
                    raise Blocked(f"{job}: published binary is not ELF")
            generated = unit.get("generated_headers") or {"root": "", "headers": []}
            for header in generated["headers"]:
                path = attempt / generated["root"] / _header_path(header["path"])
                if path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != header["sha256"]:
                    raise Blocked(f"{job}: generated header artifact changed")
            _verify_dependencies(attempt, unit)


def run(run_id: str, dagster_id: str, job: str, force: bool = False) -> dict[str, Any]:
    cfg = spec(job); base = root(run_id, job)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {cfg['dagster_job']} --wait"

    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes(job):
            raise Blocked(f"{job}: implementation changed before execution")
        # New work gates on now (inputs may have been derived at an accepted attempt's start).
        _permission(inputs["control"]["value"], job, run_id, inputs["source_snapshot_sha256"], _utc_now())
        units=[]; receipts=[]
        for lock in inputs["lock_set"]["locks"]:
            unit_key = digest(lock["unit_id"])[:12]
            unit_root = attempt / "units" / unit_key
            trial = unit_root / "trial"; registry = unit_root / "image-registry"
            trial.mkdir(parents=True); registry.mkdir(parents=True)
            image_id = lock["image"]["image_id"]
            record = inputs["image_records"][image_id]["value"]
            atomic_json(registry / f"{image_id}.json", record)
            adapter_id = "u" + unit_key
            runtime = _runtime(inputs["source_snapshot_sha256"], registry)
            request = _request(run_id, job, adapter_id, record, lock, inputs)
            terminal = ce.run_container(runtime, run_id=run_id, job_id=job,
                attempt_id=adapter_id, attempt_root=trial, request=request)
            expected = terminal["result_sha256"]
            ce.load_verified_result(trial, run_id=run_id, job_id=job, attempt_id=adapter_id,
                request=request, images_dir=registry, expected_result_sha256=expected, **_host(runtime))
            if terminal["execution_status"] != "OK":
                raise RuntimeError(f"{job}: replay for {lock['unit_id']} ended {terminal['execution_status']}")
            replay = read_json(trial / "scratch" / "replay-result.json")
            commands = replay.get("commands", [])
            # A unit whose plan has no configure step (multi-vuln: a direct compile) locks an empty
            # configure phase; replaying nothing is success, not a failed sequence.
            locked = [item for phase in spec(job)["phases"] for item in lock[phase]]
            if len(commands) != len(locked) or any(item.get("exit_code") != 0 for item in commands):
                raise RuntimeError(f"{job}: locked command sequence did not succeed")
            unit = {"unit_id": lock["unit_id"], "status": "OK", "image_id": image_id,
                    "image_digest": record["digest"], "commands": commands}
            if job == "02-build-configure":
                configuration = {"unit_id": lock["unit_id"], "source_revision": inputs["source_revision"],
                    "image_id": image_id, "image_digest": record["digest"],
                    "lock_sha256": inputs["upstream"]["lock_sha256"], "commands": commands}
                path = attempt / "outputs" / unit_key / "configuration.json"
                atomic_json(path, configuration)
                unit["configuration"] = {"path": path.relative_to(attempt).as_posix(),
                                         "sha256": "sha256:" + file_hash(path)}
            else:
                source_db = trial / "scratch" / "src" / "compile_commands.json"
                entries = _compile_db(source_db, lock["compile_database"]["compiler_allowlist"])
                if len(entries) != lock["compile_database"]["entries"]:
                    raise RuntimeError(f"{job}: replay compile database differs from the accepted lock")
                db = attempt / "outputs" / unit_key / "compile_commands.json"
                db.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source_db, db)
                binaries=[]
                for item in replay.get("binaries", []):
                    source = trial / "scratch" / "src" / item["path"]
                    if not source.is_file():
                        raise RuntimeError(f"{job}: declared binary is missing: {item['path']}")
                    target = attempt / "outputs" / unit_key / "binaries" / item["path"]
                    target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
                    binaries.append({"source_path": item["path"],
                        "artifact_path": target.relative_to(attempt).as_posix(),
                        "sha256": "sha256:" + file_hash(target), "size_bytes": target.stat().st_size})
                if not binaries:
                    raise RuntimeError(f"{job}: build produced no new executable binary")
                unit["compile_database"] = {"path": db.relative_to(attempt).as_posix(),
                    "sha256": "sha256:" + file_hash(db), "entries": len(entries)}
                unit["binaries"] = binaries
                unit["generated_headers"] = _publish_headers(replay, trial / "scratch" / "src",
                    attempt / "outputs" / unit_key / HEADERS_DIR, attempt)
                unit["build_dependencies"] = _publish_dependencies(trial / "scratch", attempt / "outputs" / unit_key, attempt)
            units.append(unit)
            receipts.append({"unit_id": lock["unit_id"], "adapter_attempt_id": adapter_id,
                "trial_path": trial.relative_to(attempt).as_posix(),
                "registry_path": registry.relative_to(attempt).as_posix(),
                "expected_result_sha256": expected})
        result = {"schema": "appsec-review/configured-build/1" if job == "02-build-configure"
                  else "appsec-review/native-build/1", "run_id": run_id,
                  "source_revision": inputs["source_revision"], "upstream": inputs["upstream"],
                  "status": "OK", "units": units, "coverage_gaps": []}
        if not units:
            # ADR-0013: nothing was resolved to build (upstream gaps say why); publish that as a gap.
            result["status"] = "OK_WITH_GAPS"
            result["coverage_gaps"] = ["no-resolved-build-units: 02-build-resolution locked no unit"]
        atomic_json(attempt / cfg["result"], result); atomic_json(attempt / RECEIPTS, receipts)
        (attempt / cfg["summary"]).write_text(f"# {job}\n\n" + "\n".join(
            f"- `{unit['unit_id']}`: {len(unit['commands'])} locked command(s) succeeded"
            for unit in units) + "\n", encoding="utf-8")
        status = {"process": job, "status": result["status"], "run_id": run_id,
            "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
            "source_revision": inputs["source_revision"], "units": len(units),
            "permissions": [f"target-execution:{cfg['profile']}@."], "network": "none",
            "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        artifacts = [cfg["result"], RECEIPTS, cfg["summary"], "status.json"]
        for unit in units:
            if job == "02-build-configure": artifacts.append(unit["configuration"]["path"])
            else:
                artifacts.append(unit["compile_database"]["path"])
                artifacts.extend(item["artifact_path"] for item in unit["binaries"])
                artifacts.extend(unit["generated_headers"]["root"] + "/" + item["path"]
                                 for item in unit["generated_headers"]["headers"])
                artifacts.append(unit["build_dependencies"]["path"])
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job,
            dagster_run_id=dagster_id, worker_kind="pinned_container", output_contract=cfg["contract"],
            input_fingerprint=fingerprint, started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Replayed the accepted lock for {len(units)} unit(s).",
            status_record=status, artifact_paths=artifacts, gaps=result["coverage_gaps"] or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, job, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=cfg["contract"], resume_command=resume,
        derive_inputs=lambda: build_resolution.lifecycle_inputs(base, lambda at: current_inputs(run_id, job, at)),
        fingerprint_inputs=fingerprint, execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(job)}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, job, attempt, record),
        blocked_summary=f"{job} preflight did not complete.",
        failed_summary=f"{job} did not publish; no older success may be used.")


def validate(run_id: str, job: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id, job); pointer = pointer or read_json(base / "accepted.json")
    at = build_resolution.accepted_started_at(base, pointer)
    inputs = current_inputs(run_id, job, at)
    attempt, _ = validate_published(base, pointer, fingerprint(inputs),
                                    expected_run_id=run_id, expected_job_id=job)
    if build_resolution.accepted_started_at(base, {"attempt_id": attempt.name}) != at:
        raise Blocked(f"{job}: accepted attempt start time changed during validation")
    _validate_attempt(run_id, job, attempt, inputs)
    return attempt


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
