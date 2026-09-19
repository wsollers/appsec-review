"""Deterministic, read-only whole-repository intake. Never executes target build files."""
from __future__ import annotations
import fnmatch
import json
import os
from pathlib import Path
import subprocess
import sys
import hashlib
import time
import re
from execution_state import ROOT, atomic_json, atomic_bytes, digest, file_hash, read_json, beneath, Blocked


def git(target, *args):
    result = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', str(target), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
    if result.returncode:
        raise Blocked('source identity query failed: ' + result.stderr.decode(errors='replace')[:500])
    return result.stdout.decode('utf-8', errors='surrogateescape').strip()


def source_identity(target):
    deadline = time.monotonic() + 120
    total_bytes = 0
    target = Path(target).resolve(strict=True)
    if not target.is_dir():
        raise ValueError('target must be a directory')
    files, unavailable, declarations = {}, [], []
    for directory, dirs, names in os.walk(target, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.git')
        for name in list(dirs) + sorted(names):
            p = Path(directory) / name
            rel = p.relative_to(target).as_posix()
            if len(files) >= 100000 or time.monotonic() > deadline:
                raise Blocked('bounded inventory limit exceeded (100000 files / 120 seconds); narrow scope or use an explicit snapshot')
            tag = getattr(p.lstat(), 'st_reparse_tag', 0)
            if tag and not p.is_symlink() and not p.is_junction():
                import ctypes
                from ctypes import wintypes
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel.CreateFileW.restype = wintypes.HANDLE
                kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
                kernel.DeviceIoControl.argtypes = [wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,ctypes.c_void_p]
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                handle = kernel.CreateFileW(str(p), 0, 7, None, 3, 0x02200000, None)
                buffer = ctypes.create_string_buffer(16384); size = wintypes.DWORD()
                try:
                    if not kernel.DeviceIoControl(handle, 0x900A8, None, 0, buffer, len(buffer), ctypes.byref(size), None):
                        raise OSError('cannot fingerprint reparse data: ' + rel)
                    files[rel] = {'kind':'unavailable-reparse','tag':tag,'sha256':hashlib.sha256(buffer.raw[:size.value]).hexdigest()}
                finally:
                    kernel.CloseHandle(handle)
                unavailable.append(rel + ': Windows cannot dereference Linux reparse point; raw link data fingerprinted')
                if name in dirs:
                    dirs.remove(name)
            elif p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()):
                files[rel] = {'kind': 'symlink', 'target': os.readlink(p)}
                unavailable.append(rel + ': symlink not followed')
                if name in dirs:
                    dirs.remove(name)
            elif p.is_file() and rel != '.git':
                before = p.stat()
                total_bytes += before.st_size
                if total_bytes > 4 * 1024 ** 3:
                    raise Blocked('bounded source fingerprint limit exceeded (4 GiB)')
                sha = hashlib.sha256()
                blob = hashlib.sha1(f'blob {before.st_size}\0'.encode())
                preview = bytearray()
                inspect_build = p.name == 'CMakeLists.txt' or p.suffix == '.cmake'
                with p.open('rb') as stream:
                    while chunk := stream.read(1024 * 1024):
                        blob.update(chunk); sha.update(chunk)
                        if inspect_build and len(preview) < 262144:
                            preview.extend(chunk[:262144-len(preview)])
                        if time.monotonic() > deadline:
                            raise Blocked('bounded source fingerprint timeout')
                h = sha.hexdigest()
                after = p.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise Blocked('source changed during hashing: ' + rel)
                files[rel] = {'kind': 'file', 'sha256': h, 'git_blob_sha1':blob.hexdigest(), 'bytes': after.st_size, 'executable': bool(after.st_mode & 0o111)}
                if inspect_build:
                    for line_no,line in enumerate(preview.decode('utf-8',errors='replace').splitlines(),1):
                        if re.match(r'\s*(find_package|add_subdirectory|add_executable|option|cmake_dependent_option|FetchContent_Declare|ExternalProject_Add)\s*\(',line,re.I):
                            declarations.append({'path':rel,'line':line_no,'text':line.strip(),'sha256':h,'basis':'declared; not executed'})
    versioned = (target / '.git').exists()
    revision = git(target, 'rev-parse', 'HEAD') if versioned else 'unversioned'
    # Do not invoke `git status`: repository-configured clean filters can execute code.
    # Compare raw file identities with index object IDs without running filters or hooks.
    dirty = []
    submodules = []
    if versioned:
        tracked = set()
        for line in git(target, 'ls-files', '--stage', '-z').split('\0'):
            if not line:
                continue
            head, path = line.split('\t', 1)
            tracked.add(path)
            if line.startswith('160000 '):
                present = (target / path / '.git').exists()
                submodules.append({'path': path, 'revision': head.split()[1], 'available': present})
                if not present:
                    unavailable.append(path + ': unavailable submodule')
            elif path not in files:
                dirty.append('deleted:' + path)
            elif files[path].get('git_blob_sha1') != head.split()[1]:
                dirty.append('changed-or-link:' + path)
        dirty += ['untracked:' + path for path in files if path not in tracked]
    else:
        dirty = ['unversioned']
    record = {'target': str(target), 'revision': revision, 'dirty': dirty, 'files': files,
              'submodules': submodules, 'unavailable': unavailable, 'build_declarations':declarations}
    record['fingerprint'] = digest(record)
    return record


def inventory(identity, config):
    catalog = read_json(ROOT / 'tooling/buildenv-catalog.json')
    families = {}; manifests = []
    extensions = {'.c':'cpp', '.h':'cpp', '.cpp':'cpp', '.cc':'cpp', '.cxx':'cpp', '.hpp':'cpp',
                  '.py':'python', '.js':'typescript', '.ts':'typescript', '.tsx':'typescript', '.jsx':'typescript',
                  '.java':'java', '.kt':'java', '.go':'go', '.rs':'rust', '.cs':'dotnet', '.fs':'dotnet',
                  '.php':'php', '.tf':'iac', '.tfvars':'iac', '.bicep':'iac', '.lua':'lua', '.rb':'ruby', '.swift':'swift'}
    include = config.get('include', ['**']); exclude = config.get('exclude', [])
    excluded = []
    for path, entry in identity['files'].items():
        if not any(fnmatch.fnmatch(path, p) for p in include) or any(fnmatch.fnmatch(path, p) for p in exclude):
            excluded.append(path); continue
        if entry['kind'] != 'file':
            continue
        name = Path(path).name
        extra_markers = {'Gemfile':'ruby','Rakefile':'ruby','Package.swift':'swift','pubspec.yaml':'dart',
                         'mix.exs':'elixir','composer.json':'php','meson.build':'cpp','BUILD':'bazel',
                         'BUILD.bazel':'bazel','WORKSPACE':'bazel','WORKSPACE.bazel':'bazel','MODULE.bazel':'bazel',
                         'Makefile':'make','GNUmakefile':'make','configure':'autotools','configure.ac':'autotools',
                         'CMakePresets.json':'cmake','Chart.yaml':'deployment','Pulumi.yaml':'iac',
                         'serverless.yml':'iac','terragrunt.hcl':'iac','Vagrantfile':'deployment'}
        if name in extra_markers:
            family = extra_markers[name]
            families.setdefault(family, []).append(path)
            manifests.append({'path':path,'family':family,'sha256':entry['sha256'],'image':None})
        family = extensions.get(Path(path).suffix.lower())
        if family:
            families.setdefault(family, []).append(path)
        for image in catalog['images']:
            if any(fnmatch.fnmatch(name, pattern) for pattern in image['project_markers']):
                # A solution alone is not proof of native scope.
                if name.endswith('.sln') and image['language'] == 'cpp':
                    continue
                manifests.append({'path': path, 'family': image['language'], 'sha256': entry['sha256'], 'image': image['image']})
                families.setdefault(image['language'], []).append(path)
        for kind, applicable in [('cicd', path.startswith(('.github/', '.gitlab/')) or name in ('.gitlab-ci.yml', 'Jenkinsfile', 'azure-pipelines.yml')),
                                 ('deployment', name.startswith('Dockerfile') or 'compose' in name or path.startswith(('deploy/', 'k8s/', 'helm/'))),
                                 ('operations', any(s in path.lower() for s in ('runbook', 'monitor', 'prometheus', 'grafana', 'alert'))),
                                 ('api', any(s in name.lower() for s in ('openapi', 'swagger')) or name.endswith('.proto'))]:
            if applicable:
                families.setdefault(kind, []).append(path)
    native = any(Path(p).suffix.lower() in {'.c','.h','.cpp','.cc','.cxx','.hpp','.vcxproj','.vcproj'} for p in identity['files'] if p not in excluded)
    native_manifests = [m for m in manifests if m['family'] == 'cpp']
    candidates = sorted(native_manifests, key=lambda m: (m['path'].count('/'), m['path']))
    primary = candidates[0]['path'] if candidates else None
    if native and primary and Path(primary).name == 'CMakeLists.txt':
        strategy = {'method': 'CMake export', 'configure_argv': ['cmake', '-S', '{read_only_source}', '-B', '{attempt_build}', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-G', 'Ninja'],
                    'link_recipe_argv': ['ninja', '-C', '{attempt_build}', '-t', 'commands'], 'executed': False}
    elif native:
        strategy = {'method': 'Inspect native build candidates; Bear/compiledb for Make or explicit vcxproj conversion',
                    'link_recipe_argv': None, 'gap': 'Link recipe query requires build-system-specific follow-up', 'executed': False}
    else:
        strategy = {'method': 'not-applicable', 'link_recipe_argv': None, 'executed': False}
    jobs = [{'job': '02-repository-partition-discovery', 'applicability': 'required', 'implemented': False,
             'coordinator': 'intake-coordinator', 'reason': 'Whole-scope routing, including hidden configuration paths'}]
    for job, applicable, persona in [('02-dev-project-discovery', bool(families), 'developer-engineer'),
                                    ('02-devops-project-discovery', bool(set(families) & {'iac','cicd','deployment'}), 'devops-engineer'),
                                    ('02-sre-operations-topology', bool(set(families) & {'operations','deployment'}), 'sre-engineer')]:
        jobs.append({'job': job, 'applicability': 'required' if applicable else 'needs-partition-review', 'persona': persona,
                     'coordinator': 'intake-coordinator', 'implemented': False, 'reason': 'Static inventory; absence is not a scope exclusion'})
    for planned in jobs:
        template=read_json(ROOT/'registry/job-templates'/(planned['job']+'.json'))
        planned['composition']=template['composition']
        planned['persona']=template['composition']['persona_id']
    return {'schema':'appsec-review/intake/1', 'source_fingerprint':identity['fingerprint'], 'source_revision':identity['revision'],
            'business_goal':config['business_goal'], 'platforms':config['platforms'], 'budget':config['budget'],
            'execution_environment':config['execution_environment'], 'permissions':config['permissions'],
            'scope':{'include':include, 'exclude':exclude, 'excluded_paths':excluded, 'unavailable':identity['unavailable'],
                     'all_paths':sorted(identity['files']), 'primary_selection_excludes_other_scope':False},
            'families':{k:sorted(set(v)) for k,v in families.items()}, 'manifests':manifests,
            'native':{'applicable':native,'compile_database_required_for_intake':False,'primary':primary,
                      'candidates':candidates,'strategy':strategy,'build_status':'NOT_EXECUTED',
                      'declarations':[d for d in identity.get('build_declarations',[]) if d['path'] not in excluded] if native else [],
                      'dependency_availability':'Not checked; resolve declared packages in the approved isolated build environment before native collection' if native else 'NOT_APPLICABLE',
                      'commands_attempted':[],
                      'coverage_status':'BLOCKED_PENDING_NATIVE_BUILD' if native else 'NOT_APPLICABLE'},
            'selected_jobs':jobs, 'ready_to_collect':True, 'pregather_complete':False,
            'findings':[], 'limitations':['Read-only deterministic discovery; manifest names and source hashes, not build execution.',
             'All non-.git files fingerprinted, including dirty/untracked/ignored inputs; symlinks recorded but not followed.',
             'Source changes checked before and after work; source must be quiescent. No transient edit/revert guarantee.',
             'Partition and specialist jobs are planned, not dispatched. Missing native coverage blocks only dependent native work.']}


def validate_intake(result, identity, config):
    from schema_validate import validate_document
    errors = validate_document(result, 'intake.schema.json')
    expected = inventory(identity, config)
    if result != expected:
        errors.append('semantic mismatch: scope, citations, native applicability, plan, claims or source identity differs from deterministic inventory')
    if errors:
        raise ValueError('; '.join(errors))


def write_intake(attempt):
    attempt = Path(attempt)
    inputs = read_json(attempt / 'inputs.json')
    source = read_json(attempt / 'evidence/source.json')
    result = inventory(source, inputs['config'])
    atomic_json(attempt / 'outputs/intake.json', result)
    text = '# Build discovery\n\nNo build was executed.\n\n' + json.dumps(result['native'], indent=2) + '\n\nWhole scope is preserved in intake.json, including CI/CD, deployment, API and operations markers.\n'
    atomic_bytes(attempt / 'outputs/build-discovery.md', text.encode())
    print('Read-only intake inventory complete.', flush=True)
    print('Native builds and scanner collection are planned, not executed.', file=sys.stderr, flush=True)


if __name__ == '__main__':
    write_intake(sys.argv[1])
