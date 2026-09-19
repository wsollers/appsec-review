"""Bounded static build discovery. Target text is evidence, never executable config."""
import hashlib
from pathlib import Path
import re

from execution_state import ROOT, Blocked, beneath, read_json
from phase1 import config_for, job_root


def collect(run_id, pointer, data):
    target = Path(config_for(run_id)['target'])
    identity = read_json(job_root(run_id)/'attempts'/pointer['attempt_id']/'evidence/source.json')
    excluded = set(data['scope']['excluded_paths'])
    evidence = []
    used = 0
    for name, info in sorted(identity['files'].items()):
        p = Path(name)
        selected = (p.name in ('CMakeLists.txt','CMakePresets.json','Makefile','meson.build','Cargo.toml','package.json','pyproject.toml')
                    or p.suffix == '.cmake' or name.startswith('.github/workflows/')
                    or (p.suffix.lower() in ('.md','.rst','.txt') and any(word in name.lower() for word in ('build','install','readme','compil'))))
        if not selected or name in excluded or info['kind'] != 'file':
            continue
        if info['bytes'] > 262144 or used + info['bytes'] > 8*1024*1024:
            raise Blocked('build evidence exceeds bounded discovery budget: '+name)
        content = beneath(target, target/name).read_bytes()
        if hashlib.sha256(content).hexdigest() != info['sha256']:
            raise Blocked('build evidence changed since intake: '+name)
        used += len(content)
        evidence.append({'path':name,'sha256':info['sha256'],'text':content.decode('utf-8',errors='replace')})
    template = read_json(ROOT/'registry/job-templates/02-dev-project-discovery.json')
    return {'files':evidence,'composition':template['composition'],
            'buildenv_catalog':read_json(ROOT/'tooling/buildenv-catalog.json')}


def discover(data, evidence):
    declarations = []
    observed_commands = []
    for file in evidence['files']:
        for number, line in enumerate(file['text'].splitlines(), 1):
            citation = {'path':file['path'],'line':number,'sha256':file['sha256'],'text':line.strip()}
            if (Path(file['path']).name=='CMakeLists.txt' or Path(file['path']).suffix=='.cmake') and re.match(r'\s*(cmake_minimum_required|find_package|option|cmake_dependent_option|project|FetchContent_Declare|ExternalProject_Add)\s*\(',line,re.I):
                declarations.append(citation)
            if re.search(r'\b(cmake|ninja|make|meson|vcpkg|apt-get|brew|conan)\b',line,re.I):
                observed_commands.append(citation)
    roots = [f['path'] for f in evidence['files'] if Path(f['path']).name=='CMakeLists.txt']
    primary = 'CMakeLists.txt' if 'CMakeLists.txt' in roots else (roots[0] if len(roots)==1 else None)
    proposals = []
    if primary:
        source = str(Path(primary).parent).replace('\\','/')
        source = '/workspace' if source=='.' else '/workspace/'+source
        proposals = [['cmake','-S',source,'-B','{run_data}/build/discovery','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
                     ['cmake','--build','{run_data}/build/discovery','--parallel','2']]
    return {'schema':'appsec-review/build-discovery/1','branch':'build_discovery',
            'source_fingerprint':data['source_fingerprint'],'source_revision':data['source_revision'],
            'composition':evidence['composition'],'target_execution':False,'findings':[],
            'build_status':'NOT_EXECUTED','dependency_availability':'NOT_VERIFIED',
            'primary_build_file':primary,'cmake_roots':roots,'declarations':declarations,
            'observed_build_text':observed_commands,'proposed_argv':proposals,
            'evidence_files':[{'path':f['path'],'sha256':f['sha256']} for f in evidence['files']],
            'buildenv_candidates':evidence['buildenv_catalog']['images'],
            'readiness':'PLAN_REQUIRES_ISOLATED_BUILD_VALIDATION' if proposals else 'BLOCKED_UNSUPPORTED_OR_AMBIGUOUS_BUILD',
            'limitations':['Static line extraction does not evaluate CMake conditions, includes or multiline expressions.',
                            'Observed target commands are untrusted citations, never submitted for execution.',
                            'Toolchain image availability, dependency resolution and successful compilation remain unverified.']}
