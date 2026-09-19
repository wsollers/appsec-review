"""Machine dependency and registry composition validation; no scheduler guesses."""
from pathlib import Path
import os
from execution_state import ROOT, identifier, read_json, file_hash, digest, Blocked
from schema_validate import validate_document

REGISTRY = ROOT / 'registry'
GRAPH = ROOT / 'job-graph.json'
IMPLEMENTATION_FILES = ['execution_state.py','process_gate.py','phase1.py','intake.py','job_graph.py']
LOADED_IMPLEMENTATION = {name:file_hash(ROOT/name) for name in IMPLEMENTATION_FILES}
KINDS = {'persona_id': ('personas', 'persona', 'persona_id'),
         'role_id': ('roles', 'role', 'role_id'), 'domain_id': ('domains', 'domain', 'domain_id'),
         'tooling_profile_id': ('tooling-profiles', 'tooling-profile', 'tooling_profile_id'),
         'output_contract_id': ('output-contracts', 'output-contract', 'contract_id')}


def composition(job, registry=REGISTRY):
    errors = validate_document(job, 'job-template.schema.json')
    records = {}
    for key, (directory, schema, field) in KINDS.items():
        rid = identifier(job['composition'][key])
        record = read_json(registry / directory / (rid + '.json'))
        errors += validate_document(record, schema + '.schema.json')
        if record.get(field) != rid:
            errors.append('registry identity mismatch: ' + rid)
        records[key] = record
    role, profile, contract = (records[k] for k in ('role_id', 'tooling_profile_id', 'output_contract_id'))
    if not set(contract['required_files']) <= set(job['outputs']['files']):
        errors.append('job omits required contract files')
    claims = set(contract.get('claim_types', []))
    if claims & set(role['forbidden_outputs']) or (claims and not claims <= set(role['allowed_outputs'])):
        errors.append('role/contract claim incompatibility')
    if profile['mode'] == 'static-only' and claims & {'runtime_deployment_claim', 'verified_security_finding', 'successful_build'}:
        errors.append('static profile cannot support runtime/verified claims')
    if job.get('implemented'):
        for key in ('timeout_seconds', 'retry', 'applicability', 'permissions', 'coordinator'):
            if key not in job:
                errors.append('missing runtime configuration: ' + key)
        if job.get('retry', {}).get('max_attempts', 0) not in (1, 2, 3):
            errors.append('retry limit must be 1..3')
        if job.get('retry',{}).get('max_attempts') != 1:
            errors.append('Phase 1 supports explicit recovery only; automatic retry must remain disabled')
        if not isinstance(job.get('timeout_seconds'),(int,float)) or job['timeout_seconds'] <= 0:
            errors.append('positive timeout required')
        if job.get('retry', {}).get('max_attempts', 1) > 1 and not job.get('retry', {}).get('side_effect_free'):
            errors.append('automatic retry requires side-effect-free work')
        if job.get('coordinator') != 'intake-coordinator':
            errors.append('implemented job must have the intake coordinating reviewer')
    if errors:
        raise ValueError('; '.join(errors))
    return records


def load_graph(path=GRAPH):
    graph = read_json(path)
    validate_graph(graph)
    return graph


def validate_graph(graph):
    jobs = graph['jobs']; names = set(jobs)
    validator = read_json(REGISTRY/'job-templates'/(identifier(graph['validator_template'])+'.json'))
    composition(validator)
    if validator['composition']['output_contract_id'] != 'execution-validation':
        raise ValueError('validator must use the trusted nonrecursive execution-validation contract')
    order = read_json(ROOT / 'process-manifest.json')['process_order']
    lane_edges = read_json(ROOT / 'process-manifest.json')['depends_on']
    for lane, dependencies in lane_edges.items():
        for dep in dependencies:
            if order.index(dep) >= order.index(lane):
                raise ValueError('invalid process order: ' + lane)
    namespaces = set()
    for name, node in jobs.items():
        identifier(name)
        identifier(node['namespace'])
        if node.get('implemented') and node['namespace'] != name:
            raise ValueError('implemented output namespace must match the job ID')
        if node['lane'] not in order:
            raise ValueError('unknown lane')
        if node['namespace'] in namespaces:
            raise ValueError('duplicate output namespace')
        namespaces.add(node['namespace'])
        template = read_json(REGISTRY / 'job-templates' / (node['template'] + '.json')) if node.get('template') else None
        if node.get('implemented') and template is None:
            raise ValueError('implemented job lacks registry composition')
        if template:
            composition(template)
            if template['composition']['output_contract_id'] != node['contract']:
                raise ValueError('graph/template output contract mismatch')
            if template['process'] != node['lane']:
                raise ValueError('job lane mismatch')
        for dep in node['dependencies']:
            if dep['job'] not in names:
                raise ValueError('missing dependency: ' + dep['job'])
            if dep['kind'] not in ('required', 'optional', 'not-applicable'):
                raise ValueError('unknown dependency kind')
            producer = jobs[dep['job']]
            if dep['contract'] != producer['contract']:
                raise ValueError('dependency contract mismatch')
            if order.index(producer['lane']) > order.index(node['lane']):
                raise ValueError('job edges violate process order')
    visiting, done = set(), set()
    def visit(name):
        if name in visiting:
            raise ValueError('dependency cycle')
        if name in done:
            return
        visiting.add(name)
        for dep in jobs[name]['dependencies']:
            visit(dep['job'])
        visiting.remove(name); done.add(name)
    for name in jobs:
        visit(name)


def dependency_ok(dep, result):
    if result is None:
        if dep['kind'] == 'optional' and not dep.get('enabled', True):
            return
        raise Blocked('missing required/enabled dependency ' + dep['job'])
    if result['status'] == 'SKIPPED':
        if result.get('reason') in dep.get('allowed_skip_reasons', []):
            return
        raise Blocked('incompatible skip: ' + dep['job'])
    if dep['kind'] == 'not-applicable' or result['status'] != 'OK':
        raise Blocked('dependency not accepted: ' + dep['job'])


def descendants(graph, name):
    found = set()
    def walk(parent):
        for child, node in graph['jobs'].items():
            if child not in found and any(d['job'] == parent for d in node['dependencies']):
                found.add(child); walk(child)
    walk(name)
    return sorted(found)


def definition_hash(job):
    if any(file_hash(ROOT/name) != value for name,value in LOADED_IMPLEMENTATION.items()):
        raise Blocked('implementation changed in a running worker; restart the worker before dispatch')
    records = composition(job)
    graph=read_json(GRAPH)
    templates={node['template'] for node in graph['jobs'].values() if node.get('template')}
    templates.add(graph['validator_template'])
    registry={}
    for name in sorted(templates):
        template=read_json(REGISTRY/'job-templates'/(name+'.json'))
        registry[name]={'template':template,'composition':composition(template)}
    paths = [ROOT / 'execution_state.py', ROOT / 'process_gate.py', ROOT / 'phase1.py', ROOT / 'intake.py',
             ROOT / 'job_graph.py', ROOT / 'phase-1-implementation-prompt.md', ROOT / 'process-manifest.json',
             ROOT / 'tooling/buildenv-catalog.json', ROOT / '00-intake-recovery/config.md', ROOT / '00-intake-recovery/prompt.md', GRAPH]
    paths += sorted((ROOT.parent / 'schemas').glob('*.schema.json'))
    orchestration = Path(os.environ.get('APPSEC_ORCHESTRATOR_ROOT', ROOT.parent / 'orchestrator/dagster'))
    runtime = {name:file_hash(orchestration/name) for name in ('definitions.py','Dockerfile','requirements.txt','requirements.lock.txt','compose.yaml','dagster.yaml')}
    return digest({'job': job, 'records': records, 'registry':registry, 'runtime':runtime, 'files': {str(p.relative_to(ROOT.parent)): file_hash(p) for p in paths}})


def mermaid(graph):
    lines = ['flowchart TD']
    for name, node in graph['jobs'].items():
        key = name.replace('-', '_')
        if node['implemented']:
            lines += [f'  {key}_config["{name}: resolve job configuration"] --> {key}_pre["{name}: pre-validation"]',
                      f'  {key}_pre --> {key}["{name}: work or reuse"]',
                      f'  {key} --> {key}_post["{name}: post-validation and publish"]']
        else:
            lines.append(f'  {key}["{name} (planned; not dispatched)"]')
        for dep in node['dependencies']:
            upstream = dep['job'].replace('-', '_') + ('_post' if graph['jobs'][dep['job']]['implemented'] else '')
            target = key + ('_config' if node['implemented'] else '')
            lines.append(f'  {upstream} -->|{dep["kind"]}| {target}')
    return '\n'.join(lines) + '\n'
