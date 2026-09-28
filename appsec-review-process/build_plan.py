"""02-build-plan: the model plans how each build-set unit is configured and built.

ADR-0012 Revision 2 decision 1 and Revision 3 (docs/processes/build-resolution.md section 3). One
live persona call (Haiku, the job template's own pin) per build-set unit of the accepted
classification. Each call reads the whole target checkout plus, staged as upstream artifacts (scope,
never citable evidence): the accepted `build-index.json`, the accepted `build-classification.json`,
the buildenv catalog and an orchestrator-written `plan-unit.json` naming the one unit to plan. It
returns `build-plan.json` with exactly one plan; the job merges the per-unit plans into the
published `build-plan.json`.

The model owns the evidence-derived content (packages, commands, feasibility). The orchestrator owns
provenance and derivations and overwrites them after the response: `source_revision`, `target`,
`index`, `classification`, `toolchain` (Revision 3: our clang, never the model's choice),
`dispositions` (the units outside the build set) and every citation `content_hash`.

`check` is the deterministic validator (pure; fixture-tested): the Revision 3 rules (no compiler
choice, no test/check/install step) and build-resolution.md section 3's (argv only, no shell,
redirection, network tool, URL or path outside /src and /build; catalog base images; package names).
`run` / `validate` are the graph node's worker on the common worker-result envelope (`persona`),
modeled on 02-build-classify. Status `OK`, `OK_WITH_GAPS` when a plan is tier C or `coverage_gaps` is
non-empty. An empty build set makes no model call and publishes a plan with no plans and every unit's
disposition (status `OK`); `02-build-resolution` is then the job that skips.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import posixpath
import re
import threading

import build_classify
import build_index
from claude_cli_invoker import ClaudeCliInvoker
import discovery_gate
from execution_state import (ROOT, Blocked, atomic_bytes, atomic_json, data_path, digest, file_hash,
                             identifier, now, read_json)
import model_version_registry as mvr
import persona_dispatch as pd
import persona_invocation as pi
import persona_prompt_assembly as ppa
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import review_cli as rc
from schema_validate import SchemaStore, validate_document
import validate_job_output as vjo

JOB = '02-build-plan'
CONTRACT = 'build-plan'
PERSONA_JOB_ID = 'b02-plan'   # short and opaque, like D01-D04 and b01-classify
RESULT = 'build-plan.json'
SUMMARY = 'build-plan-summary.md'
UNIT_FILE = 'plan-unit.json'
CATALOG_FILE = 'buildenv-catalog.json'
CATALOG_PATH = ROOT / 'tooling' / CATALOG_FILE
BUILD_SET_CLASSES = build_classify.BUILD_SET_CLASSES

# ADR-0012 Revision 3: the compiler is ours. The trial's compile database may name only these.
TOOLCHAIN = {
    'compiler': 'clang',
    'cc': '/opt/llvm/bin/clang',
    'cxx': '/opt/llvm/bin/clang++',
    'llvm_version': '21.1.0',
    'compile_database_compilers': ['/opt/llvm/bin/clang', '/opt/llvm/bin/clang++'],
}
DISPOSITIONS = {
    'interpreted': 'source-sast-and-sca',
    'container': 'dockerfile-analysis-and-base-image-scan',
    'infrastructure': 'static-iac-analysis',
    'unclassified': 'coverage-gap',
}

CODE_FILES = ('build_plan.py', 'build_classify.py', 'build_index.py', 'discovery_gate.py',
              'persona_dispatch.py', 'persona_invocation.py', 'persona_prompt_assembly.py',
              'claude_cli_invoker.py', 'publish_job_output.py', 'validate_job_output.py',
              'registry/job-templates/02-build-plan.json', 'registry/output-contracts/build-plan.json',
              '02-evidence-pregather/task-build-plan.md', 'tooling/buildenv-catalog.json')

# --- argv rules (build-resolution.md section 3; ADR-0012 Revision 3) ---------------------------------

COMPILER_RE = re.compile(r'^(?:[\w.+-]*-)?(?:gcc|g\+\+|cc|c\+\+|clang|clang\+\+|cl|clang-cl|icc|icpc|icx|tcc|'
                         r'cpp)(?:-[0-9][0-9.]*)?(?:\.exe)?$')
COMPILER_VAR_RE = re.compile(r'^(?:CC|CXX|CPP|CXXCPP|LD|CCLD|CXXLD|HOSTCC|BUILD_CC|OBJC|OBJCXX)=')
SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'csh', 'tcsh', 'busybox', 'env', 'sudo', 'su', 'doas',
          'eval', 'exec', 'xargs', 'nohup', 'timeout', 'nice'}
NETWORK_TOOLS = {'curl', 'wget', 'git', 'svn', 'hg', 'apt', 'apt-get', 'aptitude', 'dpkg', 'snap', 'pip',
                 'pip3', 'pipx', 'conda', 'gem', 'cpan', 'cpanm', 'go', 'rustup', 'docker', 'podman',
                 'nerdctl', 'scp', 'rsync', 'ssh', 'ftp', 'nc', 'ncat', 'telnet', 'vcpkg', 'conan'}
# Package managers allowed only for an offline build subcommand (never install/fetch/update).
FETCH_SUBCOMMANDS = {'install', 'i', 'add', 'update', 'upgrade', 'fetch', 'get', 'download', 'ci', 'restore',
                     'sync', 'clone', 'pull'}
TEST_RUNNERS = {'ctest', 'meson-test', 'pytest', 'tox', 'nox', 'prove', 'valgrind', 'gdb', 'lldb', 'qemu'}
MAKE_TOOLS = {'make', 'gmake', 'ninja', 'samu', 'bmake', 'mingw32-make'}
FORBIDDEN_TARGETS = {'check', 'test', 'tests', 'installcheck', 'distcheck', 'install', 'install-strip',
                     'uninstall', 'dist', 'dist-gzip', 'run', 'bench', 'benchmark'}
SHELL_TOKENS = {'|', '||', '&', '&&', ';', ';;', '>', '>>', '<', '<<', '<<<', '2>', '2>&1', '&>', '>&'}
URL_RE = re.compile(r'(?i)\b(?:https?|ftp|git|ssh|s3|gs)://|git@[\w.-]+:')
SUBSTITUTION_RE = re.compile(r'\$\(|`|\$\{')
PKG_RE = re.compile(r'^[a-z0-9][a-z0-9+.-]{0,62}$')
MAX_PACKAGES = 60


def _base(word):
    return posixpath.basename(word)


def argv_errors(argv, where):
    """Every rule one command's argv breaks (empty when it is acceptable)."""
    errors = []
    if not argv:
        return [where + ': argv is empty']
    tool = _base(argv[0])
    if COMPILER_RE.match(tool):
        errors.append(where + f': argv[0] {argv[0]!r} chooses a compiler (the toolchain is fixed: our clang)')
    if tool in SHELLS:
        errors.append(where + f': argv[0] {argv[0]!r} is a shell or command runner; commands are argv only')
    if tool in NETWORK_TOOLS:
        errors.append(where + f': argv[0] {argv[0]!r} is a network or package tool; nothing is fetched')
    if tool in {'npm', 'yarn', 'pnpm', 'cargo', 'mvn', 'gradle', 'dotnet', 'composer', 'bundle'} and \
            any(a in FETCH_SUBCOMMANDS for a in argv[1:]):
        errors.append(where + f': {tool} with a fetching subcommand; dependencies are restored during provisioning only')
    if tool in TEST_RUNNERS:
        errors.append(where + f': argv[0] {argv[0]!r} runs tests or a built program (nothing built is ever run)')
    if tool in MAKE_TOOLS or tool in {'cmake', 'meson'}:
        targets = [a for a in argv[1:] if not a.startswith('-') and '=' not in a]
        if tool == 'cmake':
            targets = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ('--target', '-t')]
        if tool == 'meson':
            targets = argv[1:2] if len(argv) > 1 else []
        bad = sorted({t for t in targets if t in FORBIDDEN_TARGETS or t.startswith(('check-', 'test-', 'install-'))})
        if bad:
            errors.append(where + f': target {", ".join(bad)} tests, installs or packages (plans are configure and build only)')
    for n, word in enumerate(argv):
        at = f'{where}.argv[{n}]'
        if word in SHELL_TOKENS or word.startswith(('>', '<', '|')):
            errors.append(at + ': shell redirection, pipe or separator (argv only)')
        if SUBSTITUTION_RE.search(word):
            errors.append(at + ': command or variable substitution (argv only)')
        if URL_RE.search(word):
            errors.append(at + ': a URL (nothing is fetched)')
        if COMPILER_VAR_RE.match(word):
            errors.append(at + f': {word.split("=", 1)[0]}= chooses a compiler or linker (the toolchain is fixed: our clang)')
        if word.startswith('/') and not (word == '/src' or word.startswith(('/src/', '/build/')) or word == '/build'):
            errors.append(at + ': an absolute path outside /src and /build')
        if '\x00' in word or '\n' in word or '\r' in word:
            errors.append(at + ': control character')
    return errors


def _relative_error(value):
    return build_classify._relative_path_error(value, allow_dot=True)


def catalog_bases(catalog):
    """Base image ids a plan may choose: the catalog's image tags without ':local'."""
    return sorted({str(entry.get('image', '')).split(':', 1)[0] for entry in catalog.get('images', [])
                   if entry.get('image')})


def canonicalize_catalog_base(value, catalog):
    """Canonicalize an exact catalog image reference to the logical id stored in a plan.

    The prompt asks for the logical id, while the staged catalog necessarily contains the runnable
    ``:local`` reference.  Treating that exact catalog value as an unambiguous spelling of the same
    choice keeps the validator strict: arbitrary tags and images are still rejected by ``check``.
    """
    references = {str(entry.get('image')): str(entry.get('image')).split(':', 1)[0]
                  for entry in catalog.get('images', []) if entry.get('image')}
    for plan in value.get('plans', []):
        image = plan.get('image')
        if isinstance(image, dict) and image.get('base') in references:
            image['base'] = references[image['base']]
    return value


def derived_dispositions(classification):
    return [{'unit_id': u['unit_id'], 'class': u['class'], 'disposition': DISPOSITIONS[u['class']]}
            for u in sorted(classification.get('units', []), key=lambda u: u['unit_id'])
            if u['class'] in DISPOSITIONS]


def check(value, classification, index, catalog, *, index_ref, classification_ref, source_revision=None,
          expected_units=None):
    """Errors (empty when valid). ``expected_units`` narrows the plan set (one persona response plans
    one unit); by default every build-set unit of the classification must be planned exactly once.
    Citation freshness is checked separately against the checkout."""
    errors = list(validate_document(value, 'build-plan.schema.json'))
    if errors:
        return errors
    if value['index'] != index_ref:
        errors.append('index does not name the accepted build index attempt and its sha256')
    if value['classification'] != classification_ref:
        errors.append('classification does not name the accepted classification attempt and its sha256')
    if value['toolchain'] != TOOLCHAIN:
        errors.append('toolchain is not the fixed clang toolchain (ADR-0012 Revision 3)')
    if value['dispositions'] != derived_dispositions(classification):
        errors.append('dispositions are not derived from the classification')
    if source_revision is not None and value['source_revision'] != source_revision:
        errors.append('source_revision is not the accepted revision')
    if value['source_revision'] != classification.get('source_revision'):
        errors.append('source_revision differs from the classification it plans')
    units = {u['unit_id']: u for u in classification.get('units', [])}
    build_set = list(classification.get('build_set') or [])
    wanted = sorted(expected_units if expected_units is not None else build_set)
    signal_ids = {s['signal_id'] for s in index.get('signals', [])}
    bases = set(catalog_bases(catalog))
    planned = []
    for n, plan in enumerate(value['plans']):
        uid = plan['unit_id']
        where = f'plans[{n}] {uid}'
        planned.append(uid)
        unit = units.get(uid)
        if unit is None or uid not in build_set:
            errors.append(where + ': not a build-set unit of the accepted classification')
            continue
        if plan['root'] != unit['root']:
            errors.append(where + f': root {plan["root"]!r} is not the classification root {unit["root"]!r}')
        if plan['class'] != unit['class']:
            errors.append(where + f': class {plan["class"]!r} is not the classification class {unit["class"]!r}')
        if plan['image']['base'] not in bases:
            errors.append(where + f': image.base {plan["image"]["base"]!r} is not a buildenv catalog image')
        names = [p['name'] for p in plan['image']['apt_packages']]
        if len(names) != len(set(names)):
            errors.append(where + ': apt package names repeat')
        if len(names) > MAX_PACKAGES:
            errors.append(where + f': more than {MAX_PACKAGES} apt packages')
        for name in names:
            if not PKG_RE.match(name):
                errors.append(where + f': apt package name {name!r} is not a package name')
            elif COMPILER_RE.match(name) or re.match(r'^(gcc|g\+\+|clang|llvm|cpp)(-[0-9.]+)?$', name):
                errors.append(where + f': apt package {name!r} is a compiler (the toolchain is fixed: our clang)')
        tier = plan['feasibility']['tier']
        phases = [c['phase'] for c in plan['commands']]
        if phases != sorted(phases, key=lambda p: ('configure', 'build').index(p)):
            errors.append(where + ': commands are not in configure-then-build order')
        if tier == 'C':
            if plan['commands']:
                errors.append(where + ': a tier C plan has no commands')
            if not any(uid in gap for gap in value['coverage_gaps']):
                errors.append(where + ': a tier C plan must be named in coverage_gaps')
        elif 'build' not in phases:
            errors.append(where + f': a tier {tier} plan needs at least one build command')
        for c, command in enumerate(plan['commands']):
            at = f'{where}.commands[{c}]'
            errors += argv_errors(command['argv'], at)
            cwd_error = _relative_error(command['cwd'])
            if cwd_error:
                errors.append(at + '.cwd ' + cwd_error)
            elif not build_classify._under(posixpath.normpath(posixpath.join(plan['root'], command['cwd'])),
                                           plan['root']):
                errors.append(at + '.cwd is outside the unit root')
        for sid in plan['signal_ids']:
            if sid not in signal_ids:
                errors.append(where + f': signal {sid} is not in the accepted index')
    if len(planned) != len(set(planned)):
        errors.append('a unit is planned more than once')
    if sorted(set(planned)) != wanted:
        missing = sorted(set(wanted) - set(planned))
        extra = sorted(set(planned) - set(wanted))
        if missing:
            errors.append('build-set units without a plan: ' + ', '.join(missing))
        if extra:
            errors.append('plans for units not asked for: ' + ', '.join(extra))
    return errors


def finalize(value, *, classification, index_ref, classification_ref, source_revision, pinned):
    """Overwrite the orchestrator-owned fields in place (never trusted from the model)."""
    value['source_revision'] = source_revision
    if isinstance(classification.get('target'), str) and classification['target']:
        value['target'] = classification['target']
    value['index'] = dict(index_ref)
    value['classification'] = dict(classification_ref)
    value['toolchain'] = json.loads(json.dumps(TOOLCHAIN))
    value['dispositions'] = derived_dispositions(classification)
    discovery_gate._backfill_citation_content_hashes(value, pinned)
    return value


def merge(unit_values, *, classification, index_ref, classification_ref, source_revision):
    """One published document from the per-unit responses (already finalized and checked)."""
    plans, gaps = [], []
    for value in unit_values:
        plans += value['plans']
        gaps += [g for g in value['coverage_gaps'] if g not in gaps]
    target = classification.get('target') or (unit_values[0]['target'] if unit_values else '')
    return {'schema': 'appsec-review/build-plan/1', 'target': target, 'source_revision': source_revision,
            'index': dict(index_ref), 'classification': dict(classification_ref),
            'toolchain': json.loads(json.dumps(TOOLCHAIN)),
            'plans': sorted(plans, key=lambda p: p['unit_id']),
            'dispositions': derived_dispositions(classification), 'coverage_gaps': gaps}


def gaps_of(value):
    gaps = [str(g) for g in value.get('coverage_gaps', []) if str(g).strip()]
    for plan in value.get('plans', []):
        if plan.get('feasibility', {}).get('tier') == 'C':
            gaps.append(f'Unit {plan["unit_id"]} is not buildable in the review image (tier C).')
    return sorted(set(gaps))


def summary_of(value, unit_summaries):
    lines = ['# Build plan', '',
             f'Toolchain: {TOOLCHAIN["compiler"]} (LLVM {TOOLCHAIN["llvm_version"]}, fixed by the orchestrator). '
             'Plans are static inferences; nothing has been built.', '']
    for plan in value['plans']:
        lines.append(f'## `{plan["unit_id"]}` ({plan["class"]}, {plan["build_system"]}, tier '
                     f'{plan["feasibility"]["tier"]})')
        lines.append('')
        lines.append(f'- Base `{plan["image"]["base"]}`; packages: '
                     + (', '.join(f'`{p["name"]}`' for p in plan['image']['apt_packages']) or 'none'))
        for command in plan['commands']:
            lines.append(f'- {command["phase"]}: `{" ".join(command["argv"])}` (cwd `{command["cwd"]}`)')
        lines.append(f'- Compile database: {plan["compile_database"]["method"]}')
        lines.append('')
    if value['dispositions']:
        lines.append('## Units without a build')
        lines.append('')
        lines += [f'- `{d["unit_id"]}` ({d["class"]}): {d["disposition"]}' for d in value['dispositions']]
        lines.append('')
    if value['coverage_gaps']:
        lines.append('## Coverage gaps')
        lines.append('')
        lines += [f'- {g}' for g in value['coverage_gaps']]
        lines.append('')
    for uid, text in unit_summaries:
        lines += [f'## Model summary for `{uid}`', '', text.strip(), '']
    return '\n'.join(lines).rstrip() + '\n'


# --- run-level worker -------------------------------------------------------------------------

def root(run_id):
    return data_path(run_id, 'jobs', JOB)


def _code_hashes():
    return {name: file_hash(ROOT / name) for name in CODE_FILES} | {
        'schemas/build-plan.schema.json': file_hash(ROOT.parent / 'schemas' / 'build-plan.schema.json')}


def current_inputs(run_id):
    """The fingerprinted input record: the checkout, the accepted classification (re-validated end to
    end by build_classify.validate, which re-validates the index and every upstream) and the index,
    pinned by hash, the catalog and the code. The model version is pinned per run."""
    target = build_index._target_root(run_id)
    classification_attempt = build_classify.validate(run_id)
    classification_path = classification_attempt / build_classify.RESULT
    classification = read_json(classification_path)
    index_ref = classification['index']
    index_path = build_index.root(run_id) / 'attempts' / identifier(index_ref['attempt_id']) / 'build-index.json'
    index = read_json(index_path)
    return {'job': JOB, 'target_root': str(target),
            'source_snapshot_sha256': 'sha256:' + index['source_fingerprint'],
            'source_revision': classification['source_revision'],
            'upstream': {'classification': {'job': build_classify.JOB, 'attempt_id': classification_attempt.name,
                                            build_classify.RESULT: file_hash(classification_path)},
                         'index': {'job': build_index.JOB, 'attempt_id': index_ref['attempt_id'],
                                   'build-index.json': file_hash(index_path)}},
            'catalog': file_hash(CATALOG_PATH),
            'code': _code_hashes()}


def _accepted_upstreams(run_id, record):
    up = record['upstream']
    cpath = (build_classify.root(run_id) / 'attempts' / identifier(up['classification']['attempt_id'])
             / build_classify.RESULT)
    ipath = build_index.root(run_id) / 'attempts' / identifier(up['index']['attempt_id']) / 'build-index.json'
    if not cpath.is_file() or file_hash(cpath) != up['classification'][build_classify.RESULT]:
        raise Blocked(f'{JOB}: the accepted classification changed since the attempt inputs were recorded')
    if not ipath.is_file() or file_hash(ipath) != up['index']['build-index.json']:
        raise Blocked(f'{JOB}: the accepted build index changed since the attempt inputs were recorded')
    if file_hash(CATALOG_PATH) != record['catalog']:
        raise Blocked(f'{JOB}: the buildenv catalog changed since the attempt inputs were recorded')
    refs = ({'attempt_id': up['index']['attempt_id'], 'sha256': up['index']['build-index.json']},
            {'attempt_id': up['classification']['attempt_id'], 'sha256': up['classification'][build_classify.RESULT]})
    return cpath, read_json(cpath), ipath, read_json(ipath), refs


def unit_request(classification, unit_id):
    """The orchestrator-written plan-unit.json: the one unit this call plans, from the classification."""
    unit = next(u for u in classification['units'] if u['unit_id'] == unit_id)
    return {'schema': 'appsec-review/plan-unit/1', 'unit_id': unit_id, 'index_unit_id': unit['index_unit_id'],
            'root': unit['root'], 'class': unit['class'], 'languages': unit['languages'],
            'signal_ids': unit['signal_ids'],
            'toolchain': 'fixed by the orchestrator: clang (LLVM 21.1.0); do not choose a compiler'}


def _stage_unit_upstreams(base, record, cpath, ipath, classification, unit_id):
    """plan-unit.json is written once per content under plan-units/ and staged with the three
    accepted upstreams into one content-addressed directory (the call's second readable root)."""
    payload = (json.dumps(unit_request(classification, unit_id), indent=2, sort_keys=True) + '\n').encode('utf-8')
    unit_sha = digest(payload.decode('utf-8'))
    unit_path = base / 'plan-units' / f'{unit_sha[:16]}.json'
    if not unit_path.is_file():
        atomic_bytes(unit_path, payload)
    up = record['upstream']
    return discovery_gate._stage_upstream_files(base, {
        'build-index.json': (ipath, up['index']['build-index.json']),
        build_classify.RESULT: (cpath, up['classification'][build_classify.RESULT]),
        CATALOG_FILE: (CATALOG_PATH, record['catalog']),
        UNIT_FILE: (unit_path, file_hash(unit_path)),
    })


def _fill_known(classification):
    """Orchestrator-known fields (finalize overwrites them anyway) filled before schema checks, so a
    null source_revision never costs a repair round (freeciv21: both units)."""
    def fill(envelope, field):
        value = envelope.get(field)
        if isinstance(value, dict):
            for key in ('source_revision', 'target'):
                if not isinstance(value.get(key), str) and isinstance(classification.get(key), str):
                    value[key] = classification[key]
    return fill


def dispatch_unit(run_id, base, record, attempt_id, n, unit_id, cpath, ipath, classification):
    """One live persona invocation for one unit. Returns (value, summary_text, pinned, persona_attempt_id).
    Raises RuntimeError when the invocation did not complete OK: nothing is published from it."""
    upstream_dir = _stage_unit_upstreams(base, record, cpath, ipath, classification, unit_id)
    persona_attempt_id = f'{attempt_id}u{n}'
    persona_attempt = base / 'persona-attempts' / persona_attempt_id
    persona_attempt.mkdir(parents=True)
    target_root = Path(record['target_root'])
    snapshot = record['source_snapshot_sha256']

    mvr.resolve_run_model_versions(run_id)
    template = ppa.load_job_template(JOB, SchemaStore())
    budget_name = template.get('budget_default')
    resolved_model = rc.resolve_model(JOB, budget_name)
    budget_usd = (rc.load_model_config().get('budget_max_usd_per_call') or {}).get(budget_name)

    def clock():
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    request = pd.build_request(JOB, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=persona_attempt_id,
                               target_root=target_root, source_snapshot_sha256=snapshot, now=clock(),
                               upstream_root=upstream_dir)
    model_identity = request['model']
    runtime = pi.PersonaRuntime(
        invoker=ClaudeCliInvoker(effort=resolved_model['effort'], budget_usd=budget_usd,
                                 fill_result=_fill_known(classification)),
        registry_dir=pd.REGISTRY_DIR, prompt_root=ppa.PROMPT_ROOT,
        readable_roots={pd.DEFAULT_READABLE_ROOT: target_root, pd.UPSTREAM_ROOT_ID: upstream_dir},
        allowed_models=(model_identity,), source_snapshot_sha256=snapshot,
        registry_ceiling=None, clock=clock, cancel=threading.Event(), stop_grace_seconds=5)
    result = pi.run_invocation(runtime, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=persona_attempt_id,
                               attempt_root=persona_attempt, request=request)
    if result['execution_status'] != 'OK':
        raise RuntimeError(
            f'{JOB}: persona dispatch for {unit_id} did not complete OK (execution_status='
            f'{result.get("execution_status")}, cause={result.get("cause")}, outcome={result.get("outcome")}); '
            f'see persona-attempts/{persona_attempt_id}/logs/persona')
    output_root = persona_attempt / Path(*request['output_root'].split('/'))
    value = read_json(output_root / RESULT)
    summary = (output_root / SUMMARY).read_text(encoding='utf-8')
    pinned = {e['path']: e['sha256'] for e in request['readable_inputs'] if e['root'] == pd.DEFAULT_READABLE_ROOT}
    return value, summary, pinned, persona_attempt_id, model_identity, result['result_sha256']


def _validate_attempt(run_id, attempt, record):
    if read_json(attempt / 'inputs.json') != record:
        raise Blocked(f'{JOB}: immutable attempt inputs changed')
    _cpath, classification, _ipath, index, (index_ref, classification_ref) = _accepted_upstreams(run_id, record)
    value = read_json(attempt / RESULT)
    errors = check(value, classification, index, read_json(CATALOG_PATH), index_ref=index_ref,
                   classification_ref=classification_ref, source_revision=record['source_revision'])
    errors += vjo._citation_errors(value, Path(record['target_root']))
    if errors:
        raise Blocked(f'{JOB}: build plan is invalid: ' + '; '.join(errors[:20]))


def run(run_id, dagster_id, force=False, dispatch=None):
    """``dispatch`` (tests only) replaces the live per-unit persona call."""
    base = root(run_id)
    resume = f'python -B appsec-review-process/launch_job.py --run-id {run_id} --job build_plan --wait'
    dispatch = dispatch or dispatch_unit

    def execute_attempt(allocation, record, fingerprint):
        attempt, attempt_id, started = allocation['attempt'], allocation['attempt_id'], allocation['started_at']
        cpath, classification, ipath, index, (index_ref, classification_ref) = _accepted_upstreams(run_id, record)
        catalog = read_json(CATALOG_PATH)
        template = read_json(ROOT / 'registry' / 'job-templates' / f'{JOB}.json')
        composition = template['composition']
        common = {'process': '02-evidence-pregather', 'budget': template.get('budget_default'),
                  'persona_id': composition['persona_id'], 'role_id': composition['role_id'],
                  'domain_id': composition['domain_id'], 'tooling_profile_id': composition['tooling_profile_id'],
                  'source_revision': record['source_revision'], 'run_id': run_id, 'job': JOB,
                  'attempt_id': attempt_id, 'dagster_run_id': dagster_id, 'started_at': started,
                  'fingerprint': fingerprint}
        build_set = list(classification.get('build_set') or [])
        unit_values, unit_summaries, pinned_all, persona = [], [], {}, []
        for n, unit_id in enumerate(sorted(build_set)):
            value, summary, pinned, persona_attempt_id, model_identity, result_sha = dispatch(
                run_id, base, record, attempt_id, n, unit_id, cpath, ipath, classification)
            if not isinstance(value, dict):
                raise ValueError(f'{JOB}: the persona result for {unit_id} is not a JSON object')
            finalize(value, classification=classification, index_ref=index_ref,
                     classification_ref=classification_ref, source_revision=record['source_revision'],
                     pinned=pinned)
            canonicalize_catalog_base(value, catalog)
            errors = check(value, classification, index, catalog, index_ref=index_ref,
                           classification_ref=classification_ref, source_revision=record['source_revision'],
                           expected_units=[unit_id])
            errors += vjo._citation_errors(value, Path(record['target_root']))
            if errors:
                raise ValueError(f'{JOB}: the plan for {unit_id} failed independent validation: '
                                 + '; '.join(errors[:20]))
            unit_values.append(value)
            unit_summaries.append((unit_id, summary))
            pinned_all.update(pinned)
            persona.append({'unit_id': unit_id, 'persona_attempt_id': persona_attempt_id,
                            'persona_result_sha256': result_sha, 'model': dict(model_identity)})
        value = merge(unit_values, classification=classification, index_ref=index_ref,
                      classification_ref=classification_ref, source_revision=record['source_revision'])
        errors = check(value, classification, index, catalog, index_ref=index_ref,
                       classification_ref=classification_ref, source_revision=record['source_revision'])
        if errors:
            raise ValueError(f'{JOB}: the merged plan failed validation: ' + '; '.join(errors[:20]))
        atomic_json(attempt / RESULT, value)
        atomic_bytes(attempt / SUMMARY, summary_of(value, unit_summaries).encode('utf-8'))
        if record['code'] != _code_hashes():
            raise Blocked(f'{JOB}: implementation changed during work')
        gaps = gaps_of(value)
        status = {**common, 'artifacts_read': sorted(pinned_all) + [f'{build_index.JOB}:build-index.json',
                                                                    f'{build_classify.JOB}:{build_classify.RESULT}',
                                                                    CATALOG_FILE],
                  'units': len(value['plans']), 'dispatch_mode': 'automatic' if persona else 'none',
                  'persona_job_id': PERSONA_JOB_ID,
                  'persona_invocations': persona, 'toolchain': TOOLCHAIN['compiler']}
        plans = '; '.join(f'{p["unit_id"]}={p["build_system"]}/tier {p["feasibility"]["tier"]}/'
                          f'{len(p["commands"])} command(s)' for p in value['plans']) or 'none (empty build set)'
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id, worker_kind='persona',
            output_contract=CONTRACT, input_fingerprint=fingerprint, started_at=started,
            execution_status='OK_WITH_GAPS' if gaps else 'OK',
            summary=f'Build plans: {plans}.'[:1000],
            status_record=status, artifact_paths=[RESULT, SUMMARY, 'status.json'], gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, record))

    def on_reuse(admitted):
        atomic_json(data_path(run_id, 'orchestration', 'dagster', dagster_id, JOB + '-reuse.json'),
                    {'status': admitted['envelope']['execution_status'], 'reused': True,
                     'publication_recovered': admitted['recovered_publication'],
                     'producer': admitted['pointer'], 'time': now()})

    def failure_inputs(exc):
        return {'run_id': run_id, 'job': JOB, 'preflight_error': f'{type(exc).__name__}: {exc}',
                'code': _code_hashes()}

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id, worker_kind='persona',
        output_contract=CONTRACT, resume_command=resume, derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: 'sha256:' + digest(value), execute_attempt=execute_attempt,
        preflight_failure_inputs=failure_inputs, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        on_reuse=on_reuse,
        blocked_summary='Build plan preflight did not complete (the classification is not accepted or stale).',
        failed_summary='Build plan was not published.')


def validate(run_id, pointer=None):
    """The accepted attempt directory, re-validated end to end (for 02-build-resolution and the SAT)."""
    base = root(run_id)
    pointer = pointer or read_json(base / 'accepted.json')
    record = current_inputs(run_id)
    attempt, _envelope = validate_published(base, pointer, 'sha256:' + digest(record),
                                            expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, record)
    return attempt


def validate_published_value(attempt_root, value, source_root, run_id):
    """validate_job_output's content check for this contract: locate the classification and index the
    plan names in the owning run, verify their hashes, and run check and citation freshness."""
    if not isinstance(value, dict) or not isinstance(value.get('classification'), dict) \
            or not isinstance(value.get('index'), dict):
        return ['build plan names no classification or index']
    owner = vjo._owning_run_root(Path(attempt_root), run_id)
    if owner is None:
        return ['cannot locate the owning run for the build plan upstreams']
    try:
        cpath = (owner / 'data' / 'jobs' / build_classify.JOB / 'attempts'
                 / identifier(value['classification'].get('attempt_id')) / build_classify.RESULT)
        ipath = (owner / 'data' / 'jobs' / build_index.JOB / 'attempts'
                 / identifier(value['index'].get('attempt_id')) / 'build-index.json')
    except ValueError:
        return ['build plan names an invalid upstream attempt id']
    if not cpath.is_file() or file_hash(cpath) != value['classification'].get('sha256'):
        return ['the classification this plan names is missing or changed']
    if not ipath.is_file() or file_hash(ipath) != value['index'].get('sha256'):
        return ['the build index this plan names is missing or changed']
    errors = check(value, read_json(cpath), read_json(ipath), read_json(CATALOG_PATH),
                   index_ref=value['index'], classification_ref=value['classification'])
    errors += vjo._citation_errors(value, source_root)
    return errors


if __name__ == '__main__':
    import sys
    attempt = validate(sys.argv[1])  # usage: build_plan.py <run_id>
    print(json.dumps({'status': 'PASS', 'attempt': str(attempt)}))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
