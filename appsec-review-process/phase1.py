"""Stateful Phase 1 adapter shared by CLI, Dagster, staging, and handoffs."""
from __future__ import annotations
import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import shlex
import subprocess
import sys
import threading
import time
import uuid

from execution_state import (ROOT, RUNS, Blocked, Lock, atomic_json, atomic_bytes, beneath, data_path,
                             digest, emergency, event, execute, file_hash, identifier, now,
                             read_json, run_path, tree_hashes)
from intake import source_identity, validate_intake, git
from job_graph import composition, definition_hash, dependency_ok, descendants, load_graph, mermaid

JOB = '00-intake'
LANE = '00-intake-recovery'


def worker_argv(job, attempt):
    # Registry selects a trusted worker contract, never arbitrary target code or shell text.
    if job.get('execution') != {'worker':'intake.py','arguments':['{attempt_root}']}:
        raise Blocked('unsupported intake worker configuration')
    return [sys.executable, '-B', str(ROOT / job['execution']['worker']), str(attempt)]


def resume_argv(run_id, action='intake'):
    return [sys.executable, '-B', str(ROOT/'phase1.py'), action, '--run-id', identifier(run_id)]


def resume_command(run_id, action='intake'):
    argv = resume_argv(run_id, action)
    return subprocess.list2cmdline(argv) if os.name == 'nt' else shlex.join(argv)


def job_root(run_id, job=JOB, scope='whole'):
    return data_path(run_id, 'jobs', identifier(job), identifier(scope))


def manifest_path(run_id):
    return beneath(run_path(run_id), run_path(run_id) / 'inputs/artifact-manifest.json')


def config_for(run_id):
    manifest = read_json(manifest_path(run_id))
    if manifest.get('orchestration_version') != 1:
        raise Blocked('legacy run is read-only to Phase 1; create a new run and explicitly import evidence')
    config = manifest['intake_config']
    if config.get('executor_platform') != os.name:
        raise Blocked('run is bound to its original execution platform; create a new run for another host/OS')
    return config


def current_inputs(run_id, job, config):
    identity = source_identity(config['target'])
    imported = config.get('imports', [])
    for record in imported:
        path = data_path(run_id, record['path'])
        if tree_hashes(path) != record['hashes']:
            raise Blocked('import hash mismatch: ' + record['path'])
    validate_supplied(run_id, config, 'intake')
    git_tool=None
    if identity['revision'] != 'unversioned':
        binary=shutil.which('git')
        if not binary:
            raise Blocked('Git metadata tool is unavailable')
        git_tool={'version':git(config['target'],'--version'),'executable_sha256':file_hash(binary)}
    dependencies = []
    graph = load_graph()
    for dep in graph['jobs'][job['job_template_id']]['dependencies']:
        result = accepted(run_id, dep['job'], fresh=True)
        dependency_ok(dep, result)
        dependencies.append({'dependency':dep,'accepted':result})
    return {'source':identity, 'config':config, 'definition_hash':definition_hash(job),
            'dependencies':dependencies,
            'supplied_artifacts':tree_hashes(data_path(run_id, config['engagement_relative'])),
            'tool':{'python':sys.version, 'executable_sha256':file_hash(sys.executable), 'git':git_tool,'worker':'trusted-read-only-intake-v1'}}


def accepted(run_id, job=JOB, scope='whole', fresh=True):
    base = job_root(run_id, job, scope)
    if not (base / 'accepted.json').exists():
        return None
    pointer = read_json(base / 'accepted.json')
    if pointer.get('status') not in ('OK','SKIPPED'):
        return None
    latest = read_json(base / 'latest.json')
    if pointer['attempt_id'] != latest['attempt_id']:
        raise Blocked('accepted pointer is not latest attempt')
    attempt = beneath(base, base / 'attempts' / identifier(pointer['attempt_id']))
    status = read_json(attempt / 'status.json')
    if status['status'] != pointer['status'] or pointer['status_sha256'] != file_hash(attempt / 'status.json'):
        raise Blocked('accepted attempt status invalid')
    hashes = tree_hashes(attempt)
    hashes.pop('status.json', None)
    if hashes != pointer['hashes']:
        raise Blocked('accepted artifact hash mismatch')
    if pointer['status'] == 'SKIPPED':
        if not pointer.get('reason') or pointer['reason'] != status.get('reason'):
            raise Blocked('skip requires matching auditable reason')
    elif job == JOB:
        inputs = read_json(attempt / 'inputs.json')
        source = read_json(attempt / 'evidence/source.json')
        validate_intake(read_json(attempt / 'outputs/intake.json'), source, inputs['config'])
        if fresh:
            template = read_json(ROOT / 'registry/job-templates/00-intake.json')
            live = current_inputs(run_id, template, config_for(run_id))
            if digest(live) != pointer['fingerprint']:
                raise Blocked('accepted intake is stale; rerun intake')
    return pointer


def invalidate(run_id, graph, job, reason):
    # Caller owns publication lock. Invalidation is a pointer tombstone; attempts stay intact.
    for name in [job, *descendants(graph, job)]:
        root = data_path(run_id, 'jobs', name)
        if root.exists():
            for path in root.glob('*/accepted.json'):
                beneath(data_path(run_id), path)
                prior = read_json(path)
                if prior.get('status') == 'OK':
                    atomic_json(path, {'status':'INVALIDATED','reason':reason,'prior_attempt':prior['attempt_id'],'time':now()})


def sync_state(run_id, state, message, attempt_id='', dagster_id=''):
    """Canonical writer; invoked under run publication lock."""
    root = run_path(run_id)
    data = read_json(root / 'run-status.json')
    budget = read_json(manifest_path(run_id)).get('intake_config',{}).get('budget','probe')
    completed = [p for p in data.get('completed_processes', []) if p != LANE]
    if state == 'OK':
        completed.append(LANE)
    resume = '02-evidence-pregather' if state == 'OK' else LANE
    action = 'handoff' if state == 'OK' else 'intake'
    command = resume_command(run_id, action)
    data.update(status='READY' if state == 'OK' else state, current_process=resume, resume_from=resume,
                failed_process=None if state == 'OK' else LANE, completed_processes=completed,
                updated_at=now(), last_message=message, rerun_command=command, rerun_argv=resume_argv(run_id, action),
                phase1_status=state, phase1_attempt_id=attempt_id, dagster_run_id=dagster_id, default_budget=budget)
    # Recovery authority is the attempt + accepted pointer. Compatibility views are repairable.
    atomic_json(root / 'processes' / LANE / 'status.json', {'process':LANE,'status':state,'run_id':run_id,
                'attempt_id':attempt_id,'dagster_run_id':dagster_id,'message':message,'budget':budget,'rerun_command':command})
    atomic_json(root / 'run-status.json', data)
    atomic_bytes(root / 'run-status.md', (f'# AppSec run {run_id}\n\nStatus: {data["status"]}\nIntake: {state}\n'
                 f'Resume: {resume}\nCommand: `{command}`\n\n{message}\n').encode())


class Session:
    """One job attempt; job lock remains held across visible validation/work ops."""
    def __init__(self, run_id, force=False, dagster_id='', cancel=None, observer=None, command=None, timeout=None):
        self.run_id = identifier(run_id); self.force = force; self.dagster_id = dagster_id
        self.cancel = cancel or threading.Event(); self.observer = observer
        self.command = command; self.timeout = timeout
        self.base = job_root(run_id); self.attempt = None; self.reused = False; self.finished = False
        self.audit = None
        self.job_lock = Lock(self.base / 'job.lock'); self.held = False

    def publication(self):
        return Lock(data_path(self.run_id, 'publication.lock'))

    def __enter__(self):
        self.job_lock.__enter__(); self.held = True
        return self

    def __exit__(self, typ, exc, tb):
        try:
            if not self.finished and (self.attempt or self.audit):
                self.fail(exc or RuntimeError('worker ended before publication'))
        finally:
            if self.held:
                self.job_lock.__exit__(typ, exc, tb); self.held = False

    def phase(self, name, fn):
        directory = (self.audit or self.attempt) / 'validation' / name
        directory.mkdir(parents=True, exist_ok=True)
        for stream in ('stdout.log','stderr.log'):
            (directory / stream).touch()
        started = now()
        try:
            result = fn()
            status, message = 'OK', name + ' passed'
            atomic_bytes(directory / 'stdout.log', (message + '\n').encode())
            return result
        except BaseException as exc:
            status, message = 'BLOCKED' if isinstance(exc, Blocked) else 'FAILED', str(exc)
            atomic_bytes(directory / 'stderr.log', (message + '\n').encode())
            raise
        finally:
            atomic_json(directory / 'status.json', {'status':status,'message':message,'started_at':started,'ended_at':now(),
                'run_id':self.run_id,'job_id':JOB+'-'+name,'attempt_id':self.result['attempt_id'] if self.reused else self.attempt.name,'dagster_run_id':self.dagster_id,
                'composition':self.validator['composition'],'bootstrap_contract':'trusted-nonrecursive-v1'})

    def configure(self):
        self.graph = load_graph()
        self.job = read_json(ROOT / 'registry/job-templates/00-intake.json')
        self.validator = read_json(ROOT / 'registry/job-templates' / (self.graph['validator_template']+'.json'))
        composition(self.job); composition(self.validator)
        return {'config':config_for(self.run_id),'job':self.job,'validator':self.validator,
                'definition_hash':definition_hash(self.job),
                'argv_template':worker_argv(self.job, '{attempt_root}')}

    def prepare(self):
        if not self.held:
            raise RuntimeError('job lock must span validation/work/publication')
        self.configure()
        # Recover only after acquiring the OS lock; a live owner cannot be displaced.
        if (self.base / 'latest.json').exists():
            old = read_json(self.base / 'latest.json')
            prior = beneath(self.base, self.base / 'attempts' / identifier(old['attempt_id']))
            state = read_json(prior / 'status.json') if (prior / 'status.json').exists() else {'status':'RUNNING'}
            if state['status'] in ('RUNNING','PREPARING','STAGED'):
                state.update(status='FAILED', cause='INTERRUPTED_WORKER', ended_at=now(), recovered_by_pid=os.getpid())
                atomic_json(prior / 'status.json', state)
                with self.publication():
                    invalidate(self.run_id, self.graph, JOB, 'interrupted prior attempt')
                    sync_state(self.run_id, 'FAILED', 'Recovered interrupted worker; old output is not reusable', prior.name, self.dagster_id)
        config = config_for(self.run_id)
        try:
            candidate = accepted(self.run_id, fresh=True) if not self.force else None
        except (Blocked, ValueError, KeyError, OSError):
            candidate = None
        if candidate:
            self.reused = True; self.result = candidate
            self.audit = beneath(self.base,self.base / 'reuses' / uuid.uuid4().hex[:12])
            self.audit.mkdir(parents=True)
            self.phase('pre',lambda:candidate)
            return candidate
        attempt_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:12]
        self.attempt = beneath(self.base, self.base / 'attempts' / attempt_id)
        self.status = {'status':'PREPARING','run_id':self.run_id,'job_id':JOB,'scope_id':'whole', 'attempt_id':attempt_id,
                       'dagster_run_id':self.dagster_id,'started_at':now(),'pid':os.getpid(),'host':socket.gethostname(),
                       'budget':config['budget'],'composition':self.job['composition'],'retry_policy':self.job['retry'],
                       'rerun_command':resume_command(self.run_id),'rerun_argv':resume_argv(self.run_id)}
        with self.publication():
            invalidate(self.run_id, self.graph, JOB, 'new attempt reserved ' + attempt_id)
        for directory in ('evidence','extracted','build','outputs','validation','logs'):
            (self.attempt / directory).mkdir(parents=True, exist_ok=False)
        atomic_json(self.attempt / 'status.json', self.status)
        with self.publication():
            invalidate(self.run_id, self.graph, JOB, 'new attempt ' + attempt_id)
            atomic_json(self.base / 'latest.json', {'attempt_id':attempt_id})
            sync_state(self.run_id, 'RUNNING', 'Intake pre-validation', attempt_id, self.dagster_id)
        def check():
            if not config['business_goal'].strip() or not config['platforms'] or config['budget'] not in ('probe','standard','full'):
                raise Blocked('goal, platforms and valid budget required')
            if 'read-source' not in config['permissions'] or not config['execution_environment']:
                raise Blocked('read-source permission and execution environment required')
            if not config['include']:
                raise Blocked('scope includes cannot be empty')
            self.inputs = current_inputs(self.run_id, self.job, config)
            self.fingerprint = digest(self.inputs)
            atomic_json(self.attempt / 'inputs.json', {'config':config,'fingerprint':self.fingerprint,
                'definition_hash':self.inputs['definition_hash'],'tool':self.inputs['tool'],'dependencies':self.inputs['dependencies'],
                'composition':self.job['composition'],'data_root':str(data_path(self.run_id))})
            atomic_json(self.attempt / 'evidence/source.json', self.inputs['source'])
            if self.cancel.is_set():
                raise InterruptedError('cancelled before work')
        try:
            self.phase('pre', check)
            self.status['status'] = 'RUNNING'; atomic_json(self.attempt / 'status.json', self.status)
        except BaseException as exc:
            self.fail(exc); raise
        return {'attempt_id':attempt_id}

    def work(self):
        if self.reused:
            logs=self.audit/'logs'; logs.mkdir()
            atomic_bytes(logs/'stdout.log',b'Validated reuse; no work invoked.\n')
            atomic_bytes(logs/'stderr.log',b'')
            event(logs/'events.jsonl','REUSE',producer_attempt_id=self.result['attempt_id'],dagster_run_id=self.dagster_id)
            return self.result
        try:
            command = self.command or worker_argv(self.job, self.attempt)
            env = {k:v for k,v in os.environ.items() if k.upper() in ('PATH','SYSTEMROOT','WINDIR','LANG','LC_ALL')}
            temporary = self.attempt / 'extracted/tmp'; temporary.mkdir()
            env.update(PYTHONDONTWRITEBYTECODE='1', APPSEC_RUN_ID=self.run_id,
                       APPSEC_ATTEMPT_ROOT=str(self.attempt), APPSEC_DATA_ROOT=str(data_path(self.run_id)),
                       TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary))
            result = execute(command, self.attempt, self.attempt / 'logs', self.timeout or self.job['timeout_seconds'],
                             self.cancel, env, self.observer)
            self.status['execution'] = result
            if result.get('error') or result['exit_code'] != 0:
                raise RuntimeError('work failed: ' + json.dumps(result))
            self.status['status'] = 'STAGED'
            atomic_json(self.attempt / 'status.json', self.status)
            return {'attempt_id':self.attempt.name}
        except BaseException as exc:
            self.fail(exc); raise

    def publish(self):
        if self.reused:
            try:
                result=self.phase('post',lambda:accepted(self.run_id))
                if result is None:
                    raise Blocked('accepted output invalidated during reuse')
                with self.publication():
                    event(data_path(self.run_id,'events.jsonl'),'REUSE',job_id=JOB,attempt_id=result['attempt_id'],dagster_run_id=self.dagster_id)
                    sync_state(self.run_id,'OK','Validated reuse; work not invoked',result['attempt_id'],self.dagster_id)
                    atomic_json(self.audit/'status.json',{'status':'OK','producer_attempt_id':result['attempt_id'],'dagster_run_id':self.dagster_id})
                self.finished=True
                return result
            except BaseException as exc:
                self.fail(exc);raise
        try:
            def check():
                if self.status['status'] != 'STAGED':
                    raise Blocked('work has not completed')
                live = current_inputs(self.run_id, self.job, config_for(self.run_id))
                if digest(live) != self.fingerprint:
                    raise Blocked('source/config/code changed during execution; reject mixed-revision output')
                result = read_json(self.attempt / 'outputs/intake.json')
                validate_intake(result, self.inputs['source'], self.inputs['config'])
                for file in ('intake.json','build-discovery.md'):
                    if not (self.attempt / 'outputs' / file).is_file():
                        raise ValueError('missing output ' + file)
                tree_hashes(self.attempt)  # Reject linked output before publication.
                if self.cancel.is_set():
                    raise InterruptedError('cancelled before publication')
            self.phase('post', check)
            self.status.update(status='OK',ended_at=now(),fingerprint=self.fingerprint,validation='OK')
            atomic_json(self.attempt / 'status.json', self.status)
            hashes = tree_hashes(self.attempt); hashes.pop('status.json')
            pointer = {'status':'OK','run_id':self.run_id,'job_id':JOB,'scope_id':'whole','attempt_id':self.attempt.name,
                       'fingerprint':self.fingerprint,'hashes':hashes,'status_sha256':file_hash(self.attempt / 'status.json'),
                       'contract':'intake','dagster_run_id':self.dagster_id,'published_at':now()}
            with self.publication():
                manifest = read_json(manifest_path(self.run_id))
                result = read_json(self.attempt / 'outputs/intake.json')
                manifest.update(source_identity={'revision':result['source_revision'],'fingerprint':result['source_fingerprint']},
                    build_discovery={'path':str(self.attempt / 'outputs/build-discovery.md'),'sha256':hashes['outputs/build-discovery.md'],'producer_attempt_id':self.attempt.name},
                    selected_jobs=result['selected_jobs'],accepted_intake=pointer,
                    partition_artifacts=[],specialist_artifacts=[])
                atomic_json(manifest_path(self.run_id), manifest)
                sync_state(self.run_id, 'OK', 'Intake validated; pregather planned, not executed', self.attempt.name, self.dagster_id)
                event(data_path(self.run_id, 'events.jsonl'), 'ACCEPTED', attempt_id=self.attempt.name, dagster_run_id=self.dagster_id)
                # Final commit point. Every required diagnostic and compatibility view is
                # durable before an accepted pointer can become visible.
                atomic_json(self.base / 'accepted.json', pointer)
            self.finished = True; self.result = pointer
            return pointer
        except BaseException as exc:
            self.fail(exc); raise

    def fail(self, exc):
        if self.finished:
            return
        state = 'BLOCKED' if isinstance(exc, Blocked) else 'FAILED'
        try:
            if self.reused:
                with self.publication():
                    invalidate(self.run_id,self.graph,JOB,'reuse validation/logging failed: '+str(exc))
                    sync_state(self.run_id,state,str(exc),self.result['attempt_id'],self.dagster_id)
                atomic_json(self.audit/'status.json',{'status':state,'error':str(exc),'producer_attempt_id':self.result['attempt_id']})
            if self.attempt:
                # A failed commit never leaves an accepted pointer visible.
                with self.publication():
                    invalidate(self.run_id, self.graph, JOB, str(exc))
                    sync_state(self.run_id, state, str(exc), self.attempt.name, self.dagster_id)
                self.status.update(status=state,ended_at=now(),error=f'{type(exc).__name__}: {exc}',
                                   cancelled=isinstance(exc,(InterruptedError,KeyboardInterrupt)))
                atomic_json(self.attempt / 'status.json', self.status)
                event(self.attempt / 'logs/events.jsonl', 'FAILURE', error=str(exc), status=state)
        except BaseException as io:
            emergency(io)
        self.finished = True


def run_intake(run_id, **kwargs):
    with Session(run_id, **kwargs) as session:
        session.prepare(); session.work()
        return session.publish(), session.reused


def import_tree(run_id, origin):
    origin = Path(origin).resolve(strict=True)
    hashes = tree_hashes(origin)  # Reject symlink escapes; imports never mutate the source.
    import_id = uuid.uuid4().hex
    dest = data_path(run_id, 'imports', import_id)
    dest.mkdir(parents=True)
    for relative, h in hashes.items():
        target = beneath(dest, dest / relative); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin / relative, target)
        if file_hash(target) != h:
            raise Blocked('import source changed during copy')
    if tree_hashes(origin) != hashes:
        raise Blocked('import source changed during copy')
    record = {'path':f'imports/{import_id}','origin':str(origin),'hashes':hashes,'imported_at':now()}
    atomic_json(data_path(run_id, 'imports', import_id + '.json'), record)
    return record


CORE = {'job_status_md':'job-status.md','job_status_json':'job-status.json','job_manifest_jsonl':'job-manifest.jsonl',
        'llm_input_md':'llm/ENGAGEMENT_LLM_INPUT.md','coverage_ledger_json':'llm/coverage-ledger.json',
        'correlated_findings_json':'llm/correlated-findings.json','deep_confirmation_json':'llm/deep-confirmation.json',
        'retrieval_plan_json':'llm/retrieval-plan.json'}


def validate_supplied(run_id, config, phase):
    out = data_path(run_id, config['engagement_relative'])
    missing = []
    for relative in CORE.values():
        path = beneath(data_path(run_id), out / relative)
        if not path.exists():
            missing.append(relative); continue
        if relative.endswith('.json'):
            value = read_json(path)
            if not isinstance(value, dict) or not value:
                raise ValueError('malformed/empty supplied artifact ' + relative)
            if relative == 'job-status.json' and value.get('status') != 'OK':
                raise Blocked('supplied pregather job status is not OK')
        elif relative.endswith('.jsonl'):
            lines = path.read_text(encoding='utf-8-sig').splitlines()
            if not any(line.strip() for line in lines):
                raise ValueError('empty job manifest')
            for line in lines:
                if line.strip() and not isinstance(json.loads(line), dict):
                    raise ValueError('invalid job manifest row')
        elif not path.read_text(encoding='utf-8-sig').strip():
            raise ValueError('empty supplied artifact ' + relative)
    if phase == 'pregather' and missing:
        raise Blocked('post-pregather missing required artifacts: ' + ', '.join(missing))
    return missing


def stage(run_id, target, project, business_goal, platforms, budget='probe', include=None, exclude=None,
          permissions=None, execution_environment='local-read-only', engagement_output='', import_legacy=False, compile_db=''):
    root = run_path(run_id)
    if not (root / 'run-status.json').exists():
        raise Blocked('create the run through run_process.py --start first')
    path = manifest_path(run_id); previous = read_json(path)
    if previous.get('intake_config',{}).get('executor_platform',os.name) != os.name:
        raise Blocked('cannot restage a run owned by another execution platform')
    if previous.get('run_id') not in ('',None,run_id):
        raise Blocked('manifest run identity mismatch')
    if previous.get('orchestration_version') != 1 and (previous.get('engagement_output') or previous.get('target',{}).get('repo_path')):
        raise Blocked('preserve legacy populated run; start a new run for explicit import')
    with Lock(data_path(run_id, 'publication.lock')):
        imports = list(previous.get('intake_config',{}).get('imports',[]))
        if engagement_output:
            external = Path(engagement_output).resolve()
            try:
                out = beneath(data_path(run_id), external)
            except ValueError:
                if not import_legacy:
                    raise Blocked('external evidence requires --import-legacy into a new run')
                record = import_tree(run_id, external); imports.append(record)
                out = data_path(run_id, record['path'])
        else:
            out = data_path(run_id, 'pending-evidence')
        compile_record = None
        if compile_db:
            cp = Path(compile_db).resolve(strict=True)
            value = read_json(cp)
            if not isinstance(value,list) or not value or any(not isinstance(x,dict) or not {'file','directory'} <= x.keys() or not ('command' in x or 'arguments' in x) for x in value):
                raise ValueError('invalid compile database')
            dest = data_path(run_id,'imports',uuid.uuid4().hex,'compile_commands.json')
            atomic_bytes(dest,cp.read_bytes())
            compile_record={'origin':str(cp),'path':dest.relative_to(data_path(run_id)).as_posix(),'sha256':file_hash(dest)}
        config = {'target':str(Path(target).resolve(strict=True)),'project':project,'business_goal':business_goal,
            'platforms':platforms,'budget':budget,'include':include or ['**'],'exclude':exclude or [],
            'permissions':permissions if permissions is not None else ['read-source'],'execution_environment':execution_environment,
            'engagement_relative':out.relative_to(data_path(run_id)).as_posix(),'imports':imports,'compile_database':compile_record,'executor_platform':os.name}
        if compile_record:
            imports.append({'path':str(Path(compile_record['path']).parent).replace('\\','/'),'origin':str(Path(compile_record['origin']).parent),
                            'hashes':{'compile_commands.json':compile_record['sha256']}})
        missing = validate_supplied(run_id, config, 'intake')
        supplied_hashes = {k:file_hash(out/v) for k,v in CORE.items() if (out/v).exists()}
        changed = previous.get('intake_config') != config or previous.get('artifact_hashes') != supplied_hashes
        if changed:
            invalidate(run_id, load_graph(), JOB, 'restaged inputs')
            for key in ('build_discovery','accepted_intake','source_identity','selected_jobs'):
                previous.pop(key,None)
            previous['invalidated_derived_artifacts'] = previous.get('derived_artifacts',{})
            previous['derived_artifacts'] = {}; previous['partition_artifacts'] = []; previous['specialist_artifacts'] = []
        previous.update(orchestration_version=1,run_id=run_id,project=project,data_root=str(data_path(run_id)),
            intake_config=config,scope={'include':config['include'],'exclude':config['exclude']},engagement_output=str(out),
            target={'repo_path':config['target'],'platforms':platforms,'business_goal':business_goal,
                    'compile_database':str(data_path(run_id,compile_record['path'])) if compile_record else ''},
            core_artifacts={k:str(out/v) if (out/v).exists() else '' for k,v in CORE.items()},
            artifact_hashes=supplied_hashes,
            notes=['Expected before pregather: '+x for x in missing])
        atomic_json(path,previous)
        if changed:
            sync_state(run_id,'READY','Staged intake; missing pregather artifacts expected')
    return previous


def handoff(run_id):
    pointer = accepted(run_id)
    if not pointer:
        raise Blocked('intake acceptance required before pregather handoff')
    attempt = job_root(run_id) / 'attempts' / pointer['attempt_id']
    result = read_json(attempt / 'outputs/intake.json')
    return '\n'.join(['# Validated Phase 1 handoff', '', 'Run: '+run_id, 'Producer attempt: '+pointer['attempt_id'],
        'Intake: '+str(attempt / 'outputs/intake.json'), 'Build plan: '+str(attempt / 'outputs/build-discovery.md'),
        'Source fingerprint: '+result['source_fingerprint'], 'Next: 02-repository-partition-discovery (planned; dispatcher not implemented).',
        'Whole scope and unavailable paths are recorded in intake.json. Do not execute target scripts from this handoff.',
        'All new evidence/build/log paths must be allocated by the adapter beneath this run data root.',
        'No security findings or successful builds are claimed.',
        'Tooling addendum: appsec-review-process/tooling/llm-retrieval-addendum.md',
        'Load skill: appsec-review-process/agent-skills/codex/evidence-retrieval/SKILL.md',
        'Use the evidence_index Dagster job and evidence_store.py search/read/similar commands for this run.',
        'Capability receipts under data/tooling qualify LSP/MCP availability; a catalog entry alone is not proof.', ''])


def pipeline_out(run_id, attempt_id, out, reserve=False):
    """Shared guard for legacy pipeline --out when called with an orchestrated run."""
    root = job_root(run_id, '02-evidence-assembly') / 'attempts' / identifier(attempt_id)
    result = beneath(root, Path(out))
    beneath(data_path(run_id),result)
    if reserve:
        config_for(run_id)
        raise Blocked('02-evidence-assembly is planned, not dispatched by Phase 1; consume the validated partition-discovery handoff first')
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__); sub = p.add_subparsers(dest='action',required=True)
    for name in ('intake','status','handoff','validate-pregather'):
        cmd = sub.add_parser(name); cmd.add_argument('--run-id',required=True)
        if name == 'intake':
            cmd.add_argument('--force',action='store_true'); cmd.add_argument('--dagster-id',default='')
    graph = sub.add_parser('graph'); graph.add_argument('--check',action='store_true')
    guard = sub.add_parser('pipeline-out'); guard.add_argument('--run-id',required=True); guard.add_argument('--attempt-id',required=True); guard.add_argument('--out',required=True); guard.add_argument('--reserve',action='store_true')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == 'intake':
            result,reused = run_intake(args.run_id,force=args.force,dagster_id=args.dagster_id)
            print(json.dumps({'status':'OK','attempt_id':result['attempt_id'],'reused':reused,'run_id':args.run_id})); return 0
        if args.action == 'status':
            recorded = read_json(run_path(args.run_id)/'run-status.json')
            try:
                result = accepted(args.run_id)
            except (Blocked,ValueError,OSError,KeyError) as exc:
                print(json.dumps({'status':'BLOCKED','reason':str(exc),'resume':resume_command(args.run_id)})); return 1
            print(json.dumps({'status':'OK' if result else recorded.get('phase1_status','BLOCKED'),
                              'run_status':recorded['status'],'resume_from':recorded.get('resume_from'),
                              'rerun_command':recorded.get('rerun_command'),'accepted':result},indent=2)); return 0 if result else 1
        if args.action == 'handoff':
            text = handoff(args.run_id)
            path = data_path(args.run_id,'handoffs',uuid.uuid4().hex+'.md'); atomic_bytes(path,text.encode()); print(path); return 0
        if args.action == 'validate-pregather':
            validate_supplied(args.run_id,config_for(args.run_id),'pregather'); return 0
        if args.action == 'pipeline-out':
            print(pipeline_out(args.run_id,args.attempt_id,args.out,args.reserve)); return 0
        if args.action == 'graph':
            text = mermaid(load_graph()); path = ROOT.parent/'docs/design-parity/job-graph.mmd'
            if args.check:
                if path.read_text() != text:
                    raise ValueError('Mermaid differs from machine graph')
            else:
                atomic_bytes(path,text.encode())
            return 0
    except BaseException as exc:
        emergency(exc); return 1


if __name__ == '__main__':
    raise SystemExit(main())
