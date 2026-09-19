"""Bounded, isolated execution of the build-discovery configure step, inside audit-buildenv-cpp.

This is the one job in the lifecycle permitted to set target_execution: True. Everything upstream
(intake, build_discovery) is static citation only and must never execute target code. This job
runs exactly one thing: the CMake *configure* step that build_discovery cited as its proposed
argv, with an explicit -G Ninja generator added, inside the sandboxed buildenv-common wrapper
(no network, read-only workspace, writable scratch, dropped caps). It never runs `cmake --build`
or any target build/link/test command, and it never installs dependencies.

Its output is immutable, hash-verified evidence of whether that configure step produced a real,
non-empty compile_commands.json using the Ninja generator -- the two open questions this job
exists to close: (1) does the discovered build genuinely support Ninja + CMAKE_EXPORT_COMPILE_
COMMANDS, and (2) does that work inside this project's isolated buildenv container, not just on
a bare host.

Architectural note: build_discovery and the other workflow-preparation branches (scope_check,
native_plan_check, discovery_handoffs) are validated by workflow.validate_branch, which recomputes
their pure branch_result() a second time and compares it byte-for-byte against the recorded
output. That model assumes the branch function has no side effects and is cheap to recompute --
true for static citation, false for a real container build. Re-running a CMake configure (let
alone a full build) on every validation call would be slow, and a fresh container run is not
guaranteed to be byte-identical to a prior one (compiler/tool version drift, filesystem ordering).
So this job manages its own immutable-attempt lifecycle directly (see run()/validate() below) and
is verified by hash integrity of the recorded evidence, not by re-execution.
"""
import json
import uuid

from execution_state import (ROOT, Blocked, Lock, atomic_json, data_path, digest, execute, file_hash,
                              identifier, now, read_json, tree_hashes)
from phase1 import config_for
import workflow

WRAPPER = ROOT.parent / 'images' / 'audit-buildenv-common' / 'run.sh'
CONFIGURE_TIMEOUT_SECONDS = 600  # configure only; no target build/link/test runs here.


def root(run_id):
    return data_path(run_id, 'jobs', '00-workflow-preparation', 'build_execution')


def discovered_plan(run_id):
    """Read and re-validate the accepted build_discovery branch. Never trust it unchecked."""
    base = data_path(run_id, 'jobs', '00-workflow-preparation', 'build_discovery')
    if not (base / 'accepted.json').exists():
        raise Blocked('build_discovery has not published an accepted branch for this run; run it first')
    pointer = read_json(base / 'accepted.json')
    attempt = workflow.validate_branch(run_id, 'build_discovery', pointer)
    return pointer, read_json(attempt / 'output.json')


def select_buildenv(output):
    if output.get('readiness') != 'PLAN_REQUIRES_ISOLATED_BUILD_VALIDATION' or not output.get('proposed_argv'):
        raise Blocked('build discovery did not produce an executable plan for this target')
    if output.get('primary_build_file') != 'CMakeLists.txt':
        raise Blocked('only a single unambiguous CMake root is supported by this executor')
    candidates = [c for c in output['buildenv_candidates'] if c['language'] == 'cpp']
    if len(candidates) != 1:
        raise Blocked('expected exactly one cpp buildenv candidate; found ' + str(len(candidates)))
    return candidates[0]


def configure_argv(output):
    """Reuse build_discovery's cited configure command verbatim, adding an explicit generator.

    build_discovery deliberately never names a generator (it only inspects source, it never
    decides how to build). This job is the first one allowed to make that choice, and states it
    explicitly rather than depending on whatever CMake would pick by default in the container.
    """
    configure = list(output['proposed_argv'][0])
    if configure[:1] != ['cmake'] or '-S' not in configure or '-B' not in configure:
        raise Blocked('unrecognized proposed configure command shape: ' + json.dumps(configure))
    if '-G' in configure:
        raise Blocked('proposed configure command already names a generator')
    b_index = configure.index('-B')
    with_generator = configure[:b_index + 2] + ['-G', 'Ninja'] + configure[b_index + 2:]
    return [arg.replace('{run_data}', '/scratch') for arg in with_generator]


def run(run_id, dagster_id, force=False):
    base = root(run_id)
    with Lock(base / 'job.lock'):
        pointer, output = discovered_plan(run_id)
        buildenv = select_buildenv(output)
        argv = configure_argv(output)
        inputs = {'discovery': pointer, 'buildenv': buildenv, 'argv': argv,
                  'code': {name: file_hash(ROOT / name) for name in ('build_execution.py',)}}
        fingerprint = digest(inputs)
        if not force and (base / 'accepted.json').exists():
            candidate = read_json(base / 'accepted.json')
            if candidate.get('fingerprint') == fingerprint:
                try:
                    validate(run_id, candidate)
                    audit = data_path(run_id, 'orchestration', 'dagster', dagster_id, 'build_execution-reuse.json')
                    atomic_json(audit, {'status': 'OK', 'reused': True, 'producer': candidate, 'time': now()})
                    return candidate
                except (ValueError, Blocked, OSError, KeyError):
                    pass
        attempt_id = uuid.uuid4().hex
        attempt = base / 'attempts' / attempt_id
        attempt.mkdir(parents=True)
        status = {'status': 'RUNNING', 'run_id': run_id, 'attempt_id': attempt_id,
                  'dagster_run_id': dagster_id, 'started_at': now(), 'fingerprint': fingerprint}
        atomic_json(base / 'accepted.json', {'status': 'PENDING', 'attempt_id': attempt_id})
        atomic_json(base / 'latest.json', {'attempt_id': attempt_id})
        try:
            atomic_json(attempt / 'status.json', status)
            atomic_json(attempt / 'inputs.json', inputs)
            target = config_for(run_id)['target']
            scratch = attempt / 'build'
            scratch.mkdir()
            wrapper_argv = ['bash', str(WRAPPER), buildenv['image'], target, str(scratch), '--', *argv]
            result = execute(wrapper_argv, ROOT.parent, attempt / 'logs', CONFIGURE_TIMEOUT_SECONDS)
            atomic_json(attempt / 'command.json', result)
            compile_commands = scratch / 'discovery' / 'compile_commands.json'
            generator_selected = (scratch / 'discovery' / 'build.ninja').exists()
            present = compile_commands.exists()
            entries = None
            sha256 = None
            if present:
                sha256 = file_hash(compile_commands)
                try:
                    entries = len(json.loads(compile_commands.read_text(encoding='utf-8')))
                except (ValueError, OSError):
                    entries = None
            failed = bool(result.get('error')) or result['exit_code'] != 0
            if failed:
                build_status = 'CONFIGURE_FAILED'
            elif present and generator_selected:
                build_status = 'CONFIGURE_OK'
            else:
                build_status = 'CONFIGURE_INCOMPLETE'
            value = {'schema': 'appsec-review/build-execution/1', 'branch': 'build_execution',
                     'run_id': run_id, 'target_execution': True,
                     'source_revision': output['source_revision'], 'upstream': pointer['fingerprint'],
                     'buildenv_image': buildenv['image'], 'argv': argv,
                     'configure_exit_code': result['exit_code'], 'configure_timed_out': result['timed_out'],
                     'generator_selected_ninja': generator_selected,
                     'compile_commands_present': present, 'compile_commands_sha256': sha256,
                     'compile_commands_entry_count': entries, 'build_status': build_status,
                     'target_build_executed': False,
                     'limitations': [
                         'Only the CMake configure step runs; no target is compiled or linked.',
                         'Dependency-resolution success is inferred from configure exit code and '
                         'generator/file presence, not from a full build.',
                         'The container has no network access; a dependency that needs network at '
                         'configure time will fail here, which is real signal, not a harness bug.']}
            atomic_json(attempt / 'output.json', value)
            status.update(status='FAILED' if failed else 'OK', ended_at=now())
            atomic_json(attempt / 'status.json', status)
            accepted = {'status': status['status'], 'branch': 'build_execution', 'run_id': run_id,
                        'attempt_id': attempt_id, 'fingerprint': fingerprint,
                        'upstream': pointer['fingerprint'], 'hashes': tree_hashes(attempt)}
            atomic_json(base / 'accepted.json', accepted)
            if failed:
                raise Blocked('configure failed inside buildenv: exit ' + str(result['exit_code']))
            return accepted
        except BaseException as exc:
            try:
                status.update(status='FAILED', error=str(exc), ended_at=now())
                atomic_json(attempt / 'status.json', status)
                atomic_json(base / 'accepted.json', {'status': 'FAILED', 'attempt_id': attempt_id})
            except BaseException:
                pass
            raise


def validate(run_id, pointer):
    """Verify recorded evidence integrity. Never re-runs the container -- see module docstring."""
    base = root(run_id)
    if pointer.get('status') != 'OK':
        raise Blocked('build_execution attempt is not OK')
    attempt = base / 'attempts' / identifier(pointer['attempt_id'])
    if tree_hashes(attempt) != pointer['hashes']:
        raise Blocked('build_execution artifacts changed since acceptance')
    if read_json(attempt / 'status.json')['status'] != 'OK':
        raise Blocked('build_execution attempt did not finish OK')
    output = read_json(attempt / 'output.json')
    if output.get('compile_commands_sha256'):
        compile_commands = attempt / 'build' / 'discovery' / 'compile_commands.json'
        if not compile_commands.exists() or file_hash(compile_commands) != output['compile_commands_sha256']:
            raise Blocked('recorded compile_commands.json evidence changed or is missing')
    return attempt
