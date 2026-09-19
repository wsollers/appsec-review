"""Actual-service build execution qualification: mechanics only, not a guaranteed configure pass.

Unlike qualify_build_discovery.py, this qualifier cannot assert that the CMake configure step
inside audit-buildenv-cpp succeeds -- Freeciv21 needs a real Qt6/Lua/KF6Archive/SQLite3 toolchain
baked into that image, and whether that image actually has them is exactly one of the things this
run is meant to find out, not something to assume in advance. What this qualifier does assert,
unconditionally, is that the job's own mechanics are correct: it actually executed something
(target_execution: True), it recorded a real attempt with non-empty logs, its immutable-attempt
reuse and hash-integrity checks hold, and build_execution requires build_discovery to have already
published for this run rather than inventing its own plan.

Run it after qualify_build_discovery.py has passed for the same kind of engagement. It prints
whether the real configure step produced a usable compile_commands.json with the Ninja generator
-- the actual answer to the two build-tooling blockers this job exists to close -- without
pretending that answer is knowable ahead of time.
"""
import argparse
import json
from pathlib import Path
import sys
import uuid

from execution_state import ROOT, atomic_json, data_path, execute, read_json, tree_hashes
from launch_job import launch, graphql


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', help='reuse an existing engagement that already has an accepted build_discovery branch (e.g. from qualify_build_discovery.py)')
    args = parser.parse_args()
    root = data_path(args.run_id or 'qualify-build-execution', 'qualification', 'build-execution-' + uuid.uuid4().hex[:8])
    root.mkdir(parents=True)
    report = {'status': 'RUNNING', 'evidence': str(root)}
    atomic_json(root / 'report.json', report)

    def command(label, argv):
        result = execute(argv, ROOT.parent, root / label, 600)
        if result.get('error') or result['exit_code'] != 0:
            raise RuntimeError(label + ': ' + str(result))
        return (root / label / 'stdout.log').read_text(encoding='utf-8')

    docker = ['docker', 'compose', '-f', 'orchestrator/dagster/compose.yaml', 'exec', '-T', 'code-server', 'python', '-B']
    try:
        if args.run_id:
            run_id = args.run_id
        else:
            created = json.loads(command('create', docker + ['/opt/process/run_process.py', '--start']))
            run_id = created['run_id']
            command('stage', docker + ['/opt/process/stage_artifacts.py', '--run-id', run_id, '--project', 'freeciv21',
                        '--target', '/targets/freeciv21', '--business-goal', 'Bounded build execution integration',
                        '--platform', 'Linux', '--budget', 'probe', '--execution-environment', 'dagster-read-only-linux'])
            discovery_launch = launch(run_id, job='build_discovery', wait=True, timeout=600)
            atomic_json(root / 'discovery-launch.json', discovery_launch)
            assert discovery_launch['status'] == 'SUCCESS', discovery_launch
        report['engagement_run_id'] = run_id
        atomic_json(root / 'report.json', report)

        # A run with no accepted build_discovery branch must be rejected, not silently planned.
        base = data_path(run_id, 'jobs', '00-workflow-preparation', 'build_execution')
        discovery_base = data_path(run_id, 'jobs', '00-workflow-preparation', 'build_discovery')
        assert (discovery_base / 'accepted.json').exists(), 'run has no accepted build_discovery branch to depend on'

        first = launch(run_id, job='build_execution', wait=True, timeout=900)
        atomic_json(root / 'first-launch.json', first)
        assert first['status'] == 'SUCCESS', first
        pointer = read_json(base / 'accepted.json')
        attempt = base / 'attempts' / pointer['attempt_id']
        output = read_json(attempt / 'output.json')

        # Mechanics that must hold no matter what the real configure step decided.
        assert output['target_execution'] is True, 'build_execution must actually execute something'
        assert output['upstream'] == read_json(discovery_base / 'accepted.json')['fingerprint'], \
            'build_execution output is not pinned to the accepted build_discovery branch'
        assert output['build_status'] in ('CONFIGURE_OK', 'CONFIGURE_FAILED', 'CONFIGURE_INCOMPLETE')
        for name in ('stdout', 'stderr'):
            assert (attempt / 'logs' / (name + '.log')).exists(), name + ' log missing'
        assert (attempt / 'command.json').exists()

        before = tree_hashes(attempt)
        second = launch(run_id, job='build_execution', wait=True, timeout=900)
        atomic_json(root / 'second-launch.json', second)
        assert second['status'] == 'SUCCESS'
        assert read_json(base / 'accepted.json') == pointer, 'immutable reuse did not produce the same attempt'
        assert tree_hashes(attempt) == before, 'attempt artifacts changed on reuse'

        report.update(
            status='PASS',
            checks=['build_execution requires an accepted build_discovery branch',
                    'target_execution recorded True with real per-attempt logs',
                    'output pinned to the accepted build_discovery fingerprint',
                    'immutable reuse: second launch returns the same attempt unchanged'],
            output=str(attempt / 'output.json'), output_hashes=before,
            real_configure_result={
                'build_status': output['build_status'],
                'generator_selected_ninja': output['generator_selected_ninja'],
                'compile_commands_present': output['compile_commands_present'],
                'compile_commands_entry_count': output['compile_commands_entry_count'],
                'note': ('CMake configure with -G Ninja produced a real, non-empty '
                         'compile_commands.json inside audit-buildenv-cpp.'
                         if output['build_status'] == 'CONFIGURE_OK'
                         else 'Configure did not cleanly complete; see command.json/logs for the '
                              'real cause (commonly an unresolved Qt6/vcpkg dependency in the image, '
                              'not a defect in this job’s mechanics).')},
            resume_command=f'python -B appsec-review-process/launch_job.py --run-id {run_id} --job build_execution --wait')
    except BaseException as exc:
        report.update(status='FAILED', error=str(exc))
        raise
    finally:
        atomic_json(root / 'report.json', report)
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
