"""Versioned static controller with per-block runtime evidence and separate cost."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

import psutil

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from study.static_scan_contract import require, sha, validate, schedule, ordered_profiles, render, normalize
from engineering.static_scanner_host import (ROOT, capture, inventory, utc, write, assert_lease,
    snapshot, preserved, sample, prepare_inputs, verify_inputs, verify_package)
from engineering.static_scanner_assets import verify_locked, DATABASES
from engineering.static_runtime_controls import RuntimeControls
from study.runtime_block_contract import CONTROL_SHA256, load_controls, schedule as runtime_schedule
from study.final_output_adapter import digest


def require_release(release, package, locks_path, plan):
    require(release is not None, 'Scientific scans require the final campaign release')
    data = json.loads(Path(release).read_text())
    require(data.get('protocol') == 'v1.0' and data.get('final_campaign_ready') is True, 'Protocol is not released')
    gates = data.get('gates', [])
    require(len(gates) == 8 and {g['id'] for g in gates} == {f'G{i}' for i in range(1, 9)} and
            all(g['passed'] is True for g in gates), 'Incomplete campaign gates')
    require(data.get('static_package_manifest_sha256') == sha(package / 'package_manifest.json'), 'Package release mismatch')
    require(data.get('static_assets_sha256') == sha(locks_path), 'Asset release mismatch')
    require(data.get('static_profile_ids') == [p['id'] for p in plan['profiles']], 'Profile release mismatch')
    require(data.get('static_schedule_sha256') == sha(package / 'schedule.json'), 'Schedule release mismatch')
    require(data.get('runtime_control_sha256') == CONTROL_SHA256, 'Runtime control release mismatch')
    require(data.get('runtime_schedule_digest') == digest(runtime_schedule()), 'Runtime schedule release mismatch')
    return data


def scanner_environment(phase):
    env = {k: v for k, v in os.environ.items() if k in ('LANG', 'LC_ALL', 'LC_CTYPE', 'HOME', 'USER', 'LOGNAME')}
    env.update(PATH='/usr/local/bin:/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1',
               TMPDIR=str(phase / 'tmp'), XDG_CACHE_HOME=str(phase / 'cache'),
               XDG_CONFIG_HOME=str(phase / 'config'), XDG_DATA_HOME=str(phase / 'data'),
               SEMGREP_SETTINGS_FILE=str(phase / 'semgrep-settings.yml'), SEMGREP_SEND_METRICS='off',
               SEMGREP_ENABLE_VERSION_CHECK='0', CHECKOV_SKIP_MAPPING='TRUE', BC_SKIP_MAPPING='TRUE',
               SYFT_CHECK_FOR_APP_UPDATE='false', SYFT_JAVA_USE_NETWORK='false',
               GRYPE_CHECK_FOR_APP_UPDATE='false', GRYPE_DB_AUTO_UPDATE='false', GRYPE_DB_VALIDATE_AGE='false',
               GRYPE_DB_CACHE_DIR=str(DATABASES['grype']), JAVA_HOME=str(ROOT / 'environment/toolset-20260922-01/jdk'),
               JAVA_OPTS='-Xmx3g', NO_COLOR='1', OMP_NUM_THREADS='4', OPENBLAS_NUM_THREADS='4')
    return env


def container_argv(profile, work, run_id, name, *, preflight=False):
    budget = profile['container_resources']
    out = work / profile['output_directory']
    argv = ['docker', 'create', '--name', name, '--pull', 'never', '--network', 'none', '--read-only',
            '--memory', str(budget['memory_gib']) + 'g', '--memory-swap', str(budget['memory_gib']) + 'g',
            '--cpus', str(budget['cpus']), '--pids-limit', str(budget['pids']),
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--user', str(os.getuid()) + ':' + str(os.getgid()), '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m',
            '--label', 'org.study.project=devsecops-electronics', '--label', 'org.study.run=' + run_id,
            '-e', 'DISABLE_CRASH_REPORT=1', '-v', str(work / profile['input_directory']) + ':/input:ro',
            '-v', str(out) + ':/output:rw']
    if preflight:
        argv += ['--entrypoint', '/bin/true', profile['image']]
    else:
        argv += [profile['image'], *profile['argv']]
    return argv


def validate_container(info, profile, work, run_id):
    host = info['HostConfig']
    resources = profile['container_resources']
    require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host.get('Privileged'), 'Container boundary changed')
    require(not host.get('PortBindings') and host['CapDrop'] == ['ALL'] and not host.get('CapAdd'), 'Container privileges/ports differ')
    require('no-new-privileges:true' in host['SecurityOpt'], 'Missing no-new-privileges')
    require(host['Memory'] == resources['memory_gib'] * 1024**3 and host['MemorySwap'] == host['Memory'] and
            host['NanoCpus'] == resources['cpus'] * 10**9 and host['PidsLimit'] == resources['pids'], 'Container budget differs')
    require(info['Config']['User'] == f'{os.getuid()}:{os.getgid()}', 'Unexpected container account')
    labels = info['Config']['Labels']
    require(labels.get('org.study.project') == 'devsecops-electronics' and labels.get('org.study.run') == run_id, 'Unowned container')
    mounts = {m['Destination']: (m['Source'], m['RW'], m['Type']) for m in info['Mounts'] if m['Type'] != 'tmpfs'}
    require(mounts == {'/input': (str(work / profile['input_directory']), False, 'bind'),
                       '/output': (str(work / profile['output_directory']), True, 'bind')}, 'Unexpected scanner mounts')
    source = (work / profile['input_directory']).resolve()
    target = (work / profile['output_directory']).resolve()
    require(source != target and target not in source.parents and source not in target.parents, 'Writable mount aliases input')


def measured(argv, phase, env, allowed, timeout, accepted):
    require(not (phase / 'receipt.json').exists(), 'Timing receipt already exists')
    receipt = {'argv': argv, 'started_utc': utc(), 'timeout_seconds': timeout, 'accepted_exit_codes': accepted,
               'status': 'running', 'measurement_scope': 'Complete profile invocation including isolation/launcher setup and output writes; input/DB copy and hash checks excluded. Process tree and separate container samples; Docker daemon excluded.'}
    write(phase / 'receipt.json', receipt)
    started, error = time.monotonic(), None
    with (phase / 'stdout').open('w') as stdout, (phase / 'stderr').open('w') as stderr, (phase / 'resources.jsonl').open('w') as samples:
        proc = subprocess.Popen([sys.executable, '-B', str(PACKAGE / 'engineering/process_accounting.py'),
                                 str(phase / 'accounting.json'), *argv], cwd=phase, env=env,
                                stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            while proc.poll() is None:
                require(time.monotonic() - started <= timeout, 'Profile timeout reached')
                row = sample(allowed)
                rss = 0
                try:
                    parent = psutil.Process(proc.pid)
                    for child in [parent, *parent.children(recursive=True)]:
                        try:
                            rss += child.memory_info().rss
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                row.update(elapsed_seconds=time.monotonic() - started, tree_rss_sum_bytes=rss)
                samples.write(json.dumps(row) + '\n'); samples.flush()
                time.sleep(0.5)
        except BaseException as exc:
            error = type(exc).__name__ + ': ' + str(exc)
            subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(proc.pid)], check=False, capture_output=True)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                subprocess.run(['sudo', '-n', 'kill', '-KILL', '--', '-' + str(proc.pid)], check=False, capture_output=True)
                proc.wait(timeout=10)
    receipt.update(finished_utc=utc(), wall_seconds=time.monotonic() - started,
                   exit_code=proc.returncode, interruption=error,
                   status='completed' if error is None and proc.returncode in accepted else 'failed')
    write(phase / 'receipt.json', receipt)
    if error:
        raise RuntimeError(error)
    return receipt


def phase_directory(path):
    path.mkdir(parents=True, exist_ok=False)
    for name in ('tmp', 'cache', 'config', 'data'):
        (path / name).mkdir()


def isolated_command(argv, phase, env, readonly, scratch_gib):
    job = {'argv': argv, 'cwd': str(phase), 'environment': env,
           'readonly': sorted(set(str(Path(p).resolve()) for p in readonly)), 'scratch_gib': scratch_gib}
    write(phase / 'isolation_job.json', job)
    return ['sudo', '-n', 'unshare', '--mount', '--net', '--fork', '--kill-child=SIGKILL', '--', '/usr/bin/python3', '-B',
            str(PACKAGE / 'engineering/aigoat_static/isolate.py'), str(phase / 'isolation_job.json')]


def execute_block(plan, locks, output, run_id, owned, block, outcomes):
    for suite in sorted(plan['suites']):
        config = plan['suites'][suite]
        sample(owned)
        work = output / 'work' / f'b{block}-{suite}'
        reset = prepare_inputs(suite, locks['inputs'][suite], work)
        verify_inputs(locks['inputs'][suite], work)
        reset['verified'] = True
        write(output / 'resets' / f'b{block}-{suite}.json', reset)
        for p in (p for p in ordered_profiles(plan) if p['suite'] == suite):
            job_id = f'b{block}-' + p['id']
            phase = output / 'jobs' / job_id; phase_directory(phase)
            record = {'job_id': job_id, 'profile': p['id'], 'block': block, 'role': p['role']}
            done = {r['job_id'] for r in outcomes if r.get('effective_status') == 'completed'}
            if not {f'b{block}-' + dep for dep in p['requires']} <= done:
                record.update(status='not_run', effective_status='unavailable', reason='Current-block SBOM dependency failed')
                outcomes.append(record); write(output / 'outcomes.json', outcomes); continue
            verify_inputs(locks['inputs'][suite], work)
            env = scanner_environment(phase)
            readonly = [work / item['destination'] for item in locks['inputs'][suite]]
            readonly += [Path(row['source']) for row in locks['runtime']]
            readonly += [Path(row['source']) for row in locks['databases'].values()]
            readonly.append(DATABASES['trivy-db'].parent)
            readonly.append(PACKAGE)
            dependency_inputs = [work / next(other['report'] for other in plan['profiles'] if other['id'] == dep)
                                 for dep in p['requires']]
            dependency_hashes = {str(path): sha(path) for path in dependency_inputs}
            readonly.extend(dependency_inputs)
            argv = render(p, work, phase)
            for value in argv:
                if str(phase / 'database-copies/trivy') == value:
                    for name, suffix in (('trivy-db', 'db'), ('trivy-java', 'java-db')):
                        target = phase / 'database-copies/trivy' / suffix
                        shutil.copytree(locks['databases'][name]['source'], target)
                        require(inventory(target) == locks['databases'][name]['files'], 'Database copy differs')
                if str(phase / 'database-copies/dependency-check') == value:
                    target = phase / 'database-copies/dependency-check'
                    shutil.copytree(locks['databases']['dependency-check']['source'], target)
                    require(inventory(target) == locks['databases']['dependency-check']['files'], 'Database copy differs')
            raw = work / p['report']; raw.parent.mkdir(parents=True, exist_ok=True)
            require(not raw.exists(), 'Native report already exists')
            if p['parser'] == 'kubescape':
                shutil.copytree(work / 'policy-assets', phase / 'policy-assets')
                require(inventory(phase / 'policy-assets') == inventory(work / 'policy-assets'), 'Policy copy differs')
                env['KS_CACHE_DIR'] = str(phase / 'policy-assets')
            write(phase / 'prepared.json', {'reset_sha256': sha(output / 'resets' / f'b{block}-{suite}.json'),
                   'prepared_utc': utc(), 'argv': argv, 'report': str(raw), 'prior_measurement_reused': False})
            if p['kind'] == 'container':
                (work / p['output_directory']).mkdir(parents=True, exist_ok=True)
                create = container_argv(p, work, run_id, run_id + '-' + job_id)
                cid = capture(create); owned.append(cid)
                info = json.loads(capture(['docker', 'inspect', cid]))[0]
                validate_container(info, p, work, run_id); write(phase / 'container_before.json', info)
                command = ['docker', 'start', '-a', cid]
            else:
                command = isolated_command(argv, phase, env, readonly, p['scratch_gib'])
            invocation_start = time.monotonic_ns()
            receipt = measured(command, phase, env, owned, p['timeout_seconds'], p['accepted_exit_codes'])
            receipt.update(started_monotonic_ns=invocation_start, finished_monotonic_ns=time.monotonic_ns())
            write(phase / 'receipt.json', receipt)
            if p['kind'] == 'container':
                info = json.loads(capture(['docker', 'inspect', cid]))[0]
                write(phase / 'container_after.json', info)
                require(not info['State']['Running'], 'Scanner container still active')
            if p['report'].endswith(('.stdout', '/stdout')):
                shutil.copyfile(phase / 'stdout', raw)
            record.update(status=receipt['status'], native_findings=None)
            try:
                report = normalize(raw, p['parser'], receipt['status'], redacted_secrets=p['redacted_secrets'])
                write(phase / 'normalized.json', report)
                record.update(effective_status=report['effective_status'], native_findings=len(report['findings']),
                              raw_sha256=sha(raw), components=len(report.get('components', [])))
            except Exception as exc:
                record.update(effective_status='unusable_report', error=type(exc).__name__ + ': ' + str(exc))
            outcomes.append(record); write(output / 'outcomes.json', outcomes)
            verify_inputs(locks['inputs'][suite], work)
            require(all(sha(path) == digest for path, digest in dependency_hashes.items()), 'Current-block SBOM modified')
            private_db = phase / 'database-copies'
            if private_db.exists():
                write(phase / 'private_database_after.json', inventory(private_db))
                shutil.rmtree(private_db)
        verify_inputs(locks['inputs'][suite], work)
        for item in locks['inputs'][suite]:
            path = work / item['destination']
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        reset.update(verified_after=True, owned_input_copies_removed=True)
        write(output / 'resets' / f'b{block}-{suite}-after.json', reset)


def execute(plan, locks, output, run_id, owned, runtime):
    outcomes = []
    for block in range(1, plan['repetitions'] + 1):
        ledger = {'block': block, 'run_id': run_id, 'status': 'running',
                  'runtime_control_sha256': CONTROL_SHA256, 'scanner_receipts': []}
        path = output / 'blocks' / f'b{block}.json'
        write(path, ledger)
        try:
            runtime.phase(block, 'before')
            ledger['scanner_interval'] = {'started_monotonic_ns': time.monotonic_ns()}
            write(path, ledger)
            execute_block(plan, locks, output, run_id, owned, block, outcomes)
            ledger['scanner_interval']['finished_monotonic_ns'] = time.monotonic_ns()
            for row in [r for r in outcomes if r['block'] == block and r['status'] != 'not_run']:
                relative = 'jobs/' + row['job_id'] + '/receipt.json'
                ledger['scanner_receipts'].append({'job_id': row['job_id'], 'path': relative, 'sha256': sha(output / relative)})
            ledger['outcomes_digest'] = digest([r for r in outcomes if r['block'] == block])
            write(path, ledger)
            runtime.phase(block, 'after')
            ledger['status'] = 'completed'
        except BaseException as error:
            ledger.update(status='failed', error=type(error).__name__ + ': ' + str(error))
            raise
        finally:
            write(path, ledger)
    return {'scanner_invocations': sum(r['status'] != 'not_run' for r in outcomes), 'model_generations': 0,
            'runtime_controls_completed': runtime.completed,
            'completed_reports': sum(r.get('effective_status') == 'completed' for r in outcomes),
            'all_profiles_have_usable_reports': all(r.get('effective_status') == 'completed' for r in outcomes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('execute',), required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError('Controller interrupted by signal ' + str(signum))
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    require(re.fullmatch(r'static-scanners-final-\d{8}-\d{2}', args.run_id), 'Invalid run ID')
    require(PACKAGE.parent == ROOT / 'environment', 'Unexpected deployed package root')
    assert_lease(); verify_package(PACKAGE)
    plan = validate(json.loads((PACKAGE / 'plan.json').read_text()))
    require(json.loads((PACKAGE / 'schedule.json').read_text()) == schedule(plan), 'Schedule differs')
    require_release(args.release, PACKAGE, args.assets, plan)
    locks = json.loads(args.assets.read_text()); verify_locked(locks)
    controls = load_controls(PACKAGE / 'reference/runtime_controls.json')
    output = ROOT / 'evidence' / args.run_id; output.mkdir(exist_ok=False)
    before = snapshot(); write(output / 'host_before.json', before)
    require(not before['active_containers'], 'Idle host required')
    owned = []
    result = {'started_utc': utc(), 'run_id': args.run_id, 'mode': args.mode, 'success': False, 'owned_containers': owned,
              'package_manifest_sha256': sha(PACKAGE / 'package_manifest.json'), 'scanner_invocations': 0, 'model_generations': 0}
    write(output / 'summary.json', result)
    try:
        sample(owned)
        write(output / 'asset_locks.json', locks)
        shutil.copyfile(PACKAGE / 'reference/runtime_controls.json', output / 'runtime_controls.json')
        shutil.copyfile(args.release, output / 'protocol_release.json')
        result['protocol_release_sha256'] = sha(output / 'protocol_release.json')
        capacity = locks['capacity']
        extra = capacity['largest_suite_input_bytes'] + capacity['max_private_database_bytes'] + capacity['retained_evidence_allowance_bytes']
        require(shutil.disk_usage('/').free >= 20 * 1024**3 + extra, 'Insufficient space for bounded reset and retained reports')
        result.update(execute(plan, locks, output, args.run_id, owned,
                              RuntimeControls(output, args.run_id, controls, locks, owned)))
        verify_locked(locks)
        result['assets_preserved'] = True
        result['success'] = True
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        for cid in owned:
            info = json.loads(capture(['docker', 'inspect', cid]))[0]
            require(info['Config']['Labels'].get('org.study.run') == args.run_id, 'Refuse unowned cleanup')
            if info['State']['Running']:
                capture(['docker', 'stop', '-t', '5', cid])
        after = snapshot(); write(output / 'host_after.json', after)
        result['historical_resources_preserved'] = preserved(before, after)
        result['success'] = result['success'] and result['historical_resources_preserved']
        result['finished_utc'] = utc(); write(output / 'summary.json', result)
        print(json.dumps(result), flush=True)
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
