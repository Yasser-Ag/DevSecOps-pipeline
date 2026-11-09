"""Exact composition of qualified components; no scanner or model execution."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from study.static_scan_contract import schedule as static_schedule, validate as validate_static
from study.dynamic_execution_contract import execution_plan
from study.runtime_block_contract import CONTROL_SHA256, schedule as runtime_schedule
from study.final_output_adapter import digest, require
from study.repeated_triage import load_inputs

REMOTE = Path('<LAB_ROOT>')
SCANNERS = REMOTE / 'environment/runtime-integration-v1'
TRIAGE = REMOTE / 'environment/triage-repeated-code-v1'
SCANNER_SHA = '06e60151cacc46b6bb57d39db4dda1292ce76f586ede82ebbe7e8c5df8e5e662'
TRIAGE_SHA = '9246db9a16772b15ebfc6c368ee317a6b9439e93a334b2ff99eab63e566aaa76'
STATIC_LOCK = REMOTE / 'evidence/static-scanners-preflight-20261022-02/asset_locks.json'
DYNAMIC_LOCK = REMOTE / 'evidence/dynamic-execution-preflight-20261022-02/asset_locks.json'
BINDINGS = 'data/references/bindings.json'
STATIC_LOCK_LOCAL = 'evidence/static_scanner_controller_2026-10-22/ubuntu-preflight-v2/asset_locks.json'
DYNAMIC_LOCK_LOCAL = 'evidence/dynamic_execution_2026-10-22/ubuntu-preflight-v2/asset_locks.json'


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_package(path, expected=None):
    path = Path(path)
    manifest = read(path / 'package_manifest.json')
    if expected:
        require(sha(path / 'package_manifest.json') == expected, 'Component manifest mismatch')
    names = [r['path'] for r in manifest['files']]
    require(len(names) == len(set(names)), 'Duplicate package path')
    require({p.relative_to(path).as_posix() for p in path.rglob('*') if p.is_file()} ==
            set(names) | {'package_manifest.json'}, 'Package allowlist differs')
    for row in manifest['files']:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe package path')
        p = path / relative
        require(not p.is_symlink() and p.resolve().is_relative_to(path.resolve()), 'Symbolic package input')
        require(p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], 'Component file mismatch: ' + row['path'])
    return manifest


def validate_join(plan, dynamic, triage, bindings):
    """Cross-component scientific units, including empty/inventory profiles."""
    profiles = [p['id'] for p in plan['profiles']] + [p['id'] for p in dynamic['profiles']]
    require(len(profiles) == len(set(profiles)) == 93, 'Profile identities differ')
    require(set(profiles) == {p['profile_id'] for p in bindings['profiles']}, 'Analysis profile routing differs')
    jobs = static_schedule(plan)
    require(len(jobs) == 375 and len({j['job_id'] for j in jobs}) == 375, 'Static schedule differs')
    require(Counter(j['block'] for j in jobs) == {i: 75 for i in range(1, 6)}, 'Static repetitions differ')
    require(len(execution_plan()['jobs']) == 95, 'Dynamic schedule differs')
    require(Counter(j['kind'] for j in execution_plan()['jobs']) == {'scanner': 90, 'target_generation': 5},
            'Dynamic detector/generator units differ')
    endpoint_ids = {r['finding_id'] for r in bindings['triage_clusters']}
    require(len(bindings['triage_clusters']) == len(endpoint_ids) == 88, 'Triage analysis population differs')
    require(len(triage['schedule']) == 16, 'Triage job count differs')
    for job in triage['schedule']:
        if job['kind'] == 'baseline':
            orders = [job['case_order']]
        else:
            require(len(job['requests']) == 176, 'Model condition count differs')
            orders = [[r['finding_id'] for r in job['requests'] if r['condition'] == condition]
                      for condition in ('alert_only', 'context')]
        require(all(len(order) == 88 and set(order) == endpoint_ids for order in orders),
                'Triage inference and evaluation identifiers differ')
    require((triage['totals']['study_decisions'], triage['totals']['study_generations']) == (2112, 1408),
            'Triage workload differs')
    require(len(bindings['populations']) == 35 and len(bindings['references']) == 338 and
            len(bindings['native_observations']) == 1988 and len(bindings['links']) == 200,
            'Reference universe differs')
    require(len(bindings['comparators']) == 6 and
            all(c['complete_member_baseline_retained'] for c in bindings['comparators']),
            'Competent comparator missing')
    return {'static_profiles': 75, 'static_jobs': 375, 'dynamic_profiles': 18, 'dynamic_jobs': 95,
            'runtime_probes': 120, 'triage_jobs': 16, 'triage_observations': 88,
            'study_decisions': 2112, 'study_generations': 1408, 'synthetic_warmups': 16,
            'populations': 35, 'reference_records': 338, 'comparator_domains': 6}


def composition(root, scanners, triage):
    root, scanners, triage = map(Path, (root, scanners, triage))
    verify_package(scanners, SCANNER_SHA)
    tm = verify_package(triage, TRIAGE_SHA)
    plan = validate_static(read(scanners / 'plan.json'))
    require(read(scanners / 'schedule.json') == static_schedule(plan), 'Static physical schedule differs')
    dynamic = read(scanners / 'dynamic_plan.json')
    require(read(scanners / 'execution_plan.json') == execution_plan(), 'Dynamic physical schedule differs')
    bindings = read(root / BINDINGS)
    totals = validate_join(plan, dynamic, load_inputs(triage / 'inputs'), bindings)
    # Verify the corrected attempted-request code, not the obsolete deployed v2.
    delta = read(root / 'evidence/dynamic_execution_2026-10-22/local-final-candidate/manifest.json')
    for row in delta['files']:
        require(sha(scanners / row['path']) == row['sha256'], 'Corrected dynamic component missing')
    return {'schema': 'final-component-composition-v1', 'scientific_release': False,
            'components': {
                'scanners': {'remote': str(SCANNERS), 'manifest_sha256': SCANNER_SHA},
                'triage': {'remote': str(TRIAGE), 'manifest_sha256': TRIAGE_SHA}},
            'static': {'package_manifest_sha256': SCANNER_SHA, 'assets': str(STATIC_LOCK),
                'asset_locks_sha256': sha(root / STATIC_LOCK_LOCAL),
                'profile_ids': [p['id'] for p in plan['profiles']],
                'schedule_sha256': sha(scanners / 'schedule.json'), 'schedule_digest': digest(static_schedule(plan)),
                'runtime_control_sha256': CONTROL_SHA256, 'runtime_schedule_digest': digest(runtime_schedule())},
            'dynamic': {'package_manifest_sha256': SCANNER_SHA, 'assets': str(DYNAMIC_LOCK),
                'asset_locks_sha256': sha(root / DYNAMIC_LOCK_LOCAL),
                **{k: execution_plan()[k] for k in ('schedule_sha256', 'profiles_sha256', 'generation_sha256')}},
            'triage': {'package_manifest_sha256': TRIAGE_SHA, 'schedule_sha256': sha(triage / 'inputs/schedule.json'),
                'candidate_manifest_sha256': tm['candidate_manifest_sha256']},
            'analysis_bindings_sha256': sha(root / BINDINGS), 'totals': totals,
            'inference_separation': 'Only the qualified triage inputs and inference_code are mounted; evaluation stays outside.'}


def component_releases(binding, protocol_sha256, gates):
    """Translate one validated gate set into the existing component schemas."""
    require(len(gates) == 8 and {g['id'] for g in gates} == {f'G{i}' for i in range(1, 9)} and
            all(g['passed'] is True for g in gates), 'Campaign gates incomplete')
    require(len(protocol_sha256) == 64 and all(c in '0123456789abcdef' for c in protocol_sha256),
            'Invalid protocol hash')
    common = {'protocol': 'v1.0', 'final_campaign_ready': True, 'gates': gates,
              'protocol_sha256': protocol_sha256, 'composition_digest': digest(binding)}
    s, t = binding['static'], binding['triage']
    return {'static': {**common, 'static_package_manifest_sha256': s['package_manifest_sha256'],
        'static_assets_sha256': s['asset_locks_sha256'], 'static_profile_ids': s['profile_ids'],
        'static_schedule_sha256': s['schedule_sha256'], 'runtime_control_sha256': s['runtime_control_sha256'],
        'runtime_schedule_digest': s['runtime_schedule_digest']},
        'dynamic': {'protocol_version': '1.0', 'final_ready': True,
            'gates': {g['id']: 'passed' for g in gates}, 'protocol_sha256': protocol_sha256,
            'composition_digest': digest(binding),
            'dynamic_execution': {k: v for k, v in binding['dynamic'].items() if k != 'assets'}},
        'triage': {**common, 'triage_package_manifest_sha256': t['package_manifest_sha256'],
            'triage_schedule_sha256': t['schedule_sha256'],
            'triage_candidate_manifest_sha256': t['candidate_manifest_sha256']}}


def command_schedule(release_root, stamp='20261023', attempt='01'):
    """97 sequential controller calls; repetition is internal to static/triage."""
    import re
    require(re.fullmatch(r'\d{8}', stamp) and re.fullmatch(r'\d{2}', attempt), 'Invalid campaign identity')
    release_root = Path(release_root)
    require(release_root.is_absolute() and release_root.is_relative_to(REMOTE / 'environment'), 'Unowned release directory')
    static_run = f'static-scanners-final-{stamp}-{attempt}'
    triage_run = f'triage-repeated-final-{stamp}-{attempt}'
    jobs = [{'id': 'static', 'run_id': static_run, 'kind': 'static',
        'argv': ['python3', '-B', str(SCANNERS / 'engineering/static_campaign_run.py'), '--mode', 'execute',
            '--run-id', static_run, '--assets', str(STATIC_LOCK), '--release', str(release_root / 'static_release.json')]}]
    for j in execution_plan()['jobs']:
        run = f"dynamic-final-{stamp}-{attempt}-{j['id']}"
        jobs.append({'id': j['id'], 'run_id': run, 'kind': j['kind'], 'block': j['block'],
            'profile_id': j['profile_id'], 'argv': ['python3', '-B', str(SCANNERS / 'engineering/dynamic_execution_run.py'),
                'execute', '--run-id', run, '--job-id', j['id'], '--asset-locks', str(DYNAMIC_LOCK),
                '--release', str(release_root / 'dynamic_release.json')]})
    jobs.append({'id': 'triage', 'run_id': triage_run, 'kind': 'triage',
        'argv': ['python3', '-B', str(TRIAGE / 'engineering/repeated_triage_run.py'), '--mode', 'execute',
                 '--run-id', triage_run, '--release', str(release_root / 'triage_release.json')]})
    require(len(jobs) == len({j['id'] for j in jobs}) == len({j['run_id'] for j in jobs}) == 97,
            'Duplicate/missing controller invocation')
    return jobs
