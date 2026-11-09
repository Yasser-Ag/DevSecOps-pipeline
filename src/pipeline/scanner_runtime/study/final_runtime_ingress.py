"""Verify each static block's own runtime evidence before interpreting its results."""
import json

from study.final_output_adapter import adapt_static, digest, require
from study.final_output_ingress import Evidence
from study.runtime_block_contract import (CONTROL_SHA256, load_controls, source_bindings,
                                          verify_phase, interval)
from study.dynamic_reset_contract import image_identity
from study.static_scan_contract import sha, schedule
from engineering.dynamic_reset_run import PROBE


def verify_block(evidence, plan, controls, locks, block, run_id, records):
    ledger = evidence.read(f'blocks/b{block}.json')
    require(ledger['block'] == block and ledger['run_id'] == run_id and ledger['status'] == 'completed',
            'Incomplete/substituted static block')
    require(ledger['runtime_control_sha256'] == CONTROL_SHA256, 'Block control identity differs')
    rows = [r for r in records if r['block'] == block]
    expected = [r for r in schedule(plan) if r['block'] == block]
    require([r['job_id'] for r in rows] == [r['job_id'] for r in expected], 'Incomplete/reordered static block')
    require(ledger['outcomes_digest'] == digest(rows), 'Static block outcomes changed')
    require(all(r['profile'] == j['profile'] for r, j in zip(rows, expected)), 'Static outcome profile differs')
    binding = source_bindings(controls, locks)
    phases = {}
    for phase in ('before', 'after'):
        prefix = f'runtime/b{block}/{phase}/'
        receipt = evidence.read(prefix + 'phase.json')
        require(receipt['source_bindings'] == binding, 'Runtime source bindings differ')
        phases[phase] = verify_phase(evidence, controls, block, phase, run_id, PROBE)
    require(phases['before']['assertions'] == phases['after']['assertions'], 'Runtime reference drift')
    require(not set(phases['before']['container_ids']) & set(phases['after']['container_ids']), 'Runtime target reused across phases')
    images = [evidence.read(f'runtime/b{block}/{p}/images.json') for p in ('before', 'after')]
    require({k: image_identity(k, v) for k, v in images[0].items()} ==
            {k: image_identity(k, v) for k, v in images[1].items()}, 'Runtime image drift between phases')
    start, end = interval(ledger['scanner_interval'])
    require(phases['before']['interval'][1] <= start <= end <= phases['after']['interval'][0],
            'Runtime controls do not bracket this scanner block')
    ran = [r for r in rows if r['status'] != 'not_run']
    require([r['job_id'] for r in ledger['scanner_receipts']] == [r['job_id'] for r in ran], 'Scanner receipt coverage differs')
    previous = start
    for row, bound in zip(ran, ledger['scanner_receipts']):
        require(bound['path'] == 'jobs/' + row['job_id'] + '/receipt.json', 'Scanner receipt outside job')
        require(sha(evidence.bind(bound['path'])) == bound['sha256'], 'Scanner receipt changed')
        receipt = evidence.read(bound['path'])
        a, b = interval(receipt)
        require(previous <= a <= b <= end and receipt['status'] == row['status'], 'Scanner interval/status differs')
        previous = b
    return {'block': block, 'verified': True, 'controls': 24,
            'container_ids': phases['before']['container_ids'] + phases['after']['container_ids'],
            'reference_overhead_seconds': sum(p['elapsed_seconds'] for p in phases.values()),
            'scanner_block_wall_seconds': (end - start) / 1e9,
            'scope': 'Construction/reference overhead and scanner block wall time are separate; neither is summed per finding.'}


def runtime_blocks(evidence, plan, locks, records, contract, summary):
    """Missing/corrupt support stays visible and cannot be replaced by a global flag."""
    results, seen = {}, set()
    for block in range(1, plan['repetitions'] + 1):
        try:
            require(contract['runtime_control_sha256'] == CONTROL_SHA256, 'Runtime release identity differs')
            controls = load_controls(evidence.bind('runtime_controls.json'))
            require(sha(evidence.bind('protocol_release.json')) == contract['release_sha256'] == summary['protocol_release_sha256'],
                    'Static protocol release identity differs')
            require(summary['run_id'] == contract['run_id'], 'Static run identity differs')
            result = verify_block(evidence, plan, controls, locks, block, summary['run_id'], records)
            require(not seen.intersection(result['container_ids']), 'Runtime container reused across blocks')
            seen.update(result['container_ids'])
            results[block] = result
        except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
            results[block] = {'block': block, 'verified': False, 'reason': type(error).__name__ + ': ' + str(error)}
    return results


def collect_static(root, plan, catalog, contract):
    evidence = Evidence(root)
    summary = evidence.read('summary.json', optional=True) or {}
    locks = evidence.read('asset_locks.json', optional=True)
    records = evidence.read('outcomes.json', optional=True) or []
    outcomes = {r['job_id']: r for r in records}
    require(len(outcomes) == len(records), 'Duplicate static outcome')
    jobs = schedule(plan)
    require(set(outcomes) <= {j['job_id'] for j in jobs}, 'Outcome outside static schedule')
    require(contract['profile_ids'] == [p['id'] for p in plan['profiles']], 'Static profile contract mismatch')
    require(contract['schedule_digest'] == digest(jobs), 'Static schedule contract mismatch')
    asset_ok = (locks is not None and sha(evidence.path('asset_locks.json')) == contract['asset_locks_sha256']
                and summary.get('assets_preserved') is True and summary.get('mode') == 'execute'
                and summary.get('package_manifest_sha256') == contract['package_manifest_sha256'])
    runtime = runtime_blocks(evidence, plan, locks, records, contract, summary)
    profiles = {p['id']: p for p in plan['profiles']}
    result = []
    for job in jobs:
        row = outcomes.get(job['job_id'])
        record = {'job_id': job['job_id'], 'profile_id': job['profile'], 'block': job['block'],
                  'runtime_reference_verified': runtime[job['block']]['verified'],
                  'native_count': None, 'measurement_eligible': False, 'observations': [], 'links': []}
        if row is None or row.get('status') == 'not_run':
            record.update(status='not_run', reason='No completed execution receipt' if row is None else row.get('reason'))
            result.append(record); continue
        p = profiles[job['profile']]
        work = 'work/b' + str(job['block']) + '-' + p['suite']
        phase = 'jobs/' + job['job_id']
        reset = 'resets/b' + str(job['block']) + '-' + p['suite']
        try:
            before = evidence.read(reset + '.json')
            after = evidence.read(reset + '-after.json')
            prepared = evidence.read(phase + '/prepared.json')
            receipt = evidence.read(phase + '/receipt.json')
            raw_name = work + '/' + p['report']
            raw = evidence.bind(raw_name)
            require(row.get('raw_sha256') == sha(raw), 'Raw report differs from execution receipt')
            require(prepared['reset_sha256'] == sha(evidence.path(reset + '.json')), 'Reset receipt identity differs')
            require(prepared['report'] == before['fresh_destination'] + '/' + p['report'], 'Prepared report is not in owned work directory')
            require(after['fresh_destination'] == before['fresh_destination'], 'Reset destination changed')
            require(before['fresh_destination'].endswith('/' + work), 'Unexpected reset path')
            require(receipt['status'] == row['status'], 'Process/outcome status disagreement')
            input_digest = digest(locks['inputs'][p['suite']]) if locks else 'unavailable'
            context = {'job_id': job['job_id'], 'block': job['block'], 'work_root': before['fresh_destination'],
                       'input_contract_sha256': input_digest, 'observed_input_sha256': input_digest,
                       'inputs_verified_before': before.get('verified') is True,
                       'inputs_verified_after': after.get('verified_after') is True,
                       'asset_lock_verified': asset_ok, 'runtime_reference_verified': runtime[job['block']]['verified'],
                       'process_status': receipt['status'], 'origin': 'fresh_execution'}
            adapted = adapt_static(raw, p, context, [x for x in catalog if x['profile_id'] == p['id']])
            require(adapted['status'] == row.get('effective_status'), 'Native report status differs from receipt')
            require(adapted['native_count'] == row.get('native_findings'), 'Native count differs from receipt')
            record.update(adapted, reset_evidence=[reset + '.json', reset + '-after.json'],
                          process_receipt=phase + '/receipt.json', raw_report=raw_name)
        except (ValueError, KeyError, TypeError, OSError) as error:
            record.update(status='unavailable', reason=type(error).__name__ + ': ' + str(error),
                          native_count=None, measurement_eligible=False, observations=[], links=[])
        result.append(record)
    return {'kind': 'static_output_collection', 'jobs': result, 'scheduled': len(jobs),
            'jobs_with_qualified_measurement': sum(r['measurement_eligible'] for r in result),
            'assets_verified': asset_ok, 'runtime_blocks': list(runtime.values()),
            'runtime_support_complete': all(r['verified'] for r in runtime.values()),
            'source_manifest': evidence.manifest(),
            'scope': 'Frozen static assertion interpretation; unmatched outputs remain unadjudicated.'}

