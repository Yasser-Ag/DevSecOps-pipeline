"""Replay one completed triage block from raw evidence, without inference or labels."""
import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engineering.audit_triage_canary import check_response, read, require, rows, sha
from engineering.audit_triage_expanded import audit_memory, compare_created_configuration, diagnose_invalid
from study.filtering_policy import baseline, chat_request
from study.final_triage_contract import digest, validate_mounts
from study.repeated_triage import verify_files
from study.triage_expanded import retain_all, input_format
from study.triage_pilot import classify_completion
from study.filter_input_contract import validate_decision


def audit_request(folder, prefix, packet, payload, expected_tokens, limit, synthetic, identity):
    measurement = read(folder / (prefix + '-measurement.json'))
    response = read(folder / (prefix + '-response.raw'))
    require(read(folder / (prefix + '-request.json')) == payload, 'Raw request differs')
    require(measurement['success'] and measurement['synthetic'] is synthetic, 'Unsuccessful request')
    require(measurement['request_id'] == prefix and measurement['finding_id'] == packet['finding_id'], 'Request identity differs')
    require(all(measurement[k] == v for k, v in identity.items()), 'Job/model/block identity differs')
    require(measurement['packet_sha256'] == digest(packet) and measurement['request_sha256'] == digest(payload), 'Input binding differs')
    reset = read(folder / (prefix + '-reset.raw'))
    require(reset['id_slot'] == 0 and type(reset['n_erased']) is int and reset['n_erased'] >= 0, 'Slot reset unconfirmed')
    check_response(response, measurement, expected_tokens, limit)
    memory = audit_memory(rows(folder / (prefix + '-memory.jsonl')), measurement)
    detail = {'request_id': prefix, 'finding_id': packet['finding_id'], **identity,
              'synthetic': synthetic, 'request_seconds': measurement['request_seconds'],
              'decision_interval_seconds': measurement['decision_interval_seconds'],
              'server_cpu_seconds': sum(measurement['server_after'][k] - measurement['server_before'][k]
                                        for k in ('user_cpu_seconds', 'system_cpu_seconds')),
              'sampled_peak_server_rss_kib': memory['sampled_peak_server_rss_kib'],
              'sampled_peak_cgroup_current_bytes': memory['sampled_peak_cgroup_current_bytes'],
              'max_memory_sample_gap_seconds': memory['max_sample_gap_seconds'],
              'finish_reason': response['choices'][0]['finish_reason'], **measurement['accounting']}
    if not synthetic:
        decision = classify_completion(response, packet, validate_decision)
        require(measurement['decision'] == decision and measurement['validation_seconds'] >= 0, 'Decision not reproduced')
        if decision['status'] != 'completed' or decision['action'] == 'abstain':
            require(decision['effective_action'] == 'retain', 'Conservative response handling differs')
        detail.update(status=decision['status'], action=decision['action'], effective_action=decision['effective_action'],
                      invalid_reason=diagnose_invalid(response, packet, decision))
    return measurement, detail


def audit(base, deployed, run_id, block):
    package, run = base / 'package-v1', base / 'completed-run-v1'
    manifest = read(base / 'remote-manifest-completed-run-v1.stdout')
    verify_files(run, manifest)
    package_manifest = read(package / 'package_manifest.json')
    verify_files(package, package_manifest['files'], ('package_manifest.json',))
    locks = read(package / 'run_locks.json')
    require(read(run / 'verified_run_locks.json') == locks, 'Pinned assets differ')
    require((package / 'study/filtering_policy.py').read_bytes() == (ROOT / 'study/filtering_policy.py').read_bytes(), 'Frozen prompt/policy implementation differs')
    # The sealed inference bundle intentionally excludes selection and label helpers.
    # Bind the exact executed function bodies instead of equating whole modules.
    for name, functions in {'filter_input_contract.py': ('validate_decision',),
                            'triage_pilot.py': ('classify_completion',),
                            'triage_expanded.py': ('retain_all', 'input_format')}.items():
        def bodies(path):
            return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(path.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name in functions}
        require(bodies(package / 'study' / name) == bodies(ROOT / 'study' / name) and
                set(bodies(package / 'study' / name)) == set(functions), 'Replay function differs: ' + name)
    summary = read(run / 'summary.json')
    require(summary['success'] and summary['finished_utc'] and summary['active_job'] is None and not summary.get('error'), 'Run incomplete')
    require(summary['mode'] == 'execute' and summary['package_manifest_sha256'] == sha(package / 'package_manifest.json'), 'Run package differs')
    require(read(run / 'final_release.json') == read(base / 'release-v1/triage_release.json'), 'Run release differs')
    require(tuple(summary[k] for k in ('study_decisions', 'study_generations', 'synthetic_generations')) == (528, 352, 4), 'Run totals differ')
    original = ROOT / 'evidence/repeated_triage_controller_2026-10-22/package-v1'
    schedule = read(package / 'inputs/schedule.json')
    require(schedule == read(original / 'inputs/schedule.json')[(block-1)*4:block*4], 'Schedule is not the designated original block')
    packets = {(c, p['finding_id']): p for c in ('alert_only', 'context') for p in rows(package / 'inputs' / (c + '.jsonl'))}
    require(len(packets) == 176, 'Packet population differs')
    payloads = {r['request_key']: r['payload'] for r in read(package / 'inputs/requests.json')}
    warmup = read(package / 'inputs/warmup.json')
    models = {m['key']: m for m in locks['models']}
    require([j['job_id'] for j in summary['jobs']] == [j['job_id'] for j in schedule], 'Phase order differs')
    before, after = read(run / 'host_before.json'), read(run / 'host_after.json')
    require(summary['historical_metadata_preserved'] and not before['active_containers'] and not after['active_containers'], 'Host boundary failed')
    require(all(after['container_config_hashes'].get(k) == v for k, v in before['container_config_hashes'].items()), 'Existing container changed')
    require(all(before[k] == after[k] for k in ('images', 'volumes', 'networks', 'registry_sha256', 'other_project_paths')), 'Shared metadata changed')
    require(set(after['container_config_hashes']) - set(before['container_config_hashes']) == set(summary['owned_container_ids']), 'Unexpected created container')
    decisions, measurements, phases = [], [], []
    previous_end = None
    for job, record in zip(schedule, summary['jobs']):
        folder = run / job['job_id']
        initial, info = read(folder / 'container_before.json'), read(folder / 'container_after.json')
        compare_created_configuration(initial, info)
        require(info['Id'] == initial['Id'] == record['container_id'] and info['Image'] == locks['harness_image'], 'Container identity differs')
        host, state = info['HostConfig'], info['State']
        require(not state['Running'] and not state['OOMKilled'] and state['ExitCode'] == record['returncode'] == 0, 'Container execution failed')
        require(host['Memory'] == host['MemorySwap'] == 12*1024**3 and host['NanoCpus'] == 8*10**9 and host['PidsLimit'] == 256, 'Resource ceiling differs')
        require(not host.get('PortBindings') and info['Config']['User'] not in ('', 'root', '0', '0:0'), 'Unexpected privileges or published ports')
        model = models[job['model']] if job['kind'] == 'model' else None
        mounts = {'/inputs': (deployed + '/inputs', False), '/code': (deployed + '/inference_code', False),
                  '/output': ('<LAB_ROOT>/evidence/' + run_id + '/' + job['job_id'], True)}
        if model:
            mounts.update({'/runtime': ('<LAB_ROOT>/environment/llama-b10964/llama-b10964', False),
                           '/model.gguf': (model['path'], False)})
        validate_mounts(info, mounts)
        if previous_end is not None:
            require(previous_end <= state['StartedAt'], 'Overlapping phases')
        previous_end = state['FinishedAt']
        resources = rows(folder / 'resources.jsonl')
        require(resources and all(set(r['active_container_ids']) <= {record['container_id']} for r in resources), 'Competing container observed')
        require(min(r['host_available_memory_bytes'] for r in resources) >= 1024**3 and min(r['root_available_bytes'] for r in resources) >= 20*1024**3, 'Host reserve violated')
        probe = read(folder / 'probe.json')
        require(probe == record['probe'] and probe['success'] and probe['mode'] == 'execute', 'Phase receipt differs')
        require(probe['interfaces'] == ['lo'] and probe['external_route_blocked'], 'Offline boundary failed')
        ledger = rows(folder / 'decisions.jsonl')
        phase = {'job_id': job['job_id'], 'container_wall_seconds': record['wall_seconds'],
                 'load_seconds': probe.get('load_seconds'), 'warmup_seconds': probe.get('warmup_seconds'),
                 'minimum_host_available_memory_bytes': min(r['host_available_memory_bytes'] for r in resources),
                 'minimum_root_available_bytes': min(r['root_available_bytes'] for r in resources)}
        phases.append(phase)
        if not model:
            require([r['finding_id'] for r in ledger] == job['case_order'] and len(ledger) == probe['study_decisions'] == 88, 'Baseline population differs')
            require(probe['study_generations'] == probe['synthetic_generations'] == 0, 'Baseline made model calls')
            policy = retain_all if job['condition'] == 'B0' else baseline
            for row in ledger:
                packet = packets['alert_only', row['finding_id']]
                expected = policy(packet)
                require(row['decision'] == expected and row['packet_sha256'] == digest(packet), 'Baseline replay differs')
                require(row['block'] == block and row['condition'] == job['condition'] and row['job_id'] == job['job_id'], 'Baseline identity differs')
                require(row['policy_cpu_ns_single_pass'] >= 0 and row['policy_interval_seconds'] > 0, 'Baseline clock invalid')
                require(0 < row['process_memory']['rss_kib'] <= row['process_memory']['high_water_rss_kib'] and row['cgroup_memory']['swap_current_bytes'] == 0, 'Baseline memory invalid')
                decisions.append({'condition': job['condition'], 'finding_id': row['finding_id'], 'block': block,
                                  'status': expected.get('status', 'completed'), 'action': expected.get('action', expected['effective_action']),
                                  'effective_action': expected['effective_action']})
            retained = sum(r['decision']['effective_action'] == 'retain' for r in ledger)
            batches = read(folder / 'timing_batches.json')
            require(len(batches) == probe['timing_batches'] == 20 and probe['timing_policy_calls'] == 1760000, 'Timing batch totals differ')
            for i, b in enumerate(batches):
                require((b['batch'], b['complete_passes'], b['cases_per_pass'], b['policy_calls']) == (i, 1000, 88, 88000), 'Timing denominator differs')
                require(b['retained_decisions'] == retained*1000 and b['wall_ns'] > 0 and b['cpu_ns'] > 0, 'Timing count differs')
                require(b['wall_ns_per_call'] == b['wall_ns']/88000 and b['cpu_ns_per_call'] == b['cpu_ns']/88000, 'Timing derivation differs')
            continue
        key = model['key']
        require(len(ledger) == probe['study_generations'] == probe['study_decisions'] == 176 and probe['synthetic_generations'] == 2, 'Model phase incomplete')
        properties = read(folder / 'server_properties.json')
        qualified = read(ROOT / 'evidence/aigoat_tokenizer_2026-10-12/ubuntu' / key / 'server_properties.json')
        require(properties['total_slots'] == 1 and properties['model_path'] == '/model.gguf' and properties['default_generation_settings']['n_ctx'] == 4096, 'Model/context/slot differs')
        require(all(properties[k] == qualified[k] for k in ('build_info', 'chat_template', 'chat_template_caps', 'bos_token', 'eos_token')), 'Tokenizer/runtime template differs')
        identity = {'model': key, 'job_id': job['job_id'], 'block': block}
        for n in (1, 2):
            packet = warmup['synthetic_packet']
            payload = {**chat_request(packet, max_tokens=1), 'cache_prompt': False, 'id_slot': 0}
            _, detail = audit_request(folder, 'synthetic-' + str(n), packet, payload, warmup['synthetic_prompt_tokens'][key], 1, True, identity)
            measurements.append(detail)
        for index, request in enumerate(job['requests'], 1):
            packet = packets[request['condition'], request['finding_id']]
            payload = payloads[request['request_key']]
            require(payload == {**chat_request(packet, max_tokens=384), 'cache_prompt': False, 'id_slot': 0}, 'Frozen prompt differs')
            require(digest(packet) == request['packet_sha256'] and digest(payload) == request['request_sha256'], 'Scheduled input binding differs')
            measurement, detail = audit_request(folder, f'request-{index:03}', packet, payload, request['expected_prompt_tokens'], 384, False, identity)
            require(ledger[index-1] == {**measurement, 'condition': request['condition'], 'input_format': input_format(packet)}, 'Ledger differs from replay')
            detail['condition'] = request['condition']
            measurements.append(detail)
            decisions.append({'condition': key + '/' + request['condition'], 'finding_id': packet['finding_id'], 'block': block,
                              **{k: detail[k] for k in ('status', 'action', 'effective_action')}})
        phase['response_statuses'] = dict(Counter(r['decision']['status'] for r in ledger))
    require(len(decisions) == 528 and len(measurements) == 356, 'Replayed totals differ')
    require(len({(r['condition'], r['finding_id']) for r in decisions}) == 528, 'Duplicate paired observation')
    return {'success': True, 'run_id': run_id, 'original_block': block, 'scientific_decisions': 528,
            'study_generations': 352, 'synthetic_generations': 4, 'verified_raw_files': len(manifest),
            'measurement_policy_audit_complete': True, 'raw_decisions_replayed': True, 'label_scoring_complete': False,
            'shared_metadata_preserved': True, 'phases': phases,
            'scope': 'One designated block; exact raw replay and execution/measurement audit. No label scoring or generalization claim.'}, decisions, measurements


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--deployed-package', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--block', type=int, choices=(1, 2), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False, parents=True)
    try:
        result, decisions, measurements = audit(args.base, args.deployed_package, args.run_id, args.block)
        for name, values in (('decisions', decisions), ('measurements', measurements)):
            path = args.output / (name + '.jsonl')
            path.write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in values))
            result[name + '_sha256'] = sha(path)
    except Exception as error:
        result = {'success': False, 'error': type(error).__name__ + ': ' + str(error)}
    result.update(audited_utc=datetime.now(timezone.utc).isoformat(), auditor_sha256=sha(Path(__file__)))
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result))
    if not result['success']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
