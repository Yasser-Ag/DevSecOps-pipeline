"""Replay observable selection, decisions and measurement checks from raw evidence."""
from collections import Counter
from datetime import datetime, timezone
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from study.triage_pilot import select_pilot, classify_completion
from study.filter_input_contract import validate_decision
from study.filtering_policy import canonical, chat_request, baseline

BASE = ROOT/'evidence/triage_pilot_2026-10-12'
RUN = BASE/'attempt-02'
QUALIFIED = ROOT/'evidence/aigoat_tokenizer_2026-10-12'


def require(value, message):
    if not value: raise ValueError(message)


def read(path): return json.loads(path.read_text())
def rows(path): return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def check_response(response, measurement, expected, limit):
    """Check raw native counters without the inference probe's accounting helper."""
    u = response['usage']; t = response['timings']
    require(u['prompt_tokens'] == t['prompt_n'] == expected, 'Unexpected prompt length')
    require(u['prompt_tokens_details']['cached_tokens'] == t['cache_n'] == 0, 'Reused prompt prefix')
    require(u['completion_tokens'] == t['predicted_n'] and 0 <= t['predicted_n'] <= limit, 'Output accounting differs')
    require(u['total_tokens'] == expected + u['completion_tokens'] <= 4096, 'Total tokens differ')
    require(measurement['expected_prompt_tokens'] == expected and measurement['output_limit'] == limit,
            'Measurement configuration differs')
    require(measurement['accounting'] == {'prompt_tokens': expected, 'completion_tokens': u['completion_tokens'],
        'cached_tokens': 0, 'prompt_ms': t['prompt_ms'], 'predicted_ms': t['predicted_ms']}, 'Derived counters differ')
    require(0 < measurement['request_seconds'] <= 300 and 0 <= measurement['reset_seconds'] <= 300,
            'Request/reset outside declared bound')
    for key in ('user_cpu_seconds', 'system_cpu_seconds'):
        require(measurement['server_after'][key] >= measurement['server_before'][key], 'CPU counter decreased')


def main():
    remote = RUN/'ubuntu'; package = RUN/'canary-package-v2'
    summary = read(remote/'summary.json'); locks = read(remote/'run_locks.json')
    require(summary['success'] and summary['historical_metadata_preserved'], 'Canary incomplete')
    require(summary['study_generations'] == 16 and summary['synthetic_generations'] == 4, 'Generation count differs')
    require(summary['package_manifest_sha256'] == sha(package/'package_manifest.json'), 'Wrong execution package')
    require(locks == read(package/'run_locks.json'), 'Execution locks differ')
    require(sha(ROOT/'engineering/TRIAGE_CANARY_CORRECTION_2026-10-12.md') == locks['correction_sha256'], 'Correction record drift')
    for row in read(RUN/'collection_manifest.json')['files']:
        p = remote/row['path']; require(p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], 'Collection drift')
    for row in read(package/'package_manifest.json')['files']:
        p = package/row['path']; require(p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], 'Package drift')
    selection = read(BASE/'selection.json')
    require(sha(BASE/'selection.json') == locks['canary_selection_sha256'], 'Selection changed after execution')
    require(sha(ROOT/'engineering/TRIAGE_PILOT_PLAN.md') == selection['plan_sha256'], 'Plan changed after execution')
    population = {c: rows(QUALIFIED/'joint-feasible-v1'/(c+'.jsonl')) for c in ('alert_only', 'context')}
    for c in population:
        require(sha(QUALIFIED/'joint-feasible-v1'/(c+'.jsonl')) == selection['source_packet_hashes'][c], 'Qualified population drift')
    budgets = read(QUALIFIED/'combined_selection.json')
    selected, canary = select_pilot(population['alert_only'], population['context'], budgets,
                                  {p['finding_id'] for p in population['alert_only'][:314]})
    require(selection['strata'] == selected and selection['canary'] == canary, 'Selection not reproduced')
    config = read(package/'inputs/configuration.json')
    packets = {c: rows(package/'inputs'/(c+'.jsonl')) for c in population}
    population_indexes = {c: {p['finding_id']: p for p in population[c]} for c in population}
    for c, values in packets.items():
        require(len(values) == 4 and [p['finding_id'] for p in values] == [r['finding_id'] for r in canary], 'Wrong canary population')
        require(all(p == population_indexes[c][p['finding_id']] for p in values), 'Canary content differs')
    expected_deterministic = []
    for item in selected:
        p = population_indexes['alert_only'][item['finding_id']]
        expected_deterministic += [{'finding_id': p['finding_id'], 'condition': 'B0', 'effective_action': 'retain'}, baseline(p)]
    require(rows(BASE/'deterministic_decisions.jsonl') == expected_deterministic, 'Deterministic baseline differs')
    before = read(remote/'host_before.json'); after = read(remote/'host_after.json')
    require(all(after['container_config_hashes'].get(k) == v for k, v in before['container_config_hashes'].items()), 'Historical container changed')
    for key in ('images', 'volumes', 'networks', 'registry_sha256', 'other_project_paths'):
        require(before[key] == after[key], 'Historical metadata changed: '+key)
    require(not before['active_containers'] and not after['active_containers'], 'Active workload at boundaries')
    require(set(after['container_config_hashes'])-set(before['container_config_hashes']) == set(summary['owned_container_ids']), 'Unexpected new container')
    require([r['key'] for r in summary['models']] == [r['key'] for r in locks['models']], 'Model condition differs')
    measured = []; models = []; previous_end = None
    for model, record in zip(locks['models'], summary['models']):
        key = model['key']; folder = remote/key; probe = read(folder/'probe.json')
        require(probe == record['probe'] and probe['success'] and probe['study_generations'] == 8 and probe['synthetic_generations'] == 2, 'Incomplete model')
        require(probe['interfaces'] == ['lo'] and probe['external_route_blocked'], 'Network boundary failed')
        properties = read(folder/'server_properties.json')
        prior_properties = read(QUALIFIED/'ubuntu'/key/'server_properties.json')
        require(properties['total_slots'] == 1 and properties['model_path'] == '/model.gguf'
                and properties['default_generation_settings']['n_ctx'] == 4096, 'Unexpected server model/slot/context count')
        for field in ('build_info', 'chat_template', 'chat_template_caps', 'bos_token', 'eos_token'):
            require(properties[field] == prior_properties[field], 'Tokenizer/template configuration changed: '+field)
        info = read(folder/'container_after.json'); host = info['HostConfig']; state = info['State']
        require(not state['Running'] and state['ExitCode'] == 0 and not state['OOMKilled'], 'Container failure')
        require(info['Id'] == record['container_id'] and info['Image'] == locks['harness_image'], 'Container identity differs')
        require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and host['Memory'] == host['MemorySwap'] == 12*1024**3, 'Isolation configuration differs')
        require(host['NanoCpus'] == 8*10**9 and host['PidsLimit'] == 256, 'CPU/process limit differs')
        require('ALL' in host['CapDrop'] and 'no-new-privileges:true' in host['SecurityOpt'] and info['Config']['User'] not in ('', '0', 'root'), 'Privileges differ')
        expected_mounts = {'/runtime': '<LAB_ROOT>/environment/llama-b10964/llama-b10964',
            '/model.gguf': model['path'], '/inputs': '<LAB_ROOT>/environment/triage-canary-code-v2/inputs',
            '/code': '<LAB_ROOT>/environment/triage-canary-code-v2/inference_code',
            '/output': '<LAB_ROOT>/evidence/triage-canary-20261012-02/'+key}
        mounts = {m['Destination']: m for m in info['Mounts']}
        require(set(mounts) == set(expected_mounts), 'Unexpected inference mount')
        for k, path in expected_mounts.items():
            require(mounts[k]['Source'] == path and mounts[k]['RW'] == (k == '/output'), 'Changed mount access/source')
        if previous_end is not None:
            require(previous_end <= state['StartedAt'], 'Model executions overlap')
        previous_end = state['FinishedAt']
        resources = rows(folder/'resources.jsonl')
        require(resources and all(set(r['active_container_ids']) <= {record['container_id']} for r in resources), 'Competing workload')
        require(min(r['host_available_memory_bytes'] for r in resources) >= 1024**3 and
                min(r['root_available_bytes'] for r in resources) >= 20*1024**3, 'Reserve violated')
        for n in (1, 2):
            prefix = 'synthetic-'+str(n); m = read(folder/(prefix+'-measurement.json'))
            expected_request = chat_request(config['synthetic_packet'], max_tokens=1)
            expected_request.update(cache_prompt=False, id_slot=0)
            require(read(folder/(prefix+'-request.json')) == expected_request, 'Synthetic request differs')
            require(m['success'] and m['synthetic'], 'Synthetic check failed')
            require(read(folder/(prefix+'-reset.raw'))['id_slot'] == 0, 'Wrong reset slot')
            check_response(read(folder/(prefix+'-response.raw')), m, config['synthetic_prompt_tokens'][key], 1)
        decisions = rows(folder/'decisions.jsonl'); require(len(decisions) == 8, 'Missing decision row')
        replay = []
        for i, case in enumerate(config['cases']):
            for condition in ('alert_only', 'context'):
                prefix = 'case-'+str(i+1)+'-'+condition; packet = packets[condition][i]
                request = read(folder/(prefix+'-request.json')); response = read(folder/(prefix+'-response.raw'))
                m = read(folder/(prefix+'-measurement.json')); reset = read(folder/(prefix+'-reset.raw'))
                expected = chat_request(packet); expected.update(cache_prompt=False, id_slot=0)
                require(request == expected, 'Prompt/payload changed')
                require(m['success'] and not m['synthetic'] and reset['id_slot'] == 0 and isinstance(reset['n_erased'], int), 'Missing reset/accounting confirmation')
                require(m['packet_sha256'] == hashlib.sha256(canonical(packet).encode()).hexdigest(), 'Input hash differs')
                require(m['decision'] == classify_completion(response, packet, validate_decision), 'Decision not reproduced')
                expected_tokens = case['counts'][key]['alert' if condition == 'alert_only' else 'selected_context']
                source_budget = next(r for r in budgets if r['finding_id'] == packet['finding_id'])
                require(case['counts'] == source_budget['counts'], 'Token expectation changed')
                check_response(response, m, expected_tokens, 384)
                replay.append({**m, 'condition': condition, 'input_format': case['input_format'], 'model': key})
                measured.append({'model': key, 'condition': condition, 'finding_id': packet['finding_id'],
                    'input_format': case['input_format'], 'added_context': len(packet['evidence']) > 1,
                    'status': m['decision']['status'], 'action': m['decision']['action'],
                    'effective_action': m['decision']['effective_action'],
                    'finish_reason': response['choices'][0]['finish_reason'],
                    'request_seconds': m['request_seconds'], 'reset_seconds': m['reset_seconds'],
                    'server_cpu_seconds': sum(m['server_after'][k]-m['server_before'][k] for k in ('user_cpu_seconds', 'system_cpu_seconds')),
                    **m['accounting']})
        require(decisions == replay, 'Retained decision journal differs')
        model_rows = [r for r in measured if r['model'] == key]
        models.append({'key': key, 'study_generations': len(model_rows),
            'valid_decisions': sum(r['status'] == 'completed' for r in model_rows),
            'actions': dict(Counter(r['action'] for r in model_rows)),
            'effective_actions': dict(Counter(r['effective_action'] for r in model_rows)),
            'load_seconds': probe['load_seconds'], 'server_resources': probe['server_resources'],
            'minimum_host_available_memory_bytes': min(r['host_available_memory_bytes'] for r in resources),
            'request_seconds_total': sum(r['request_seconds'] for r in model_rows)})
    with (RUN/'audited_measurements.csv').open('x') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(measured[0])); writer.writeheader(); writer.writerows(measured)
    result = {'success': True, 'verified_utc': datetime.now(timezone.utc).isoformat(),
        'cases': 4, 'pilot_strata': len(selected), 'study_generations': 16, 'synthetic_generations': 4,
        'models': models, 'historical_containers_preserved': len(before['container_config_hashes']),
        'scanners_invoked': False, 'new_security_labels': 0,
        'scope': 'Execution canary only; decisions have not been joined to truth. Four cases do not establish accuracy, superiority or population latency.',
        'measurements_sha256': sha(RUN/'audited_measurements.csv')}
    (RUN/'verification_summary.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
