"""Independently reconstruct all six pilot conditions from sealed raw evidence."""
from collections import Counter
import copy
from datetime import datetime, timezone
import csv
import hashlib
import io
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engineering.audit_triage_canary import require, read, rows, sha, check_response
from study.filtering_policy import baseline, canonical, chat_request
from study.filter_input_contract import validate_decision
from study.triage_pilot import select_pilot, classify_completion
from study.triage_expanded import retain_all, validate_population, input_format

BASE = ROOT/'evidence/triage_expanded_2026-10-12'
QUALIFIED = ROOT/'evidence/aigoat_tokenizer_2026-10-12'
CANARY = ROOT/'evidence/triage_pilot_2026-10-12'


def diagnose_invalid(response, packet, decision):
    """Describe rejected output without repairing it or changing its decision."""
    if decision['status'] == 'completed': return ''
    if decision.get('error'): return decision['error']
    try:
        def unique(pairs):
            value = {}
            for k,v in pairs:
                if k in value: raise ValueError('Duplicate response field')
                value[k] = v
            return value
        value = json.loads(response['choices'][0]['message']['content'],object_pairs_hook=unique)
        if not isinstance(value,dict) or set(value) != {'finding_id','action','evidence_ids','rationale'}: return 'Unexpected response fields'
        if value['finding_id'] != packet['finding_id']: return 'Wrong finding identity'
        if value['action'] not in ('retain','dismiss','abstain'): return 'Unknown action'
        ids = value['evidence_ids']; allowed = {e['id'] for e in packet['evidence']}
        if not isinstance(ids,list) or not all(isinstance(x,str) for x in ids) or len(set(ids)) != len(ids) or not set(ids) <= allowed:
            return 'Unsupported evidence reference'
        if value['action'] == 'dismiss' and not ids: return 'Dismissal requires supplied evidence'
        if not isinstance(value['rationale'],str) or not 1 <= len(value['rationale']) <= 2000: return 'Invalid rationale'
    except (ValueError,TypeError,KeyError,IndexError) as error:
        return type(error).__name__+': '+str(error)
    raise ValueError('Invalid output has no reconstructed reason')


def audit_memory(samples, measurement):
    require(len(samples) >= 2, 'Missing memory boundary samples')
    times = [r['elapsed_seconds'] for r in samples]
    require(all(0 <= a <= b for a,b in zip(times,times[1:])), 'Nonmonotonic memory samples')
    for r in samples:
        require(0 < r['server']['rss_kib'] <= r['server']['high_water_rss_kib'], 'Invalid process RSS')
        c = r['cgroup']
        require(0 < c['current_bytes'] <= c['peak_bytes'] <= 12*1024**3, 'Invalid cgroup memory')
        require(c['swap_current_bytes'] == 0, 'Container used swap')
    expected = {'interval_seconds':0.25, 'samples':len(samples),
                'sampled_peak_server_rss_kib':max(r['server']['rss_kib'] for r in samples),
                'sampled_peak_cgroup_current_bytes':max(r['cgroup']['current_bytes'] for r in samples),
                'scope':'Observed request peaks; process high-water and cgroup peak fields are lifetime counters.'}
    require(measurement['memory'] == expected, 'Memory summary not reproduced')
    require(times[-1] >= measurement['request_seconds'], 'Memory trace does not span request')
    require(measurement['decision_interval_seconds'] >= measurement['request_seconds'] + measurement['reset_seconds'], 'Decision interval omits measured work')
    return {**expected, 'max_sample_gap_seconds':max(b-a for a,b in zip(times,times[1:]))}


def compare_created_configuration(initial, final):
    """Allow only the observed false-to-null default in newly created containers."""
    before = copy.deepcopy(initial)
    normalized = False
    if before['HostConfig'].get('OomKillDisable') is False and 'OomKillDisable' in final['HostConfig'] and final['HostConfig']['OomKillDisable'] is None:
        before['HostConfig']['OomKillDisable'] = None
        normalized = True
    for field in ('Config','HostConfig','Mounts'):
        require(before[field] == final[field], 'Container configuration changed')
    require(final['HostConfig'].get('OomKillDisable') is not True, 'OOM kill protection disabled')
    return normalized


def audit_container(folder, record, locks, model=None):
    info = read(folder/'container_after.json'); initial = read(folder/'container_before.json')
    host = info['HostConfig']; state = info['State']; key = record['key']
    require(info['Id'] == initial['Id'] == record['container_id'] and info['Image'] == locks['harness_image'], 'Container identity differs')
    default_normalized = compare_created_configuration(initial,info)
    require(not state['Running'] and state['ExitCode'] == 0 and not state['OOMKilled'] and record['returncode'] == 0, 'Container failure')
    require(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'], 'Network/root isolation differs')
    require(host['Memory'] == host['MemorySwap'] == 12*1024**3 and host['NanoCpus'] == 8*10**9 and host['PidsLimit'] == 256, 'Resource boundary differs')
    require('ALL' in host['CapDrop'] and 'no-new-privileges:true' in host['SecurityOpt'] and info['Config']['User'] not in ('','0','root'), 'Privileges differ')
    expected = {'/inputs':'<LAB_ROOT>/environment/triage-expanded-code-v1/inputs',
                '/code':'<LAB_ROOT>/environment/triage-expanded-code-v1/inference_code',
                '/output':'<LAB_ROOT>/evidence/triage-expanded-20261012-01/'+key}
    if model:
        expected.update({'/runtime':'<LAB_ROOT>/environment/llama-b10964/llama-b10964','/model.gguf':model['path']})
    mounts = {m['Destination']:m for m in info['Mounts']}
    require(set(mounts) == set(expected), 'Unexpected mount (including possible oracle exposure)')
    for dest,path in expected.items():
        require(mounts[dest]['Source'] == path and mounts[dest]['RW'] == (dest == '/output'), 'Mount source/access differs')
    observed = rows(folder/'resources.jsonl')
    require(observed and all(set(r['active_container_ids']) <= {record['container_id']} for r in observed), 'Competing container')
    require(min(r['host_available_memory_bytes'] for r in observed) >= 1024**3 and min(r['root_available_bytes'] for r in observed) >= 20*1024**3, 'Host reserve violated')
    return state, observed, default_normalized


def audit_baseline_batches(batches, retained):
    require(len(batches) == 20, 'Missing baseline timing batches')
    for i,b in enumerate(batches):
        require(b['batch'] == i and b['complete_passes'] == 1000 and b['cases_per_pass'] == 29 and b['policy_calls'] == 29000, 'Timing denominator differs')
        require(b['retained_decisions'] == retained*1000, 'Timing loop decisions differ')
        require(b['wall_ns'] > 0 and b['cpu_ns'] > 0 and b['wall_ns_per_call'] == b['wall_ns']/29000 and b['cpu_ns_per_call'] == b['cpu_ns']/29000, 'Timing derivation differs')


def csv_text(values):
    stream = io.StringIO(); writer = csv.DictWriter(stream,fieldnames=list(values[0]))
    writer.writeheader(); writer.writerows(values); return stream.getvalue()


def main():
    remote = BASE/'ubuntu'; package = BASE/'package-v1'
    summary = read(remote/'summary.json'); locks = read(remote/'run_locks.json')
    require(summary['success'] and summary['historical_metadata_preserved'] and summary['active_phase'] is None, 'Pilot incomplete')
    require(summary['study_decisions'] == 58 and summary['study_generations'] == 116 and summary['synthetic_generations'] == 4, 'Pilot population incomplete')
    require(summary['package_manifest_sha256'] == sha(package/'package_manifest.json') and locks == read(package/'run_locks.json'), 'Execution package differs')
    require(sha(BASE/'ubuntu-evidence.tar.gz') == read(BASE/'collection_manifest.json')['archive_sha256'], 'Collected archive changed')
    for root, manifest in [(remote, read(BASE/'collection_manifest.json')), (package, read(package/'package_manifest.json'))]:
        require({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()} == {r['path'] for r in manifest['files']} | ({'package_manifest.json'} if root == package else set()), 'Unmanifested file')
        for r in manifest['files']:
            p = root/r['path']; require(p.stat().st_size == r['bytes'] and sha(p) == r['sha256'], 'Evidence/package drift')
    require(sha(ROOT/'engineering/TRIAGE_EXPANDED_PLAN_2026-10-12.md') == locks['expanded_plan_sha256'], 'Plan changed')
    require(sha(CANARY/'selection.json') == locks['selection_sha256'] and sha(ROOT/'study/filtering_policy.py') == locks['frozen_prompt_code_sha256'], 'Selection/prompt drift')
    require(sha(ROOT/'study/filter_input_contract.py') == locks['decision_validator_source_sha256'], 'Validator drift')
    for name in ('filtering_policy.py','triage_pilot.py','filter_decision.py'):
        require((package/'inference_code'/name).read_bytes() == (CANARY/'attempt-02/canary-package-v2/inference_code'/name).read_bytes(), 'Canary decision semantics changed')
    selection = read(CANARY/'selection.json')
    population = {c:rows(QUALIFIED/'joint-feasible-v1'/(c+'.jsonl')) for c in ('alert_only','context')}
    budgets = read(QUALIFIED/'combined_selection.json')
    require(sha(QUALIFIED/'combined_selection.json') == selection['source_selection_sha256'], 'Token-budget selection changed')
    for c in population:
        require(sha(QUALIFIED/'joint-feasible-v1'/(c+'.jsonl')) == selection['source_packet_hashes'][c], 'Qualified packet source changed')
    selected, canary = select_pilot(population['alert_only'],population['context'],budgets,{p['finding_id'] for p in population['alert_only'][:314]})
    require(selected == selection['strata'] and canary == selection['canary'], 'Selection not reproduced')
    config = read(package/'inputs/configuration.json'); packets = {c:rows(package/'inputs'/(c+'.jsonl')) for c in population}
    validate_population(config,packets)
    require([x['finding_id'] for x in selected] == [x['finding_id'] for x in config['cases']], 'Full population/order differs')
    for c in packets:
        index = {p['finding_id']:p for p in population[c]}
        require(all(p == index[p['finding_id']] for p in packets[c]), 'Selected packet bytes changed semantically')
    for i,case in enumerate(config['cases']):
        budget = next(b for b in budgets if b['finding_id'] == case['finding_id'])
        require(case['counts'] == budget['counts'] and case['input_format'] == input_format(packets['alert_only'][i]), 'Count/format changed')
    before = read(remote/'host_before.json'); after = read(remote/'host_after.json')
    require(all(after['container_config_hashes'].get(k) == v for k,v in before['container_config_hashes'].items()), 'Historical container changed')
    for k in ('images','volumes','networks','registry_sha256','other_project_paths'):
        require(before[k] == after[k], 'Other project metadata changed: '+k)
    require(not before['active_containers'] and not after['active_containers'], 'Active work at boundaries')
    require(set(after['container_config_hashes'])-set(before['container_config_hashes']) == set(summary['owned_container_ids']) and len(summary['owned_container_ids']) == 4, 'Unexpected created containers')
    require([r['key'] for r in summary['baselines']] == ['B0','B1'] and [r['key'] for r in summary['models']] == [m['key'] for m in locks['models']], 'Phase order differs')
    flat = []; details = []; phases = []; previous_end = None
    for record in summary['baselines']+summary['models']:
        key = record['key']; folder = remote/key; model = next((m for m in locks['models'] if m['key'] == key),None)
        state, resources, default_normalized = audit_container(folder,record,locks,model)
        if previous_end is not None: require(previous_end <= state['StartedAt'], 'Sequential phases overlap')
        previous_end = state['FinishedAt']
        probe = read(folder/'probe.json')
        require(probe == record['probe'] and probe['success'] and probe['interfaces'] == ['lo'] and probe['external_route_blocked'], 'Probe/network qualification differs')
        phases.append({'condition_or_model':key, 'container_wall_seconds':record['wall_seconds'],
                       'oom_kill_disable_false_to_null':default_normalized,
                       'input_loading_seconds':probe['input_loading_seconds'],
                       'minimum_host_available_memory_bytes':min(r['host_available_memory_bytes'] for r in resources),
                       'minimum_root_available_bytes':min(r['root_available_bytes'] for r in resources),
                       'load_seconds':probe.get('load_seconds'),
                       'process_lifetime_peak_rss_kib':probe.get('server_resources',probe.get('process_resources'))['max_rss_kib'],
                       'container_lifetime_peak_bytes':probe['cgroup_after']['peak_bytes']})
        decisions = rows(folder/'decisions.jsonl')
        if model is None:
            require(len(decisions) == probe['study_decisions'] == 29 and probe['study_generations'] == 0, 'Baseline count differs')
            policy = retain_all if key == 'B0' else baseline
            for i,(packet,r) in enumerate(zip(packets['alert_only'],decisions)):
                expected = policy(packet)
                require(r['finding_id'] == packet['finding_id'] and r['condition'] == key and r['decision'] == expected == read(folder/('case-'+str(i+1)+'-decision.json')), 'Baseline decision not reproduced')
                require(r['packet_sha256'] == hashlib.sha256(canonical(packet).encode()).hexdigest(), 'Baseline input identity changed')
                require(r['decision_interval_seconds'] > 0 and r['policy_cpu_ns_single_pass'] >= 0, 'Invalid baseline clock')
                require(0 < r['process_memory']['rss_kib'] <= r['process_memory']['high_water_rss_kib'] and r['cgroup_memory']['swap_current_bytes'] == 0, 'Baseline memory differs')
                flat.append({'condition':key,'finding_id':packet['finding_id'],'status':expected.get('status','completed'),
                             'action':expected.get('action','retain'),'effective_action':expected['effective_action'],
                             'error':'','request_seconds':'','decision_interval_seconds':r['decision_interval_seconds'],
                             'peak_server_rss_kib':r['process_memory']['rss_kib'],
                             'peak_cgroup_current_bytes':r['cgroup_memory']['current_bytes'],
                             'added_context':False})
            retained = sum(r['decision']['effective_action'] == 'retain' for r in decisions)
            batches = read(folder/'timing_batches.json'); audit_baseline_batches(batches,retained)
            require(probe['timing_policy_calls'] == 580000 and probe['timing_batches'] == 20 and probe['retained_sink'] == retained*20000, 'Baseline timing probe differs')
            phases[-1].update(policy_loop_median_wall_ns_per_call=statistics.median(b['wall_ns_per_call'] for b in batches),
                              policy_loop_median_cpu_ns_per_call=statistics.median(b['cpu_ns_per_call'] for b in batches))
            continue
        require(len(decisions) == probe['study_generations'] == 58 and probe['synthetic_generations'] == 2, 'Model count differs')
        properties = read(folder/'server_properties.json'); qualified = read(QUALIFIED/'ubuntu'/key/'server_properties.json')
        require(properties['total_slots'] == 1 and properties['model_path'] == '/model.gguf' and properties['default_generation_settings']['n_ctx'] == 4096, 'Model/slot/context differs')
        for field in ('build_info','chat_template','chat_template_caps','bos_token','eos_token'):
            require(properties[field] == qualified[field], 'Qualified template/runtime differs')
        requests = [(f'synthetic-{n}',config['synthetic_packet'],config['synthetic_prompt_tokens'][key],1,None,None) for n in (1,2)]
        requests += [('case-'+str(i+1)+'-'+c,packets[c][i],case['counts'][key]['alert' if c == 'alert_only' else 'selected_context'],384,c,case)
                     for i,case in enumerate(config['cases']) for c in ('alert_only','context')]
        replay = []
        for prefix,packet,expected_tokens,limit,condition,case in requests:
            m = read(folder/(prefix+'-measurement.json')); response = read(folder/(prefix+'-response.raw'))
            expected = chat_request(packet,max_tokens=limit); expected.update(cache_prompt=False,id_slot=0)
            require(read(folder/(prefix+'-request.json')) == expected, 'Prompt/request changed')
            require(m['success'] and m['synthetic'] == (condition is None) and m['request_id'] == prefix, 'Request failed or identity changed')
            require(m['finding_id'] == packet['finding_id'] and m['packet_sha256'] == hashlib.sha256(canonical(packet).encode()).hexdigest(), 'Request packet differs')
            reset = read(folder/(prefix+'-reset.raw'))
            require(reset['id_slot'] == 0 and isinstance(reset['n_erased'],int) and reset['n_erased'] >= 0, 'Cache erasure unconfirmed')
            check_response(response,m,expected_tokens,limit)
            memory = audit_memory(rows(folder/(prefix+'-memory.jsonl')),m)
            if condition is None: continue
            decision = classify_completion(response,packet,validate_decision)
            require(m['decision'] == decision and m['validation_seconds'] >= 0, 'Decision not reproduced')
            replay.append({**m,'condition':condition,'input_format':case['input_format'],'model':key})
            flat.append({'condition':key+'/'+condition,'finding_id':packet['finding_id'],'status':decision['status'],
                         'action':decision['action'],'effective_action':decision['effective_action'],'error':diagnose_invalid(response,packet,decision),
                         'request_seconds':m['request_seconds'],'decision_interval_seconds':m['decision_interval_seconds'],
                         'peak_server_rss_kib':memory['sampled_peak_server_rss_kib'],
                         'peak_cgroup_current_bytes':memory['sampled_peak_cgroup_current_bytes'],
                         'added_context':len(packet['evidence']) > 1})
            details.append({'model':key,'condition':condition,'finding_id':packet['finding_id'],'input_format':case['input_format'],
                            'finish_reason':response['choices'][0]['finish_reason'], 'reset_seconds':m['reset_seconds'],
                            'validation_seconds':m['validation_seconds'],
                            'server_cpu_seconds':sum(m['server_after'][k]-m['server_before'][k] for k in ('user_cpu_seconds','system_cpu_seconds')),
                            'memory_samples':memory['samples'],'max_sample_gap_seconds':memory['max_sample_gap_seconds'],**m['accounting']})
        require(decisions == replay, 'Decision journal differs from raw replay')
    require(len(flat) == 174 and len(details) == 116, 'Incomplete final table')
    condition_summaries = []
    for key in dict.fromkeys(r['condition'] for r in flat):
        values = [r for r in flat if r['condition'] == key]
        require(len(values) == 29, 'Unequal condition denominator')
        latency = [r['request_seconds'] for r in values if r['request_seconds'] != '']
        condition_summaries.append({'condition':key,'cases':29,'statuses':dict(Counter(r['status'] for r in values)),
             'actions':dict(Counter(r['action'] for r in values)),'effective_actions':dict(Counter(r['effective_action'] for r in values)),
             'errors':dict(Counter(r['error'] for r in values if r['error'])),
             'request_seconds_total':sum(latency) if latency else None,
             'request_seconds_median':statistics.median(latency) if latency else None,
             'request_seconds_min':min(latency) if latency else None,'request_seconds_max':max(latency) if latency else None,
             'decision_interval_seconds_total':sum(r['decision_interval_seconds'] for r in values),
             'peak_observed_rss_kib':max(r['peak_server_rss_kib'] for r in values),
             'peak_observed_cgroup_current_bytes':max(r['peak_cgroup_current_bytes'] for r in values),
             'added_context_cases':sum(r['added_context'] for r in values)})
    for name,values in [('audited_decisions.csv',flat),('audited_llm_accounting.csv',details)]:
        with (BASE/name).open('x',newline='') as stream: stream.write(csv_text(values))
    result = {'success':True,'verified_utc':datetime.now(timezone.utc).isoformat(),'cases':29,'conditions':condition_summaries,
              'study_decisions':174,'deterministic_decisions':58,'study_generations':116,'synthetic_generations':4,
              'phases':phases,'historical_containers_preserved':len(before['container_config_hashes']),
              'collected_files':len(read(BASE/'collection_manifest.json')['files']),
              'decisions_sha256':sha(BASE/'audited_decisions.csv'),'accounting_sha256':sha(BASE/'audited_llm_accounting.csv'),
              'new_security_labels':0,'scanners_invoked':False,
              'scope':'One fixed development batch. Validity is output-contract validity, not security correctness. No truth labels joined by this audit. RSS samples, cgroup accounting and lifetime high-water values have different scopes. Fixed order, no OS cache flush; no population timing ranking.'}
    with (BASE/'verification_summary.json').open('x') as stream: stream.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2))


if __name__ == '__main__': main()
