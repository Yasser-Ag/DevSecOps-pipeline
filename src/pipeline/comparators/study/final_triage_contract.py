"""Observable-only scheduling and isolation contract for the repeated triage study.

This module never reads evaluation labels and never launches a workload.
Repeated decisions measure execution stability, not independent vulnerabilities.
"""
from collections import Counter
import hashlib

from study.filtering_policy import canonical, chat_request

MODELS = ('qwen35-9b-q4km', 'gemma4-e4b-qat-q40')
CONDITIONS = ('alert_only', 'context')
BLOCKS = 4
CASES = 88
CONTEXT_LIMIT = 4096
OUTPUT_LIMIT = 384
TOKEN_MARGIN = 32
ORDER_SALT = 'dsxa-repeated-triage-20261022-v1'


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def validate_inputs(packets, tokens):
    if set(packets) != set(CONDITIONS):
        raise ValueError('Both information conditions are required')
    ids = [p['finding_id'] for p in packets['alert_only']]
    if len(ids) != CASES or len(set(ids)) != CASES:
        raise ValueError('Expected 88 unique, locked candidates')
    if [p['finding_id'] for p in packets['context']] != ids:
        raise ValueError('Paired input identity/order differs')
    if len(tokens) != CASES or {t['finding_id'] for t in tokens} != set(ids):
        raise ValueError('Token qualification identity differs')
    by_token = {t['finding_id']: t for t in tokens}
    for index, fid in enumerate(ids):
        a, c = (packets[k][index] for k in CONDITIONS)
        for packet in (a, c):
            required = {'schema_version', 'finding_id', 'context_status', 'evidence'}
            if not required <= set(packet) or set(packet) - required - {'instructions'}:
                raise ValueError('Unexpected inference packet fields')
            if not packet['evidence'] or packet['evidence'][0]['id'] != 'alert':
                raise ValueError('Native alert is missing')
            evidence_ids = [e['id'] for e in packet['evidence']]
            if len(evidence_ids) != len(set(evidence_ids)):
                raise ValueError('Duplicate evidence ID')
        if len(a['evidence']) != 1 or a['evidence'][0] != c['evidence'][0]:
            raise ValueError('Information conditions changed the native claim')
        token = by_token[fid]
        if not token['alert_inference_eligible'] or not token['context_inference_eligible']:
            raise ValueError('Ineligible qualified packet')
        if digest(c) != token['selected_context_sha256']:
            raise ValueError('Qualified context changed')
        if set(token['counts']) != set(MODELS):
            raise ValueError('Both pinned model token counts are required')
        for counts in token['counts'].values():
            if set(counts) != {'alert', 'selected_context'}:
                raise ValueError('Unknown token accounting field')
            if any(type(n) is not int or n < 1 or
                   n + OUTPUT_LIMIT + TOKEN_MARGIN > CONTEXT_LIMIT for n in counts.values()):
                raise ValueError('Unqualified context/output budget')
    return ids


def request_payload(packet):
    return {**chat_request(packet, max_tokens=OUTPUT_LIMIT), 'cache_prompt': False, 'id_slot': 0}


def build_schedule(packets, tokens):
    ids = validate_inputs(packets, tokens)
    token_by_id = {t['finding_id']: t for t in tokens}
    packet_by_key = {(condition, p['finding_id']): p
                     for condition in CONDITIONS for p in packets[condition]}
    order = sorted(ids, key=lambda fid: digest([ORDER_SALT, fid]))
    rank = {fid: n for n, fid in enumerate(order)}
    jobs = []
    for block in range(BLOCKS):
        # ABBA between models; reversed case order on alternate blocks.
        models = MODELS if block in (0, 3) else MODELS[::-1]
        case_order = order if block % 2 == 0 else order[::-1]
        baselines = ('B0', 'B1') if block % 2 == 0 else ('B1', 'B0')
        for baseline in baselines:
            jobs.append({'job_id': f'b{block + 1}-{baseline}', 'kind': 'baseline',
                         'block': block + 1, 'condition': baseline, 'case_order': case_order})
        for model in models:
            requests = []
            for fid in case_order:
                # Each case receives each condition first twice, identically for both models.
                conditions = CONDITIONS if (rank[fid] + block) % 2 == 0 else CONDITIONS[::-1]
                for condition in conditions:
                    packet = packet_by_key[condition, fid]
                    requests.append({'finding_id': fid, 'condition': condition,
                        'request_key': model + '/' + condition + '/' + fid,
                        'packet_sha256': digest(packet),
                        'request_sha256': digest(request_payload(packet)),
                        'expected_prompt_tokens': token_by_id[fid]['counts'][model][
                            'alert' if condition == 'alert_only' else 'selected_context']})
            jobs.append({'job_id': f'b{block + 1}-{model}', 'kind': 'model',
                         'block': block + 1, 'model': model, 'requests': requests,
                         'synthetic_warmups': 2, 'new_server_process': True,
                         'slot_erase_before_every_request': True})
    return jobs


def validate_schedule(schedule, ids):
    if len(schedule) != 16 or len({j['job_id'] for j in schedule}) != 16:
        raise ValueError('Missing or duplicated phase')
    decisions = Counter()
    for job in schedule:
        if job['block'] not in range(1, BLOCKS + 1):
            raise ValueError('Invalid repeat block')
        if job['kind'] == 'baseline':
            if set(job['case_order']) != set(ids) or len(job['case_order']) != CASES:
                raise ValueError('Incomplete deterministic phase')
            for fid in job['case_order']:
                decisions[job['block'], job['condition'], fid] += 1
        elif job['kind'] == 'model':
            if job['model'] not in MODELS or len(job['requests']) != 2 * CASES:
                raise ValueError('Incomplete model phase')
            for row in job['requests']:
                if row['condition'] not in CONDITIONS or row['finding_id'] not in ids:
                    raise ValueError('Unexpected model condition/case')
                decisions[job['block'], job['model'] + ':' + row['condition'], row['finding_id']] += 1
        else:
            raise ValueError('Unknown phase')
    expected = {(b, c, fid) for b in range(1, BLOCKS + 1) for c in
                ('B0', 'B1') + tuple(m + ':' + c for m in MODELS for c in CONDITIONS) for fid in ids}
    if set(decisions) != expected or set(decisions.values()) != {1}:
        raise ValueError('Schedule does not pair every case/condition/block exactly once')
    return {'blocks': BLOCKS, 'jobs': len(schedule), 'cases': len(ids),
            'study_decisions': len(decisions), 'study_generations': CASES * 2 * 2 * BLOCKS,
            'synthetic_generations': 2 * 2 * BLOCKS}


def validate_mounts(info, expected):
    """Fail closed on extra mounts, changed access, host network or privileges."""
    host = info['HostConfig']
    if host['NetworkMode'] != 'none' or not host['ReadonlyRootfs'] or host.get('Privileged'):
        raise ValueError('Isolation boundary differs')
    if set(host.get('CapDrop') or ()) != {'ALL'} or host.get('CapAdd'):
        raise ValueError('Capability boundary differs')
    if not any(s in ('no-new-privileges', 'no-new-privileges:true') for s in host.get('SecurityOpt') or ()):
        raise ValueError('Privilege escalation guard missing')
    mounts = info['Mounts']
    if len(mounts) != len(expected) or {m['Destination'] for m in mounts} != set(expected):
        raise ValueError('Extra or missing mount')
    for mount in mounts:
        source, writable = expected[mount['Destination']]
        if mount['Type'] != 'bind' or mount['Source'] != source or mount['RW'] is not writable:
            raise ValueError('Changed mount source/access')


def require_execution_ready(manifest):
    gates = manifest.get('gates', [])
    if manifest.get('protocol') != 'v1.0' or manifest.get('final_campaign_ready') is not True:
        raise ValueError('Final protocol is not released')
    if len(gates) != 8 or {g['id'] for g in gates} != {f'G{i}' for i in range(1, 9)}:
        raise ValueError('Incomplete campaign gates')
    if any(g['passed'] is not True for g in gates):
        raise ValueError('Unmet campaign dependency')
