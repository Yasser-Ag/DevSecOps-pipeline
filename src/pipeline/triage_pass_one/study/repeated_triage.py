"""Validate sealed observable inputs and select one repeated-triage phase."""
import hashlib
import json
from pathlib import Path

from study.final_triage_contract import (MODELS, build_schedule, validate_inputs,
    validate_schedule, request_payload, digest)

INPUT_FILES = {'alert_only.jsonl', 'context.jsonl', 'tokens.json', 'schedule.json',
               'requests.json', 'warmup.json', 'execution.json'}


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def read(path):
    return json.loads(path.read_text())


def verify_files(root, entries, additional=()):
    root = root.resolve()
    names = set()
    for row in entries:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() in names:
            raise ValueError('Unsafe or duplicate package entry')
        names.add(relative.as_posix())
        path = root / relative
        path.resolve().relative_to(root)
        if path.is_symlink() or not path.is_file() or path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
            raise ValueError('Sealed file drift: ' + relative.as_posix())
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != names | set(additional):
        raise ValueError('Unmanifested or missing files')


def load_inputs(root):
    root = Path(root)
    manifest = read(root / 'input_manifest.json')
    if {r['path'] for r in manifest['files']} != INPUT_FILES:
        raise ValueError('Input allowlist differs')
    verify_files(root, manifest['files'], ('input_manifest.json',))
    packets = {c: [json.loads(line) for line in (root / (c + '.jsonl')).read_text().splitlines()]
               for c in ('alert_only', 'context')}
    tokens = read(root / 'tokens.json')
    ids = validate_inputs(packets, tokens)
    schedule = read(root / 'schedule.json')
    totals = validate_schedule(schedule, ids)
    if schedule != build_schedule(packets, tokens):
        raise ValueError('Counterbalanced schedule differs from the bound contract')
    rows = read(root / 'requests.json')
    requests = {r['request_key']: r['payload'] for r in rows}
    expected = {m + '/' + c + '/' + p['finding_id']: request_payload(p)
                for m in MODELS for c in packets for p in packets[c]}
    if len(rows) != len(requests) or requests != expected:
        raise ValueError('Prompt/request specification drift')
    warmup = read(root / 'warmup.json')
    if set(warmup) != {'synthetic_packet', 'synthetic_prompt_tokens'} or set(warmup['synthetic_prompt_tokens']) != set(MODELS):
        raise ValueError('Synthetic warmup contract differs')
    if warmup['synthetic_packet']['finding_id'] in ids:
        raise ValueError('Warmup overlaps study cases')
    if any(type(n) is not int or not 1 <= n <= 3680 for n in warmup['synthetic_prompt_tokens'].values()):
        raise ValueError('Synthetic token budget invalid')
    execution = read(root / 'execution.json')
    expected_execution = {'schema': 'repeated-triage-1', 'baseline_timing_batches': 20,
        'baseline_passes_per_batch': 1000, 'model_phase_timeout_seconds': 21600,
        'baseline_phase_timeout_seconds': 180, 'preflight_phase_timeout_seconds': 180,
        'request_timeout_seconds': 300, 'server_readiness_timeout_seconds': 240,
        'container_memory_bytes': 12 * 1024**3, 'container_cpus': 8,
        'minimum_start_memory_bytes': 12 * 1024**3, 'minimum_free_disk_bytes': 20 * 1024**3}
    if execution != expected_execution:
        raise ValueError('Execution/measurement settings differ')
    return {'ids': ids, 'packets': packets, 'tokens': tokens, 'schedule': schedule,
            'requests': requests, 'warmup': warmup, 'execution': execution, 'totals': totals,
            'packet_index': {(c, p['finding_id']): p for c in packets for p in packets[c]}}


def select_job(data, job_id):
    selected = [j for j in data['schedule'] if j['job_id'] == job_id]
    if len(selected) != 1:
        raise ValueError('Unknown or duplicated job')
    return selected[0]


def request_rows(data, job):
    if job['kind'] != 'model':
        raise ValueError('Model requests required')
    for index, row in enumerate(job['requests'], 1):
        packet = data['packet_index'][row['condition'], row['finding_id']]
        payload = data['requests'][row['request_key']]
        if digest(packet) != row['packet_sha256'] or digest(payload) != row['request_sha256']:
            raise ValueError('Scheduled request changed')
        yield f'request-{index:03}', row, packet, payload
