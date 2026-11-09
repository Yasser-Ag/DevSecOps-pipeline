"""Evidence contract for separately timed static-block construction controls."""
import json
import re
from pathlib import Path

from study.dynamic_reset_contract import require, sha, runtime_service, runtime_assertion, image_identity

CONTROL_SHA256 = '2a8f06be1a7d5ca0292aa88e8610f94f7dabe7bb1dd47ef434f8b054fce4bf38'
CASE_IDS = tuple(f'{prefix}{i:02d}' for prefix in ('D', 'C') for i in range(1, 7))


def load_controls(path):
    require(sha(path) == CONTROL_SHA256, 'Qualified runtime control definition changed')
    rows = json.loads(Path(path).read_text())
    require(tuple(r['case_id'] for r in rows) == CASE_IDS, 'Runtime control universe/order differs')
    for row in rows:
        runtime_service(row, 'validate-only')
    return rows


def control_id(block, phase, case):
    require(type(block) is int and 1 <= block <= 5 and phase in ('before', 'after') and
            case in CASE_IDS, 'Invalid runtime control coordinate')
    return f'b{block}-{phase}-{case.lower()}'


def schedule():
    return [{'id': control_id(b, p, c), 'block': b, 'phase': p, 'case_id': c}
            for b in range(1, 6) for p in ('before', 'after') for c in CASE_IDS]


def source_bindings(controls, locks):
    """Use exact source coordinates; several distinct Compose cases share bytes."""
    inputs = locks['inputs']['configuration']
    roots = [r for r in inputs if r['destination'] == 'reference/scanner-inputs']
    require(len(roots) == 1, 'Missing/duplicate runtime source input')
    files = {r['path']: r for r in roots[0]['files']}
    bindings = []
    for row in controls:
        case = row['case_id'].lower()
        rel = ('docker/' + case + '/Dockerfile' if case.startswith('d') else
               'compose/' + case + '/compose.yaml')
        require(files.get(rel, {}).get('sha256') == row['source_sha256'], 'Runtime source coordinate/hash differs: ' + rel)
        bindings.append({'case_id': row['case_id'], 'suite': 'configuration',
                         'destination': roots[0]['destination'], 'path': rel,
                         'source_sha256': row['source_sha256']})
    return bindings


def validate_container(info, row, name, run_id, identity, probe, image):
    """Check actual Docker state before trusting a probe's favorable output."""
    cfg, host = info['Config'], info['HostConfig']
    expected = runtime_service(row, name)
    image_identity(expected['image'], image)
    require(info['Image'] == image['Id'] and cfg['Image'] == expected['image'], 'Runtime image identity differs')
    require(re.fullmatch('[0-9a-f]{64}', info['Id']) and info['Name'] == '/' + name, 'Runtime container identity differs')
    require(cfg['Cmd'] == ['python', '-c', probe] and not cfg.get('Entrypoint'), 'Runtime probe command changed')
    require(cfg.get('User', '') == expected.get('user', image['Config'].get('User', '')), 'Runtime user override differs')
    labels = cfg.get('Labels', {})
    require(all(labels.get(k) == v for k, v in {
        'org.study.project': 'devsecops-electronics', 'org.study.run': run_id,
        'org.study.runtime': identity, 'org.study.reset': name}.items()), 'Unowned runtime container')
    require(host['NetworkMode'] == 'none' and not host.get('PortBindings') and not host.get('PublishAllPorts'), 'Runtime network/ports differ')
    require(not info.get('Mounts') and not cfg.get('Volumes') and not host.get('Binds') and
            not host.get('VolumesFrom') and not host.get('Tmpfs'), 'Runtime control has a mount')
    require(not host.get('Privileged') and not host.get('CapAdd') and host.get('CapDrop') == ['ALL'] and
            not host.get('Devices') and not host.get('DeviceRequests'), 'Runtime privileges differ')
    require(host.get('PidMode', '') == '' and host.get('IpcMode') == 'private' and
            host.get('UTSMode', '') == '' and host.get('UsernsMode', '') == '', 'Runtime namespaces differ')
    require(host.get('ReadonlyRootfs') is expected.get('read_only', False), 'Runtime root filesystem differs')
    require(sorted(host.get('SecurityOpt') or []) == sorted(expected.get('security_opt', [])), 'Runtime security options differ')
    require(host['Memory'] == 128 * 1024**2 and host['PidsLimit'] == 32 and
            host['NanoCpus'] == 10**9 and host['MemorySwap'] in (128 * 1024**2, 256 * 1024**2), 'Runtime resource bounds differ')
    require(host.get('RestartPolicy', {}).get('Name') == 'no' and not host.get('AutoRemove'), 'Runtime lifecycle differs')
    return True


def interval(row):
    start, end = row['started_monotonic_ns'], row['finished_monotonic_ns']
    require(type(start) is int and type(end) is int and 0 <= start <= end, 'Invalid monotonic interval')
    return start, end


def verify_phase(evidence, controls, block, phase, run_id, probe):
    prefix = f'runtime/b{block}/{phase}/'
    receipt = evidence.read(prefix + 'phase.json')
    require(receipt['block'] == block and receipt['phase'] == phase and receipt['run_id'] == run_id,
            'Cross-block/phase runtime evidence')
    require(receipt['status'] == 'completed' and receipt['control_file_sha256'] == CONTROL_SHA256,
            'Incomplete runtime phase or changed controls')
    require([r['case_id'] for r in receipt['controls']] == list(CASE_IDS), 'Incomplete runtime phase members')
    begin, end = interval(receipt)
    previous, assertions, container_ids = begin, [], []
    images = evidence.read(prefix + 'images.json')
    require(set(images) == {r['service']['image'] for r in controls}, 'Runtime image inventory differs')
    for row, member in zip(controls, receipt['controls']):
        case = row['case_id']; base = prefix + case + '/'
        require(member['receipt'] == base + 'receipt.json', 'Runtime receipt coordinate differs')
        path = evidence.bind(member['receipt'])
        require(sha(path) == member['sha256'], 'Runtime receipt changed')
        value = evidence.read(member['receipt'])
        identity = control_id(block, phase, case)
        require(value['id'] == identity and value['case_id'] == case and value['run_id'] == run_id and
                value['status'] == 'completed' and value['removed'] is True, 'Runtime control incomplete')
        start, stop = interval(value)
        require(previous <= start <= stop <= end, 'Overlapping/out-of-order runtime controls')
        previous = stop
        for name, digest in value['files'].items():
            require('/' not in name and name not in ('.', '..'), 'Unsafe control artifact')
            require(sha(evidence.bind(base + name)) == digest, 'Runtime artifact changed: ' + name)
        require({'created.json','finished.json','probe.stdout','probe.json','probe.stderr','resources.jsonl',
                 'remove.json','remove.stdout','remove.stderr','cleanup-before.json'} <= set(value['files']),
                'Missing runtime evidence binding')
        first, last = evidence.read(base + 'created.json'), evidence.read(base + 'finished.json')
        require(first['Id'] == last['Id'] == value['container_id'], 'Runtime container was substituted')
        for info in (first, last):
            validate_container(info, row, value['container_name'], run_id, identity, probe, images[row['service']['image']])
        require(first['State']['Status'] == 'created' and not first['State']['Running'], 'Runtime container was previously started')
        state = last['State']
        require(state['Status'] == 'exited' and not state['Running'] and state['ExitCode'] == 0 and not state['OOMKilled'],
                'Runtime probe did not exit normally')
        command = evidence.read(base + 'probe.json')
        require(command['argv'] == ['docker','start','-a',first['Id']] and command['returncode'] == 0 and
                not command.get('error'), 'Runtime probe command receipt differs')
        a, b = interval(command)
        require(start <= a <= b <= stop, 'Runtime probe timing outside control')
        removal = evidence.read(base + 'remove.json')
        require(removal['argv'] == ['docker','rm',first['Id']] and removal['returncode'] == 0 and
                not removal.get('error'), 'Runtime cleanup command receipt differs')
        c, d = interval(removal)
        require(b <= c <= d <= stop, 'Runtime cleanup timing differs')
        require(evidence.read(base + 'cleanup-before.json')['Id'] == first['Id'], 'Runtime cleanup identity differs')
        raw = json.loads(evidence.bind(base + 'probe.stdout').read_text())
        require(type(raw.get('uid')) is int and type(raw.get('gid')) is int and
                type(raw.get('no_new_privs')) is int and raw['no_new_privs'] in (0,1) and
                type(raw.get('rootfs_writable')) is bool and raw.get('write_errno') in (None,30),
                'Malformed raw runtime values')
        assertion = {**runtime_assertion(row, raw), 'raw': raw}
        require(assertion == value['assertion'], 'Runtime assertion differs from raw output')
        assertions.append(assertion); container_ids.append(first['Id'])
    require(len(set(container_ids)) == 12, 'Reused runtime container within phase')
    return {'interval': (begin, end), 'assertions': assertions, 'container_ids': container_ids,
            'elapsed_seconds': (end - begin) / 1e9}
