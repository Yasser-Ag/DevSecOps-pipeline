"""Fresh-state contracts for the retained dynamic targets, independent of scanners."""
import copy
import hashlib
import json
from pathlib import Path
import re

ROOT = Path('<LAB_ROOT>')
AIGOAT = ROOT / 'environment/aigoat-qualification-20261012-01'
PYTHON = 'python@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e'
BACKEND = 'sha256:182d2c61f364de5bb2c79d44c5948b0f9aed3eb9c9c4937cad514e6b2f5aaef5'
OLLAMA = 'sha256:4423b85c3df4a1a38c3dd04cbd7d46c31fab9a923ed18e52a6636018c8a6a679'
MODEL = 'mistral:7b-instruct-v0.3-q4_K_M'
MODEL_DIGEST = '6577803aa9a036369e481d648a2baebb381ebc6e897f2bb9a766a2aa7bfbc1cf'
CRAPI_SERVICES = {'api.mypremiumdealership.com', 'chromadb', 'crapi-chatbot',
                  'crapi-community', 'crapi-identity', 'crapi-web', 'crapi-workshop',
                  'mailhog', 'mongodb', 'postgresdb'}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def owned_output(path):
    path = Path(path)
    require(path.parent == ROOT / 'evidence' and
            re.fullmatch(r'dynamic-resets-preflight-20261022-0[1234]', path.name),
            'Only a new, scoped qualification output is allowed')
    require(not path.exists() and not path.is_symlink(), 'Preserve previous output')
    return path


def pinned(image):
    return bool(re.fullmatch(r'(?:[^\s]+@)?sha256:[0-9a-f]{64}', image))


def image_identity(requested, inspected):
    """Verify the exact locally resolved image; default listings omit some IDs."""
    require(pinned(requested), 'Mutable image reference')
    identities = {inspected['Id'], inspected.get('Descriptor', {}).get('digest')}
    identities.update(r.rsplit('@', 1)[-1] for r in inspected.get('RepoDigests', []))
    require(requested.rsplit('@', 1)[-1] in identities, 'Inspected image does not match the pinned reference')
    require(inspected.get('Architecture') == 'amd64' and inspected.get('Os') == 'linux', 'Unexpected target image platform')
    return {key: inspected.get(key) for key in
            ('Id', 'RepoDigests', 'Descriptor', 'Architecture', 'Os', 'Config', 'RootFS')}


def lock_rows(value):
    """Accept the two recorded lock schemas without weakening identity checks."""
    rows = ([{'path': key, 'sha256': digest} for key, digest in value.items()]
            if isinstance(value, dict) else value)
    require(isinstance(rows, list) and rows, 'Empty or unsupported lock inventory')
    for row in rows:
        path = Path(row['path'])
        require(not path.is_absolute() and '..' not in path.parts and bool(row['path']), 'Unsafe locked input path')
        require(re.fullmatch('[0-9a-f]{64}', row['sha256']), 'Invalid locked digest')
    require(len({r['path'] for r in rows}) == len(rows), 'Duplicate locked input')
    return rows


def model_inventory(root, expected):
    """Lock weights plus the observed Ollama migration metadata, without escaping."""
    root = Path(root)
    alias = 'manifests-v2/ollama.com/library/mistral/7b-instruct-v0.3-q4_K_M'
    target = 'blobs/sha256-' + MODEL_DIGEST
    metadata = 'metadata/sha256-f5074b1221da0f5a2910d33b642efa5b9eb58cfdddca1c79e16d7ad28aa2b31f.json'
    allowed = set(expected) | {alias, metadata}
    rows = {}
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            require(rel == alias and path.resolve() == (root / target).resolve() and
                    path.resolve().is_relative_to(root.resolve()), 'Unexpected model alias')
        if path.is_file():
            require(rel in allowed, 'Unexpected model-store file')
            rows[rel] = {'sha256': sha(path), 'bytes': path.stat().st_size,
                         'link': str(path.readlink()) if path.is_symlink() else None}
    require(set(rows) == allowed, 'Model store inventory differs')
    for rel, digest in expected.items():
        require(rows[rel]['sha256'] == digest and rows[rel]['link'] is None, 'Locked model file changed')
    return rows


def crapi_profile(template, name, state, network, volumes):
    """Keep target configurations; replace historical state and remove ingress."""
    require(set(template['services']) == CRAPI_SERVICES | {'lab-ingress', 'audit-proxy'},
            'Unexpected crAPI template services')
    result = {'name': name, 'services': {}, 'networks': {
        'default': {'external': True, 'name': network}}, 'volumes': {}}
    for service in sorted(CRAPI_SERVICES):
        cfg = copy.deepcopy(template['services'][service])
        require(pinned(cfg['image']), 'Target image must be immutable')
        require(not cfg.get('privileged') and not cfg.get('network_mode'), 'Unsafe target mode')
        require(not cfg.get('devices') and not cfg.get('cap_add'), 'Unexpected target privileges')
        cfg['container_name'] = name + '-' + service
        cfg['labels'] = {'org.study.project': 'devsecops-electronics', 'org.study.reset': name}
        cfg['ports'] = []
        cfg['networks'] = {'default': None}
        cfg['restart'] = 'no'
        cfg['pull_policy'] = 'never'
        cfg['logging'] = {'driver': 'json-file', 'options': {'max-size': '5m', 'max-file': '2'}}
        for mount in cfg.get('volumes', []):
            if mount['type'] == 'bind':
                require(service == 'crapi-identity' and mount['target'] == '/app/keys',
                        'Unexpected writable target bind')
                mount['source'] = str(Path(state) / 'keys')
            else:
                require(mount['type'] == 'volume' and mount['source'] in volumes, 'Unknown volume')
        if service == 'mongodb':
            # Mongo declares an additional image volume: name it explicitly for ownership.
            cfg['volumes'].append({'type': 'volume', 'source': 'mongo-config', 'target': '/data/configdb'})
        result['services'][service] = cfg
    for key, value in volumes.items():
        result['volumes'][key] = {'external': True, 'name': value}
    return result


def aigoat_profile(template, name, state, output, package, network):
    """Fresh SQLite/Chroma, shared read-only weights, no frontend or published port."""
    services = copy.deepcopy(template['services'])
    result = {'name': name, 'services': {}, 'networks': {
        'isolated': {'external': True, 'name': network}}}
    for key, image in [('backend', BACKEND), ('ollama', OLLAMA)]:
        cfg = services[key]
        cfg.update(image=image, container_name=name + '-' + key, pull_policy='never',
                   ports=[], labels={'org.study.project': 'devsecops-electronics', 'org.study.reset': name},
                   restart='no', networks=['isolated'])
        cfg['logging'] = {'driver': 'json-file', 'options': {'max-size': '5m', 'max-file': '2'}}
        if key == 'backend':
            cfg['command'] = ['python', '-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000']
            cfg.pop('depends_on', None)
            cfg['environment']['PYTHONDONTWRITEBYTECODE'] = '1'
            cfg['volumes'] = [str(Path(state) / 'data') + ':/app/data:rw',
                              str(AIGOAT / 'config.json') + ':/app/config/config.yml:ro',
                              str(AIGOAT / 'embedding') + ':/models/embedding:ro',
                              str(package) + ':/study:ro', str(output) + ':/evidence:rw']
        else:
            cfg['environment']['OLLAMA_MODELS'] = '/models'
            cfg['volumes'] = [str(AIGOAT / 'state/models/models') + ':/models:ro']
            # Keys/caches live in the new container layer; prior model state is immutable.
        result['services'][key] = cfg
    return result


def runtime_service(row, name, network='none'):
    cfg = copy.deepcopy(row['service'])
    require(row['case_id'] in {f'{prefix}{i:02d}' for prefix in ('C', 'D') for i in range(1, 7)},
            'Only the twelve safe runtime controls may execute')
    require(pinned(cfg['image']) and cfg.get('network_mode') == network == 'none', 'Unsafe image/network')
    require(not cfg.get('privileged') and not cfg.get('volumes') and not cfg.get('devices') and
            not cfg.get('cap_add') and cfg.get('cap_drop') == ['ALL'], 'Unsafe runtime control')
    require(int(cfg['mem_limit']) == 128 * 1024**2 and cfg['pids_limit'] == 32, 'Runtime resource bound differs')
    cfg.update(container_name=name, restart='no', pull_policy='never',
               labels={'org.study.project': 'devsecops-electronics', 'org.study.reset': name})
    cfg.pop('entrypoint', None)
    return cfg


def runtime_assertion(row, value):
    require(value.get('cap_eff') == '0000000000000000', 'Effective capabilities are not empty')
    key = row['property']
    if key in ('runtime_uid_zero', 'final_default_process_uid_zero'):
        observed = value['uid'] == 0
    elif key == 'writable_rootfs':
        require(value.get('write_errno') in (None, 30), 'Write failed for a reason other than read-only filesystem')
        observed = value['rootfs_writable']
    elif key == 'no_new_privileges_disabled':
        observed = value['no_new_privs'] == 0
    else:
        raise ValueError('Unbound runtime property: ' + key)
    require(type(observed) is bool and observed == row['positive'], 'Runtime construction assertion differs')
    return {'case_id': row['case_id'], 'property': key, 'observed': observed,
            'expected': row['positive'], 'passed': True}


def semantic_signature(kind, records):
    """Compare behavior across resets without equating randomized IDs or tokens."""
    if kind == 'crapi':
        require(len(records) == 11 and all(r['passed'] for r in records), 'Incomplete crAPI controls')
        fields = ('id', 'status', 'matches_owner')
    else:
        require(len(records) == 13 and all(r['passed'] for r in records), 'Incomplete AIGoat controls')
        fields = ('id', 'status', 'expected_in_context', 'observed_in_context', 'exclusion_controls')
    signature = [{k: r[k] for k in fields if k in r} for r in records]
    require(len({r['id'] for r in signature}) == len(signature), 'Duplicated reference control')
    return sorted(signature, key=lambda r: r['id'])


def safe_seed_members(members):
    names = [m.name for m in members]
    require(len(names) == len(set(names)), 'Duplicated seed member')
    require(sum(m.size for m in members) <= 64 * 1024**2, 'Seed too large')
    for member in members:
        path = Path(member.name)
        require(not path.is_absolute() and '..' not in path.parts and
                path.parts and path.parts[0] == 'data' and (member.isfile() or member.isdir()),
                'Unsafe seed archive member')


def check_model_tags(value):
    rows = value.get('models', [])
    require(len(rows) == 1 and rows[0].get('name') == MODEL and rows[0].get('digest') == MODEL_DIGEST,
            'Unexpected target generator identity')
    return {'model': MODEL, 'digest': MODEL_DIGEST, 'generation_requested': False}
