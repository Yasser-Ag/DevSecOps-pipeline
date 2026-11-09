"""Construct bounded development controls independently of detector output."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import yaml


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def inspect_key(path, public=False):
    """Use OpenSSL to derive a format-independent public-key identity."""
    command = ['openssl', 'pkey'] + (['-pubin'] if public else [])
    command += ['-in', str(path), '-pubout', '-outform', 'DER']
    p = subprocess.run(command, capture_output=True, timeout=30)
    return {'parse_exit_code': p.returncode,
            'public_der_sha256': hashlib.sha256(p.stdout).hexdigest() if p.returncode == 0 else None,
            'stderr': p.stderr.decode(errors='replace')}


def docker_from_reference(base_image):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', base_image):
        raise ValueError('Invalid digest')
    # Dockerfile FROM requires a repository digest, not an image-ID-looking tag.
    return 'python@' + base_image


def generate(out, base_image, source_dir):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', base_image):
        raise ValueError('An immutable local image reference is required')
    out.mkdir(parents=True, exist_ok=False)
    inputs = out/'scanner-inputs'
    secrets = inputs/'secrets'; secrets.mkdir(parents=True)
    construction = out/'construction'; construction.mkdir()
    commands = []

    def run(argv):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        commands.append({'command': argv, 'exit_code': p.returncode, 'stderr': p.stderr})
        if p.returncode:
            raise RuntimeError('Independent key construction failed')

    for name in ('s01.pem', 's04.pem'):
        run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
             '-out', str(secrets/name)])
    shutil.copyfile(secrets/'s01.pem', secrets/'s02.pem')
    run(['openssl', 'pkey', '-in', str(secrets/'s01.pem'), '-traditional', '-out', str(secrets/'s03.pem')])
    run(['openssl', 'pkey', '-in', str(secrets/'s01.pem'), '-pubout', '-out', str(secrets/'s05.pem')])
    run(['openssl', 'req', '-new', '-x509', '-key', str(secrets/'s01.pem'), '-subj',
         '/CN=development.invalid', '-days', '1', '-out', str(secrets/'s06.pem')])
    (secrets/'s07.txt').write_text('PRIVATE_KEY_FILE=${RUNTIME_KEY_FILE}\n')
    secret_rows = []
    for index in range(1, 8):
        path = secrets/('s%02d.' % index + ('txt' if index == 7 else 'pem'))
        parsed = inspect_key(path)
        if (parsed['parse_exit_code'] == 0) != (index <= 4):
            raise ValueError('Private-material assertion failed')
        secret_rows.append({'case_id': 'S%02d' % index, 'path': str(path.relative_to(inputs)),
                            'property': 'parseable_private_key_material', 'positive': index <= 4,
                            'key_identity': parsed['public_der_sha256'], 'independent_parse': parsed,
                            'credential_validity': 'not_registered_or_tested', 'sha256': sha(path)})
    if len({r['key_identity'] for r in secret_rows if r['positive']}) != 2:
        raise ValueError('Expected two distinct generated key identities')
    public = inspect_key(secrets/'s05.pem', public=True)
    if public['public_der_sha256'] != secret_rows[0]['key_identity']:
        raise ValueError('Public control identity mismatch')
    write_json(construction/'commands.json', commands)
    write_json(construction/'public-control.json', public)
    (construction/'openssl-version.txt').write_text(subprocess.check_output(['openssl', 'version', '-a'], text=True))

    # These expected final UIDs are defined before builds or detector execution.
    base_from = docker_from_reference(base_image)
    specifications = [
        ('D01', f'FROM {base_from}\nUSER 65532:65532\n', 65532, 'explicit_final_nonroot'),
        ('D02', f'FROM {base_from}\nUSER 0:0\n', 0, 'explicit_final_root'),
        ('D03', f'FROM {base_from} AS builder\nUSER 65532:65532\nFROM {base_from}\nUSER 0:0\n', 0, 'nonroot_builder_root_final'),
        ('D04', f'FROM {base_from} AS parent\nUSER 65532:65532\nFROM parent\n', 65532, 'inherited_nonroot_final'),
        ('D05', f'FROM {base_from} AS builder\nUSER 0:0\nFROM {base_from}\nUSER 65532:65532\n', 65532, 'root_builder_nonroot_final'),
        ('D06', f'FROM {base_from}\n', 0, 'base_default_user'),
    ]
    docker_rows = []
    for case, text, uid, mechanism in specifications:
        path = inputs/'docker'/case.lower()/'Dockerfile'; path.parent.mkdir(parents=True)
        path.write_text(text + 'CMD ["python", "-c", "print(1)"]\n')
        docker_rows.append({'case_id': case, 'path': str(path.relative_to(inputs)),
                            'property': 'final_default_process_uid_zero', 'positive': uid == 0,
                            'expected_uid': uid, 'mechanism': mechanism, 'sha256': sha(path),
                            'reference_status': 'construction_assertion_pending_runtime'})

    base = {'image': base_image, 'user': '65532:65532', 'network_mode': 'none',
            'read_only': True, 'privileged': False, 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m',
            'pids_limit': 32, 'cpus': 1.0, 'command': ['python', '-c', 'print(1)']}
    changes = [('runtime_uid_zero', 'user', '0:0', True),
               ('writable_rootfs', 'read_only', False, True),
               ('no_new_privileges_disabled', 'security_opt', [], True),
               ('privileged_enabled', 'privileged', True, False),
               ('host_network_enabled', 'network_mode', 'host', False),
               ('docker_socket_mounted', 'volumes', ['/var/run/docker.sock:/var/run/docker.sock:ro'], False)]
    compose_rows = []
    for group, (prop, key, value, runtime) in enumerate(changes):
        for offset in range(2):
            case = 'C%02d' % (group * 2 + offset + 1)
            service = json.loads(json.dumps(base))
            if offset:
                service[key] = value
            document = {'services': {'worker': service}}
            path = inputs/'compose'/case.lower()/'compose.yaml'; path.parent.mkdir(parents=True)
            path.write_text(yaml.safe_dump(document, sort_keys=False))
            compose_rows.append({'case_id': case, 'path': str(path.relative_to(inputs)),
                'resource': 'services.worker', 'property': prop, 'positive': bool(offset),
                'source_key': key, 'source_value': service.get(key), 'runtime_eligible': runtime,
                'sha256': sha(path), 'reference_status': 'declared_property',
                'runtime_scope': 'bounded_probe' if runtime else 'not_executed_static_only'})
    sources = out/'primary_sources'; shutil.copytree(source_dir, sources)
    doc_urls = {'compose-services.html': 'https://docs.docker.com/reference/compose-file/services/',
                'dockerfile.html': 'https://docs.docker.com/reference/dockerfile/',
                'openssl-pkey.html': 'https://docs.openssl.org/3.0/man1/openssl-pkey/'}
    manifest = {'schema_version': 'configuration-development-1',
        'created_before_scans_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'base_image': base_image, 'purpose': 'development_only', 'generator_sha256': sha(__file__),
        'secrets': secret_rows, 'docker': docker_rows, 'compose': compose_rows,
        'primary_sources': [{'path': p.name, 'url': doc_urls[p.name], 'sha256': sha(p)} for p in sorted(sources.iterdir())],
        'limits': ['Constructed controls, not representative applications or leaked active credentials.',
                   'Negative labels apply only to the named property.',
                   'Only safe Compose variants are executed; no exploitability claim.',
                   'Generated keys are nondeterministic; retained bytes define this corpus.']}
    write_json(out/'reference_manifest.json', manifest)
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--base-image', required=True); p.add_argument('--sources', type=Path, required=True)
    a = p.parse_args(); m = generate(a.output, a.base_image, a.sources)
    print(json.dumps({'secrets': len(m['secrets']), 'docker': len(m['docker']), 'compose': len(m['compose'])}))
