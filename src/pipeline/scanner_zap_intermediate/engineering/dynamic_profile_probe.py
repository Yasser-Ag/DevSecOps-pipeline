"""Exercise proxy/reference semantics and render private scanner inputs, without scanning."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.dynamic_reset_contract import require
from study.api_references import ownership, bearer_digest
from study.authorization_references import validate_access
from study.dynamic_scan_contract import (profiles, inputs, scanner_command, checker_command,
                                        generation_workload, compare_controls, LISTING, LOCATION, MISSING)
from engineering.dynamic_reset_probe import NoRedirect


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')
    temporary.chmod(0o600)
    # The backend probe runs as the target's root user; the proxy is unprivileged.
    # Keep the new private control owned by its dedicated directory owner.
    if os.geteuid() == 0:
        owner = path.parent.stat()
        os.chown(temporary, owner.st_uid, owner.st_gid)
    temporary.replace(path)


def request(base, method, path, body=None, token=None):
    require(base in ('http://crapi-web:80', 'http://127.0.0.1:8000', 'http://proxy:8080'), 'Unowned probe base')
    require(path.startswith('/') and not path.startswith('//'), 'Invalid probe route')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, method=method, headers=headers,
        data=None if body is None else json.dumps(body).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(4 * 1024**2 + 1)
        require(len(raw) <= 4 * 1024**2, 'Oversized probe response')
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw.decode(errors='replace')
        return {'status': response.code, 'body': body, 'body_sha256': hashlib.sha256(raw).hexdigest(),
                'headers': dict(response.headers.items())}


def crapi_matrix(base, fixture, mode):
    ids = ownership(fixture)
    rows = []
    for actor in ('a', 'b', 'absent', 'invalid'):
        token = fixture[actor]['token'] if actor in ('a', 'b') else None if actor == 'absent' else 'invalid-development-token'
        for owner in ('a', 'b'):
            response = request(base, 'GET', LOCATION.format(ids[owner]), token=token)
            rows.append({'id': actor + '-location-' + owner, 'response': response,
                         'passed': validate_access(response, actor, owner, mode, ids[owner], fixture[owner]['email'])})
    for actor in ('a', 'b'):
        response = request(base, 'GET', LISTING, token=fixture[actor]['token'])
        ok = response['status'] == 200 and isinstance(response['body'], list) and [x['uuid'] for x in response['body']] == [ids[actor]]
        rows.append({'id': actor + '-own-list', 'response': response, 'passed': ok})
    response = request(base, 'GET', LOCATION.format(MISSING), token=fixture['a']['token'])
    rows.append({'id': 'missing-object', 'response': response, 'passed': response['status'] == 404})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=['crapi', 'aigoat'])
    parser.add_argument('--output', type=Path, default=Path('/evidence'))
    args = parser.parse_args()
    out = args.output
    fixture = json.loads((out / 'private_fixture.json').read_text())
    if args.target == 'crapi':
        roles = {bearer_digest(x['token']): k for k, x in fixture.items()}
        roles[bearer_digest('invalid-development-token')] = 'invalid'
        route_owners = {LOCATION.format(v): k for k, v in ownership(fixture).items()}
        source = json.loads((Path('/study/reference/crapi_upstream.json')).read_text())
        direct_base = 'http://crapi-web:80'
    else:
        from engineering.aigoat_api import driver
        driver.request = request
        roles = {bearer_digest(x['token']): k for k, x in fixture['actors'].items()}
        roles[bearer_digest('invalid-aigoat-qualification-token')] = 'invalid'
        route_owners = {}
        source = json.loads((out / 'upstream_openapi.json').read_text())
        direct_base = 'http://127.0.0.1:8000'

    def phase(name, mode='raw', maximum=128):
        write(Path('/control/current.json'), {'target': args.target, 'phase': name, 'mode': mode,
              'max_requests': maximum, 'roles': roles, 'route_owners': route_owners})

    def matrix(name, base, mode='raw'):
        phase(name, mode)
        if args.target == 'crapi':
            rows = crapi_matrix(base, fixture, mode)
            write(out / (name + '.json'), {'controls': rows})
        else:
            driver.matrix(out, name, base)
            rows = json.loads((out / (name + '.json')).read_text())['controls']
        require(all(x['passed'] for x in rows), 'Reference assertion failed')
        return rows

    direct = matrix('dynamic-direct', direct_base)
    proxied = matrix('dynamic-proxy', 'http://proxy:8080')
    equivalence = compare_controls(args.target, direct, proxied)
    write(out / 'proxy_equivalence.json', equivalence)
    if args.target == 'crapi':
        matrix('dynamic-gated', 'http://proxy:8080', 'gated')
    phase('scope-controls')
    invalid = [('DELETE', LISTING, None), ('GET', '/identity/api/auth/login', None)] if args.target == 'crapi' else [
        ('DELETE', '/api/knowledge-base/', None), ('GET', '/api/auth/demo-users/', None),
        ('POST', '/api/surfaces/rag.kb/execute', {})]
    controls = []
    for method, path, body in invalid:
        response = request('http://proxy:8080', method, path, body)
        controls.append({'id': method + ' ' + path, 'response': response,
                         'passed': response['status'] == 403 and 'X-Study-Gate' in response['headers']})
    phase('budget-controls', maximum=2)
    route = LISTING if args.target == 'crapi' else '/api/products/'
    for i in range(3):
        response = request('http://proxy:8080', 'GET', route)
        passed = response['status'] == 429 and response['headers'].get('X-Study-Gate') == 'request_count_budget' if i == 2 else 'X-Study-Gate' not in response['headers']
        controls.append({'id': 'request-budget-' + str(i), 'response': response, 'passed': passed})
    write(out / 'gate_controls.json', controls)
    require(all(c['passed'] for c in controls), 'Proxy scope/budget control failed')
    bound = []
    for row in profiles():
        if row['target'] != args.target:
            continue
        directory = out / 'dynamic-inputs' / row['id']
        directory.mkdir(parents=True)
        values = inputs(row['id'], fixture, source, 'http://proxy:8080')
        if row['tool'] in ('nuclei', 'schemathesis', 'zap'):
            values['template.yaml'] = Path('/study/reference/http-missing-security-headers.yaml').read_text()
        for name, value in values.items():
            if isinstance(value, str):
                (directory / name).write_text(value)
                (directory / name).chmod(0o600)
            else:
                write(directory / name, value)
        command = checker_command(row['id']) if row['tool'] == 'restler' else scanner_command(
            row['id'], '/zap/wrk' if row['tool'] == 'zap' else '/work', 'http://proxy:8080', values['authorization.json']['token'])
        write(directory / 'command.json', command)
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.is_file()}
        bound.append({'id': row['id'], 'files': hashes, 'executed': False, 'native_input_root_is_placeholder': row['tool'] in ('nuclei', 'schemathesis')})
    write(out / 'bound_profiles.json', bound)
    if args.target == 'aigoat':
        write(out / 'generated_answer_workload.json', generation_workload())
    write(out / 'dynamic_profile_summary.json', {'success': True, 'equivalence': equivalence,
        'gate_controls': len(controls), 'bound_profiles': len(bound), 'scanner_invocations': 0, 'generations': 0,
        'scientific_execution': False})


if __name__ == '__main__':
    main()
