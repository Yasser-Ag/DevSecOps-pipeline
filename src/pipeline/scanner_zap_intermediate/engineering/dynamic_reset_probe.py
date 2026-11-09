"""Bounded reference probes for reset qualification, never scanner measurements."""
import argparse
import hashlib
import json
from pathlib import Path
import quopri
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.api_references import ownership, vehicle_mail, location_matches
from study.dynamic_reset_contract import require, semantic_signature, check_model_tags


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(base, method, path, body=None, token=None):
    require(base in {'http://crapi-web:80', 'http://mailhog:8025', 'http://127.0.0.1:8000',
                     'http://ollama:11434'}, 'Unexpected reference target')
    require(path.startswith('/') and not path.startswith('//') and '#' not in path, 'Nonlocal reference route')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, method=method, headers=headers,
        data=None if body is None else json.dumps(body).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=180)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1048577)
        require(len(raw) <= 1048576, 'Reference response too large')
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors='replace')
        return {'status': response.code, 'body': parsed, 'body_sha256': hashlib.sha256(raw).hexdigest()}


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def crapi(out):
    base = 'http://crapi-web:80'
    accounts, setup, rows = {}, [], []
    # Deliberately reuse the same accounts in both fresh databases. A surviving
    # account from the previous reset must cause signup to fail, not be reused.
    for i, role in enumerate(('a', 'b')):
        email, password = 'reset-' + role + '@example.com', 'Lab!' + secrets.token_hex(12)
        signup = request(base, 'POST', '/identity/api/auth/signup',
                         {'email': email, 'password': password, 'name': 'Reset ' + role, 'number': '999000020' + str(i)})
        setup.append({'role': role, 'signup': signup})
        write(out / 'setup.json', setup)
        require(signup['status'] == 200, 'Fresh account signup failed')
        login = request(base, 'POST', '/identity/api/auth/login', {'email': email, 'password': password})
        require(login['status'] == 200 and isinstance(login['body'], dict) and login['body'].get('token'), 'Login failed')
        token, detail = login['body']['token'], None
        for attempt in range(20):
            messages = request('http://mailhog:8025', 'GET', '/api/v2/messages?limit=50')
            require(messages['status'] == 200, 'Mail listing failed')
            for mail in messages['body'].get('items', []):
                if email in [x.get('Mailbox', '') + '@' + x.get('Domain', '') for x in mail.get('To', [])]:
                    message = request('http://mailhog:8025', 'GET', '/api/v1/messages/' + urllib.parse.quote(mail['ID'], safe=''))
                    require(message['status'] == 200, 'Mail retrieval failed')
                    detail = vehicle_mail(quopri.decodestring(message['body']['Content']['Body']).decode())
                    break
            if detail:
                break
            time.sleep(1)
        require(detail, 'Enrollment mail missing')
        enrollment = request(base, 'POST', '/identity/api/v2/vehicle/add_vehicle', detail, token)
        require(enrollment['status'] == 200, 'Enrollment failed')
        listing = request(base, 'GET', '/identity/api/v2/vehicle/vehicles', token=token)
        require(listing['status'] == 200, 'Vehicle list failed')
        accounts[role] = {'email': email, 'token': token, 'vehicles': listing['body']}
        setup[-1].update(enrollment=enrollment, listing=listing)
        write(out / 'setup.json', setup)
    ids = ownership(accounts)
    write(out / 'private_fixture.json', accounts)
    (out / 'private_fixture.json').chmod(0o600)
    for actor, token in [(r, accounts[r]['token']) for r in ('a', 'b')] + [('absent', None), ('invalid', 'invalid-development-token')]:
        for owner in ('a', 'b'):
            response = request(base, 'GET', '/identity/api/v2/vehicle/' + ids[owner] + '/location', token=token)
            matches = location_matches(response, ids[owner], accounts[owner]['email'])
            passed = matches if actor in ('a', 'b') else response['status'] in (401, 403) and not matches
            rows.append({'id': actor + '-location-' + owner, 'status': response['status'],
                         'matches_owner': matches, 'passed': passed, 'response': response})
    for actor in ('a', 'b'):
        response = request(base, 'GET', '/identity/api/v2/vehicle/vehicles', token=accounts[actor]['token'])
        valid = response['status'] == 200 and len(response['body']) == 1 and response['body'][0]['uuid'] == ids[actor]
        rows.append({'id': actor + '-own-list', 'status': response['status'], 'passed': valid, 'response': response})
    response = request(base, 'GET', '/identity/api/v2/vehicle/<MASKED:fixture:125>/location', token=accounts['a']['token'])
    rows.append({'id': 'missing-object', 'status': response['status'], 'passed': response['status'] == 404, 'response': response})
    write(out / 'controls.json', rows)
    signature = semantic_signature('crapi', rows)
    write(out / 'summary.json', {'success': True, 'controls': len(rows), 'objects': ids, 'signature': signature,
          'scanner_invocations': 0, 'generations': 0, 'unit': 'one documented defect, two owned objects'})


def aigoat(out):
    from engineering.aigoat_api import driver
    driver.request = request
    driver.setup(out)
    driver.matrix(out, 'reference', 'http://127.0.0.1:8000')
    raw = json.loads((out / 'reference.json').read_text())
    rows = []
    for record in raw['controls']:
        row = {'id': record['id'], 'status': record['response']['status'], 'passed': record['passed']}
        if 'expected_in_context' in record:
            row.update(expected_in_context=record['expected_in_context'],
                       observed_in_context=sorted({s[1] for s in record['context_signature']}),
                       exclusion_controls=sorted({s[2] for s in record['context_signature'] if s[2] is not None}))
        rows.append(row)
    tags = request('http://ollama:11434', 'GET', '/api/tags')
    write(out / 'model_tags.json', tags)
    require(tags['status'] == 200, 'Target generator unavailable')
    model = check_model_tags(tags['body'])
    write(out / 'summary.json', {'success': True, 'controls': len(rows), 'signature': semantic_signature('aigoat', rows),
          'ownership_unchanged': raw['ownership_unchanged'], 'target_generator': model,
          'scanner_invocations': 0, 'generations': 0,
          'unit': 'one retrieval ACL scenario, two documents; no generated-answer claim'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['crapi', 'aigoat'])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    (crapi if args.kind == 'crapi' else aigoat)(args.output)


if __name__ == '__main__':
    main()
