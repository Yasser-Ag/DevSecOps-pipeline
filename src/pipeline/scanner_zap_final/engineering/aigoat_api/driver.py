"""Create isolated fixtures and record reference controls, never detector findings."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import urllib.error
import urllib.request

if __package__:
    from .contract import QUERIES
else:
    from contract import QUERIES


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def request(base, method, path, body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        response = urllib.request.urlopen(req, timeout=180)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(1048577)
        if len(data) > 1048576:
            raise ValueError('Reference response too large')
        try:
            parsed = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            parsed = {'unparsed_body': data.decode('utf-8', errors='replace')}
        return {'status': response.code, 'body': parsed,
                'body_sha256': hashlib.sha256(data).hexdigest(), 'gate': response.headers.get('X-Study-Gate')}


def database_documents(ids):
    with sqlite3.connect('file:/app/data/aigoat.db?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        return [dict(db.execute('SELECT id, title, owner_id, content FROM knowledge_base_entries WHERE id=?', (i,)).fetchone()) for i in ids]


def setup(out):
    base = 'http://127.0.0.1:8000'
    users = request(base, 'GET', '/api/auth/demo-users/')['body']['users']
    with sqlite3.connect('file:/app/data/aigoat.db?mode=ro', uri=True) as db:
        actor_ids = dict(db.execute('SELECT username, id FROM users WHERE username IN (?, ?)', ('alice', 'bob')).fetchall())
    actors = {u['username']: {'id': actor_ids[u['username']], 'token': u['demo_token']}
              for u in users if u['username'] in ('alice', 'bob')}
    if set(actors) != {'alice', 'bob'} or actors['alice']['id'] == actors['bob']['id']:
        raise ValueError('Two distinct fixture actors required')
    docs = {}
    for i, name in enumerate(('alice', 'bob')):
        marker = name.upper() + 'QUAL20261012'
        payload = {'title': name.title() + ' qualification coupon',
                   'content': f'The private qualification coupon for {name.title()} is {marker}. This document belongs to {name.title()}.',
                   'category': 'qualification', 'trust_tier': 'user'}
        response = request(base, 'POST', '/api/knowledge-base/', payload, actors[name]['token'])
        save(out / ('created_' + name + '.json'), {'request': payload, 'response': response})
        if response['status'] != 200:
            raise ValueError('Fixture document creation failed')
        docs[name] = {'id': response['body']['id'], 'query': QUERIES[i], 'marker': marker, 'payload': payload}
    sync = request(base, 'PATCH', '/api/knowledge-base/', token=actors['alice']['token'])
    save(out / 'sync.json', sync)
    if sync['status'] != 200:
        raise ValueError('Fixture indexing failed')
    fixture = {'actors': actors, 'documents': docs}
    save(out / 'private_fixture.json', fixture); (out / 'private_fixture.json').chmod(0o600)
    rows = database_documents([d['id'] for d in docs.values()])
    for row, (name, doc) in zip(rows, docs.items()):
        if row['owner_id'] != actors[name]['id'] or row['content'] != doc['payload']['content']:
            raise ValueError('Independent fixture ownership/content mismatch')
    save(out / 'ownership_before.json', rows)
    save(out / 'public_fixture.json', {'actors': {name: {'id': actor['id']} for name, actor in actors.items()}, 'documents': docs})
    schema = request(base, 'GET', '/openapi.json')
    if schema['status'] != 200:
        raise ValueError('Runtime OpenAPI acquisition failed')
    save(out / 'upstream_openapi.json', schema['body'])


def matrix(out, label, base):
    fixture = json.loads((out / 'private_fixture.json').read_text())
    actors, docs = fixture['actors'], fixture['documents']
    records = []
    for owner, doc in docs.items():
        for actor in ('alice', 'bob'):
            for level in (0, 2):
                payload = {'query': doc['query'], 'defense_level': level, 'top_k': 5, 'hybrid': False}
                response = request(base, 'POST', '/api/knowledge-base/trace', payload, actors[actor]['token'])
                candidates = response['body'].get('candidates', [])
                selected = [c for c in candidates if c.get('entry_id') == doc['id']]
                expected = actor == owner or level == 0
                passed = response['status'] == 200 and bool(selected) and all(bool(c['included_in_context']) == expected for c in selected)
                if not expected:
                    passed &= all(c.get('excluded_by_control') == 'retrieval.acl' for c in selected)
                records.append({'id': f'{owner}-document-{actor}-L{level}', 'actor': actor,
                                'request': payload, 'response': response, 'expected_in_context': expected,
                                'passed': passed, 'context_signature': sorted((c.get('chunk_id'), c.get('included_in_context'), c.get('excluded_by_control')) for c in selected)})
    for role, token in [('absent', None), ('invalid', 'invalid-aigoat-qualification-token')]:
        for method, path, body in [('GET', '/api/knowledge-base/', None), ('POST', '/api/knowledge-base/trace', {'query': QUERIES[0], 'top_k': 5, 'hybrid': False, 'defense_level': 0})]:
            response = request(base, method, path, body, token)
            records.append({'id': role + '-' + method, 'response': response, 'passed': response['status'] == 401})
    response = request(base, 'GET', '/api/products/')
    records.append({'id': 'public-products', 'response': response, 'passed': response['status'] == 200})
    ownership = database_documents([doc['id'] for doc in docs.values()])
    baseline = json.loads((out / 'ownership_before.json').read_text())
    result = {'label': label, 'base': base, 'controls': records, 'ownership_unchanged': ownership == baseline,
              'success': all(r['passed'] for r in records) and ownership == baseline,
              'scope': 'Reference-only checks; one scenario, two documents. No scanner finding or application-wide confidentiality claim.'}
    save(out / (label + '.json'), result)
    if not result['success']:
        raise ValueError('Reference checks failed: ' + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['setup', 'matrix', 'gate'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--label', default='reference')
    parser.add_argument('--base', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    if args.action == 'setup':
        setup(args.output)
    elif args.action == 'matrix':
        matrix(args.output, args.label, args.base)
    else:
        rows = []
        for method, path in [('DELETE', '/api/knowledge-base/'), ('POST', '/api/surfaces/rag.kb/execute'), ('GET', '/api/auth/demo-users/')]:
            result = request(args.base, method, path, {} if method == 'POST' else None)
            rows.append({'method': method, 'path': path, 'response': result, 'passed': result['status'] == 403 and bool(result['gate'])})
        save(args.output / 'gate_checks.json', rows)
        if not all(r['passed'] for r in rows):
            raise ValueError('Qualification route gate failed')


if __name__ == '__main__':
    main()
