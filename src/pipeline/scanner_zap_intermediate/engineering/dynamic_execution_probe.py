"""Reference checks and fixed target generation; never invoke a scanner."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engineering.dynamic_profile_probe import crapi_matrix, request, write
from engineering.dynamic_reset_probe import NoRedirect
from study.dynamic_scan_contract import generation_workload
from study.dynamic_reset_contract import require


def model_request(route, body=None, timeout=180):
    require(route in ('/api/ps', '/api/generate'), 'Unknown generator control')
    data = None if body is None else json.dumps(body).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request('http://ollama:11434' + route, data=data, headers={'Content-Type': 'application/json'})
    start = time.monotonic()
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(1024**2 + 1)
        require(len(raw) <= 1024**2, 'Generator control response budget')
        return {'status': response.code, 'body': json.loads(raw), 'elapsed_seconds': time.monotonic() - start}


def generation(out, fixture):
    # Empty-prompt preload is measured separately; it is not an answer observation.
    model = generation_workload()[0]['model']
    write(out / 'generator-before.json', model_request('/api/ps'))
    write(out / 'generator-load.json', model_request('/api/generate',
          {'model': model, 'stream': False, 'keep_alive': -1}))
    loaded = model_request('/api/ps'); write(out / 'generator-loaded.json', loaded)
    require([x['name'] for x in loaded['body']['models']] == [model], 'Unexpected loaded generator')
    rows = []
    for case in generation_workload():
        start = time.monotonic()
        row = {'id': case['id'], 'request': case, 'status': 'running', 'started_unix': time.time()}
        token = fixture['actors'][case['actor']]['token']
        req = urllib.request.Request('http://127.0.0.1:8000' + case['route'], method=case['method'],
                data=json.dumps(case['body']).encode(), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        rows.append(row)
        write(out / 'generation.json', rows)
        try:
            try: response = opener.open(req, timeout=case['timeout_seconds'])
            except urllib.error.HTTPError as error: response = error
            with response:
                raw = response.read(1024**2 + 1)
                require(len(raw) <= 1024**2, 'Generated response budget')
                row.update(http_status=response.code, response=json.loads(raw), response_sha256=hashlib.sha256(raw).hexdigest())
            result = row['response'].get('result', {})
            reply = result.get('reply', '')
            require(isinstance(reply, str), 'Invalid generated reply type')
            doc = fixture['documents']['alice']
            row.update(non_fallback_reply=bool(reply.strip()) and reply != "I couldn't process that request.",
                       marker_emitted=doc['marker'] in reply,
                       reference_in_context=any(c.get('entry_id') == doc['id'] for c in result.get('context_used') or []),
                       status='completed' if row['http_status'] == 200 else 'failed')
        except Exception as error:
            row['status'] = 'failed'
            row['error'] = type(error).__name__ + ': ' + str(error)
        row['elapsed_seconds'] = time.monotonic() - start
        row['finished_unix'] = time.time()
        write(out / 'generation.json', rows)
    write(out / 'generator-after.json', model_request('/api/ps'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['reference', 'generation'])
    parser.add_argument('--target', choices=['crapi', 'aigoat'], required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--mode', choices=['raw', 'gated'], default='raw')
    args = parser.parse_args()
    require(args.name in ('before', 'after', 'generation'), 'Unknown evidence phase')
    out = Path('/evidence')
    fixture = json.loads((out / 'private_fixture.json').read_text())
    if args.action == 'generation':
        require(args.target == 'aigoat', 'Wrong generator target')
        generation(out, fixture)
    elif args.target == 'crapi':
        rows = crapi_matrix('http://proxy:8080', fixture, args.mode)
        write(out / (args.name + '.json'), {'controls': rows})
        require(all(x['passed'] for x in rows), 'Reference state drift')
    else:
        from engineering.aigoat_api import driver
        driver.request = request
        driver.matrix(out, args.name, 'http://proxy:8080')
        require(all(r['passed'] for r in json.loads((out / (args.name + '.json')).read_text())['controls']), 'Reference state drift')


if __name__ == '__main__':
    main()
