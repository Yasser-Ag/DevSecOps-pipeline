"""Retained dynamic workloads and their explicit measurement boundaries.

Inputs specify operations, actors and budgets, never expected detector labels.
The plan is not a protocol release or permission to execute a scientific run.
"""
import copy
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from study.dynamic_reset_contract import require
from study.api_references import ownership, project_schema
from study.authorization_references import single_route_schema
from engineering.aigoat_api.contract import permitted as rag_permitted, projected_schema

ZAP = 'sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef'
RESTLER = 'sha256:d53d78a15f1279d07315c503536c8c741889073dd02678aa57311e4a55f04af5'
SCHEMATHESIS = '<LAB_ROOT>/environment/toolset-completion-20260922-01/python/bin/schemathesis'
MISSING = '<MASKED:fixture:125>'
LOCATION = '/identity/api/v2/vehicle/{}/location'
LISTING = '/identity/api/v2/vehicle/vehicles'
REPEATS = 5


def profiles():
    rows = []
    for target, valid, lot in [('crapi', 'valid-a', 'E09'), ('aigoat', 'valid-alice', 'E10')]:
        for tool in ('schemathesis', 'nuclei', 'zap'):
            for condition in (valid, 'invalid'):
                rows.append({'id': target + '-' + tool + '-' + condition, 'target': target,
                    'tool': tool, 'condition': condition, 'lot': lot, 'role': 'native_detector',
                    'mode': ('passive_api_import' if target == 'aigoat' else 'active_api_scan') if tool == 'zap'
                            else 'finite_positive_generation' if target == 'aigoat' and tool == 'schemathesis'
                            else 'schema_generation' if tool == 'schemathesis' else 'one_upstream_header_template',
                    'timeout_seconds': (300 if tool == 'zap' else 150) if target == 'aigoat' else 480,
                    'accepted_exit_codes': [0, 1, 2] if tool == 'zap' else [0, 1] if tool == 'schemathesis' else [0],
                    'request_budget': 128 if target == 'aigoat' else 4096,
                    'budget_origin': 'retained development limit' if target == 'aigoat' else 'new explicit final engineering ceiling',
                    'transport_scope': 'crapi_read_only' if target == 'crapi' else '<MASKED:fixture:127>',
                    'reset': 'fresh target database and fixtures before each profile and repetition',
                    'reference_before_after': True})
    for owner in ('a', 'b'):
        for condition in ('raw-no-checker', 'raw-namespace', 'gated-namespace'):
            rows.append({'id': 'crapi-restler-' + owner + '-' + condition, 'target': 'crapi',
                'tool': 'restler', 'condition': condition, 'owner': owner, 'lot': 'E09',
                'role': 'directed_authorization_checker', 'mode': 'gated' if condition.startswith('gated') else 'raw',
                'checker_enabled': condition != 'raw-no-checker', 'timeout_seconds': 120,
                'accepted_exit_codes': [0], 'request_budget': 128,
                'budget_origin': 'new explicit final engineering ceiling',
                'transport_scope': '<MASKED:fixture:127>',
                'reset': 'fresh target database, fixtures and compiled grammar before each profile and repetition',
                'reference_before_after': True,
                'unit': 'two object directions within one documented authorization defect; gate is a constructed control'})
    return rows


def profile(identity):
    rows = [r for r in profiles() if r['id'] == identity]
    require(len(rows) == 1, 'Unknown dynamic profile')
    return copy.deepcopy(rows[0])


def proxy_base(base):
    parsed = urlsplit(base)
    require(parsed.scheme == 'http' and not parsed.username and not parsed.password and
            not parsed.query and not parsed.fragment and parsed.path == '' and parsed.port == 8080,
            'Invalid private proxy base')
    if parsed.hostname not in ('audit-proxy', 'authorization-proxy', 'proxy'):
        ip = ipaddress.ip_address(parsed.hostname or '')
        require(ip.version == 4 and any(ip in ipaddress.ip_network(n) for n in
                ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')), 'Proxy must use an owned private network')
    return parsed.hostname


def permitted(target, method, route, body, route_owners, scope='<MASKED:fixture:127>'):
    """Constrain the transport without supplying success labels to scanners."""
    require(scope in ('<MASKED:fixture:127>', 'crapi_read_only'), 'Unknown transport scope')
    if target == 'aigoat':
        require(scope == '<MASKED:fixture:127>', 'AIGoat retains its finite retrieval scope')
        return rag_permitted(method, route, body)
    require(target == 'crapi', 'Unknown target')
    parsed = urlsplit(route)
    if (parsed.scheme or parsed.netloc or parsed.fragment or len(route) > 2048 or not route.startswith('/') or
            any(ord(ch) < 32 or ord(ch) == 127 for ch in route)):
        return False, 'nonlocal_or_oversized_target'
    if scope == 'crapi_read_only':
        if method != 'GET':
            return False, 'method_or_route_outside_scope'
        return (not body), 'get_body' if body else None
    routes = set(route_owners) | {LISTING, LOCATION.format(MISSING)}
    if method != 'GET' or parsed.path not in routes:
        return False, 'method_or_route_outside_scope'
    return (not body), 'get_body' if body else None


def authorization_gate(method, path, actor, route_owners, mode):
    require(mode in ('raw', 'gated'), 'Unknown ownership control mode')
    owner = route_owners.get(urlsplit(path).path)
    return mode == 'gated' and method == 'GET' and owner is not None and actor in ('a', 'b') and actor != owner


def scanner_command(identity, directory, base, token):
    """Return exact native argv; authentication values stay in private run files."""
    row = profile(identity)
    require(row['tool'] != 'restler', 'Use the directed checker binding')
    hostname = proxy_base(base)
    d = Path(directory)
    require(d.is_absolute() and '..' not in d.parts, 'Input directory must be absolute')
    require(isinstance(token, str) and token and not any(c in token for c in '\r\n\x00'), 'Invalid ephemeral token')
    ai = row['target'] == 'aigoat'
    env = {}
    header = 'Authorization: Bearer ' + token
    if row['tool'] == 'nuclei':
        argv = ['/usr/local/bin/nuclei', '-l', str(d / 'urls.txt'), '-t', str(d / 'template.yaml'),
            '-config', str(d / 'nuclei.yml'), '-H', header, '-jsonl', '-o', str(d / 'nuclei.jsonl'),
            '-tlog', str(d / 'requests.jsonl'), '-elog', str(d / 'errors.jsonl'), '-duc', '-ni', '-silent',
            '-no-stdin', '-rl', '2' if ai else '5', '-c', '1', '-dr', '-retries', '0', '-timeout', '10' if ai else '5']
    elif row['tool'] == 'schemathesis':
        argv = [SCHEMATHESIS, 'run', str(d / 'openapi.json'), '--url', base, '--header', header,
                '--workers', '1', '--phases', 'examples,fuzzing']
        if ai:
            argv += ['--mode', 'positive', '--max-examples', '5', '--seed', '117', '--no-shrink',
                     '--request-timeout', '15', '--request-retries', '0']
        else:
            argv += ['--max-examples', '5', '--seed', '117', '--max-time', '30', '--request-timeout', '5']
        argv += ['--generation-database', 'none', '--checks', 'not_a_server_error',
                 '--report', 'json,junit,har', '--report-dir', str(d / 'reports')]
    else:
        env.update(ZAP_AUTH_HEADER='Authorization', ZAP_AUTH_HEADER_VALUE='Bearer ' + token,
                   ZAP_AUTH_HEADER_SITE=hostname)
        argv = ['/zap/zap-api-scan.py', '-t', str(d / 'openapi.json'), '-f', 'openapi']
        if ai:
            argv += ['-S']
        argv += ['-J', 'zap.json', '-P', '10091', '-T', '3', '-z',
                 '-silent -notel -config connection.timeoutInSecs=15' if ai else
                 '-silent -notel -config connection.timeoutInSecs=5 -config scanner.maxScanDurationInMins=1 -config scanner.threadPerHost=2']
    return {'argv': argv, 'environment_additions': env, 'cwd': str(d),
            'timeout_seconds': row['timeout_seconds'], 'accepted_exit_codes': row['accepted_exit_codes']}


def checker_command(identity):
    row = profile(identity)
    require(row['tool'] == 'restler', 'Not a directed checker profile')
    argv = ['/RESTler/restler/Restler', 'test', '--grammar_file', '/grammar/grammar.py',
            '--dictionary_file', '/grammar/dict.json', '--settings', '/work/settings.json',
            '--host', 'authorization-proxy', '--target_port', '8080', '--no_ssl']
    if row['checker_enabled']:
        argv += ['--enable_checkers', 'namespacerule']
    return {'argv': argv, 'cwd': '/work', 'image': RESTLER, 'timeout_seconds': row['timeout_seconds'],
            'accepted_exit_codes': [0], 'compile_argv': ['/RESTler/restler/Restler', 'compile', '--api_spec', '/work/openapi.json'],
            'compile_timeout_seconds': 180,
            'environment_additions': {'RESTLER_TELEMETRY_OPTOUT': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
                                      'DOTNET_CLI_HOME': '/tmp', 'HOME': '/tmp'}}


def inputs(identity, fixture, upstream, base):
    row = profile(identity)
    proxy_base(base)
    if row['target'] == 'crapi':
        ids = ownership(fixture)
        if row['tool'] == 'restler':
            owner = row['owner']
            shadow = 'b' if owner == 'a' else 'a'
            return {'openapi.json': single_route_schema(upstream, ids[owner], owner),
                'tokens.txt': json.dumps({owner: {}, shadow: {}}) + '\nAuthorization: Bearer ' + fixture[owner]['token'] +
                              '\nAuthorization: Bearer ' + fixture[shadow]['token'] + '\n',
                'settings.json': {'authentication': {'token': {'location': '/work/tokens.txt', 'token_refresh_interval': 3600}},
                    'checkers': {'namespacerule': {'trigger_on_dynamic_objects': False,
                                                  'trigger_objects': [LOCATION.format(ids[owner])]}},
                    'max_combinations': 1, 'max_sequence_length': 2, 'request_throttle_ms': 20, 'include_user_agent': False}}
        token = fixture['a']['token'] if row['condition'] == 'valid-a' else 'invalid-development-token'
        schema = project_schema(upstream, ids, base)
        urls = [base + LISTING] + [base + LOCATION.format(ids[x]) for x in ('a', 'b')]
    else:
        token = fixture['actors']['alice']['token'] if row['condition'] == 'valid-alice' else 'invalid-aigoat-qualification-token'
        schema = projected_schema(upstream, base)
        urls = [base + '/api/products/', base + '/api/knowledge-base/']
    return {'authorization.json': {'token': token}, 'openapi.json': schema,
            'urls.txt': '\n'.join(urls) + '\n', 'nuclei.yml': '{}\n'}


def generation_workload():
    """Keep four source-defined generator cases distinct from scanner and triage results."""
    return [{'id': 'alice-document-' + actor + '-L' + str(level), 'actor': actor, 'owner': 'alice',
        'method': 'POST', 'route': '/api/surfaces/rag.kb/execute',
        'body': {'input': {'message': 'What is the private qualification coupon for Alice?',
                          'use_kb': True, 'defense_level': level, 'top_k': 5, 'hybrid': False}},
        'timeout_seconds': 180, 'model': 'mistral:7b-instruct-v0.3-q4_K_M',
        'endpoints': ['HTTP completion', 'non-fallback reply', 'context membership', 'literal marker emission', 'wall time'],
        'scope': 'One fixed document scenario with two actors and two defense settings; not four independent vulnerabilities.'}
        for actor in ('alice', 'bob') for level in (0, 2)]


def compare_controls(target, direct, proxied):
    """Strict coverage and raw/semantic checks; a truncated zip cannot pass."""
    require(target in ('crapi', 'aigoat'), 'Unknown control family')
    count = 11 if target == 'crapi' else 13
    require(len(direct) == len(proxied) == count, 'Incomplete proxy equivalence matrix')
    a, b = ({r['id']: r for r in rows} for rows in (direct, proxied))
    require(len(a) == len(b) == count and a.keys() == b.keys(), 'Duplicate or mismatched control identities')
    for key in a:
        x, y = a[key], b[key]
        require(x['passed'] is True and y['passed'] is True, 'Reference control failed: ' + key)
        require(x['response']['status'] == y['response']['status'], 'Proxy status changed: ' + key)
        if target == 'crapi' and x['response']['status'] == 200:
            require(x['response']['body_sha256'] == y['response']['body_sha256'], 'Proxy changed successful response bytes')
        if target == 'aigoat':
            require(x.get('context_signature') == y.get('context_signature'), 'Proxy changed document context')
    return {'success': True, 'controls': count,
            'basis': 'status and successful response hashes' if target == 'crapi' else 'status and document/context membership; scores are not an equality endpoint'}


def transport_completion(rows, accepted_request_count):
    """A gate or transport failure is a limitation, never a target negative."""
    require(isinstance(rows, list) and rows, 'Missing independent request trace')
    errors = [r for r in rows if r.get('harness_error')]
    gates = [r for r in rows if r.get('gate_reason')]
    reached = [r for r in rows if r.get('forwarded')]
    return {'effective_transport_status': 'failed' if errors else 'completed_with_limitations' if gates else 'completed',
            'requests': len(rows), 'forwarded': len(reached), 'gate_responses': len(gates), 'harness_errors': len(errors),
            'actual_scope_verified': bool(reached) and len(reached) <= accepted_request_count,
            'gate_responses_are_target_findings': False}


def plan():
    rows = profiles()
    return {'schema': 'dynamic-scanner-bindings-v1', 'profiles': rows, 'repetitions': REPEATS,
        'planned_native_detector_invocations': 12 * REPEATS, 'planned_directed_checker_invocations': 6 * REPEATS,
        'planned_grammar_compilations': 6 * REPEATS, 'generation_workload': generation_workload(),
        'planned_target_generations': 4 * REPEATS,
        'target_generation_reset': 'fresh original seed, corpus and fixture for each four-case block; one sequential target generator; no triage model',
        'timing': 'Separate reset/fixture/compile/model-load costs from execution; record order and failures; no global host cache flush.',
        'independence': 'Repetitions measure execution variability, not new applications or independent defects.',
        'crapi_harness_amendments': ['No published ports; scanner-only internal network via fixed-upstream proxy.',
            'Native crAPI scanners retain relative GET discovery probes to the fixed isolated upstream; fixture-only routing is reserved for reference/RESTler controls.',
            'Request ceiling and body/response budgets; all rejected requests explicitly retained.',
            'Explicit empty Nuclei configuration replaces implicit host configuration; same pinned header template.'],
        'pending': ['Final controller must select and verify the locally replayed crapi_read_only scope for native scanners; Ubuntu preflight v2 qualified fixture scope only.',
                    'executable lifecycle/accounting binding for final jobs',
                    'whole-study applicability and analysis bindings', 'protocol v1.0 release'],
        'protocol_frozen': False, 'scientific_execution': False}
