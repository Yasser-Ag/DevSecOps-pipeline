"""Fresh native identities and evidence-bounded assertion reuse.

These adapters do not merge native records or manufacture reference labels.
Static assertion reuse is conditional on an independently verified unchanged
input state; dynamic and runtime endpoints additionally need fresh reference
evidence before scientific scoring.
"""
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from study.static_scan_contract import normalize, sha
from study.api_native_reports import parse_api_report
from study.dynamic_execution_contract import native_report


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def historical_work_roots(profile):
    """Derive exact run-root aliases from paired original and final argv values."""
    roots = set()
    for template in profile['argv']:
        if '{WORK}' not in template:
            continue
        parts = template.split('{WORK}')
        pattern = re.escape(parts[0])
        for i, part in enumerate(parts[1:]):
            pattern += (r'(?P<root><LAB_ROOT>/[^:]+?)' if i == 0 else r'(?P=root)') + re.escape(part)
        for original in profile['historical_command']:
            match = re.fullmatch(pattern, original)
            if match:
                roots.add(match['root'].rstrip('/'))
    return sorted(roots, key=lambda v: (-len(v), v))


# These fields identify serialization/occurrence positions, not claim semantics.
# Nested package IDs and native evidence remain untouched.
TRANSIENT_TOP = frozenset(('finding_id', 'native_index', 'native_locator',
                           'raw_report_sha256', 'truth', 'native_id', 'similarity_id'))


def canonical_content(value, aliases=()):
    if isinstance(value, str):
        for old, new in sorted(aliases, key=lambda x: -len(x[0])):
            require(old.startswith('/') and len(old) > 10, 'Overbroad path alias')
            # Only exact root tokens followed by a path boundary are substituted.
            value = re.sub(re.escape(old) + r'(?=/|$)', lambda _: new, value)
        return value
    if isinstance(value, list):
        return [canonical_content(x, aliases) for x in value]
    if isinstance(value, dict):
        return {k: canonical_content(v, aliases) for k, v in value.items()}
    return value


def semantic_content(row, aliases=()):
    return canonical_content({k: v for k, v in row.items() if k not in TRANSIENT_TOP}, aliases)


def static_rows(raw, profile, process_status='completed'):
    parsed = normalize(raw, profile['parser'], process_status,
                       redacted_secrets=profile['redacted_secrets'])
    findings = []
    for i, native in enumerate(parsed['findings']):
        row = deepcopy(native)
        if profile['parser'] == 'bandit':
            row['native_locator'] = '/results/' + str(i)
        require(isinstance(row.get('native_locator'), str), 'Native record lacks source pointer')
        findings.append(row)
    parsed['findings'] = findings
    return parsed


def catalog_entries(profile, parsed, scoped_observations, links):
    """Join the old oracle to its original bytes once, then use semantic keys."""
    index = {(r['raw_report_sha256'], r['native_locator']): r for r in scoped_observations}
    require(len(index) == len(scoped_observations), 'Duplicate historical source pointer')
    edge_index = defaultdict(list)
    for edge in links:
        edge_index[edge['finding_id']].append(edge)
    aliases = [(r, '<WORK>') for r in historical_work_roots(profile)]
    rows, accounted = [], set()
    for native in parsed['findings']:
        old = index.get((parsed['raw_report_sha256'], native['native_locator']))
        if old is None:
            continue
        content = semantic_content(native, aliases)
        rows.append({'profile_id': profile['id'], 'signature': digest(content), 'content': content,
                     'historical_finding_id': old['finding_id'], 'population': old['population'],
                     'scoped_native_label': old['native_label'], 'interpretation_evidence': old['evidence'],
                     'links': edge_index[old['finding_id']]})
        accounted.add(old['finding_id'])
    missing = sorted(r['finding_id'] for r in scoped_observations if r['finding_id'] not in accounted)
    require(not missing, 'Historical native pointer absent from bound report: ' + str(missing[:3]))
    return rows


def assertion_key(row):
    return digest({'population': row['population'], 'label': row['scoped_native_label'],
                   'links': sorted((r['case_id'], r['relation'], r['scope']) for r in row['links'])})


def adapt_static(raw, profile, context, catalog):
    required = ('job_id', 'block', 'work_root', 'input_contract_sha256', 'observed_input_sha256',
                'inputs_verified_before', 'inputs_verified_after', 'asset_lock_verified', 'process_status', 'origin')
    require(all(k in context for k in required), 'Incomplete static execution context')
    require(type(context['block']) is int and 1 <= context['block'] <= 5, 'Unknown repetition block')
    require(context['work_root'].startswith('/'), 'Missing absolute work root')
    require(context['origin'] in ('historical_replay', 'fresh_execution', 'synthetic_test'), 'Unspecified evidence origin')
    eligible_state = (context['asset_lock_verified'] is True and context['inputs_verified_before'] is True and context['inputs_verified_after'] is True
                      and context['observed_input_sha256'] == context['input_contract_sha256'])
    parsed = static_rows(raw, profile, context['process_status'])
    status = parsed['effective_status']
    usable = eligible_state and status == 'completed'
    candidates = defaultdict(list)
    for row in catalog:
        require(row['profile_id'] == profile['id'], 'Cross-profile catalog use')
        require(digest(row['content']) == row['signature'], 'Corrupt semantic catalog entry')
        candidates[row['signature']].append(row)
    aliases = [(context['work_root'], '<WORK>')]
    if context['origin'] == 'historical_replay':
        aliases += [(r, '<WORK>') for r in historical_work_roots(profile)]
    observations, edges = [], []
    for native in parsed['findings']:
        content = semantic_content(native, aliases)
        signature = digest(content)
        identity = 'native-' + digest([context['job_id'], profile['id'], parsed['raw_report_sha256'], native['native_locator']])
        matches = candidates.get(signature, [])
        interpretations = {assertion_key(r) for r in matches}
        runtime_ok = not any(r['population'] == 'docker' for r in matches) or context.get('runtime_reference_verified') is True
        bound = usable and len(interpretations) == 1 and runtime_ok
        row = {'finding_id': identity, 'profile_id': profile['id'], 'job_id': context['job_id'],
               'block': context['block'], 'raw_report_sha256': parsed['raw_report_sha256'],
               'native_locator': native['native_locator'], 'signature': signature, 'native_content': content,
               'population': matches[0]['population'] if bound else None,
               'scoped_native_label': matches[0]['scoped_native_label'] if bound else 'unresolved',
               'binding_status': ('bound_identical_assertion' if bound else 'input_state_unverified' if not eligible_state
                                  else 'incomplete_execution' if status != 'completed' else
                                  'runtime_reference_pending' if not runtime_ok else
                                  'ambiguous_interpretation' if len(interpretations) > 1 else 'unadjudicated'),
               'historical_witness_ids': sorted(r['historical_finding_id'] for r in matches) if bound else [],
               'scope': 'Same complete normalized assertion on the locked static input; not warning-pair equivalence.'}
        observations.append(row)
        if bound:
            for edge in matches[0]['links']:
                edges.append({**deepcopy(edge), 'finding_id': identity,
                              'binding_evidence': {'profile_id': profile['id'], 'signature': signature,
                                                   'input_contract_sha256': context['input_contract_sha256'],
                                                   'job_id': context['job_id']}})
    require(len({r['finding_id'] for r in observations}) == len(observations), 'Duplicate fresh native pointer')
    return {'profile_id': profile['id'], 'job_id': context['job_id'], 'status': status,
            'measurement_eligible': usable, 'input_state_verified': eligible_state,
            'raw_report_sha256': parsed['raw_report_sha256'], 'observations': observations,
            'links': edges, 'inventory': parsed.get('components', []), 'diagnostics': parsed['diagnostics'],
            'native_count': len(observations), 'bound_assertions': sum(r['binding_status'] == 'bound_identical_assertion' for r in observations),
            'role': profile['role'], 'detector_count': None if profile['role'] == 'inventory' or not usable else len(observations),
            'new_human_annotations': 0, 'evidence_origin': context['origin'],
            'new_scientific_measurement': context['origin'] == 'fresh_execution'}


def fixture_identity(target, fixture, base_urls=()):
    """Public role/coordinate aliases only; no token values enter this artifact."""
    authorities = []
    for url in base_urls:
        parsed = urlsplit(url)
        require(parsed.scheme == 'http' and parsed.netloc and not parsed.username and
                not parsed.password and parsed.path in ('', '/'), 'Invalid owned proxy origin')
        authorities.append(parsed.netloc)
    if target == 'crapi':
        from study.api_references import ownership
        ids = ownership(fixture)
        require(set(ids) == {'a', 'b'} and len(set(ids.values())) == 2, 'Invalid crAPI ownership fixture')
        routes = {'/identity/api/v2/vehicle/' + v + '/location': '/identity/api/v2/vehicle/{owner:' + k + '}/location'
                  for k, v in ids.items()}
        return {'target': target, 'route_aliases': routes, 'document_aliases': {},
                'allowed_authorities': authorities, 'roles': ['a', 'b', 'absent', 'invalid']}
    require(target == 'aigoat', 'Unknown fixture target')
    require(set(fixture['actors']) == {'alice', 'bob'}, 'Unexpected AIGoat actors')
    docs = fixture['documents']
    require(set(docs) == {'alice', 'bob'} and docs['alice']['id'] != docs['bob']['id'], 'Invalid document fixture')
    return {'target': target, 'route_aliases': {}, 'allowed_authorities': authorities,
            'document_aliases': {str(v['id']): 'document-owner:' + k for k, v in docs.items()},
            'roles': ['alice', 'bob', 'absent', 'invalid']}


def logical_route(value, fixture):
    parsed = urlsplit(value)
    # Preserve query and fragment: neither is silently stripped from identity.
    return fixture['route_aliases'].get(parsed.path, parsed.path) + (
        '?' + parsed.query if parsed.query else '') + ('#' + parsed.fragment if parsed.fragment else '')


def request_coordinate(native, trace, fixture):
    method, url = native.get('method'), native.get('url')
    request = native.get('request')
    if request:
        match = re.fullmatch(r'([A-Z]+) (\S+) HTTP/[0-9.]+', request.splitlines()[0])
        require(match is not None, 'Unknown native request line')
        require(method is None or method == match[1], 'Contradictory native method')
        require(url and logical_route(match[2], fixture) == logical_route(url, fixture), 'Native request and URL disagree')
        method = match[1]
    if not method or not url:
        return {'status': 'unlocalized', 'reason': 'Native request coordinate unavailable'}
    origin = urlsplit(url)
    if origin.scheme != 'http' or origin.netloc not in fixture['allowed_authorities'] or origin.username:
        return {'status': 'unresolved', 'reason': 'Native origin is not the recorded owned proxy'}
    path = logical_route(url, fixture)
    candidates = [r for r in trace if r.get('forwarded') and r.get('method') == method
                  and logical_route(r.get('path', ''), fixture) == path]
    identities = {(r.get('auth_role'), r.get('status')) for r in candidates}
    if not candidates or len(identities) != 1:
        return {'status': 'unresolved', 'reason': 'Missing or ambiguous role/status trace',
                'method': method, 'path': path, 'candidate_contexts': sorted([list(x) for x in identities], key=str)}
    role, status = next(iter(identities))
    if role not in fixture['roles'] or type(status) is not int:
        return {'status': 'unresolved', 'reason': 'Unqualified role/status'}
    return {'status': 'localized', 'method': method, 'path': path, 'actor': role, 'response_status': status,
            'trace_request_ids': [r.get('sequence') for r in candidates]}


def adapt_dynamic(directory, profile, context, trace, fixture):
    """Retain native alert/bucket units and bind fresh logical coordinates."""
    parsed = native_report(profile['tool'], directory)
    records = []
    if profile['tool'] == 'restler':
        for native in parsed['units']:
            path = Path(directory) / native['native_path']
            records.append((sha(path), '/', {'unit': 'native_bug_bucket', **native}))
    else:
        report = parsed['reports'][0]
        normalized = parse_api_report(Path(directory) / report['path'], profile['tool'], context['process_status'])
        records = [(report['sha256'], r['native_locator'], r) for r in normalized['findings']]
    observations = []
    for raw_sha, pointer, native in records:
        if profile['tool'] == 'restler':
            coordinate = {'status': 'bucket_coordinate_only', 'method': native['reported_method'],
                          'path': logical_route(native['reported_endpoint'], fixture),
                          'requires': 'Fresh independent shadow-user response evidence; stored replay is not the oracle.'}
        else:
            coordinate = request_coordinate(native, trace, fixture)
        observations.append({'finding_id': 'native-' + digest([context['job_id'], profile['id'], raw_sha, pointer]),
                             'profile_id': profile['id'], 'job_id': context['job_id'], 'block': context['block'],
                             'raw_report_sha256': raw_sha, 'native_locator': pointer,
                             'native_content': native, 'coordinate': coordinate, 'scoped_native_label': 'unresolved'})
    require(len({r['finding_id'] for r in observations}) == len(observations), 'Duplicate native dynamic identity')
    complete = (context['process_status'] == 'completed' and context.get('reference_before_passed') is True
                and context.get('reference_after_passed') is True and not parsed['limitations'])
    return {'profile_id': profile['id'], 'job_id': context['job_id'], 'observations': observations,
            'native_count': len(observations), 'measurement_eligible': complete,
            'reference_state_verified': context.get('reference_before_passed') is True and context.get('reference_after_passed') is True,
            'reports': parsed['reports'], 'limitations': parsed['limitations'],
            'native_labels_assigned': False, 'role': profile['role'],
            'scope': 'Fresh request identities; scientific endpoint projection needs independent current reference evidence.'}


def generation_observations(rows, expected_ids, fixture):
    ids = [r['id'] for r in rows]
    require(len(set(ids)) == len(ids) and set(ids) <= set(expected_ids), 'Unexpected generation request')
    result = []
    for identity in expected_ids:
        row = next((r for r in rows if r['id'] == identity), None)
        result.append({'request_id': identity, 'attempted': row is not None,
                       'status': row.get('status') if row else 'not_run',
                       'http_status': row.get('http_status') if row else None,
                       'non_fallback_reply': row.get('non_fallback_reply') if row else None,
                       'marker_emitted': row.get('marker_emitted') if row else None,
                       'reference_in_context': row.get('reference_in_context') if row else None,
                       'wall_seconds': row.get('elapsed_seconds') if row else None,
                       'document': ('document-owner:' + row.get('request', {}).get('owner', '')) if row else None,
                       'role': 'target_behavior_not_scanner_or_triage'})
    return result
