"""Fresh, typed dynamic reference projections; no whole-warning label inference."""
import base64
import hashlib
import json

from study.final_output_adapter import logical_route, require
from study.api_references import location_matches


def header_predicate(native):
    rule = native.get('native_rule')
    if rule == 'http-missing-security-headers' and isinstance(native.get('matcher'), str):
        return 'missing_header:' + native['matcher'].lower()
    if rule == '10021':
        return 'missing_header:x-content-type-options'
    if rule == '100000' and native.get('native_alert_ref') == '100000-1':
        return 'response_is_4xx'
    return None


def http_projection(observation, references, reference_trace, fixture):
    coordinate = observation['coordinate']
    predicate = header_predicate(observation['native_content'])
    if coordinate['status'] != 'localized' or predicate is None:
        return {'status': 'unqualified', 'links': [], 'reason': 'No qualified native HTTP predicate/coordinate'}
    candidates = [r for r in reference_trace if r.get('phase') in ('before', 'after')
                  and r.get('forwarded') and not r.get('harness_error')
                  and r['method'] == coordinate['method'] and r['auth_role'] == coordinate['actor']
                  and logical_route(r['path'], fixture) == coordinate['path']]
    if {r['phase'] for r in candidates} != {'before', 'after'}:
        return {'status': 'reference_unavailable', 'links': []}
    values = []
    for r in candidates:
        headers = {h.lower() for h, _ in r['response_headers']}
        value = (predicate.split(':', 1)[1] not in headers) if predicate.startswith('missing_header:') else 400 <= r['status'] < 500
        values.append((r['status'], value))
    if len(set(values)) != 1 or values[0][0] != coordinate['response_status']:
        return {'status': 'reference_drift', 'links': [], 'observed_predicates': values}
    observed = values[0][1]
    ids = []
    for reference in references:
        c = reference.get('details', {}).get('coordinate', {})
        if (reference['population'] == 'aigoat-http-properties' and
                c.get('resource') == coordinate['method'] + ' ' + coordinate['path'] and
                c.get('context') == coordinate['actor'] and c.get('property') == predicate):
            ids.append(reference)
    require(len(ids) <= 1, 'Ambiguous frozen HTTP reference')
    if not ids:
        return {'status': 'outside_frozen_reference', 'links': [], 'observed_predicate': observed}
    reference = ids[0]
    expected = reference['truth'] == 'positive'
    if reference['truth'] not in ('positive', 'negative') or observed is not expected:
        return {'status': 'reference_drift', 'links': [], 'observed_predicate': observed}
    return {'status': 'verified_property', 'observed_predicate': observed,
            'links': [{'finding_id': observation['finding_id'], 'case_id': reference['case_id'],
                       'relation': 'supports' if observed else 'contradicts',
                       'scope': 'Fresh exact HTTP property only; native security correctness remains unassigned.'}],
            'witnesses': [{'phase': r['phase'], 'sequence': r['sequence'], 'response_sha256': r['response_sha256']}
                          for r in candidates], 'native_label': 'unresolved'}


def authorization_projection(observation, reference_by_owner, trace, fixture, private_fixture):
    native = observation['native_content']
    if native.get('checker') != 'NameSpaceRuleChecker' or native.get('reported_method') != 'GET':
        return {'status': 'unqualified', 'links': []}
    route = observation['coordinate']['path']
    owners = [owner for owner in ('a', 'b') if route == '/identity/api/v2/vehicle/{owner:' + owner + '}/location']
    if len(owners) != 1:
        return {'status': 'outside_frozen_reference', 'links': []}
    owner = owners[0]; witnesses = []
    vehicle = private_fixture[owner]['vehicles'][0]['uuid']
    for r in trace:
        if not (r.get('phase') == 'scanner' and r.get('forwarded') and not r.get('harness_error')
                and r.get('method') == 'GET' and r.get('auth_role') in ('a', 'b') and r['auth_role'] != owner
                and logical_route(r['path'], fixture) == route):
            continue
        raw = base64.b64decode(r['response_body_base64'], validate=True)
        require(hashlib.sha256(raw).hexdigest() == r['response_sha256'], 'Shadow response content/hash mismatch')
        try: body = json.loads(raw)
        except ValueError: continue
        if location_matches({'status': r['status'], 'body': body}, vehicle, private_fixture[owner]['email']):
            witnesses.append({'phase': 'scanner', 'sequence': r['sequence'], 'response_sha256': r['response_sha256']})
    if not witnesses:
        return {'status': 'no_independent_disclosure_witness', 'links': []}
    require(owner in reference_by_owner, 'Missing frozen object-instance reference')
    return {'status': 'verified_object_disclosure', 'links': [{'finding_id': observation['finding_id'],
            'case_id': reference_by_owner[owner], 'relation': 'supports',
            'scope': 'Supplied object instance; independently observed cross-user response. Native reproduce flag is not the oracle.'}],
            'witnesses': witnesses, 'underlying_defect_family': 'crapi-known-bola-defect'}


def rag_reference_observations(references, before, after, private_fixture=None):
    """One document ACL scenario; own-document inclusion is a negative control."""
    result = []
    for reference in references:
        if reference['population'] != 'aigoat-rag-context-authorization':
            continue
        key = reference['source_reference_id'].split(':')[-1]
        rows = [next((r for r in phase.get('controls', []) if r['id'] == key), None) for phase in (before, after)]
        if any(r is None or r.get('passed') is not True for r in rows):
            result.append({'case_id': reference['case_id'], 'status': 'reference_unavailable'}); continue
        owner, context = key.split('-document-')
        actor, level = context.rsplit('-L', 1)
        own = owner == actor
        values = []
        for row in rows:
            signature = row.get('context_signature', [])
            if (row.get('actor') != actor or not signature or
                    any(not isinstance(c, (list, tuple)) or len(c) != 3 or type(c[1]) is not bool for c in signature)):
                break
            flags = {c[1] for c in signature}
            if len(flags) != 1 or next(iter(flags)) is not (own or level == '0'):
                break
            if private_fixture is not None:
                document = private_fixture['documents'][owner]['id']
                response = row.get('response', {})
                selected = [c for c in response.get('body', {}).get('candidates', []) if c.get('entry_id') == document]
                actual = [[c.get('chunk_id'), c.get('included_in_context'), c.get('excluded_by_control')] for c in selected]
                if response.get('status') != 200 or sorted(actual) != sorted([list(c) for c in signature]):
                    break
            if not next(iter(flags)) and any(c[2] != 'retrieval.acl' for c in signature):
                break
            values.append(not own and next(iter(flags)))
        if (reference['truth'] not in ('positive', 'negative') or len(values) != 2 or
                values[0] != values[1] or values[0] != (reference['truth'] == 'positive')):
            result.append({'case_id': reference['case_id'], 'status': 'reference_drift'}); continue
        result.append({'case_id': reference['case_id'], 'status': 'verified_context_property',
                       'unauthorized_inclusion': values[0], 'role': 'reference_check_not_scanner',
                       'scanner_coverage': None, 'scenario_family': 'aigoat:llm02-4'})
    return result
