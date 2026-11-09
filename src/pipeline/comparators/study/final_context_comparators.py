"""Typed fresh HTTP and AIGoat property comparators, with complete member retention."""
from collections import Counter
import re
from urllib.parse import urlsplit

from study.final_output_adapter import logical_route, require
from study.final_dynamic_projection import http_projection, header_predicate
from study.final_static_comparators import relative_path
from study.matching_baselines import match_requests
from study.matching_development_analysis import HEADERS
from study.aigoat_linkage import observed_coordinate, coordinate, key, retention, groups


def native_response_consistent(native, coord):
    response = native.get('response')
    if not response: return True
    if not isinstance(response, str): return False
    match = re.fullmatch(r'HTTP/[0-9.]+ (\d{3})(?: .*)?', response.splitlines()[0])
    return match is not None and int(match[1]) == coord.get('response_status')


def crapi_headers(job, templates, reference_trace, fixture):
    """Use newly observed response properties; do not transfer an old header label."""
    require(job.get('measurement_eligible') is True and job.get('status') == 'completed',
            'Incomplete crAPI job is not a comparator measurement')
    require(job['profile_id'] in ('crapi-nuclei-valid-a', 'crapi-nuclei-invalid'), 'Wrong header comparator profile')
    actor = 'a' if job['profile_id'].endswith('-valid-a') else 'invalid'
    partition = 'crapi-api-development:' + ('valid-a' if actor == 'a' else 'invalid')
    selected = [r for r in templates if r['partition'] == partition]
    expected = {(f'/identity/api/v2/vehicle/{{owner:{owner}}}/location', h) for owner in ('a','b') for h in HEADERS}
    require(len(selected) == 20 and {(r['path'], r['name']) for r in selected} == expected,
            'Frozen header template scope changed')
    refs, unverified = [], []
    for template in selected:
        candidates = [r for r in reference_trace if r.get('phase') in ('before','after') and
            r.get('forwarded') and not r.get('harness_error') and r.get('method') == 'GET' and
            r.get('auth_role') == actor and logical_route(r['path'], fixture) == template['path']]
        values = {(r['status'], template['name'] not in {h.lower() for h, _ in r['response_headers']}) for r in candidates}
        if {r['phase'] for r in candidates} != {'before','after'} or len(values) != 1:
            unverified.append({'case_id': template['case_id'], 'reason': 'Missing or unstable independent before/after reference'}); continue
        status, absent = values.pop()
        refs.append({**template, 'allowed_statuses': [status], 'property_absent': absent,
            'reference_witnesses': [{'phase': r['phase'], 'sequence': r['sequence'],
                                    'response_sha256': r['response_sha256']} for r in candidates]})
    findings, excluded = [], []
    for obs in job['observations']:
        n, c = obs['native_content'], obs.get('coordinate', {})
        if not (n.get('native_rule') == 'http-missing-security-headers' and n.get('matcher') in HEADERS
                and c.get('status') == 'localized' and c.get('actor') == actor and c.get('method') == 'GET'
                and native_response_consistent(n, c)
                and (c.get('path'), n['matcher']) in expected):
            excluded.append({'finding_id': obs['finding_id'], 'reason': 'Outside qualified request/header context'}); continue
        findings.append({'finding_id': obs['finding_id'], 'partition': partition, 'target': 'crapi',
            'method': c['method'], 'path': c['path'], 'surface': 'header', 'name': n['matcher'],
            'status_code': c['response_status'], 'weakness': {'class': 'response_header_absence',
                'variant': {'header': n['matcher']}}, 'native_locator': obs['native_locator']})
    index = {r['case_id']: r for r in refs}
    methods = {}
    for mode in ('legacy','v2'):
        matches = match_requests(refs, findings, {'crapi': 'crapi'}, mode)
        # A contradiction remains evidence, not an exception erasing a negative outcome.
        for match in matches:
            if match['status'] == 'matched':
                match['property_relation'] = 'supports' if index[match['case_id']]['property_absent'] else 'contradicts'
        methods[mode] = {'links': matches, 'status_counts': dict(Counter(m['status'] for m in matches))}
    return {'references': refs, 'unverified_references': unverified, 'observations': findings,
            'excluded': excluded, 'methods': methods, 'comparison_complete': not unverified,
            'scope': 'Observed header absence per route/role/status; not a security TP/FP judgment.'}


def aigoat_static_coordinate(profile_id, native):
    profile = profile_id.removeprefix('aigoat-')
    if profile == 'compose-kics-compose-deployment-qualified': profile = 'kics-compose-deployment-qualified'
    row = dict(native)
    if profile.startswith(('checkov-docker-', 'trivy-config-')):
        view = 'original' if profile.endswith('original') else 'deployment'
        row['path'] = relative_path(row.get('path'), ('<WORK>/inputs/' + view + '/docker/', ''))
    return observed_coordinate({'id': profile, 'api': False}, row)


def aigoat(jobs, references, dynamic_contexts, expected_profiles):
    """Recompute coordinates and links; grouping never receives truth or old links."""
    from study.final_static_comparators import selected_jobs
    chosen = selected_jobs(jobs, expected_profiles)
    index = {}
    for reference in references:
        coord = reference.get('details', {}).get('coordinate')
        if reference['population'] == 'aigoat-declared-properties' and coord:
            require(key(coord) not in index, 'Duplicate independent declared property')
            index[key(coord)] = reference
    observables, links, excluded, diagnostics = [], [], [], []
    for job in chosen:
        api = job['profile_id'] in dynamic_contexts
        for obs in job['observations']:
            coord = None
            if api:
                trace, fixture = dynamic_contexts[job['profile_id']]
                c = obs.get('coordinate', {}); predicate = header_predicate(obs['native_content'])
                consistent = native_response_consistent(obs['native_content'], c)
                if c.get('status') == 'localized' and predicate and consistent and not urlsplit(c['path']).query and not urlsplit(c['path']).fragment:
                    coord = coordinate('http_response', 'api-state:aigoat:block-' + str(job['block']),
                                       c['method'] + ' ' + c['path'], predicate, c['actor'])
                frozen_context = any(r['population'] == 'aigoat-http-properties' and
                    r.get('details',{}).get('coordinate',{}).get('resource') == c.get('method','') + ' ' + c.get('path','') and
                    r.get('details',{}).get('coordinate',{}).get('context') == c.get('actor') and
                    r.get('details',{}).get('coordinate',{}).get('property') == predicate for r in references)
                if not consistent:
                    projected = {'status': 'native_trace_response_conflict', 'links': []}
                elif not frozen_context:
                    projected = {'status': 'outside_frozen_reference', 'links': []}
                else:
                    projected = http_projection(obs, references, trace, fixture)
                links.extend(projected['links'])
                diagnostics.append({'finding_id': obs['finding_id'], **projected})
            else:
                try: coord = aigoat_static_coordinate(job['profile_id'], obs['native_content'])
                except ValueError as error:
                    excluded.append({'finding_id': obs['finding_id'], 'reason': str(error)})
                ref = index.get(key(coord)) if coord else None
                if ref and ref['truth'] in ('positive','negative'):
                    links.append({'finding_id': obs['finding_id'], 'case_id': ref['case_id'],
                                  'relation': 'supports' if ref['truth'] == 'positive' else 'contradicts'})
            observables.append({'finding_id': obs['finding_id'], 'profile': job['profile_id'], 'coordinate': coord})
    require(len({o['finding_id'] for o in observables}) == len(observables), 'Duplicate AIGoat observation')
    qualified = [o for o in observables if o['coordinate']]
    return {'observations': observables, 'links': links, 'unlocalized': excluded, 'dynamic_projection': diagnostics,
            'comparison_complete': not any(d['status'] in ('reference_unavailable','reference_drift') for d in diagnostics),
            'outside_comparator_ids': [o['finding_id'] for o in observables if not o['coordinate']],
            'groups': {m: groups(qualified, m) for m in ('coarse_property','competent_exact')},
            'effects': retention(qualified, links),
            'scope': 'Literal/observed property support only. Representative selection is a counterfactual; all members are primary.'}
