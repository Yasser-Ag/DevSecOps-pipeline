"""Local historical replay of fresh comparator integration. Never launch a scanner."""
import argparse
from collections import Counter
import json
import platform
from importlib.metadata import version
from pathlib import Path

from study.final_comparator_inputs import Inputs, AIGOAT_STATIC, AIGOAT_DYNAMIC, sha
from study.final_output_adapter import (adapt_static, adapt_dynamic, historical_work_roots,
    fixture_identity, logical_route, digest, require)
from study.final_static_comparators import (sast, identities, kubernetes, terraform,
    checked_raw, IDENTITY_PROFILES, K8S_PROFILES, TF_PROFILES)
from study.final_context_comparators import aigoat, crapi_headers


def static_replay(inputs):
    jobs, reports = [], {}
    selected = set(IDENTITY_PROFILES) | set(K8S_PROFILES) | set(TF_PROFILES) | set(AIGOAT_STATIC) | {'java-semgrep','java-findsecbugs'}
    for p in inputs.plan['profiles']:
        if p['id'] not in selected: continue
        raw = inputs.bind(inputs.plan['suites'][p['suite']]['source_directory'] + '/' + p['historical_report'])
        state = digest(inputs.plan['suites'][p['suite']]['local_input_hashes'])
        context = {'job_id': 'historical-replay-' + p['id'], 'block': 1,
            'work_root': '/qualified/comparator/historical-replay', 'input_contract_sha256': state,
            'observed_input_sha256': state, 'inputs_verified_before': True, 'inputs_verified_after': True,
            'asset_lock_verified': True, 'process_status': 'completed', 'origin': 'historical_replay'}
        job = {**adapt_static(raw, p, context, []), 'block': 1}
        # The comparator deliberately receives no assertion labels or old links.
        jobs.append(job)
        if p['id'] in K8S_PROFILES or p['id'] in TF_PROFILES:
            reports[p['id']] = checked_raw(job, raw, [(r, '<WORK>') for r in historical_work_roots(p)])
    require(len(jobs) == len(selected), 'Missing static replay profile')
    return jobs, reports


def dynamic_replay(inputs):
    """Translate recorded phase names, preserving actual before/after requests.

The old crAPI logger predates the forwarded/sequence fields. A recorded HTTP
response without harness_error establishes forwarding; its physical line is the
request identity. This compatibility rule is confined to historical replay.
No reference response is duplicated or synthesized.
"""
    plan = inputs.json('evidence/final_output_2026-10-22/package-v2/dynamic_plan.json')
    paths = inputs.json('evidence/final_output_2026-10-22/candidate-v1/dynamic_replay.json')
    paths = {r['profile_id']: r['directory'] for r in paths}
    wanted = set(AIGOAT_DYNAMIC) | {'crapi-nuclei-valid-a','crapi-nuclei-invalid'}
    jobs, contexts, transformations = [], {}, []
    for p in plan['profiles']:
        if p['id'] not in wanted: continue
        target = p['target']; label = p['id'].removeprefix(target + '-')
        root = ('evidence/api_development_2026-09-22/attempt-02' if target == 'crapi'
                else 'evidence/aigoat_api_2026-10-12/run-02')
        raw_trace = inputs.bind(root + '/proxy-logs/requests.jsonl')
        original = [json.loads(line) for line in raw_trace.read_text().splitlines()]
        phases = {label: 'scanner', ('reference-before' if target == 'crapi' else 'reference-proxy'): 'before',
                  'reference-after-' + label: 'after'}
        trace = []
        for i, row in enumerate(original, 1):
            if row.get('phase') not in phases: continue
            copy = dict(row); copy['phase'] = phases[row['phase']]
            if target == 'crapi':
                copy['forwarded'] = type(row.get('status')) is int and not row.get('harness_error')
                copy['sequence'] = i
            trace.append(copy)
            transformations.append({'profile_id': p['id'], 'source': str(raw_trace.relative_to(inputs.root)),
                'line': i, 'original_phase': row['phase'], 'phase': copy['phase'],
                'response_sha256': row['response_sha256']})
        scanner_trace = [r for r in trace if r['phase'] == 'scanner']
        require(scanner_trace and all(r.get('forwarded') and not r.get('harness_error') for r in trace),
                'Historical proxy trace failed')
        if target == 'crapi':
            ref = inputs.json(root + '/behavior_reference.json')
            fixture = {'target': 'crapi', 'route_aliases': {'/identity/api/v2/vehicle/' + uuid + '/location':
                '/identity/api/v2/vehicle/{owner:' + actor + '}/location' for actor, uuid in ref['objects'].items()},
                'document_aliases': {}, 'allowed_authorities': ['127.0.0.1:10080'],
                'roles': ['a','b','absent','invalid']}
        else:
            private = inputs.json(root + '/fixtures/private_fixture.json')
            fixture = fixture_identity('aigoat', private, ['http://<MASKED:ip_address:3>:8080'])
        require({r['phase'] for r in trace} == {'scanner','before','after'}, 'Incomplete historical lifecycle')
        context = {'job_id': 'historical-replay-' + p['id'], 'block': 1, 'process_status': 'completed',
                   'reference_before_passed': True, 'reference_after_passed': True}
        job = {**adapt_dynamic(inputs.root / paths[p['id']], p, context, scanner_trace, fixture),
               'block': 1, 'status': 'completed', 'evidence_origin': 'historical_replay',
               'new_scientific_measurement': False}
        for report in job['reports']: inputs.bind(paths[p['id']] + '/' + report['path'])
        jobs.append(job); contexts[p['id']] = (trace, fixture)
    require(len(jobs) == len(wanted), 'Missing dynamic replay profile')
    return jobs, contexts, transformations


def replay(root):
    inputs = Inputs(root); refs = inputs.references()
    for name in ('study/final_static_comparators.py', 'study/final_context_comparators.py',
                 'study/final_comparator_inputs.py', 'study/final_comparator_ingress.py',
                 'study/test_final_comparators.py', 'engineering/qualify_fresh_comparators.py',
                 'engineering/FRESH_COMPARATOR_ACTION_2026-10-22.md',
                 'engineering/audit_fresh_comparators.py'):
        inputs.bind(name)
    sjobs, reports = static_replay(inputs)
    djobs, contexts, transformations = dynamic_replay(inputs)
    results = {
        'sast': sast(sjobs, refs['java'], refs['java_partition']),
        'identity': identities(sjobs, refs['aliases'], refs['secrets'], refs['identity']),
        'kubernetes': kubernetes(sjobs, reports, refs['kubernetes']),
        'terraform': terraform(sjobs, reports, refs['terraform']),
        'dast': {j['profile_id']: crapi_headers(j, refs['crapi_templates'], *contexts[j['profile_id']])
                 for j in djobs if j['profile_id'].startswith('crapi-')},
        'aigoat': aigoat(sjobs + djobs, refs['references'],
                        {p: contexts[p] for p in AIGOAT_DYNAMIC}, (*AIGOAT_STATIC, *AIGOAT_DYNAMIC))}
    oldroot = 'evidence/final_technical_2026-10-22/candidate-v3/comparators/'
    old = {n: inputs.json(oldroot + n + '_replay.json') for n in ('sast_dast','identity','kubernetes','terraform','aigoat')}
    checks = []
    def check(name, actual, expected):
        require(actual == expected, 'Historical comparator replay mismatch: ' + name)
        checks.append({'check': name, 'passed': True})
    for method, value in results['sast']['methods'].items():
        previous = old['sast_dast']['sast']['methods'][method]
        for k in ('status_counts','supported_findings','unsupported_findings','groups','duplicate_groups'):
            if k in value and not isinstance(value[k], list): check('sast.' + method + '.' + k, value[k], previous[k])
        check('sast.' + method + '.group_sizes', {v['key']:len(v['members']) for v in value['groups']},
              {v['key']:len(v['members']) for v in previous['groups']})
    check('identity.pair_counts', results['identity']['pair_counts'], {k:v['counts'] for k,v in old['identity']['pairs'].items()})
    check('identity.stages', results['identity']['stages'], old['identity']['stages'])
    check('identity.effects', results['identity']['effects'], old['identity']['effects'])
    check('kubernetes.association_counts', results['kubernetes']['association_counts'], dict(Counter(r['association'] for r in old['kubernetes'])))
    previous_outcomes = inputs.json('evidence/configuration_matching_2026-09-22/local-verification-v2/analysis/outcomes.json')
    old_links = {r['outcome_id']:r for r in old['kubernetes']}
    def associated_units(outcomes, links):
        index = {r['outcome_id']:r for r in links}
        return sorted((r['corpus'],r['tool'],r['native_locator'],
                       {k:v for k,v in index[r['outcome_id']].items() if k != 'outcome_id'}) for r in outcomes)
    check('kubernetes.exact_associations', associated_units(results['kubernetes']['outcomes'],results['kubernetes']['associations']),
          associated_units(previous_outcomes,list(old_links.values())))
    check('terraform.matching', results['terraform']['matching'], old['terraform'])
    previous_tf = inputs.json('evidence/workflow_iac_matching_2026-09-23/development-analysis-v3/terraform_outcomes.json')
    fields = ('corpus','tool','native_locator','path','resource','status','reference_id','positive','agreement')
    check('terraform.exact_associations', sorted(tuple(r[k] for k in fields) for r in results['terraform']['outcomes']),
          sorted(tuple(r[k] for k in fields) for r in previous_tf))
    check('dast.references', sum(len(v['references']) for v in results['dast'].values()), 40)
    check('dast.observations', sum(len(v['observations']) for v in results['dast'].values()), old['sast_dast']['dast']['eligible_findings'])
    for mode in ('legacy','v2'):
        counts = Counter()
        for value in results['dast'].values():
            require(value['comparison_complete'], 'Incomplete historical header reference')
            counts.update(value['methods'][mode]['status_counts'])
        check('dast.' + mode, dict(counts), old['sast_dast']['dast']['methods'][mode]['status_counts'])
    # Fresh hashes change the lexical representative. Compare the invariant
    # all-member results, and retain the new representative diagnostic as such.
    for now, previous in zip(results['aigoat']['effects'], old['aigoat']):
        for k in ('method','reporting_policy','groups','input_findings','input_supported_cases'):
            check('aigoat.' + now['method'] + '.' + now['reporting_policy'] + '.' + k, now[k], previous[k])
        if now['reporting_policy'] == 'all_members':
            for k in ('retained_findings','retained_supported_cases','lost_supported_case_ids'):
                check('aigoat.' + now['method'] + '.' + k, now[k], previous[k])
    # Historical pointer identities are used only here to audit the replay,
    # after every fresh observable and link has been independently recomputed.
    from study.coverage_registry import identity
    witnesses = {o['finding_id']:identity('finding-',o['raw_report_sha256'],o['native_locator'])
                 for j in sjobs+ djobs for o in j['observations']}
    old_property_path = inputs.bind('evidence/aigoat_linkage_2026-10-12/development-v5/property_links.jsonl')
    old_properties = [json.loads(line) for line in old_property_path.read_text().splitlines()]
    check('aigoat.exact_property_links', sorted((witnesses[r['finding_id']],r['case_id'],r['relation']) for r in results['aigoat']['links']),
          sorted((r['finding_id'],r['case_id'],r['relation']) for r in old_properties))
    dependencies = {n:version(n) for n in ('tree-sitter','tree-sitter-java','PyYAML')}
    require(dependencies['tree-sitter'] == '0.25.2' and dependencies['tree-sitter-java'] == '0.23.5',
            'Unqualified Java parser version')
    wheel_manifest = inputs.json('evidence/matching_development_2026-09-22/package-v1/source_manifest.json')
    for row in wheel_manifest['files']:
        if row['path'].endswith('.whl'):
            path = inputs.bind('evidence/matching_development_2026-09-22/' + row['path'])
            require(sha(path) == row['sha256'], 'Pinned parser wheel changed')
    return inputs, results, {'checks': checks, 'historical_phase_translations': transformations,
        'static_profiles': len(sjobs), 'dynamic_profiles': len(djobs),
        'environment': {'python':platform.python_version(), 'platform':platform.platform(), 'dependencies':dependencies},
        'origin': 'historical_native_replay_with_actual_recorded_reference_phases',
        'synthetic_reference_responses': 0, 'new_scientific_measurements': 0,
        'representative_policy_note': 'Lexical representative identities are job/report scoped; only all-member invariants must reproduce exactly.'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output: require(not args.output.exists(), 'Preserve prior qualification output')
    inputs, results, audit = replay(args.root)
    if args.output:
        args.output.mkdir(parents=True)
        for name, content in {**results, 'audit': audit, 'source_manifest': inputs.manifest()}.items():
            (args.output / (name + '.json')).write_text(json.dumps(content, sort_keys=True, indent=2) + '\n')
        manifest = [{'path': p.name, 'sha256': sha(p), 'bytes': p.stat().st_size} for p in sorted(args.output.glob('*.json'))]
        (args.output / 'output_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({k: v for k, v in audit.items() if k not in ('checks','historical_phase_translations')} |
                     {'checks_passed': len(audit['checks']), 'bound_files': len(inputs.files)}))


if __name__ == '__main__': main()
