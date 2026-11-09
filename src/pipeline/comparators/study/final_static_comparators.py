"""Apply the frozen static comparators to freshly identified native observations.

Grouping receives observable features only. Reference assignment is a later
operation. Callers must supply verified input bytes and completed ingress jobs;
unavailable jobs cannot silently become empty successful measurements.
"""
from collections import Counter
import hashlib
import json
import re

from study.final_output_adapter import canonical_content, digest, require
from study.matching_baselines import JavaScopes, sast_key, group_keys, fingerprint
from study.identity_matching import pair_audit, reporting_effect, stage_effect
from study.identity_development_analysis import component_locations, assign_references
from study.configuration_development_cases import inspect_key
from study.configuration_matching import (registry_for_text, trivy_outcomes,
    checkov_outcomes, associate, file_pass_counterfactual)
from study.workflow_iac_matching import kics_resource, pair_diagnostics, pass_suppression


def selected_jobs(jobs, profiles):
    """One block and exactly one receipt per required profile, including empty reports."""
    chosen = [j for j in jobs if j['profile_id'] in profiles]
    counts = Counter(j['profile_id'] for j in chosen)
    require(set(counts) == set(profiles) and all(n == 1 for n in counts.values()),
            'Missing or duplicate comparator profile')
    require(len({j['block'] for j in chosen}) == 1, 'Do not pool repetition blocks')
    require(all(j.get('status') == 'completed' and j.get('measurement_eligible') is True
                and j.get('native_count') == len(j['observations']) for j in chosen),
            'Incomplete/unqualified comparator input is not zero detections')
    ids = [o['finding_id'] for j in chosen for o in j['observations']]
    require(len(ids) == len(set(ids)), 'Duplicate native identity')
    return chosen


def relative_path(value, prefixes):
    """Strip only a declared invocation prefix; never match an arbitrary suffix."""
    require(isinstance(value, str) and bool(value), 'Missing source path')
    candidates = set()
    for prefix in prefixes:
        if prefix and value.startswith(prefix):
            candidates.add(value[len(prefix):])
    if not candidates and '' in prefixes and not value.startswith(('/', '<WORK>')):
        candidates.add(value)
    require(len(candidates) == 1, 'Unsupported/ambiguous invocation path: ' + value)
    result = candidates.pop()
    require(bool(result) and all(p not in ('', '.', '..') for p in result.split('/')),
            'Unsafe relative source path')
    return result


def checked_raw(job, raw_path, aliases=()):
    """PASS records are read from the same native report validated by ingress."""
    raw = raw_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == job['raw_report_sha256'], 'Raw report changed')
    return canonical_content(json.loads(raw), aliases)


def sast(jobs, sources, partition):
    chosen = selected_jobs(jobs, ('java-semgrep', 'java-findsecbugs'))
    trees = {path: JavaScopes(content, path) for path, content in sources.items()}
    require(trees and all(t.valid for t in trees.values()), 'Invalid/missing Java source')
    rows, excluded = [], []
    for job in chosen:
        for obs in job['observations']:
            n = obs['native_content']
            try:
                path = relative_path(n.get('path'), ('/scanner-inputs/java/src/main/java/',
                    '<WORK>/scanner-inputs/java/src/main/java/', ''))
            except ValueError as error:
                excluded.append({'finding_id': obs['finding_id'], 'reason': str(error)})
                continue
            if path not in trees:
                excluded.append({'finding_id': obs['finding_id'], 'reason': 'Outside fixed Java selection'})
                continue
            rows.append({'finding_id': obs['finding_id'], 'source_path': path,
                'source_sha256': hashlib.sha256(sources[path]).hexdigest(),
                'native_locator': obs['native_locator'],
                'methods': {m: sast_key(trees[path], n.get('line_start'), n.get('cwes', []), partition, m)
                            for m in ('line', 'scope_offset', 'normalized_scope_offset')}})
    methods = {}
    for method in ('line', 'scope_offset', 'normalized_scope_offset'):
        members = [{'finding_id': r['finding_id'], **r['methods'][method]} for r in rows]
        methods[method] = {**group_keys(members), 'status_counts': dict(Counter(r['status'] for r in members))}
    return {'observations': rows, 'excluded': excluded, 'methods': methods,
            'native_records': sum(j['native_count'] for j in chosen), 'source_files': len(trees),
            'scope': 'Fingerprint membership only; source cases do not establish warning identity truth.'}


IDENTITY_PROFILES = ('sca-grype-filesystem', 'sca-trivy-rootfs', 'sca-dependency-check',
                    'sca-grype-image', 'sca-trivy-image', 'configuration-gitleaks',
                    'configuration-trivy-secret')


def identities(jobs, aliases, secret_sources, reference_nodes):
    chosen = selected_jobs(jobs, IDENTITY_PROFILES)
    features, excluded = [], []
    for job in chosen:
        profile = job['profile_id']
        for obs in job['observations']:
            n = obs['native_content']
            base = {'finding_id': obs['finding_id'], 'profile': profile,
                    'native_locator': obs['native_locator'], 'raw_report_sha256': job['raw_report_sha256']}
            if profile.startswith('sca-'):
                canonical = aliases.get(n.get('advisory_id'))
                purls = n.get('package', {}).get('purls', [])
                if canonical is None or len(purls) != 1 or n.get('suppressed'):
                    excluded.append({**base, 'reason': 'Outside named advisories/ambiguous/suppressed'}); continue
                view = 'image' if profile.endswith('-image') else 'source'
                locations = component_locations(n['package'])
                require(locations, 'Selected component has no location')
                for path in locations:
                    prefixes = ('<WORK>/build-context/scanner-inputs/',) if profile == 'sca-dependency-check' else ('', '/')
                    relative = relative_path(path, prefixes)
                    features.append({**base, 'observation_id': obs['finding_id'] + ':location:' + fingerprint(relative),
                        'partition': 'sca-development-fixed-release', 'family': 'sca', 'artifact': view,
                        'stage': 'image_scan' if view == 'image' else 'source_sca', 'path': relative,
                        'purl': purls[0], 'reported_advisory': n['advisory_id'], 'canonical_advisory': canonical})
            else:
                if n.get('native_rule') != 'private-key':
                    excluded.append({**base, 'reason': 'Outside selected private-material predicate'}); continue
                prefixes = ('<WORK>/reference/scanner-inputs/secrets/',) if profile.endswith('gitleaks') else ('',)
                path = 'secrets/' + relative_path(n.get('path'), prefixes)
                if path not in secret_sources:
                    excluded.append({**base, 'reason': 'No verified source bytes for key observation'}); continue
                source = secret_sources[path]
                features.append({**base, 'observation_id': obs['finding_id'], 'family': 'secret',
                    'partition': 'secret-development-fixed-source', 'stage': 'secret_scan',
                    'artifact': 'source', 'path': path, 'file_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                    'public_der_sha256': inspect_key(source)['public_der_sha256']})
    lookups = {'sca': {}, 'secret': {}}
    for ref in reference_nodes:
        if ref['family'] == 'sca': lookups['sca'][(ref['artifact'], ref['path'], ref['advisory'])] = ref
        elif ref['family'] == 'secret': lookups['secret'][ref['path']] = ref
    assignments = assign_references(features, lookups)
    pairs, effects, stages = {}, [], []
    for family, methods in [('sca', ('component_literal', 'component_alias', 'artifact_occurrence')),
                            ('secret', ('secret_path', 'secret_bytes', 'secret_key'))]:
        selected = [f for f in features if f['family'] == family]
        for method in methods:
            for unit in ('object', 'occurrence'):
                pairs[family + ':' + method + ':' + unit] = pair_audit(selected, assignments, method, unit)
                effects.append({'family': family, **reporting_effect(selected, assignments, method, unit)})
                if family == 'sca': stages.append(stage_effect(selected, assignments, method, unit))
    return {'observations': features, 'assignments': assignments, 'excluded': excluded,
            'pair_counts': {k: v['counts'] for k, v in pairs.items()}, 'effects': effects, 'stages': stages}


K8S_PROFILES = {
    **{f'infrastructure-{corpus}-{tool}-kubernetes': (corpus, tool)
       for corpus in ('controls', 'originals') for tool in ('trivy', 'checkov')},
    'k8s-scope-matrix-trivy': ('matrix', 'trivy'), 'k8s-scope-matrix-checkov': ('matrix', 'checkov'),
    'k8s-scope-split-trivy': ('split', 'trivy')}


def kubernetes(jobs, reports, sources):
    chosen = selected_jobs(jobs, K8S_PROFILES)
    registry = {'objects': [], 'identities': [], 'references': []}
    for (corpus, path), content in sorted(sources.items()):
        parsed = registry_for_text(content.decode(), path, corpus)
        for key in registry: registry[key].extend(parsed[key])
    outcomes = []
    for job in chosen:
        corpus, tool = K8S_PROFILES[job['profile_id']]
        raw = reports[job['profile_id']]
        rows = (trivy_outcomes if tool == 'trivy' else checkov_outcomes)(raw, corpus)
        for row in rows:
            row['outcome_id'] = 'outcome:' + digest([job['job_id'], job['raw_report_sha256'], row['native_locator']])
            row['raw_report_sha256'] = job['raw_report_sha256']
        outcomes.extend(rows)
    links = [associate(o, registry['identities'], registry['objects']) for o in outcomes]
    original = [(o, l) for o, l in zip(outcomes, links) if o['corpus'] == 'originals']
    return {'registry': registry, 'outcomes': outcomes, 'associations': links,
        'association_counts': dict(Counter(l['association'] for l in links)),
        'original_file_pass_counterfactual': file_pass_counterfactual([o for o, _ in original], [l for _, l in original]),
        'scope': 'Typed declared non-root property; no live runtime UID or general scanner accuracy inference.'}


TF_PROFILES = {f'infrastructure-{corpus}-{tool}-terraform': (corpus, tool)
               for corpus in ('controls', 'originals') for tool in ('checkov', 'trivy', 'kics')}


def terraform(jobs, reports, references):
    chosen = selected_jobs(jobs, TF_PROFILES)
    outcomes = []

    def add(job, corpus, tool, pointer, native_path, resource, status, first, last, ingress=None):
        prefix = corpus + '/terraform/'
        path = prefix + relative_path(native_path, ('<WORK>/reference/scanner-inputs/' + prefix,
                                                     '/input/', '../../input/', '/'+prefix, prefix, ''))
        # Locate using source geometry before inspecting its predicate truth.
        refs = [r for r in references if r['corpus'] == corpus and r['path'] == path and r['resource'] == resource]
        require(len(refs) <= 1, 'Ambiguous independent Terraform resource')
        ref = refs[0] if refs else None
        reason = None
        if ref:
            lo, hi = ref['resource_span']
            localized = type(first) is int and type(last) is int and lo <= first <= last <= hi
            if tool == 'trivy':
                span = ref.get('ingress_span')
                localized = localized and span is not None and span[0] <= first <= last <= span[1]
            localized = localized and (ingress is None or ingress == ref['ingress_index'])
            if not localized:
                ref = None; reason = 'Native span/ingress disagrees with independent resource geometry'
        if status not in ('PASSED', 'FAILED'):
            ref = None; reason = 'Unqualified native outcome status'
        outcomes.append({'observation_id': 'outcome:' + digest([job['job_id'], job['raw_report_sha256'], pointer]),
            'tool': tool, 'corpus': corpus, 'native_locator': pointer, 'path': path, 'resource': resource,
            'status': status, 'property': 'declared_unrestricted_tcp_22',
            'reference_id': ref['reference_id'] if ref else None, 'positive': ref['positive'] if ref else None,
            'agreement': (status == 'FAILED') == ref['positive'] if ref else None,
            'unscored_reason': reason or (None if ref else 'No qualified resource-property reference')})

    for job in chosen:
        corpus, tool = TF_PROFILES[job['profile_id']]; raw = reports[job['profile_id']]
        if tool == 'checkov':
            for b, block in enumerate(raw if isinstance(raw, list) else [raw]):
                for kind in ('passed_checks', 'failed_checks', 'skipped_checks'):
                    for i, row in enumerate(block['results'].get(kind, [])):
                        if row['check_id'] != 'CKV_AWS_24': continue
                        indices = {int(m[1]) for key in row['check_result'].get('evaluated_keys', [])
                                   if (m := re.match(r'ingress/\[(\d+)\]/', key))}
                        pointer = (f'/{b}' if isinstance(raw, list) else '') + f'/results/{kind}/{i}'
                        # Several ingress causes cannot be projected onto one frozen instance.
                        ingress = next(iter(indices)) if len(indices) == 1 else -1 if indices else None
                        path = row.get('file_abs_path') or corpus + '/terraform/' + row['file_path'].lstrip('/')
                        add(job, corpus, tool, pointer, path, row['resource'], row['check_result']['result'],
                            *row['file_line_range'], ingress)
        elif tool == 'trivy':
            for b, block in enumerate(raw.get('Results', [])):
                for i, row in enumerate(block.get('Misconfigurations', [])):
                    if row['ID'] != 'AWS-0107': continue
                    meta = row['CauseMetadata']
                    add(job, corpus, tool, f'/Results/{b}/Misconfigurations/{i}', block['Target'],
                        meta['Resource'], {'FAIL':'FAILED', 'PASS':'PASSED'}.get(row['Status'], row['Status']),
                        meta['StartLine'], meta['EndLine'])
        else:
            for q, query in enumerate(raw['queries']):
                if query['query_id'] != '65905cec-d691-4320-b320-2000436cb696': continue
                for i, row in enumerate(query['files']):
                    resource, ingress = kics_resource(row['search_key'])
                    add(job, corpus, tool, f'/queries/{q}/files/{i}', row['file_name'], resource,
                        'FAILED', row['line'], row['line'], ingress)
    matching, counterfactual = [], []
    for corpus in ('controls', 'originals'):
        positive = [o for o in outcomes if o['corpus'] == corpus and o['status'] == 'FAILED' and o['reference_id']]
        for name, fields in [('file_property', ('path','property')), ('resource_property', ('path','resource','property'))]:
            matching.append({'corpus': corpus, 'condition': name, **pair_diagnostics(positive, fields)})
        refs = [r for r in references if r['corpus'] == corpus and r['positive']]
        checkov = [r for r in outcomes if r['corpus'] == corpus and r['tool'] == 'checkov' and r['reference_id']]
        counterfactual.append({'corpus': corpus,
            'file_pass_suppression_lost': pass_suppression(refs, checkov, ('path','property')),
            'resource_pass_suppression_lost': pass_suppression(refs, checkov, ('path','resource','property'))})
    return {'outcomes': outcomes, 'matching': matching, 'counterfactual': counterfactual,
            'scope': 'Declared resource-property identity; loss diagnostics are explicit counterfactuals.'}
