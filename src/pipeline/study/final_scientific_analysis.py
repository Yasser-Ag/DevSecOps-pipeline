"""Post-execution descriptive analyses on frozen, typed reference populations.

No scanner, model, network request, label creation or threshold selection occurs
here. Counts describe supported evidence, not undiscovered vulnerabilities.
"""
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json


CONDITIONS = ('B0', 'B1', 'Q-A', 'Q-C', 'G-A', 'G-C')
MODEL_CONDITIONS = {
    'qwen35-9b-q4km/alert_only': 'Q-A',
    'qwen35-9b-q4km/context': 'Q-C',
    'gemma4-e4b-qat-q40/alert_only': 'G-A',
    'gemma4-e4b-qat-q40/context': 'G-C',
}
RULE_PREFIX = 'devsecops_access.environment.scanner-assets-20260921-01.semgrep.'
FRESH_RULE_PREFIX = 'home.lab.' + RULE_PREFIX


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def reconcile_semgrep(job, catalog):
    """Reuse only an identical assertion after one exact rule-prefix alias.

Original native content, identity and signature remain unchanged. Both original
and comparison signatures are retained. All other content must match exactly.
This corrects source binding, not the historical label or warning-pair identity.
"""
    require(job['profile_id'] == 'java-semgrep', 'Repair is restricted to java-semgrep')
    require(job.get('measurement_eligible') is True and job.get('input_state_verified') is True,
            'Unverified execution cannot inherit assertions')
    require(not job['links'], 'Expected the preserved unbound Semgrep ingress')
    candidates = defaultdict(list)
    for entry in catalog:
        require(entry['profile_id'] == 'java-semgrep', 'Cross-profile catalog')
        require(digest(entry['content']) == entry['signature'], 'Corrupt catalog signature')
        require(entry['content'].get('tool') == 'semgrep', 'Unexpected catalog tool')
        require(entry['content']['native_rule'].startswith(RULE_PREFIX), 'Unexpected old rule prefix')
        candidates[entry['signature']].append(entry)
    fixed, changes = deepcopy(job), []
    for obs in fixed['observations']:
        require(obs['binding_status'] == 'unadjudicated' and not obs['historical_witness_ids'],
                'Repair would replace an existing interpretation')
        require(digest(obs['native_content']) == obs['signature'], 'Corrupt fresh signature')
        content = deepcopy(obs['native_content'])
        rule = content.get('native_rule', '')
        if content.get('tool') != 'semgrep' or not rule.startswith(FRESH_RULE_PREFIX):
            continue
        content['native_rule'] = rule[len('home.lab.'):]
        comparison_signature = digest(content)
        matches = candidates.get(comparison_signature, [])
        # Do not guess between colliding records, even if their labels agree.
        if len(matches) != 1:
            continue
        entry = matches[0]
        require(content == entry['content'], 'Signature collision')
        proof = {'operation': 'exact_semgrep_rule_prefix_alias',
                 'original_signature': obs['signature'],
                 'comparison_signature': comparison_signature,
                 'original_native_rule': rule, 'catalog_native_rule': content['native_rule'],
                 'only_normalized_field': 'native_rule',
                 'historical_finding_id': entry['historical_finding_id']}
        obs.update(population=entry['population'], scoped_native_label=entry['scoped_native_label'],
                   historical_witness_ids=[entry['historical_finding_id']],
                   binding_status='bound_exact_assertion_after_rule_prefix_alias',
                   analysis_correction=proof)
        for edge in entry['links']:
            fixed['links'].append({**deepcopy(edge), 'finding_id': obs['finding_id'],
                                  'binding_evidence': {'profile_id': job['profile_id'],
                                                       'job_id': job['job_id'], **proof}})
        changes.append({'finding_id': obs['finding_id'], 'label': entry['scoped_native_label'], **proof})
    fixed['bound_assertions'] = len(changes)
    fixed['analysis_correction_scope'] = 'Exact serialized rule-prefix alias; original bytes and labels preserved.'
    return fixed, changes


def coverage_row(job, population, references):
    """Reference-supported counts; a profile-wide applicability rate is not inferred."""
    name = population['population']
    refs = {r['case_id']: r for r in references if r['population'] == name}
    positive = {k for k, r in refs.items() if r['truth'] == 'positive'}
    negative = {k for k, r in refs.items() if r['truth'] == 'negative'}
    eligible = job.get('measurement_eligible') is True and job.get('role') != 'inventory'
    supports, contradicts = set(), set()
    if eligible:
        for edge in job.get('links', []):
            cid = edge['case_id']
            if cid not in refs:
                continue
            if edge['relation'] == 'supports':
                require(cid in positive, 'Support must refer to a positive scoped reference')
                supports.add(cid)
            elif edge['relation'] == 'contradicts':
                require(cid in negative, 'Contradiction must refer to a negative scoped reference')
                contradicts.add(cid)
    observations = job.get('observations', [])
    labels = Counter(o.get('scoped_native_label', 'unresolved') for o in observations
                     if o.get('population') == name)
    return {'block': job['block'], 'profile_id': job['profile_id'], 'job_id': job['job_id'],
            'population': name, 'unit': population['unit'], 'endpoint_kind': population['endpoint_kind'],
            'role': job.get('role'), 'measurement_eligible': eligible,
            'normalized_population_eligible': population['normalized_detection_eligible'],
            'catalog_positive_references': len(positive), 'catalog_negative_references': len(negative),
            'supported_positive_cases': sorted(supports) if eligible else None,
            'contradicted_negative_cases': sorted(contradicts) if eligible else None,
            'supported_positive_count': len(supports) if eligible else None,
            'contradicted_negative_count': len(contradicts) if eligible else None,
            'native_count': job.get('native_count'), 'scoped_native_labels': dict(labels),
            'limitations': job.get('limitations', []),
            'profile_recall': None,
            'interpretation': 'Supported witnesses within the catalog; per-profile applicability denominators are not inferred. '
                              'Unlinked warnings remain unadjudicated; inventory and incomplete runs receive no detections.'}


def population_omissions(population, rows, references, group_by=None):
    """Paired omissions of saved outputs, not measured end-to-end runtime savings."""
    name = population['population']
    rows = [r for r in rows if r['population'] == name and r['role'] != 'inventory']
    require(len({r['profile_id'] for r in rows}) == len(rows), 'Repeated profiles pooled across blocks')
    require(len({r['block'] for r in rows}) <= 1, 'Execution repeats are not independent cases')
    usable = [r for r in rows if r['measurement_eligible']]
    unavailable = sorted(r['profile_id'] for r in rows if not r['measurement_eligible'])
    full = set().union(*(set(r['supported_positive_cases']) for r in usable))
    refs = {r['case_id']: r for r in references if r['population'] == name and r['truth'] == 'positive'}
    require(full <= refs.keys(), 'Supported case outside positive reference universe')
    groups = defaultdict(list)
    for row in usable:
        key = row['profile_id'] if group_by is None else group_by.get(row['profile_id'])
        require(key, 'Missing stage assignment')
        groups[key].append(row)
    comparisons = []
    for key, members in sorted(groups.items()):
        omitted = {r['profile_id'] for r in members}
        retained = set().union(*(set(r['supported_positive_cases']) for r in usable
                                 if r['profile_id'] not in omitted))
        lost = full - retained
        object_ids = {refs[c]['object_id'] for c in full if refs[c].get('object_id')}
        retained_objects = {refs[c]['object_id'] for c in retained if refs[c].get('object_id')}
        comparisons.append({'omitted': key, 'omitted_profiles': sorted(omitted),
                            'supported_before': len(full), 'supported_after': len(retained),
                            'lost_case_ids': sorted(lost), 'lost_count': len(lost),
                            'object_count_before': len(object_ids) if object_ids else None,
                            'object_count_after': len(retained_objects) if object_ids else None,
                            'lost_object_count': len(object_ids - retained_objects) if object_ids else None})
    return {'population': name, 'block': rows[0]['block'] if rows else None,
            'grouping': 'profile' if group_by is None else 'recorded_stage',
            'unit': population['unit'], 'catalog_positive_count': len(refs),
            'qualified_profile_union': sorted(full), 'qualified_profile_union_count': len(full),
            'full_comparison_available': not unavailable and bool(usable),
            'unavailable_profiles': unavailable, 'comparisons': comparisons,
            'normalized_population_eligible': population['normalized_detection_eligible'],
            'interpretation': 'Set differences among eligible recorded outputs. Partial unions are not full-pipeline coverage. '
                              'Absence of a supported witness is not automatically a detector false negative.'}


def canonical_condition(value):
    if value in ('B0', 'B1'):
        return value
    require(value in MODEL_CONDITIONS, 'Unknown model/condition')
    return MODEL_CONDITIONS[value]


def triage_metrics(endpoints, decisions):
    """One pass and condition. Never mix declarations with security correctness."""
    ids = {e['finding_id'] for e in endpoints}
    require(len(ids) == len(endpoints), 'Duplicate endpoint')
    require(set(decisions) == ids, 'Missing or unexpected decision')
    require(len({r.get('block') for r in decisions.values()}) <= 1, 'Repeated passes pooled')
    require(len({r.get('condition') for r in decisions.values()}) <= 1, 'Conditions pooled')
    groups = defaultdict(list)
    for e in endpoints:
        require(e['endpoint_truth'] in ('true', 'false'), 'Unresolved triage reference')
        groups[(e['evaluation_domain'], e['population'])].append(e)
    result = []
    for (domain, pop), group in sorted(groups.items()):
        true = {e['finding_id'] for e in group if e['endpoint_truth'] == 'true'}
        false = {e['finding_id'] for e in group if e['endpoint_truth'] == 'false'}
        require(domain in ('inherited_native_assertion', 'literal_declaration_assertion'), 'Unknown endpoint domain')
        require(domain != 'literal_declaration_assertion' or not false, 'No false declaration oracle')
        dismissed, invalid, abstained = set(), set(), set()
        for e in group:
            d = decisions[e['finding_id']]
            require(d['effective_action'] in ('retain', 'dismiss'), 'Unknown effective action')
            if d['status'] != 'completed' or d['action'] == 'abstain':
                require(d['effective_action'] == 'retain', 'Nonvalid decision did not retain')
            if d['status'] != 'completed':
                invalid.add(e['finding_id'])
            elif d['action'] == 'abstain':
                abstained.add(e['finding_id'])
            if d['effective_action'] == 'dismiss':
                require(d['status'] == 'completed' and d['action'] == 'dismiss', 'Unvalidated dismissal')
                dismissed.add(e['finding_id'])
        before = set().union(*(set(e['positive_support_case_ids']) for e in group))
        after = set().union(*(set(e['positive_support_case_ids']) for e in group if e['finding_id'] not in dismissed))
        result.append({'population': pop, 'evaluation_domain': domain, 'observations': len(group),
                       'source_clusters': sorted({c for e in group for c in e['source_clusters']}),
                       'true_total': len(true), 'false_total': len(false),
                       'dismissed_true': len(true & dismissed), 'dismissed_false': len(false & dismissed),
                       'dismissed_ids': sorted(dismissed), 'invalid_ids': sorted(invalid),
                       'abstained_ids': sorted(abstained),
                       'positive_cases_before': sorted(before), 'positive_cases_after': sorted(after),
                       'lost_positive_case_ids': sorted(before - after),
                       'false_warning_removal': len(false & dismissed) / len(false) if false else None,
                       'true_warning_loss': len(true & dismissed) / len(true)
                                            if domain == 'inherited_native_assertion' and true else None,
                       'declared_assertion_retention': len(true - dismissed) / len(true)
                                            if domain == 'literal_declaration_assertion' and true else None})
    return result


def cluster_sensitivity(endpoints, decisions):
    output = []
    for cluster in sorted({c for e in endpoints for c in e['source_clusters']}):
        subset = [e for e in endpoints if cluster not in e['source_clusters']]
        keep = {e['finding_id'] for e in subset}
        output.append({'omitted_source_cluster': cluster,
                       'metrics': triage_metrics(subset, {k: v for k, v in decisions.items() if k in keep})})
    return output


def score_pass(endpoints, rows):
    require(len(rows) == len(endpoints) * len(CONDITIONS), 'Incomplete six-condition pass')
    require(len({r['block'] for r in rows}) == 1, 'Pass contains multiple blocks')
    grouped = defaultdict(dict)
    for r in rows:
        condition = canonical_condition(r['condition'])
        require(r['finding_id'] not in grouped[condition], 'Duplicate paired decision')
        grouped[condition][r['finding_id']] = r
    require(set(grouped) == set(CONDITIONS), 'Condition set differs')
    summaries, sensitivities = [], []
    for condition in CONDITIONS:
        summaries.extend({'condition': condition, 'block': rows[0]['block'], **r}
                         for r in triage_metrics(endpoints, grouped[condition]))
        sensitivities.append({'condition': condition,
                              'leave_one_source_cluster_out': cluster_sensitivity(endpoints, grouped[condition])})
    return summaries, sensitivities, grouped


def paired_decisions(left, right):
    require(set(left) == set(right), 'Paired populations differ')
    effects = []
    for fid in sorted(left):
        a, b = left[fid], right[fid]
        effects.append({'finding_id': fid,
                        'effective_action_changed': a['effective_action'] != b['effective_action'],
                        'action_changed': a['action'] != b['action'],
                        'status_changed': a['status'] != b['status'],
                        'left': {k: a[k] for k in ('action', 'status', 'effective_action')},
                        'right': {k: b[k] for k in ('action', 'status', 'effective_action')}})
    return effects
