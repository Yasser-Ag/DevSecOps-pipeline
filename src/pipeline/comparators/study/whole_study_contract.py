"""Typed applicability, provenance routing and descriptive analysis contracts.

Routing identifies candidate domains. It never assigns truth to a new report.
Archived labels cannot be transferred by a raw-report index or by shared CWE.
"""
from collections import Counter, defaultdict
import hashlib
import json


CONDITIONS = ('B0', 'B1', 'Q-A', 'Q-C', 'G-A', 'G-C')
CONTRASTS = (('Q-C', 'B1'), ('G-C', 'B1'), ('Q-A', 'G-A'),
             ('Q-C', 'G-C'), ('Q-C', 'Q-A'), ('G-C', 'G-A'))
COMPOSE = tuple('compose:' + p for p in (
    'runtime_uid_zero', 'writable_rootfs', 'no_new_privileges_disabled',
    'privileged_enabled', 'host_network_enabled', 'docker_socket_mounted',
    'unqualified-native'))
COMPARATORS = {
    'sast_line_scope_normalized_scope': ('sast-java',),
    'dast_request_legacy_and_v2': ('api-native:a', 'api-native:invalid'),
    'component_and_secret_identity': ('sca', 'secret'),
    'kubernetes_typed_association': tuple('kubernetes:' + c for c in ('controls', 'originals', 'matrix', 'split')),
    'terraform_resource_property': ('terraform:controls', 'terraform:originals'),
    'aigoat_competent_exact_vs_coarse': ('aigoat-declared-properties', 'aigoat-http-properties'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def lot(population):
    for prefix, name in (
        ('sast-java', 'E01'), ('sca', 'E02'), ('os-advisory', 'E03'),
        ('secret', 'E04'), ('docker', 'E05'), ('compose:', 'E05'),
        ('workflow-', 'E06'), ('terraform:', 'E07'), ('kubernetes:', 'E08'),
        ('api-', 'E09'), ('aigoat-rag-', 'E11'), ('aigoat-', 'E10')):
        if population.startswith(prefix):
            return name
    raise ValueError('Unmapped population: ' + population)


def static_route(profile):
    name, suite = profile['id'], profile['suite']
    domain, note = [], ''
    if suite == 'java':
        if name == 'java-checkov':
            note = 'crAPI Dockerfile characterization; not the six synthetic runtime controls or Java benchmark labels'
        else:
            require(name in ('java-semgrep', 'java-findsecbugs'), 'Unknown Java profile')
            domain = ['sast-java']
    elif suite == 'sca':
        domain = ['sca']
    elif suite == 'configuration':
        if profile['parser'] in ('gitleaks', 'trivy-secret'):
            domain = ['secret']
        elif profile['parser'] == 'kics':
            domain = list(COMPOSE)
        else:
            require(profile['parser'] in ('checkov', 'hadolint', 'trivy-config'), 'Unknown configuration profile')
            domain = ['docker']
    elif suite == 'infrastructure':
        corpus = name.split('-')[1]
        require(corpus in ('controls', 'originals'), 'Unknown infrastructure corpus')
        if 'kubernetes' in name or 'kubescape' in name:
            domain = ['kubernetes:' + corpus]
        elif 'terraform' in name:
            domain = ['terraform:' + corpus]
        elif 'workflow' in name or 'zizmor' in name:
            domain = ['workflow-job:' + corpus, 'workflow-global:' + corpus]
        else:
            raise ValueError('Unknown infrastructure profile: ' + name)
    elif suite == 'k8s-scope':
        domain = ['kubernetes:' + ('split' if '-split-' in name else 'matrix')]
    elif suite == 'os':
        domain = ['os-advisory']
    elif suite.startswith('aigoat'):
        if profile['parser'] in ('kics', 'hadolint') or '-docker-' in name or '-config-' in name:
            domain = ['aigoat-declared-properties']
        else:
            parser = profile['parser']
            family = 'trivy' if parser in ('trivy', 'trivy-secret') else parser
            if family == 'syft':
                note = 'AIGoat component inventory; no independent native vulnerability oracle'
            else:
                require(family in ('bandit', 'checkov', 'gitleaks', 'grype', 'semgrep', 'trivy', 'zizmor'),
                        'Unknown AIGoat profile')
                domain = ['aigoat-unresolved:' + family]
    else:
        raise ValueError('Unknown static suite: ' + suite)
    inventory = profile['role'] == 'inventory'
    return {'profile_id': name, 'execution_kind': 'static', 'role': profile['role'],
            'tool': profile['parser'], 'candidate_populations': domain,
            'can_award_detection': not inventory and bool(domain),
            'unmatched_output': 'preserve_unadjudicated',
            'interpretation': note or ('Inventory support only; component presence is not detection.' if inventory
                                     else 'Require typed endpoint and independent evidence; routing alone assigns no label.')}


def dynamic_route(profile):
    name, target = profile['id'], profile['target']
    if target == 'crapi':
        domain = ['api-authorization'] if profile['tool'] == 'restler' else [
            'api-native:invalid' if profile['condition'] == 'invalid' else 'api-native:a']
    else:
        require(target == 'aigoat', 'Unknown dynamic target')
        domain = ['aigoat-http-properties']
    return {'profile_id': name, 'execution_kind': 'dynamic', 'role': profile['role'],
            'tool': profile['tool'], 'candidate_populations': domain,
            'can_award_detection': True, 'unmatched_output': 'preserve_unadjudicated',
            'interpretation': ('Supplied two-user object fixtures and checker enabled/disabled conditions; '
                               'not unrestricted autonomous BOLA discovery.' if profile['tool'] == 'restler'
                               else 'Exact method, route, actual authentication context and property required; '
                                    'HTTP findings do not establish semantic RAG detection.')}


def historical_profile(finding):
    """Resolve an archived profile name without inspecting its truth label."""
    pop, name = finding['population'], finding['profile']
    if pop == 'sast-java':
        return 'java-' + name
    if pop == 'sca':
        return 'sca-' + name
    if pop in ('secret', 'docker') or pop.startswith('compose:'):
        return 'configuration-' + name
    if pop.startswith(('terraform:', 'workflow-')):
        return 'infrastructure-' + name
    if pop.startswith('kubernetes:'):
        corpus = pop.split(':')[1]
        return ('k8s-scope-' + name if corpus in ('matrix', 'split') else
                'infrastructure-' + name + '-kubernetes')
    if pop == 'os-advisory':
        return 'os-' + name
    if pop == 'api-authorization':
        return 'crapi-restler-' + name
    if pop.startswith('api-native:'):
        return 'crapi-' + name
    if pop.startswith('aigoat-'):
        prefix = 'aigoat-compose-' if name == 'kics-compose-deployment-qualified' else (
            'aigoat-workflow-' if name == 'checkov-workflow-qualified' else 'aigoat-')
        return prefix + name
    raise ValueError('Unmapped historical finding')


def source_cluster(reference):
    """Conservative dependence groups, not assertions of vulnerability identity."""
    pop, details = reference['population'], reference.get('details', {})
    source = reference.get('source_reference_id', '')
    if pop == 'sast-java':
        require(source.startswith('owasp-java-1.2:BenchmarkTest'), 'Missing benchmark case')
        return source
    if pop == 'sca':
        path = details.get('path', '')
        family = 'log4j' if 'log4j' in path else 'commons-text' if 'commons-text' in path else None
        require(family, 'Unspecified Maven source family')
        return 'maven:' + family
    if pop == 'secret':
        return 'synthetic-private-material-control-family'
    if pop == 'docker' or pop.startswith('compose:'):
        return 'constructed-container-controls'
    if pop.startswith('terraform:'):
        return 'terraform:' + pop.split(':')[1]
    if pop.startswith('workflow-'):
        return 'workflow:' + pop.split(':')[1]
    if pop.startswith('kubernetes:'):
        return 'kubernetes:' + pop.split(':')[1]
    if pop == 'os-advisory':
        return 'ubi-vendor-image-lineage'
    if pop == 'api-authorization':
        return 'crapi-known-bola-defect'
    if pop.startswith('aigoat-'):
        return 'aigoat:llm02-4' if pop.startswith('aigoat-rag') else 'aigoat-development'
    raise ValueError('Unspecified reference source cluster: ' + pop)


def population_contract(population, references, findings, links, routes):
    name = population['population']
    refs = [r for r in references if r['population'] == name]
    obs = [r for r in findings if r['population'] == name]
    ids = {r['finding_id'] for r in obs}
    edges = [r for r in links if r['finding_id'] in ids]
    qualified = population['linkage_status'] == 'qualified'
    rag = name == 'aigoat-rag-context-authorization'
    partial = name in ('aigoat-declared-properties', 'aigoat-http-properties')
    endpoint_kind = ('reference_context_observation' if rag else
                     'specified_property_projection' if partial else
                     'qualified_reference_endpoint' if qualified else 'descriptive_or_unresolved')
    excluded = []
    if not qualified:
        excluded.append('No normalized scanner coverage or native TP/FP rate from this population.')
    if rag:
        excluded.append('No qualified semantic-RAG scanner; unavailable coverage is null, not zero.')
    if name == 'sast-java':
        excluded.append('Case/CWE labels do not establish warning-pair equivalence; no SAST false-merge rate.')
    if name.startswith('workflow-'):
        excluded.append('Declared permission and policy warning do not establish effective live capability.')
    if name.startswith('kubernetes:'):
        excluded.append('Declaration inheritance is not a measured process UID or full native-policy truth.')
    if partial:
        excluded.append('Literal/header-property support is not native security correctness or exploitability.')
    eligible_metrics = ['cost']
    if qualified:
        eligible_metrics += ['case_detection' if name in ('sast-java', 'sca', 'secret', 'os-advisory', 'api-authorization')
                             else 'property_coverage', 'unique_stage_contribution']
    if name == 'sast-java':
        eligible_metrics.append('case_confusion')
    return {'population': name, 'lot': lot(name), 'unit': population['unit'],
            'endpoint': population['endpoint'], 'historical_linkage_status': population['linkage_status'],
            'endpoint_kind': endpoint_kind, 'normalized_detection_eligible': qualified,
            'eligible_metric_ids': eligible_metrics,
            'case_ids_by_truth': {k: sorted(r['case_id'] for r in refs if r['truth'] == k)
                                  for k in ('positive', 'negative', 'unresolved')},
            'native_ids_by_label': {k: sorted(r['finding_id'] for r in obs if r['native_label'] == k)
                                    for k in ('true', 'false', 'unresolved')},
            'support_links': sum(r['relation'] == 'supports' for r in edges),
            'candidate_links': sum(r['relation'] == 'candidate' for r in edges),
            'final_profiles': sorted(r['profile_id'] for r in routes if name in r['candidate_populations']),
            'comparator_ids': [c for c, pops in COMPARATORS.items() if name in pops],
            'exclusions': excluded,
            'nonsecurity_or_unmatched_outputs': 'Preserved outside the qualified endpoint denominator.'}


def triage_clusters(endpoints, findings, references, links):
    findings = {r['finding_id']: r for r in findings}
    references = {r['case_id']: r for r in references}
    support = defaultdict(set)
    for edge in links:
        if edge['relation'] == 'supports':
            support[edge['finding_id']].add(edge['case_id'])
    rows = []
    for endpoint in endpoints:
        fid = endpoint['finding_id']
        require(fid in findings, 'Unknown triage finding')
        refs = [references[r] for r in endpoint['linked_reference_ids']]
        require(refs, 'Triage endpoint without source cluster')
        clusters = sorted({source_cluster(r) for r in refs})
        if endpoint['population'] == 'sast-java':
            require(clusters == [endpoint['source_case_if_sast']], 'SAST source-cluster disagreement')
        declaration = endpoint['evaluation_domain'] == 'literal_declaration_assertion'
        require(endpoint['security_accuracy_eligible'] is not declaration and
                endpoint['declaration_retention_eligible'] is declaration, 'Mixed endpoint domains')
        row = {k: endpoint[k] for k in ('finding_id', 'population', 'evaluation_domain', 'endpoint_truth')}
        row.update(source_clusters=clusters, case_ids=sorted(r['case_id'] for r in refs),
                   positive_support_case_ids=sorted(support[fid]),
                   independent_application=False, repeat_blocks=4)
        rows.append(row)
    return rows


def descriptive_triage(endpoints, decisions):
    """One condition/block, preserving missing outcomes and typed denominators.

    decisions: {finding_id: {action: retain/dismiss/abstain, status: valid/...}}.
    Missing/invalid replies retain. No conversion into an evaluation label.
    """
    ids = {e['finding_id'] for e in endpoints}
    require(len(ids) == len(endpoints), 'Duplicate endpoint')
    require(set(decisions) <= ids, 'Decision for unknown finding')
    groups = defaultdict(list)
    for endpoint in endpoints:
        groups[(endpoint['population'], endpoint['evaluation_domain'])].append(endpoint)
    out = []
    for (population, domain), rows in sorted(groups.items()):
        invalid = missing = abstain = 0
        dismissed = set()
        for row in rows:
            decision = decisions.get(row['finding_id'])
            if decision is None:
                missing += 1
            elif decision.get('status') != 'valid' or decision.get('action') not in ('retain', 'dismiss', 'abstain'):
                invalid += 1
            elif decision['action'] == 'abstain':
                abstain += 1
            elif decision['action'] == 'dismiss':
                dismissed.add(row['finding_id'])
        true = {r['finding_id'] for r in rows if r['endpoint_truth'] == 'true'}
        false = {r['finding_id'] for r in rows if r['endpoint_truth'] == 'false'}
        declaration = domain == 'literal_declaration_assertion'
        require(not declaration or not false, 'Unexpected false declaration endpoint')
        out.append({'population': population, 'evaluation_domain': domain,
                    'scheduled': len(rows), 'responses_present': len(rows) - missing,
                    'missing': missing, 'invalid': invalid, 'abstain': abstain,
                    'true_total': len(true), 'false_total': len(false),
                    'false_warning_removal': None if declaration or not false else len(false & dismissed) / len(false),
                    'true_warning_loss': None if declaration or not true else len(true & dismissed) / len(true),
                    'declaration_retention': (len(true - dismissed) / len(true)) if declaration and true else None,
                    'dismissed_ids': sorted(dismissed)})
    return out


def cluster_sensitivity(endpoints, decisions):
    """Leave one conservative source cluster out; a range, never a CI."""
    clusters = sorted({c for r in endpoints for c in r['source_clusters']})
    variants = []
    for cluster in clusters:
        retained = [r for r in endpoints if cluster not in r['source_clusters']]
        keep = {r['finding_id'] for r in retained}
        variants.append({'excluded_source_cluster': cluster, 'retained_cases': len(keep),
                         'metrics': descriptive_triage(retained, {k: v for k, v in decisions.items() if k in keep})})
    return variants


def validate_bindings(bundle):
    """Reject routing gaps and unsupported scoring promotions before release."""
    pops = {p['population']: p for p in bundle['populations']}
    routes = {r['profile_id']: r for r in bundle['profiles']}
    require(len(pops) == 35 and len(routes) == 93, 'Population/profile universe changed')
    require(len(bundle['profiles']) == 93, 'Duplicate profile')
    for route in routes.values():
        require(set(route['candidate_populations']) <= set(pops), 'Unknown routed population')
        if route['role'] == 'inventory':
            require(not route['can_award_detection'], 'Inventory promoted to detector')
    for p in pops.values():
        expected = sorted(r['profile_id'] for r in routes.values() if p['population'] in r['candidate_populations'])
        require(p['final_profiles'] == expected, 'Population/profile routing mismatch')
        require(p['normalized_detection_eligible'] == (p['historical_linkage_status'] == 'qualified'),
                'Unsupported detection eligibility promotion')
    require(not pops['aigoat-rag-context-authorization']['final_profiles'], 'HTTP scanner promoted to RAG detector')
    obs = bundle['native_observations']
    require(len(obs) == 1988 and len({r['finding_id'] for r in obs}) == len(obs), 'Native record population changed')
    for r in obs:
        require(r['profile_id'] in routes and r['population'] in routes[r['profile_id']]['candidate_populations'],
                'Historical native observation routed to incompatible profile')
    refs = bundle['references']
    require(len(refs) == 338 and len({r['case_id'] for r in refs}) == 338, 'Reference universe changed')
    for r in refs:
        require(r['source_cluster'] and r['population'] in pops, 'Missing reference cluster')
    require(set(COMPARATORS) == {r['id'] for r in bundle['comparators']}, 'Comparator family missing')
    for row in bundle['comparators']:
        require(row['complete_member_baseline_retained'], 'Competent complete-member baseline removed')
        require(row['population_domains'] == list(COMPARATORS[row['id']]), 'Comparator domain changed')
        if row['id'] == 'sast_line_scope_normalized_scope':
            require(not row['warning_pair_identity_scoring'], 'Unqualified SAST pair identity')
    endpoints = bundle['triage_clusters']
    require(len(endpoints) == 88 and len({r['finding_id'] for r in endpoints}) == 88, 'Triage cohort changed')
    require(Counter((r['evaluation_domain'], r['endpoint_truth']) for r in endpoints) == Counter({
        ('inherited_native_assertion', 'true'): 62, ('inherited_native_assertion', 'false'): 11,
        ('literal_declaration_assertion', 'true'): 15}), 'Triage endpoint domains changed')
    negative = [r for r in endpoints if r['endpoint_truth'] == 'false']
    require(len({c for r in negative for c in r['source_clusters']}) == 7, 'False-warning source clusters changed')
    require(bundle['analysis']['primary_contrasts'] == [list(c) for c in CONTRASTS], 'Contrasts changed')
    require(bundle['analysis']['repeats_are_independent_cases'] is False, 'Repeated-case inflation')
    return {'populations': len(pops), 'static_profiles': sum(r['execution_kind'] == 'static' for r in routes.values()),
            'dynamic_profiles': sum(r['execution_kind'] == 'dynamic' for r in routes.values()),
            'native_observations': len(obs), 'references': len(refs), 'triage_endpoints': len(endpoints),
            'false_warning_source_clusters': 7, 'comparator_families': len(COMPARATORS)}
