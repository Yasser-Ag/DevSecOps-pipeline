"""Fixed full-pilot identities and deterministic policy adapters."""


def input_format(packet):
    native = packet['evidence'][0]['content']; tool = native['tool']
    if native.get('package'): return 'component'
    if tool in ('semgrep', 'findsecbugs', 'bandit'): return 'source'
    if tool in ('nuclei', 'zap', 'restler'): return 'http'
    if tool in ('checkov', 'trivy-config', 'kics', 'hadolint', 'zizmor'): return 'declaration'
    if tool == 'gitleaks': return 'secret'
    return 'other'


def retain_all(packet):
    return {'finding_id': packet['finding_id'], 'condition': 'B0', 'effective_action': 'retain'}


def validate_population(config, packets):
    ids = [p['finding_id'] for p in config['cases']]
    if len(ids) != 29 or len(set(ids)) != 29:
        raise ValueError('Expected exactly 29 unique pilot cases')
    if set(packets) != {'alert_only', 'context'}:
        raise ValueError('Missing information condition')
    for condition in packets:
        if [p['finding_id'] for p in packets[condition]] != ids:
            raise ValueError('Pilot population/order differs')
    for case in config['cases']:
        if set(case['counts']) != {'qwen35-9b-q4km', 'gemma4-e4b-qat-q40'}:
            raise ValueError('Missing model token qualification')
        for counts in case['counts'].values():
            if set(counts) != {'alert', 'selected_context'} or any(type(n) is not int or not 1 <= n <= 3680 for n in counts.values()):
                raise ValueError('Unqualified input budget')
