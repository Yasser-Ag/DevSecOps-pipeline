"""Unchanged pilot policy helpers."""

def retain_all(packet):
    return {'finding_id': packet['finding_id'], 'condition': 'B0', 'effective_action': 'retain'}

def input_format(packet):
    native = packet['evidence'][0]['content']; tool = native['tool']
    if native.get('package'): return 'component'
    if tool in ('semgrep', 'findsecbugs', 'bandit'): return 'source'
    if tool in ('nuclei', 'zap', 'restler'): return 'http'
    if tool in ('checkov', 'trivy-config', 'kics', 'hadolint', 'zizmor'): return 'declaration'
    if tool == 'gitleaks': return 'secret'
    return 'other'
