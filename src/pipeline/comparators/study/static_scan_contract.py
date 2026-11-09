"""Contracts for repeated static scanner jobs, separate from scientific scoring."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative(value):
    path = Path(value)
    require(bool(value) and not path.is_absolute() and '..' not in path.parts,
            'Unsafe relative path: ' + value)
    return path


def validate(plan):
    require(plan['schema'] == 'static-scan-plan-1', 'Unknown plan schema')
    require(plan['repetitions'] == 5, 'Scanner repetition count differs')
    require(plan['measurement_reuse'] is False, 'Measurement reuse is prohibited')
    ids = [p['id'] for p in plan['profiles']]
    require(len(ids) == len(set(ids)), 'Duplicate profile identity')
    require(set(plan['suites']) == {p['suite'] for p in plan['profiles']}, 'Suite set differs')
    for suite in plan['suites'].values():
        for item in suite['inputs']:
            relative(item['destination'])
            require(item['source'].startswith('<LAB_ROOT>/'), 'Input outside study root')
    for p in plan['profiles']:
        require(re.fullmatch(r'[a-z0-9-]+', p['id']) is not None, 'Unsafe profile identity')
        relative(p['report'])
        require(p['parser'] in ('semgrep', 'checkov', 'findsecbugs', 'trivy', 'syft', 'grype',
                               'dependency-check', 'gitleaks', 'hadolint', 'trivy-secret',
                               'trivy-config', 'kics', 'zizmor', 'kubescape', 'bandit'), 'Unsupported report parser')
        require(p['kind'] in ('native', 'container'), 'Unknown execution kind')
        require(p['accepted_exit_codes'] and all(type(c) is int for c in p['accepted_exit_codes']),
                'Exit-code contract absent')
        require(0 < p['timeout_seconds'] <= 1800, 'Unbounded profile timeout')
        require(isinstance(p['argv'], list) and all(isinstance(a, str) for a in p['argv']), 'Non-argv command')
        require(not any('/evidence/' in a or '/environment/configuration-matching-code-v1/inputs' in a
                        for a in p['argv']), 'Historical execution path remains')
        require(not any('..' in a.split('/') for a in p['argv']), 'Command traverses a parent directory')
        require(set(re.findall(r'\{([^}]+)\}', json.dumps(p['argv']))) <= {'WORK', 'PHASE'}, 'Unknown template')
        if p['kind'] == 'native':
            require(Path(p['argv'][0]).is_absolute(), 'Native executable must be absolute')
            require(Path(p['argv'][0]).name not in ('bash', 'sh', 'zsh', 'python', 'python3'), 'Shell/script launcher not a scanner')
        else:
            require(re.fullmatch('sha256:[a-f0-9]{64}', p['image']) is not None, 'Mutable scanner image')
            relative(p['input_directory']); relative(p['output_directory'])
            require(p['argv'][0] == 'scan', 'Unexpected container entrypoint arguments')
            source, target = Path(p['input_directory']), Path(p['output_directory'])
            require(source != target and source not in target.parents and target not in source.parents,
                    'Writable output mount aliases scanner input')
        for dependency in p['requires']:
            require(dependency in ids and dependency != p['id'], 'Missing/self dependency')
            other = next(x for x in plan['profiles'] if x['id'] == dependency)
            require(other['suite'] == p['suite'], 'Cross-suite dependency is unqualified')
    order = ordered_profiles(plan)
    require(len(order) == len(ids), 'Cyclic dependency graph')
    require(plan['study_model_generations'] == 0, 'Static plan must not invoke models')
    return plan


def ordered_profiles(plan):
    """Stable topological order; preserve receipt order among eligible jobs."""
    pending = list(plan['profiles'])
    result, done = [], set()
    while pending:
        eligible = next((p for p in pending if set(p['requires']) <= done), None)
        if eligible is None:
            raise ValueError('Cyclic dependency graph')
        result.append(eligible); done.add(eligible['id']); pending.remove(eligible)
    return result


def schedule(plan):
    validate(plan)
    return [{'job_id': f'b{block}-' + p['id'], 'block': block, 'profile': p['id'], 'suite': p['suite'],
             'requires': [f'b{block}-' + d for d in p['requires']]}
            for block in range(1, plan['repetitions'] + 1)
            for suite in sorted(plan['suites']) for p in ordered_profiles(plan) if p['suite'] == suite]


def render(profile, work, phase):
    require(Path(work).is_absolute() and Path(phase).is_absolute(), 'Execution roots must be absolute')
    argv = [x.replace('{WORK}', str(work)).replace('{PHASE}', str(phase)) for x in profile['argv']]
    require(not any(re.search(r'\{(?:WORK|PHASE)\}', a) for a in argv), 'Unresolved command template')
    return argv


def normalize(raw, tool, execution_status, *, redacted_secrets=False):
    """Report parsing is independent of process success and expected finding counts."""
    from study.native_reports import parse_report
    from study.configuration_native_reports import parse_configuration_report
    from study.infrastructure_native_reports import parse_infrastructure_report
    from study.sca_native_reports import parse_sca_report
    if tool in ('semgrep', 'checkov', 'findsecbugs'):
        return parse_report(raw, tool, execution_status)
    if tool in ('syft', 'grype', 'trivy', 'dependency-check'):
        return parse_sca_report(raw, tool, execution_status)
    if tool in ('zizmor', 'kubescape'):
        return parse_infrastructure_report(raw, tool, execution_status)
    if tool == 'bandit':
        data = json.loads(Path(raw).read_text())
        require(all(k in data for k in ('results', 'errors', 'metrics')), 'Incomplete Bandit report')
        return {'tool': tool, 'raw_report_sha256': sha(raw), 'findings': data['results'],
                'effective_status': execution_status if execution_status != 'completed' else
                    'completed_with_limitations' if data['errors'] else 'completed',
                'diagnostics': {'errors': data['errors'], 'metrics': data['metrics']}}
    result = parse_configuration_report(raw, tool, execution_status)
    if tool == 'gitleaks' and redacted_secrets:
        for finding in result['findings']:
            finding['reported_secret_sha256'] = None
            finding['secret_redacted'] = True
        result['contract'] += ' Redacted placeholders are not secret-material identities.'
    return result
