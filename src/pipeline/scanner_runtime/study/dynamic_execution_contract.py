"""Final dynamic job identity and conservative native-output validation."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from study.dynamic_reset_contract import require, sha
from study.dynamic_scan_contract import profiles, profile, generation_workload, REPEATS
from study.restler_native import parse_bucket


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def schedule():
    return [{'id': 'b%02d-%s' % (block, identity), 'block': block, 'profile_id': identity,
             'kind': 'target_generation' if identity == 'aigoat-generation' else 'scanner',
             'reset': 'fresh target state before this job'}
            for block in range(1, REPEATS + 1)
            for identity in [r['id'] for r in profiles()] + ['aigoat-generation']]


def job(identity):
    rows = [r for r in schedule() if r['id'] == identity]
    require(len(rows) == 1, 'Job outside sealed dynamic schedule')
    return rows[0]


def execution_plan():
    return {'schema': 'dynamic-execution-v1', 'jobs': schedule(),
            'schedule_sha256': digest(schedule()), 'profiles_sha256': digest(profiles()),
            'generation_sha256': digest(generation_workload()),
            'scientific_execution_requires': 'protocol v1.0, all eight gates, exact package and assets',
            'measurements': ['reset', '<MASKED:fixture:127>', 'compile', 'model_load', 'tool_execution',
                             'reference_before_after', 'cleanup'],
            'missing_measurements': 'null with explicit reason; never imputed as zero',
            'repetition_interpretation': 'execution variability, not independent vulnerabilities'}


def require_release(release, package, assets):
    require(release.get('protocol_version') == '1.0' and release.get('final_ready') is True,
            'Final protocol is not released')
    gates = release.get('gates', {})
    require(set(gates) == {'G' + str(i) for i in range(1, 9)} and
            all(v == 'passed' for v in gates.values()), 'Final readiness gates are incomplete')
    binding = release.get('dynamic_execution', {})
    require(binding.get('package_manifest_sha256') == sha(Path(package) / 'package_manifest.json'),
            'Released package identity differs')
    require(binding.get('asset_locks_sha256') == sha(assets), 'Released asset identity differs')
    for key in ('schedule_sha256', 'profiles_sha256', 'generation_sha256'):
        require(binding.get(key) == execution_plan()[key], 'Released dynamic binding differs: ' + key)
    return True


def one(root, pattern):
    files = sorted(Path(root).glob(pattern))
    require(len(files) == 1, 'Expected one native report: ' + pattern)
    return files[0]


def read_json(path):
    require(path.is_file() and not path.is_symlink(), 'Missing or symbolic native report')
    return json.loads(path.read_text())


def native_report(tool, directory):
    """Validate native units without assigning security correctness or merging them."""
    d = Path(directory)
    issues, files, units = [], [], []
    if tool == 'nuclei':
        p = d / 'nuclei.jsonl'
        require(p.is_file() and not p.is_symlink(), 'Missing Nuclei output; not an empty result')
        files.append(p)
        for index, line in enumerate(p.read_text().splitlines()):
            raw = json.loads(line)
            require({'template-id', 'matched-at', 'info'} <= raw.keys(), 'Invalid Nuclei record')
            units.append({'native_pointer': '/line/' + str(index + 1), 'kind': 'template_match',
                          'rule': raw['template-id'], 'route': urlsplit(raw['matched-at']).path})
        errors = d / 'errors.jsonl'
        if errors.exists():
            files.append(errors)
            if errors.read_text().strip():
                issues.append('native_request_errors')
    elif tool == 'zap':
        p = d / 'zap.json'; raw = read_json(p); files.append(p)
        require(raw.get('@programName') == 'ZAP' and isinstance(raw.get('site'), list), 'Invalid ZAP report')
        for i, site in enumerate(raw['site']):
            require(isinstance(site.get('alerts'), list), 'Missing ZAP alerts list')
            for j, alert in enumerate(site['alerts']):
                require('pluginid' in alert and isinstance(alert.get('instances'), list), 'Invalid ZAP alert')
                for k, instance in enumerate(alert['instances']):
                    require('uri' in instance, 'Missing ZAP occurrence URI')
                    units.append({'native_pointer': f'/site/{i}/alerts/{j}/instances/{k}',
                                  'kind': 'alert_instance', 'rule': str(alert['pluginid']),
                                  'route': urlsplit(instance['uri']).path})
    elif tool == 'schemathesis':
        p = one(d, 'reports/json-*.json'); raw = read_json(p); files.append(p)
        require(raw.get('complete') is True and isinstance(raw.get('failures'), list), 'Incomplete Schemathesis report')
        require(isinstance(raw.get('operations'), dict) and isinstance(raw.get('errors'), list), 'Invalid Schemathesis schema')
        operations = raw['operations']
        require(all(type(operations.get(k)) is int for k in ('total', 'selected', 'tested', 'errored', 'skipped')),
                'Missing operation accounting')
        if operations['tested'] != operations['selected'] or operations['errored'] or raw['errors']:
            issues.append('native_operations_incomplete_or_errored')
        if raw.get('stop_reason') != 'completed':
            issues.append('native_stop_reason:' + str(raw.get('stop_reason')))
        har = one(d, 'reports/har-*.json'); files.append(har)
        require(isinstance(read_json(har).get('log', {}).get('entries'), list), 'Invalid HAR')
        junit = one(d, 'reports/junit-*.xml'); files.append(junit)
        require(ET.parse(junit).getroot().tag == 'testsuites', 'Invalid JUnit report')
        units = [{'native_pointer': '/failures/' + str(i), 'kind': 'native_failure'}
                 for i, _ in enumerate(raw['failures'])]
    elif tool == 'restler':
        p = one(d, '**/logs/testing_summary.json'); raw = read_json(p); files.append(p)
        require(isinstance(raw.get('total_requests_sent'), dict) and isinstance(raw.get('bug_buckets'), dict),
                'Invalid RESTler completion summary')
        require(type(raw.get('num_sequence_failures')) is int, 'Missing RESTler sequence status')
        if raw['num_sequence_failures']:
            issues.append('native_sequence_failures')
        for p in sorted(d.glob('**/bug_buckets/*.json')):
            raw = read_json(p); files.append(p)
            if 'checker_name' in raw:
                units.append(parse_bucket(raw, p.relative_to(d).as_posix()))
    else:
        raise ValueError('Unknown native report type')
    return {'parsed': True, 'tool': tool, 'native_unit_count': len(units), 'units': units,
            'limitations': issues, 'native_units_are_unique_vulnerabilities': False,
            'reports': [{'path': p.relative_to(d).as_posix(), 'sha256': sha(p), 'bytes': p.stat().st_size} for p in files]}


def completion(identity, process, parsed, trace, expected_operations):
    """All operation coverage comes from the independently recorded forwarded trace."""
    row = profile(identity)
    required = set(tuple(x) for x in expected_operations)
    require(required, 'Missing declared operation scope')
    reached = {(r.get('method'), urlsplit(r.get('path', '')).path) for r in trace if r.get('forwarded')}
    gates = sum(bool(r.get('gate_reason')) for r in trace)
    harness = sum(bool(r.get('harness_error')) for r in trace)
    missing = sorted(required - reached)
    failed = bool(process.get('error') or process.get('returncode') not in row['accepted_exit_codes'] or
                  not parsed.get('parsed') or harness or not trace or not reached)
    limitations = list(parsed.get('limitations', []))
    if gates: limitations.append('explicit_proxy_gates')
    if missing: limitations.append('declared_operations_not_reached')
    if len(trace) > row['request_budget']: limitations.append('request_budget_exceeded')
    if process.get('accounting') is None: limitations.append('execution_accounting_unavailable')
    return {'status': 'failed' if failed else 'completed_with_limitations' if limitations else 'completed',
            'native_report': parsed, 'limitations': limitations, 'requests': len(trace),
            'forwarded_requests': sum(bool(r.get('forwarded')) for r in trace),
            'gate_responses': gates, 'harness_errors': harness, 'missing_operations': missing,
            'negative_security_result': False,
            'interpretation': 'Completion is an engineering endpoint; native units need independent scientific evaluation.'}
