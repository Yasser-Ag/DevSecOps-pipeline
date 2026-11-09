"""Audit saved development evidence and separate occurrence, object and context."""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import posixpath

from study.configuration_development_cases import inspect_key
from study.configuration_references import docker_instructions
from study.configuration_native_reports import parse_configuration_report
from study.native_reports import parse_report


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def locate(raw, pointer):
    value = raw
    for key in pointer.split('/')[1:]:
        key = key.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    if not isinstance(value, dict):
        raise ValueError('Native pointer must resolve to a finding object')
    return value


def case_for_path(path, cases):
    normal = posixpath.normpath(path)
    matches = []
    for row in cases:
        relative = row['path'].split('/', 1)[1]
        if normal == relative or normal.endswith('/'+relative):
            matches.append(row)
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous input location: '+path)
    return matches[0]


def stage_scope(text, start, end):
    starts = [x['line'] for x in docker_instructions(text) if x['instruction'] == 'FROM']
    if not starts:
        raise ValueError('Missing build stages')
    if not isinstance(start, int) or start <= 0:
        return 'unknown'
    if not isinstance(end, int):
        end = start
    if end < start:
        raise ValueError('Invalid source span')
    first = max((i for i, line in enumerate(starts) if line <= start), default=-1)
    last = max((i for i, line in enumerate(starts) if line <= end), default=-1)
    if first != last:
        return 'spans_stages'
    return 'final_stage' if first == len(starts)-1 else 'intermediate_stage'


def validate_runtime(case, runtime, container):
    probe = runtime['probe']; config = container['HostConfig']
    if container['State']['ExitCode'] != 0 or container['State']['Running']:
        raise ValueError('Probe did not exit cleanly')
    if config['Privileged'] or config['NetworkMode'] != 'none' or container.get('Mounts'):
        raise ValueError('Unexpected runtime isolation boundary')
    if int(probe['cap_eff'], 16) != 0:
        raise ValueError('Unexpected effective capabilities')
    if probe['write_errno'] not in (0, 30):
        raise ValueError('Write failure does not independently establish a read-only filesystem')
    if config['ReadonlyRootfs'] != (probe['write_errno'] == 30):
        raise ValueError('Declared rootfs state and behavior disagree')
    if case['case_id'].startswith('D'):
        if probe['uid'] != case['expected_uid']:
            raise ValueError('Final process UID disagrees with independent reference')
    else:
        actual = {'runtime_uid_zero': probe['uid'] == 0,
                  'writable_rootfs': probe['write_errno'] == 0,
                  'no_new_privileges_disabled': probe['no_new_privs'] == 0}[case['property']]
        if actual != case['positive']:
            raise ValueError('Runtime property disagrees with independent reference')
    return True


def same_user_declaration(image_user, container_user):
    """Absent and empty declarations both retain the image's default user."""
    return image_user == container_user or (image_user in (None, '') and container_user in (None, ''))


def analyze(run, out):
    run = Path(run); out = Path(out)
    reference = json.loads((run/'reference/reference_manifest.json').read_text())
    manifest = json.loads((run/'manifest.json').read_text())
    if not manifest['success']:
        raise ValueError('Runtime qualification is incomplete')
    for row in json.loads((run/'collection.json').read_text())['files']:
        if sha(run/row['path']) != row['sha256']:
            raise ValueError('Collected evidence changed: '+row['path'])
    inputs = run/'reference/scanner-inputs'
    for family in ('secrets', 'docker', 'compose'):
        for row in reference[family]:
            if sha(inputs/row['path']) != row['sha256']:
                raise ValueError('Reference input changed')
    for case in reference['secrets']:
        parsed = inspect_key(inputs/case['path'])
        if (parsed['parse_exit_code'] == 0) != case['positive'] or parsed['public_der_sha256'] != case['key_identity']:
            raise ValueError('Independent key verification disagrees')

    traces, summaries = [], []
    for label, info in sorted(manifest['reports'].items()):
        raw_path = run/info['raw_path']; tool = info['tool']
        phase = next(x for x in manifest['phases'] if x['label'] == label)
        report = parse_report(raw_path, tool, phase['outcome']) if tool == 'checkov' else parse_configuration_report(raw_path, tool, phase['outcome'])
        stored = json.loads((run/(label+'.normalized.json')).read_text())
        if report['raw_report_sha256'] != stored['raw_report_sha256'] or report['findings'] != stored['findings']:
            raise ValueError('Native adapter replay differs')
        raw = json.loads(raw_path.read_text())
        family = 'secrets' if tool in ('gitleaks','trivy-secret') else 'compose' if tool == 'kics' else 'docker'
        for finding in report['findings']:
            native = locate(raw, finding['native_locator'])
            case = case_for_path(finding['path'], reference[family])
            trace = {'profile': label, 'finding_id': finding['finding_id'], 'case_id': case['case_id'],
                'native_rule': finding['native_rule'], 'message': finding.get('message'),
                'line_start': finding.get('line_start'), 'line_end': finding.get('line_end'),
                'resource': finding.get('resource'), 'native_locator': finding['native_locator'],
                'raw_report_sha256': report['raw_report_sha256'], 'adjudication': 'not_automatically_assigned'}
            if family == 'docker':
                trace['source_stage_scope'] = stage_scope((inputs/case['path']).read_text(), finding.get('line_start'), finding.get('line_end'))
                trace['reference_final_uid'] = case['expected_uid']
            if family == 'secrets':
                trace['private_material_reference'] = case['positive']
                trace['independent_key_identity'] = case['key_identity']
                trace['endpoint'] = 'presence_of_parseable_private_material_only'
            traces.append(trace)
        summaries.append({'profile': label, 'native_findings': len(report['findings']),
            'status': report['effective_status'], 'raw_report_sha256': report['raw_report_sha256'],
            'executed_in_attempt': phase.get('executed_in_this_attempt', True),
            'reused_from_run': Path(phase['reused_from']).name if 'reused_from' in phase else None})

    secret_conditions = []
    for tool in ('gitleaks', 'trivy-secret'):
        observed = [x for x in traces if x['profile'] == tool and x['native_rule'] == 'private-key']
        flagged = {x['case_id'] for x in observed}
        positive = {x['case_id'] for x in reference['secrets'] if x['positive']}
        negative = {x['case_id'] for x in reference['secrets'] if not x['positive']}
        secret_conditions.append({'profile': tool, 'positive_occurrences_flagged': len(flagged & positive),
            'positive_occurrences_total': len(positive), 'negative_controls_unflagged': len(negative-flagged),
            'negative_controls_total': len(negative), 'distinct_key_objects_flagged': len({x['independent_key_identity'] for x in observed if x['private_material_reference']}),
            'scope': 'Selected material-presence controls; not general secret-scanner accuracy or live-credential detection.'})

    relations = []
    for left, right in itertools.combinations([x for x in reference['secrets'] if x['positive']], 2):
        relations.append({'left': left['case_id'], 'right': right['case_id'], 'same_file_occurrence': False,
            'same_file_bytes': left['sha256'] == right['sha256'], 'same_cryptographic_key': left['key_identity'] == right['key_identity'],
            'basis': 'OpenSSL public DER identity and independent file hashes; no scanner fingerprint used.'})
    runtime_rows = []
    for case in reference['docker'] + [x for x in reference['compose'] if x['runtime_eligible']]:
        key = case['case_id']; runtime = manifest['runtime'][key]
        container = json.loads((run/(key.lower()+'.container.json')).read_text())
        validate_runtime(case, runtime, container)
        if key.startswith('D'):
            image = json.loads((run/(key.lower()+'.image.json')).read_text())
            iid = (run/(key.lower()+'.image.id')).read_text().strip()
            if not (iid == image['Id'] == runtime['image'] == container['Image']):
                raise ValueError('Built image and executed container lineage disagree')
            if not same_user_declaration(image['Config'].get('User'), container['Config'].get('User')):
                raise ValueError('Unexpected runtime USER override in Dockerfile probe')
        else:
            if container['Image'] != reference['base_image']:
                raise ValueError('Compose base image changed')
        runtime_rows.append({'case_id': key, 'property': case['property'], 'positive': case['positive'],
                             **runtime['probe'], 'independent_validation': True})
    diagnostic = [x for x in traces if x['profile'] == 'hadolint' and x['native_rule'] == 'DL3002'
                  and x['source_stage_scope'] == 'intermediate_stage' and x['reference_final_uid'] != 0]
    checkov_raw = json.loads((run/manifest['reports']['checkov']['raw_path']).read_text())
    user_checks = []
    for block_index, block in enumerate(checkov_raw if isinstance(checkov_raw, list) else [checkov_raw]):
        for list_name in ('passed_checks', 'failed_checks'):
            for row_index, row in enumerate(block['results'][list_name]):
                if row['check_id'] not in ('CKV_DOCKER_3', 'CKV_DOCKER_8'):
                    continue
                case = case_for_path(row.get('file_abs_path') or row['file_path'], reference['docker'])
                pointer = (f'/{block_index}' if isinstance(checkov_raw, list) else '') + f'/results/{list_name}/{row_index}'
                locate(checkov_raw, pointer)
                user_checks.append({'case_id': case['case_id'], 'check_id': row['check_id'],
                    'native_status': row['check_result']['result'], 'native_name': row['check_name'],
                    'reference_final_uid': case['expected_uid'], 'native_locator': pointer,
                    'raw_report_sha256': sha(run/manifest['reports']['checkov']['raw_path']),
                    'interpretation': 'Native rule outcome and independent runtime endpoint retained separately.'})
    result = {'schema_version': 'configuration-development-analysis-1',
        'purpose': 'development_qualification', 'reference_manifest_sha256': sha(run/'reference/reference_manifest.json'),
        'profiles': summaries, 'secret_material_controls': secret_conditions,
        'secret_identity_relations': relations, 'runtime_observations': runtime_rows,
        'checkov_user_check_observations': user_checks,
        'intermediate_root_warnings_with_nonroot_final_process': diagnostic,
        'limits': ['Not a final campaign, a strong matching baseline or representative scanner ranking.',
                  'Public-key identity and file occurrence are different valid units; neither universally replaces the other.',
                  'A build-stage warning is not automatically false because the final process is non-root.',
                  'Configuration warnings outside the specified endpoint remain unadjudicated.',
                  'Timing has one development invocation per condition and no fair comparative speed interpretation.']}
    out.mkdir(parents=True, exist_ok=False)
    (out/'analysis.json').write_text(json.dumps(result, indent=2)+'\n')
    (out/'finding_traces.json').write_text(json.dumps(traces, indent=2)+'\n')
    for name, rows in [('runtime_observations', runtime_rows), ('secret_identity_relations', relations)]:
        with (out/(name+'.csv')).open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--run', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); result = analyze(a.run, a.output)
    print(json.dumps({'profiles': result['profiles'], 'runtime_probes': len(result['runtime_observations']),
                      'source_context_diagnostics': len(result['intermediate_root_warnings_with_nonroot_final_process'])}, indent=2))
