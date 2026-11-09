"""Audit static development reports without equating policies and truth units."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import posixpath
import re
import yaml

from study.configuration_development_analysis import locate
from study.configuration_native_reports import parse_configuration_report
from study.infrastructure_cases import effective_contents, effective_nonroot, unrestricted_ssh
from study.infrastructure_native_reports import parse_infrastructure_report
from study.native_reports import parse_report


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def literal_groups(text):
    """Read only the generated literal grammar; reject expressions and other HCL."""
    groups = {}; current = None; state = 'outside'; rule = None
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        if state == 'outside':
            match = re.fullmatch(r'resource "aws_security_group" "([a-z0-9]+)" \{', line)
            if not match: raise ValueError('Unsupported control HCL')
            current = 'aws_security_group.' + match[1]
            if current in groups: raise ValueError('Duplicate resource address')
            state = 'resource'; rule = {}
        elif line == 'ingress {' and state == 'resource':
            state = 'ingress'
        elif line == '}':
            if state == 'ingress': state = 'resource_end'
            elif state == 'resource_end':
                if set(rule) != {'protocol','from_port','to_port','cidr_blocks','ipv6_cidr_blocks'}:
                    raise ValueError('Incomplete literal rule')
                groups[current] = rule; state = 'outside'
            else: raise ValueError('Unexpected block ending')
        elif state in ('resource', 'ingress'):
            key, separator, value = line.partition(' = ')
            if not separator: raise ValueError('Unsupported literal attribute')
            value = json.loads(value)
            if state == 'ingress' and key != 'description':
                if key in rule: raise ValueError('Duplicate attribute')
                rule[key] = value
            elif key not in ('name','description','vpc_id'):
                raise ValueError('Unsupported attribute')
        else: raise ValueError('Unsupported generated control grammar')
    if state != 'outside': raise ValueError('Unclosed control HCL')
    return groups


def source_candidates(path, files, corpus, family):
    if not isinstance(path, str): return []
    normal = posixpath.normpath(path); prefix = corpus+'/'+family+'/'
    candidates = []
    for row in files:
        if not row['path'].startswith(prefix): continue
        relative = row['path'][len(prefix):]
        if normal == relative or normal.endswith('/'+relative): candidates.append(row['path'])
    return sorted(candidates)


def validate_reference(inputs, reference):
    for row in reference['files']:
        path = inputs/row['path']
        if sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise ValueError('Changed input file')
    groups = literal_groups((inputs/'controls/terraform/main.tf').read_text())
    for case in reference['cases']:
        path = inputs/case['path']; prop = case['property']
        if sha(path) != case['source_sha256']: raise ValueError('Changed case input')
        if prop == 'declared_unrestricted_tcp_22':
            value = groups[case['resource']]; positive = unrestricted_ssh(value)
        else:
            doc = yaml.safe_load(path.read_text())
            if prop == 'declared_contents_write':
                value = effective_contents(doc, doc['jobs'][case['resource'].split('.')[1]])
                positive = None if value is None else value == 'write'
            else:
                container = doc['spec']['containers'][case['container_index']]
                resource = '/'.join([doc['kind'],doc['metadata']['namespace'],doc['metadata']['name'],'containers',container['name']])
                if resource != case['resource']: raise ValueError('Wrong container identity')
                if prop == 'declared_nonroot_enforcement_disabled': value = effective_nonroot(doc['spec'],container)
                elif prop == 'declared_privileged': value = container['securityContext']['privileged']
                elif prop == 'declared_writable_rootfs': value = container['securityContext']['readOnlyRootFilesystem']
                else: raise ValueError('Unknown endpoint')
                positive = None if value is None else value if prop == 'declared_privileged' else not value
        if value != case['reference_value'] or positive is not case['positive']:
            raise ValueError('Source and reference disagree: '+case['case_id'])
    return len(reference['cases'])


def analyze(run, out):
    run, out = Path(run), Path(out)
    manifest = json.loads((run/'manifest.json').read_text())
    if not manifest['success'] or len(manifest['reports']) != 16:
        raise ValueError('Incomplete planned static qualification')
    collection = run/'collection-v2.json' if (run/'collection-v2.json').exists() else run/'collection.json'
    for row in json.loads(collection.read_text())['files']:
        if sha(run/row['path']) != row['sha256']: raise ValueError('Collected bytes changed')
    reference = json.loads((run/'reference/reference_manifest.json').read_text())
    inputs = run/'reference/scanner-inputs'; validated = validate_reference(inputs,reference)
    for row in reference['upstream']:
        if sha(inputs/row['path']) != row['sha256']: raise ValueError('Original source bytes changed')
    for row in reference['sources']:
        if sha(run/'reference/primary_sources'/row['path']) != row['sha256']: raise ValueError('Reference documentation changed')
    receipt = json.loads((run/'input_receipt.json').read_text())
    if receipt['reference_sha256'] != sha(run/'reference/reference_manifest.json'):
        raise ValueError('Reference differs from pre-scan receipt')
    if not reference['created_before_scans_utc'] < receipt['before_scans_utc']:
        raise ValueError('Missing pre-scan reference chronology')
    profiles, traces, outcomes = [], [], []
    for label, info in sorted(manifest['reports'].items()):
        corpus = label.split('-')[0]; tool = info['tool']
        family = 'workflow' if tool == 'zizmor' else 'kubernetes' if tool == 'kubescape' else label.rsplit('-',1)[1]
        raw_path = run/info['raw_path']; raw = json.loads(raw_path.read_text())
        parser = parse_report if tool == 'checkov' else parse_infrastructure_report if tool in ('zizmor','kubescape') else parse_configuration_report
        parsed = parser(raw_path,tool,info['execution_status'])
        stored = json.loads((run/(label+'.normalized.json')).read_text())
        for key in ('findings','diagnostics','raw_report_sha256','effective_status'):
            if parsed[key] != stored[key]: raise ValueError('Adapter replay differs: '+label)
        resolved = 0; secondary = 0
        for finding in parsed['findings']:
            locate(raw,finding['native_locator'])
            candidates = source_candidates(finding['path'],reference['files'],corpus,family)
            if len(candidates) == 1: resolved += 1
            for location in finding.get('locations',[]):
                locate(raw,location['native_locator']); secondary += 1
                linked = source_candidates(location['path'],reference['files'],corpus,family)
                if len(linked) != 1: raise ValueError('Ambiguous workflow location')
                span = location.get('offset_span')
                if span and not 0 <= span['start'] <= span['end'] <= (inputs/linked[0]).stat().st_size:
                    raise ValueError('Invalid native byte span')
            if finding.get('resource_locator'): locate(raw,finding['resource_locator'])
            traces.append({'profile':label,**finding,'input_candidates':candidates,
                'case_candidates_by_file_only':[c['case_id'] for c in reference['cases'] if c['path'] in candidates],
                'adjudication':'unassigned; file association is not weakness identity'})
        if tool == 'checkov':
            for block_index, block in enumerate(raw if isinstance(raw,list) else [raw]):
                for collection in ('passed_checks','failed_checks','skipped_checks'):
                    for index, row in enumerate(block['results'][collection]):
                        pointer = (f'/{block_index}' if isinstance(raw,list) else '')+f'/results/{collection}/{index}'
                        locate(raw,pointer)
                        outcomes.append({'profile':label,'rule':row['check_id'],'status':row['check_result']['result'],
                            'path':row.get('file_abs_path') or row.get('file_path'),'resource':row.get('resource'),
                            'message':row.get('check_name'),'native_locator':pointer})
        elif tool == 'trivy-config':
            for block_index, block in enumerate(raw.get('Results',[])):
                for index,row in enumerate(block.get('Misconfigurations',[])):
                    outcomes.append({'profile':label,'rule':row['ID'],'status':row['Status'],'path':block['Target'],
                        'resource':(row.get('CauseMetadata') or {}).get('Resource'),'message':row.get('Message'),
                        'native_locator':f'/Results/{block_index}/Misconfigurations/{index}'})
        elif tool == 'kubescape':
            for row in parsed['diagnostics']['control_outcomes']:
                locate(raw,row['native_locator']);locate(raw,row['resource_locator'])
                outcomes.append({'profile':label,'rule':row['native_rule'],'status':row['status']['status'],
                    'path':row['path'],'resource':row['resource_id'],'message':row['message'],
                    'native_locator':row['native_locator'],'rules':row['rules']})
        stderr = (run/(label+'.stderr')).read_text()
        profiles.append({'profile':label,'tool':tool,'status':parsed['effective_status'],
            'raw_report_sha256':sha(raw_path),'native_findings':len(parsed['findings']),
            'findings_linked_to_one_input':resolved,'all_workflow_locations':secondary,
            'coverage_diagnostics':parsed['diagnostics'],
            'embedded_trivy_checks': 'Falling back to embedded checks' in stderr,
            'scope':'Native observations only, not counts of distinct vulnerabilities.'})
    selected = [o for o in outcomes if o['profile'].startswith('controls-') and o['rule'] in (
        'CKV2_GHA_1','CKV_AWS_24','AWS-0107','CKV_K8S_23','KSV-0012','C-0013','C-0017','C-0057')]
    result = {'schema_version':'infrastructure-analysis-1','purpose':'development_qualification',
        'reference_manifest_sha256':sha(run/'reference/reference_manifest.json'),
        'reference_cases_verified':validated,'input_files_verified':len(reference['files']),
        'upstream_files_verified':len(reference['upstream']),'profiles':profiles,
        'native_findings_total':len(traces),'selected_control_outcomes':selected,
        'control_reference_counts':dict(Counter(str(c['positive']) for c in reference['cases'])),
        'limits':['Declared configuration is not observed runtime or exploitability.',
                  'The literal Terraform reader is restricted to constructed controls, not arbitrary HCL.',
                  'Original-source findings remain unadjudicated; no global precision or recall.',
                  'A native policy can test more than the reference endpoint; PASS does not prove universal safety.',
                  'A Pod, container, job and Terraform address are different units; file-only candidates are not matching decisions.',
                  'Zizmor default persona, embedded Trivy policies and Kubescape NSA file mode are explicit profile limits.',
                  'These development families and observed outcomes cannot be final holdouts.']}
    out.mkdir(parents=True,exist_ok=False)
    for name, data in [('analysis',result),('finding_traces',traces),('control_outcomes',outcomes)]:
        (out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
    return result


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=analyze(a.run,a.output)
    print(json.dumps({'cases':r['reference_cases_verified'],'profiles':len(r['profiles']),'findings':r['native_findings_total']}))
