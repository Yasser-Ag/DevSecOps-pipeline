"""Replay bounded comparators on retained reports; never rerun a detector."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from study.matching_baselines import JavaScopes, sast_key, group_keys, match_requests

HEADERS=('strict-transport-security','content-security-policy','permissions-policy',
         'x-frame-options','x-content-type-options','x-permitted-cross-domain-policies',
         'referrer-policy','cross-origin-embedder-policy','cross-origin-opener-policy',
         'cross-origin-resource-policy')


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):return json.loads(Path(path).read_text())


def run_analysis(inputs, output):
    inputs,output=Path(inputs),Path(output)
    if output.exists():raise FileExistsError('Preserve prior analysis')
    source_manifest=read(inputs/'inputs_manifest.json')
    for item in source_manifest['files']:
        p=inputs/item['path']
        if p.stat().st_size!=item['bytes'] or sha(p)!=item['sha256']:raise ValueError('Changed analysis input')
    source=inputs/'sast';selection=read(source/'development_selection.json')['cases']
    case_paths={};trees={}
    for case in selection:
        path=case['source_path'];file=source/'scanner-inputs/java'/path
        if sha(file)!=case['source_sha256']:raise ValueError('Changed OWASP source')
        relative=path.removeprefix('src/main/java/');case_paths[relative]=case
        trees[relative]=JavaScopes(file.read_bytes(),relative)
        if not trees[relative].valid:raise ValueError('Selected reference Java does not parse')
    rows=[];grouped={};partition='owasp-development:'+selection[0]['commit']
    for tool in ('semgrep','findsecbugs'):
        report=read(source/(tool+'.normalized.json'))
        raw=source/('semgrep.json' if tool=='semgrep' else 'findsecbugs.xml')
        if sha(raw)!=report['raw_report_sha256']:raise ValueError('Changed raw SAST report')
        for finding in report['findings']:
            path=finding.get('path') or ''
            if tool=='semgrep':
                prefix='/scanner-inputs/java/src/main/java/'
                if path.count(prefix)!=1:raise ValueError('Unexpected source mapping')
                path=path.split(prefix)[1]
            if path not in trees:raise ValueError('Unresolved source path')
            # Reference case labels are retained as context, never read by keys.
            item={'finding_id':finding['finding_id'],'tool':tool,'source_path':path,
                'native_locator':finding['native_locator'],'source_sha256':case_paths[path]['source_sha256'],
                'reported_span':[finding.get('line_start'),finding.get('line_end')],
                'published_case_id':case_paths[path]['case_id'],'adjudication':'unresolved; source-case membership is not a warning verdict',
                'methods':{}}
            for method in ('line','scope_offset','normalized_scope_offset'):
                item['methods'][method]=sast_key(trees[path],finding.get('line_start'),finding['cwes'],partition,method)
            rows.append(item)
    for method in ('line','scope_offset','normalized_scope_offset'):
        members=[{'finding_id':x['finding_id'],**x['methods'][method]} for x in rows]
        groups=group_keys(members);grouped[method]={**groups,'status_counts':dict(sorted(Counter(r['status'] for r in members).items()))}
    api=inputs/'api';reference=read(api/'probes/reference-before.json');reference_hash=sha(api/'probes/reference-before.json')
    refs=[];condition_routes={}
    for condition,actor in [('valid-a','a'),('invalid','invalid')]:
        probes=[r for r in reference if r['actor']==actor and r['expected_relation'] in ('own_object','cross_user','unauthenticated')]
        if len(probes)!=2:raise ValueError('Expected two independent location probes')
        condition_routes[condition]={r['response']['path']:r['response'] for r in probes}
        for path,response in condition_routes[condition].items():
            names={k.lower() for k,_ in response['headers']}
            for header in HEADERS:
                case_id=hashlib.sha256(json.dumps([condition,path,header]).encode()).hexdigest()
                refs.append({'case_id':case_id,'partition':'crapi-api-development:'+condition,
                    'target':'crapi','method':'GET','path':path,'surface':'header','name':header,
                    'weakness':{'class':'response_header_absence','variant':{'header':header}},
                    'allowed_statuses':[response['status']],'property_absent':header not in names,
                    'independent_evidence':{'path':'api/probes/reference-before.json','sha256':reference_hash,
                        'body_sha256':response['body_sha256']},'unit':'header_absence_on_one_response_condition'})
    findings=[];excluded=[]
    for condition in condition_routes:
        label='nuclei-'+condition;report=read(api/(label+'.normalized.json'))
        if sha(api/'scanner-inputs'/label/'nuclei.jsonl')!=report['raw_report_sha256']:raise ValueError('Changed raw DAST report')
        for finding in report['findings']:
            address=urlsplit(finding['url']);path=address.path;header=finding['matcher']
            if address.scheme!='http' or address.netloc!='127.0.0.1:10080':raise ValueError('Unexpected native target')
            if finding['native_rule']!='http-missing-security-headers' or path not in condition_routes[condition] or header not in HEADERS:
                excluded.append({'finding_id':finding['finding_id'],'reason':'outside selected independently probed response/header endpoint'});continue
            request_line=finding['request'].splitlines()[0].split()
            if len(request_line)!=3 or request_line[0]!='GET' or request_line[1]!=path:raise ValueError('Native request differs from endpoint projection')
            response=finding['response'];first=response.splitlines()[0].split()
            if not first[0].startswith('HTTP/') or not first[1].isdigit():raise ValueError('Unknown native HTTP status')
            findings.append({'finding_id':finding['finding_id'],'partition':'crapi-api-development:'+condition,
                'target':'http://127.0.0.1:10080','method':'GET','path':path,'surface':'header','name':header,
                'status_code':int(first[1]),'weakness':{'class':'response_header_absence','variant':{'header':header}},
                'native_locator':finding['native_locator'],'raw_report_sha256':report['raw_report_sha256']})
    aliases={'crapi':'crapi','http://127.0.0.1:10080':'crapi'}
    comparisons={mode:match_requests(refs,findings,aliases,mode) for mode in ('v2','legacy')}
    ref_index={r['case_id']:r for r in refs}
    for matches in comparisons.values():
        for match in matches:
            if match['status']=='matched' and not ref_index[match['case_id']]['property_absent']:
                raise ValueError('Native absence finding contradicts independent response headers')
    result={'schema_version':'matching-development-1','purpose':'post_outcome_comparator_qualification',
        'input_manifest_sha256':sha(inputs/'inputs_manifest.json'),
        'sast':{'source_files':len(trees),'native_findings':len(rows),'methods':grouped,
            'meaning':'Fingerprint agreement and membership only; no ground-truth false-merge/split rate.'},
        'dast':{'reference_cases':len(refs),'absent_properties':sum(r['property_absent'] for r in refs),
            'present_properties':sum(not r['property_absent'] for r in refs),'eligible_findings':len(findings),'excluded_findings':excluded,
            'methods':{k:{'status_counts':dict(sorted(Counter(x['status'] for x in v).items())),
                'links':v} for k,v in comparisons.items()},
            'meaning':'Observed header absence under a specific request/token condition, not general vulnerability adjudication.'},
        'limits':['Java-specific paper adaptations; no exact GitLab implementation or data-flow equivalence.',
            'All methods receive the same version/condition partition; no manufactured cross-run collision.',
            'No final scanner accuracy, novel superiority or representative identity-error rate established.',
            'API reference covers only two location routes; vehicle-list findings remain unscored.',
            'Known development outcomes cannot be presented as an untouched test set.']}
    output.mkdir(parents=True)
    for name,value in [('analysis',result),('sast_fingerprints',rows),('dast_references',refs),('dast_findings',findings)]:
        (output/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=run_analysis(a.inputs,a.output)
    print(json.dumps({'sast_findings':r['sast']['native_findings'],'dast_findings':r['dast']['eligible_findings']}))
