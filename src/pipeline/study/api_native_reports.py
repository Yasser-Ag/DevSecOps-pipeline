"""Retain native DAST instances and aggregate failure groups without label guessing."""
import hashlib
import json
from pathlib import Path
from study.native_reports import _rows,_required,_cwes


def zap(document):
    if not isinstance(document,dict) or document.get('@programName')!='ZAP':raise ValueError('Not a ZAP report')
    rows=[];groups=[]
    for i,site in enumerate(_rows(document.get('site'),'ZAP sites')):
        for j,alert in enumerate(_rows(site.get('alerts'),'ZAP alerts')):
            instances=_rows(alert.get('instances'),'ZAP instances')
            groups.append({'site':site.get('@name'),'pluginid':alert.get('pluginid'),'reported_count':alert.get('count'),'retained_instances':len(instances)})
            if not instances:raise ValueError('Alert has no retained instances')
            for k,instance in enumerate(instances):
                rows.append({'native_rule':str(_required(alert,'pluginid')),'native_alert_ref':alert.get('alertRef'),
                    'message':alert.get('name'),'severity':alert.get('riskcode'),'confidence':alert.get('confidence'),
                    'url':_required(instance,'uri'),'method':instance.get('method'),'parameter':instance.get('param'),
                    'attack':instance.get('attack'),'evidence':instance.get('evidence'),'native_id':instance.get('id'),
                    'cwes':_cwes(int(alert['cweid'])) if str(alert.get('cweid','')).isdigit() else [],
                    'native_locator':f'/site/{i}/alerts/{j}/instances/{k}','unit':'native_alert_instance'})
    return rows,{'report_status':'completed','alert_groups':groups,'insights':document.get('insights'),'version':document.get('@version')}


def nuclei(lines):
    rows=[]
    for index,document in enumerate(lines):
        info=document.get('info') or {}
        rows.append({'native_rule':_required(document,'template-id'),'matcher':document.get('matcher-name'),
            'url':document.get('matched-at') or document.get('url'),'host':document.get('host'),
            'method':None,'message':info.get('name'),'severity':info.get('severity'),
            'cwes':_cwes((info.get('classification') or {}).get('cwe-id')),
            'request':document.get('request'),'response':document.get('response'),
            'extracted_results':document.get('extracted-results'),'native_locator':f'/{index}',
            'unit':'native_template_matcher_result'})
    return rows,{'report_status':'completed','coverage_evidence':'Requires successful execution and independent captured requests; empty JSONL alone is insufficient.'}


def schemathesis(document):
    if not isinstance(document,dict) or not document.get('schemathesis_version'):raise ValueError('Missing Schemathesis version')
    if not isinstance(document.get('operations'),dict) or not isinstance(document.get('complete'),bool):raise ValueError('Missing completion/coverage')
    rows=[]
    for i,failure in enumerate(_rows(document.get('failures'),'Schemathesis failures')):
        if not isinstance(failure.get('operations'),list):raise ValueError('Missing failure operation scope')
        rows.append({'native_rule':_required(failure,'type'),'message':failure.get('title'),
            'severity':failure.get('severity'),'operations':failure['operations'],'reported_count':failure.get('count'),
            'url':None,'method':None,'cwes':[],'native_locator':f'/failures/{i}',
            'unit':'aggregate_failure_group_not_a_unique_vulnerability'})
    diagnostics={k:document.get(k) for k in ('schemathesis_version','complete','stop_reason','exit_code','operations','phases','test_cases','errors','warnings','auth')}
    limited=not document['complete'] or document.get('stop_reason') in ('max_time','max_failures') or bool(document.get('errors'))
    diagnostics['report_status']='completed_with_limitations' if limited else 'completed'
    return rows,diagnostics


def parse_api_report(path,tool,execution_status):
    if execution_status not in ('completed','failed','timed_out','interrupted','not_run'):raise ValueError('Unknown execution status')
    raw=Path(path).read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if tool=='nuclei':rows,diagnostics=nuclei([json.loads(x) for x in raw.splitlines() if x.strip()])
    elif tool=='zap':rows,diagnostics=zap(json.loads(raw))
    elif tool=='schemathesis':rows,diagnostics=schemathesis(json.loads(raw))
    else:raise ValueError('Unknown API adapter')
    for i,row in enumerate(rows):row.update(finding_id=f'{tool}:{digest[:16]}:{i}',native_index=i,truth='not_adjudicated')
    return {'tool':tool,'raw_report_sha256':digest,'execution_status':execution_status,
        'effective_status':diagnostics['report_status'] if execution_status=='completed' else execution_status,
        'findings':rows,'diagnostics':diagnostics,'contract':'Retain native units, request context and limits; no identity or truth assignment.'}
