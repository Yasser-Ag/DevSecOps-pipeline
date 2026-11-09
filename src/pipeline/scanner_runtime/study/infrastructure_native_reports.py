"""Preserve workflow locations and Kubernetes resource/control outcomes."""
import hashlib
import json
from pathlib import Path

from study.native_reports import _required, _rows


def zizmor(report):
    rows=[]
    for i,r in enumerate(_rows(report,'zizmor root')):
        locations=[]
        for j,loc in enumerate(_rows(r.get('locations'),'zizmor locations')):
            symbolic=loc.get('symbolic') or {}; concrete=loc.get('concrete') or {}
            point=concrete.get('location') or {}; start=point.get('start_point') or {}; end=point.get('end_point') or {}
            locations.append({'path':((symbolic.get('key') or {}).get('Local') or {}).get('verbatim_path'),
                'symbolic_key':symbolic.get('key'),'route':symbolic.get('route'),'kind':symbolic.get('kind'),
                'annotation':symbolic.get('annotation'),'native_zero_based_start':start,'native_zero_based_end':end,
                'line_start':start['row']+1 if isinstance(start.get('row'),int) else None,
                'line_end':end['row']+1 if isinstance(end.get('row'),int) else None,
                'offset_span':point.get('offset_span'),'native_locator':f'/{i}/locations/{j}'})
        primary=next((x for x in locations if x['kind']=='Primary'), locations[0] if locations else {})
        rows.append({'native_rule':_required(r,'ident'),'message':r.get('desc'),'url':r.get('url'),
            'determinations':r.get('determinations'),'ignored':r.get('ignored'),'locations':locations,
            'path':primary.get('path'),'line_start':primary.get('line_start'),'line_end':primary.get('line_end'),
            'native_locator':f'/{i}','location_basis':'native_primary_and_all_secondary_locations'})
    return rows, {'report_status':'completed','ignored_findings':sum(x['ignored'] is True for x in rows),
                  'coverage_evidence':'requires_execution_collection_logs'}


def kubescape(report):
    if not isinstance(report,dict) or not isinstance(report.get('summaryDetails'),dict):
        raise ValueError('Missing Kubescape summary metadata')
    resources={}
    for index,r in enumerate(_rows(report.get('resources'),'Kubescape resources')):
        key=_required(r,'resourceID')
        if key in resources: raise ValueError('Duplicate native resource ID')
        resources[key]=(index,r)
    findings=[]; outcomes=[]
    for i,result in enumerate(_rows(report.get('results'),'Kubescape results')):
        resource_id=_required(result,'resourceID')
        if resource_id not in resources: raise ValueError('Result has no resource evidence')
        resource_index,resource=resources[resource_id]; obj=resource.get('object') or {}; source=resource.get('source') or {}
        for j,control in enumerate(_rows(result.get('controls'),'Kubescape controls')):
            state=control.get('status')
            if not isinstance(state,dict) or state.get('status') not in ('passed','failed','skipped','excluded'):
                raise ValueError('Unknown Kubescape control status')
            row={'native_rule':_required(control,'controlID'),'message':control.get('name'),
                'resource_id':resource_id,'status':state,'severity':control.get('severity'),
                'path':source.get('relativePath'),'source':source,'source_path_in_object':obj.get('sourcePath'),
                'resource_kind':obj.get('kind'),'resource_name':(obj.get('metadata') or {}).get('name'),
                'resource_namespace':(obj.get('metadata') or {}).get('namespace'),
                'rules':control.get('rules'),'native_locator':f'/results/{i}/controls/{j}',
                'resource_locator':f'/resources/{resource_index}',
                'location_basis':'resource_control_with_remediation_paths_not_independent_findings'}
            outcomes.append(row)
            if state['status']=='failed': findings.append(dict(row))
    return findings, {'report_status':'completed','control_outcomes':outcomes,
        'resource_count':len(resources),'summary':report['summaryDetails'],
        'metadata':report.get('metadata'),'attributes':report.get('attributes'),
        'limits':'A failed resource/control is one native observation; remediation paths do not automatically count weaknesses.'}


def parse_infrastructure_report(path,tool,execution_status):
    if execution_status not in {'completed','completed_with_limitations','failed','timed_out','interrupted','not_run'}:
        raise ValueError('Invalid execution status')
    raw=Path(path).read_bytes();digest=hashlib.sha256(raw).hexdigest();document=json.loads(raw)
    if tool=='zizmor':rows,diagnostic=zizmor(document)
    elif tool=='kubescape':rows,diagnostic=kubescape(document)
    else:raise ValueError('Unknown infrastructure adapter')
    for index,row in enumerate(rows):
        row.update(native_index=index,finding_id=f'{tool}:{digest[:16]}:{index}',tool=tool,
                   raw_report_sha256=digest,truth='not_adjudicated',cwes=[])
    return {'schema_version':'infrastructure-findings-1','tool':tool,'raw_report':str(path),
        'raw_report_sha256':digest,'execution_status':execution_status,
        'effective_status':diagnostic['report_status'] if execution_status=='completed' else execution_status,
        'findings':rows,'diagnostics':diagnostic,'contract':'Native multiplicity/context retained without case or truth assignment.'}
