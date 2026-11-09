"""Replay preserved workflow/IaC reports against typed source declarations."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from study.configuration_development_analysis import locate
from study.infrastructure_cases import unrestricted_ssh
from study.infrastructure_development_analysis import literal_groups, source_candidates, validate_reference
from study.workflow_iac_matching import (declared_contents, kics_resource, literal_rule,
    pair_diagnostics, pass_suppression, route_byte_span, route_context, route_value, workflow_document)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text())
def require(condition, message):
    if not condition: raise ValueError(message)


def source_span(text, first, last):
    lines = text.splitlines()
    require(1 <= first <= last <= len(lines), 'Invalid source coordinate')
    return '\n'.join(lines[first-1:last])


def build_registry(run):
    reference = read(run/'reference/reference_manifest.json')
    inputs = run/'reference/scanner-inputs'
    receipt = read(run/'input_receipt.json')
    require(receipt['reference_sha256']==sha(run/'reference/reference_manifest.json'),'Prescan registry changed')
    require(reference['created_before_scans_utc'] < receipt['before_scans_utc'],'Prescan chronology missing')
    validate_reference(inputs, reference)
    workflows, jobs, steps, needs, terraform = [], [], [], [], []
    documents = {}
    for source in reference['files']:
        path = source['path']
        if '/workflow/' not in path: continue
        text = (inputs/path).read_text(); doc = workflow_document(text); documents[path] = doc
        corpus = path.split('/')[0]
        workflows.append({'reference_id':path+'#/permissions','path':path,'corpus':corpus,
            'source_sha256':source['sha256'],'declared_permissions':doc.get('permissions'),
            'scope':'workflow_global_policy','event_declaration':doc.get('on')})
        for name, job in doc['jobs'].items():
            value, origin = declared_contents(doc, job)
            identity = path+'#/jobs/'+name
            jobs.append({'reference_id':identity+'/permissions/contents','path':path,'corpus':corpus,
                'job':name,'property':'declared_contents_write','value':value,'declaration_origin':origin,
                'positive':None if value is None else value == 'write','source_sha256':source['sha256'],
                'reference_timing':'prescan_control' if corpus == 'controls' else 'post_outcome_source_annotation',
                'scope':'Declared permission before event/organization restrictions; not live capability.'})
            dep = job.get('needs', [])
            for parent in [dep] if isinstance(dep, str) else dep:
                require(parent in doc['jobs'], 'Missing dependency job')
                needs.append({'source':identity,'relation':'declared_needs','target':path+'#/jobs/'+parent})
            for index, step in enumerate(job.get('steps', [])):
                steps.append({'reference_id':identity+'/steps/'+str(index),'path':path,'job':name,'index':index,
                              'uses':step.get('uses'),'source_sha256':source['sha256']})
    groups = literal_groups((inputs/'controls/terraform/main.tf').read_text())
    text = (inputs/'controls/terraform/main.tf').read_text()
    headers = [(m[1],text[:m.start()].count('\n')+1) for m in re.finditer(r'^resource "aws_security_group" "([a-z0-9]+)" \{', text, re.M)]
    starts = {name:line for name,line in headers}
    for case in reference['cases']:
        if case['property'] != 'declared_unrestricted_tcp_22': continue
        first = starts[case['resource'].split('.')[1]]
        last = first+12
        require(literal_rule(source_span(text,first+4,last-1)) == {**groups[case['resource']], 'description':'Declared ingress'}, 'Control source span')
        terraform.append({'reference_id':case['case_id'],'path':case['path'],'corpus':'controls',
            'resource':case['resource'],'property':case['property'],'positive':case['positive'],
            'resource_span':[first,last],'ingress_span':[first+4,last-1], 'ingress_index':0,
            'source_sha256':case['source_sha256'],'reference_timing':'prescan_control'})
    # Fixed-source, post-outcome annotations. These assertions do not parse arbitrary HCL.
    ec2 = 'originals/terraform/terraform/aws/ec2.tf'; source = (inputs/ec2).read_text()
    require(source_span(source,77,77) == 'resource "aws_security_group" "web-node" {', 'Resource declaration changed')
    web = literal_rule(source_span(source,83,89)); ssh = literal_rule(source_span(source,90,96))
    require(web == {'from_port':80,'to_port':80,'protocol':'tcp','cidr_blocks':['0.0.0.0/0']}, 'Unexpected web ingress')
    require(ssh == {'from_port':22,'to_port':22,'protocol':'tcp','cidr_blocks':['0.0.0.0/0']}, 'Unexpected SSH ingress')
    require(not unrestricted_ssh(web) and unrestricted_ssh(ssh), 'Source predicate disagrees')
    terraform.append({'reference_id':'TG-web-node-tcp22','path':ec2,'corpus':'originals',
        'resource':'aws_security_group.web-node','property':'declared_unrestricted_tcp_22','positive':True,
        'resource_span':[77,115],'ingress_span':[90,96],'ingress_index':1,
        'source_sha256':sha(inputs/ec2),'reference_timing':'post_outcome_source_annotation'})
    db = 'originals/terraform/terraform/aws/db-app.tf'; source = (inputs/db).read_text()
    expected = ['resource "aws_security_group_rule" "ingress" {','type = "ingress"',
        'from_port = "3306"','to_port = "3306"','protocol = "tcp"',
        'cidr_blocks = ["${aws_vpc.web_vpc.cidr_block}"]','security_group_id = aws_security_group.default.id','}']
    require([' '.join(s.split()) for s in source_span(source,136,143).splitlines()] == expected, 'Standalone rule source changed')
    terraform.append({'reference_id':'TG-database-rule-tcp22','path':db,'corpus':'originals',
        'resource':'aws_security_group_rule.ingress','property':'declared_unrestricted_tcp_22','positive':False,
        'resource_span':[136,143],'ingress_span':None,'ingress_index':None,
        'source_sha256':sha(inputs/db),'reference_timing':'post_outcome_source_annotation',
        'rationale':'TCP/3306 excludes TCP/22 independently of unresolved CIDR expression.'})
    relations = [{'source':'TG-database-rule-tcp22','relation':'declared_security_group_id',
        'target':db+'#aws_security_group.default','target_span':[117,134],
        'scope':'Declaration relation only. No inline ingress on target is not a clean effective-group label.'}]
    return {'workflows':workflows,'jobs':jobs,'steps':steps,'needs':needs,'terraform':terraform,
            'terraform_relations':relations,'source_manifest_sha256':sha(run/'reference/reference_manifest.json')}, documents


def analyze(run, output):
    run, output = Path(run), Path(output)
    collection_name = 'collection-v2.json' if (run/'collection-v2.json').exists() else 'collection.json'
    collection = read(run/collection_name)
    for row in collection['files']:
        require(sha(run/row['path']) == row['sha256'], 'Collected evidence changed: '+row['path'])
    manifest = read(run/'manifest.json'); require(manifest['success'], 'Incomplete original scan')
    registry, documents = build_registry(run)
    reference = read(run/'reference/reference_manifest.json')
    inputs = run/'reference/scanner-inputs'
    outcomes, locations, permission_warnings, source_reports = [], [], [], []

    def source_path(native, corpus, family):
        candidates = source_candidates(native,reference['files'],corpus,family)
        require(len(candidates) == 1,'Ambiguous source path: '+native)
        return candidates[0]

    def add_tf(tool, corpus, pointer, path, resource, status, first=None, last=None, ingress=None):
        candidates = [r for r in registry['terraform'] if r['path']==path and r['resource']==resource]
        require(len(candidates) <= 1, 'Ambiguous source declaration')
        ref = candidates[0] if candidates else None
        if ref:
            if first is not None:
                lo,hi = ref['resource_span']
                require(lo <= first <= (last or first) <= hi, 'Native coordinates outside resource')
                if tool == 'trivy':
                    require(ref['ingress_span'][0] <= first <= last <= ref['ingress_span'][1], 'Wrong ingress localization')
            if ingress is not None: require(ref['ingress_index']==ingress, 'Wrong native ingress index')
        outcomes.append({'observation_id':corpus+'/'+tool+pointer,'tool':tool,'corpus':corpus,
            'native_locator':pointer,'path':path,'resource':resource,'status':status,
            'property':'declared_unrestricted_tcp_22','reference_id':ref['reference_id'] if ref else None,
            'positive':ref['positive'] if ref else None,
            'agreement':(status=='FAILED') == ref['positive'] if ref else None,
            'unscored_reason':None if ref else 'No inline-ingress reference; external rule relation retained separately.'})

    for corpus in ('controls','originals'):
        for family in ('workflow','terraform'):
            label=corpus+'-checkov-'+family; info=manifest['reports'][label]; raw=read(run/info['raw_path'])
            source_reports.append({'profile':label,'path':info['raw_path'],'sha256':sha(run/info['raw_path'])})
            for b, block in enumerate(raw if isinstance(raw,list) else [raw]):
                for kind in ('passed_checks','failed_checks','skipped_checks'):
                    for index,row in enumerate(block['results'][kind]):
                        selected = 'CKV2_GHA_1' if family=='workflow' else 'CKV_AWS_24'
                        if row['check_id'] != selected: continue
                        pointer=(f'/{b}' if isinstance(raw,list) else '')+f'/results/{kind}/{index}'
                        require(locate(raw,pointer)==row,'Invalid native pointer')
                        path=source_path(row.get('file_abs_path') or row['file_path'],corpus,family)
                        status=row['check_result']['result'];require(status in ('PASSED','FAILED'),'Unsupported skipped observation')
                        if family=='terraform':
                            indices = {int(m[1]) for key in row['check_result'].get('evaluated_keys',[])
                                       if (m := re.match(r'ingress/\[(\d+)\]/',key))}
                            require(len(indices)<=1,'Multiple ingress causes need separate qualification')
                            add_tf('checkov',corpus,pointer,path,row['resource'],status,*row['file_line_range'],
                                   ingress=next(iter(indices)) if indices else None)
                        else:
                            permission_warnings.append({'observation_id':label+pointer,'tool':'checkov','corpus':corpus,
                                'path':path,'native_locator':pointer,'rule':selected,'status':status,
                                'scope':'workflow_global_policy','job':None,'effective_contents_write':None,
                                'reason':'Global policy rule cannot substitute for effective job permission.'})
        label=corpus+'-trivy-terraform';info=manifest['reports'][label];raw=read(run/info['raw_path'])
        source_reports.append({'profile':label,'path':info['raw_path'],'sha256':sha(run/info['raw_path'])})
        for b,block in enumerate(raw.get('Results',[])):
            for index,row in enumerate(block.get('Misconfigurations',[])):
                if row['ID']!='AWS-0107':continue
                meta=row['CauseMetadata'];require(row['Status']=='FAIL','Unqualified Trivy status')
                add_tf('trivy',corpus,f'/Results/{b}/Misconfigurations/{index}',source_path(block['Target'],corpus,'terraform'),
                       meta['Resource'],'FAILED',meta['StartLine'],meta['EndLine'])
        label=corpus+'-kics-terraform';info=manifest['reports'][label];raw=read(run/info['raw_path'])
        source_reports.append({'profile':label,'path':info['raw_path'],'sha256':sha(run/info['raw_path'])})
        for q,query in enumerate(raw['queries']):
            if query['query_id']!='65905cec-d691-4320-b320-2000436cb696':continue
            for index,row in enumerate(query['files']):
                resource, ingress = kics_resource(row['search_key'])
                add_tf('kics',corpus,f'/queries/{q}/files/{index}',source_path(row['file_name'],corpus,'terraform'),
                       resource,'FAILED',row['line'],row['line'],ingress)
        label=corpus+'-zizmor';info=manifest['reports'][label];raw=read(run/info['raw_path'])
        source_reports.append({'profile':label,'path':info['raw_path'],'sha256':sha(run/info['raw_path'])})
        for f,finding in enumerate(raw):
            for n,location in enumerate(finding['locations']):
                symbolic=location['symbolic']; native=symbolic['key']['Local']['verbatim_path']
                path=source_path(native,corpus,'workflow');route=symbolic['route']['route']
                route_value(documents[path],route);context,job,index=route_context(route)
                span=location['concrete']['location']['offset_span'];content=(inputs/path).read_bytes()
                require(0<=span['start']<=span['end']<=len(content),'Native span outside bytes')
                node_first,node_last=route_byte_span(content.decode(),route)
                require(node_first<=span['start']<=span['end']<=node_last,'Native span outside symbolic YAML node')
                locations.append({'observation_id':label+f'/{f}','native_locator':f'/{f}/locations/{n}',
                    'rule':finding['ident'],'path':path,'route':route,'kind':symbolic['kind'],
                    'context':context,'job':job,'step':index,'offset_span':span,'yaml_node_span':[node_first,node_last],
                    'slice_sha256':hashlib.sha256(content[span['start']:span['end']]).hexdigest()})
                if finding['ident']=='excessive-permissions' and symbolic['kind']=='Primary':
                    value = declared_contents(documents[path],documents[path]['jobs'][job])[0] if job else None
                    permission_warnings.append({'observation_id':label+f'/{f}','tool':'zizmor','corpus':corpus,
                        'path':path,'native_locator':f'/{f}','rule':finding['ident'],'status':'FAILED',
                        'scope':context+'_default_policy','job':job,'effective_contents_write':None if value is None else value=='write',
                        'reason':'Absent default declaration does not establish actual write capability.'})
    matching = []
    for corpus in ('controls','originals'):
        positive = [r for r in outcomes if r['corpus']==corpus and r['status']=='FAILED' and r['reference_id']]
        for name,keys in [('file_property',('path','property')),('resource_property',('path','resource','property'))]:
            matching.append({'corpus':corpus,'condition':name,**pair_diagnostics(positive,keys)})
    projection=[]
    for warning in permission_warnings:
        if warning['tool']!='checkov':continue
        for job in registry['jobs']:
            if warning['path']!=job['path']:continue
            projection.append({'reference_id':job['reference_id'],'corpus':job['corpus'],'status':warning['status'],
                'source_positive':job['positive'],'incorrect_projection_agreement':None if job['positive'] is None else (warning['status']=='FAILED')==job['positive']})
    counterfactual=[]
    for corpus in ('controls','originals'):
        positive = [r for r in registry['terraform'] if r['corpus']==corpus and r['positive']]
        rows = [r for r in outcomes if r['corpus']==corpus and r['tool']=='checkov']
        counterfactual.append({'corpus':corpus,'file_pass_suppression_lost':pass_suppression(positive,rows,('path','property')),
            'resource_pass_suppression_lost':pass_suppression(positive,rows,('path','resource','property'))})
    summary={'schema_version':'workflow-iac-context-1','phase':'development_after_outcome_access',
        'collection_sha256':sha(run/collection_name),'source_reports':source_reports,
        'workflows':len(registry['workflows']),'jobs':len(registry['jobs']),'steps':len(registry['steps']),
        'job_status_counts':dict(Counter(str(j['positive']) for j in registry['jobs'])),
        'terraform_references':len(registry['terraform']),'terraform_native_outcomes':len(outcomes),
        'terraform_scored_outcomes':sum(o['agreement'] is not None for o in outcomes),
        'terraform_agreements':sum(o['agreement'] is True for o in outcomes),
        'zizmor_verified_locations':len(locations),'typed_permission_observations':len(permission_warnings),
        'matching':matching,'terraform_pass_counterfactual':counterfactual,
        'wrong_global_to_job_projection':dict(Counter('unknown' if p['incorrect_projection_agreement'] is None else 'agreement' if p['incorrect_projection_agreement'] else 'disagreement' for p in projection)),
        'global_pass_hides_declared_write_jobs':[p['reference_id'] for p in projection if p['status']=='PASSED' and p['source_positive'] is True],
        'limits':['Controls and original cases are reported separately; correlated observations are not independent trials.',
            'Original source annotations and grouping/suppression diagnostics follow outcome access.',
            'File grouping errors do not imply loss when all member identities are retained.',
            'Scope projection and PASS suppression are explicit counterfactuals, not observed scanner behavior.',
            'No cloud deployment, token-capability measurement, overall precision/recall or new-method superiority.']}
    output.mkdir(parents=True,exist_ok=False)
    for name,value in [('analysis',summary),('registry',registry),('terraform_outcomes',outcomes),('workflow_locations',locations),
                       ('permission_observations',permission_warnings),('scope_projection',projection)]:
        (output/(name+'.json')).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(analyze(args.run,args.output),indent=2))
