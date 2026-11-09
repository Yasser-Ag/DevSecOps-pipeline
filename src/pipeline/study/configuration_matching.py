"""Kubernetes source identities and conservative native policy associations."""
import re
from pathlib import Path

import yaml

from study.matching_baselines import fingerprint


class UniqueLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate keys instead of silently choosing a value."""
    def construct_mapping(self,node,deep=False):
        keys=set()
        for key,_ in node.value:
            value=self.construct_object(key,deep=deep)
            if value in keys:raise ValueError('Duplicate YAML key')
            keys.add(value)
        return super().construct_mapping(node,deep=deep)


def documents(text,path):
    docs=list(yaml.load_all(text,Loader=UniqueLoader));syntax=list(yaml.compose_all(text))
    result=[]
    for index,(obj,node) in enumerate(zip(docs,syntax)):
        if obj is None:continue
        if not isinstance(obj,dict) or not isinstance(obj.get('metadata'),dict):
            raise ValueError('Expected Kubernetes object')
        if not all(isinstance(obj.get(k),str) and obj[k] for k in ('apiVersion','kind')):
            raise ValueError('Missing Kubernetes type')
        if not isinstance(obj['metadata'].get('name'),str):raise ValueError('Missing resource name')
        result.append({'document_id':fingerprint([path,index]),'path':path,'document_index':index,
            'kind':obj['kind'],'api_version':obj['apiVersion'],'name':obj['metadata']['name'],
            'declared_namespace':obj['metadata'].get('namespace'),'line_start':node.start_mark.line+1,
            'line_end':node.end_mark.line+(node.end_mark.column>0),'object':obj,'syntax':node})
    return result


def spec_route(kind):
    if kind=='Pod':return ('spec',)
    if kind in {'Deployment','ReplicaSet','ReplicationController','StatefulSet','DaemonSet','Job','DeploymentConfig'}:
        return ('spec','template','spec')
    if kind=='CronJob':return ('spec','jobTemplate','spec','template','spec')
    return None


def at(value,route):
    for key in route:value=value[key]
    return value


def node_at(node,route):
    for key in route:
        if isinstance(key,int):node=node.value[key]
        else:
            candidates=[v for k,v in node.value if k.value==key]
            if len(candidates)!=1:raise ValueError('Ambiguous source syntax route')
            node=candidates[0]
    return node


def inherited_field(pod,container,name):
    parent=pod.get('securityContext') or {};local=container.get('securityContext') or {}
    if not isinstance(parent,dict) or not isinstance(local,dict):raise ValueError('Invalid security context')
    if name in local and local[name] is not None:return local[name],'container'
    if name in parent and parent[name] is not None:return parent[name],'pod'
    return None,'unspecified'


def trivy_074_line_deltas(text,parsed):
    """Map the pinned parser's omitted separator lines to physical source lines.

    Trivy v0.74.0 parser.Parse splits bare document separators and increments
    offsets by countLines(partial), including its empty-partial special case.
    Only semantically identical, uniquely located single-object partials qualify.
    Unsupported YAML layouts remain unlocalized rather than receiving a guess.
    """
    separators=list(re.finditer(r'(?m:^---\r?\n)',text))
    start=0;native_offset=0;physical_offset=0;result={}
    for separator in [*separators,None]:
        stop=separator.start() if separator else len(text)
        partial=text[start:stop]
        try:
            obj=yaml.load(partial,Loader=UniqueLoader);node=yaml.compose(partial)
            matches=[d for d in parsed if node is not None and
                     d['line_start']==physical_offset+node.start_mark.line+1 and d['object']==obj]
            if len(matches)==1:result[matches[0]['document_id']]=physical_offset-native_offset
        except yaml.YAMLError:
            pass
        native_offset+=1 if partial=='' else partial.count('\n')+(not partial.endswith('\n'))
        physical_offset+=partial.count('\n')+(1 if separator else 0)
        start=separator.end() if separator else len(text)
    return result


def registry_for_text(text,path,corpus):
    identities=[];references=[];objects=[]
    parsed=documents(text,path);deltas=trivy_074_line_deltas(text,parsed)
    for document in parsed:
        obj=document['object'];route=spec_route(document['kind'])
        public={k:v for k,v in document.items() if k not in ('object','syntax')}
        objects.append({**public,'workload':route is not None,'corpus':corpus})
        if route is None:continue
        pod=at(obj,route);seen=set()
        for kind in ('containers','initContainers','ephemeralContainers'):
            containers=pod.get(kind,[])
            if not isinstance(containers,list):raise ValueError('Invalid container list')
            for index,container in enumerate(containers):
                name=container.get('name')
                if not isinstance(name,str) or not name or name in seen:raise ValueError('Ambiguous container name')
                seen.add(name)
                value,origin=inherited_field(pod,container,'runAsNonRoot')
                uid,uid_origin=inherited_field(pod,container,'runAsUser')
                if value is not None and type(value) is not bool:raise ValueError('runAsNonRoot must be boolean')
                if uid is not None and (type(uid) is not int or uid<0):raise ValueError('Invalid declared UID')
                node=node_at(document['syntax'],(*route,kind,index))
                identity={**public,'corpus':corpus,'container_type':kind,'container_name':name,
                    'container_index':index,'container_line_start':node.start_mark.line+1,
                    'container_line_end':node.end_mark.line+(node.end_mark.column>0),
                    'trivy_074_line_delta':deltas.get(document['document_id']),
                    'property':'runAsNonRoot','context':'declared_effective_field'}
                rid='k8s-property:'+fingerprint([corpus,path,document['document_index'],kind,name,'runAsNonRoot'])
                identity['reference_id']=rid;identities.append(identity)
                references.append({'reference_id':rid,'effective_runAsNonRoot':value,'value_origin':origin,
                    'guard_not_declared_true':value is not True,
                    'explicitly_disabled':None if value is None else not value,
                    'effective_declared_uid':uid,'uid_origin':uid_origin,
                    'actual_runtime_uid':'not_assessed','basis':'Source fields and Kubernetes precedence, not scanner output',
                    'evidence_ids':[path,'sources/kubernetes-v1.36.3-securitycontext-util.go']})
    return {'objects':objects,'identities':identities,'references':references}


def trivy_outcomes(raw,corpus):
    if raw.get('Trivy',{}).get('Version')!='0.74.0':
        raise ValueError('Unqualified Trivy coordinate version')
    rows=[]
    for i,block in enumerate(raw.get('Results',[])):
        if block.get('Type')!='kubernetes':continue
        for j,item in enumerate(block.get('Misconfigurations',[])):
            if item.get('ID')!='KSV-0012':continue
            status=item.get('Status')
            if status not in {'PASS','FAIL','EXCEPTION'}:raise ValueError('Unknown Trivy status')
            rows.append({'outcome_id':f'{corpus}:trivy:{i}:{j}','corpus':corpus,'tool':'trivy',
                'path':block['Target'],'status':status,'message':item.get('Message'),
                'line_start':item.get('CauseMetadata',{}).get('StartLine'),
                'line_end':item.get('CauseMetadata',{}).get('EndLine'),
                'coordinate_profile':'trivy-0.74.0-yaml-parser',
                'native_locator':f'/Results/{i}/Misconfigurations/{j}'})
    return rows


def checkov_outcomes(raw,corpus):
    rows=[]
    for i,block in enumerate(raw if isinstance(raw,list) else [raw]):
        for name in ('passed_checks','failed_checks','skipped_checks'):
            for j,item in enumerate(block['results'][name]):
                if item['check_id']!='CKV_K8S_23':continue
                pointer=(f'/{i}' if isinstance(raw,list) else '')+f'/results/{name}/{j}'
                rows.append({'outcome_id':f'{corpus}:checkov:{i}:{name}:{j}',
                    'corpus':corpus,'tool':'checkov','path':item['file_path'].lstrip('/'),
                    'status':item['check_result']['result'],'resource':item['resource'],
                    'native_locator':pointer})
    return rows


def associate(outcome,identities,objects):
    """Use report semantics and source identities only; never truth values.

    Checkov's root rule reports the whole resource and inspects regular
    containers. FAIL establishes a resource-level result, not each member.
    """
    candidates=[r for r in identities if r['corpus']==outcome['corpus'] and r['path']==outcome['path']]
    docs=[r for r in objects if r['corpus']==outcome['corpus'] and r['path']==outcome['path']]
    base={'outcome_id':outcome['outcome_id'],'candidate_reference_ids':[],
          'definite_reference_ids':[],'unit':None}
    if not docs:return {**base,'association':'unresolved_source_path'}
    if outcome['tool']=='checkov':
        matched=[d for d in docs if outcome['resource']=='.'.join([d['kind'],d['declared_namespace'] or 'default',d['name']])]
        if len(matched)!=1:return {**base,'association':'ambiguous_resource'}
        selected=[r for r in candidates if r['document_id']==matched[0]['document_id'] and r['container_type']=='containers']
        return {**base,'association':'resource_aggregate','unit':'resource_rule',
                'document_id':matched[0]['document_id'],'candidate_reference_ids':[r['reference_id'] for r in selected],
                'definite_reference_ids':[r['reference_id'] for r in selected] if len(selected)==1 else []}
    if outcome['status']!='FAIL':
        if len(docs)!=1:return {**base,'association':'unresolved_multi_document_status'}
        if not docs[0]['workload']:return {**base,'association':'non_workload_status','document_id':docs[0]['document_id']}
        selected=[r for r in candidates if r['container_type'] in ('containers','initContainers')]
        return {**base,'association':'resource_aggregate','unit':'resource_rule','document_id':docs[0]['document_id'],
                'candidate_reference_ids':[r['reference_id'] for r in selected],
                'definite_reference_ids':[r['reference_id'] for r in selected] if len(selected)==1 else []}
    match=re.fullmatch(r"Container '([^']+)' of ([A-Za-z]+) '([^']+)' should set 'securityContext.runAsNonRoot' to true",outcome.get('message') or '')
    if not match:return {**base,'association':'unsupported_message'}
    name,kind,resource=match.groups();start=outcome.get('line_start');end=outcome.get('line_end')
    if type(start) is not int or type(end) is not int or end<start:return {**base,'association':'missing_source_span'}
    selected=[]
    for r in candidates:
        if r['container_name']!=name or r['kind']!=kind or r['name']!=resource:continue
        if r['container_type'] not in ('containers','initContainers'):continue
        profile=outcome.get('coordinate_profile','physical')
        delta=0 if profile=='physical' else r.get('trivy_074_line_delta') if profile=='trivy-0.74.0-yaml-parser' else None
        if delta is not None and r['container_line_start']<=start+delta<=end+delta<=r['container_line_end']:
            selected.append((r,delta))
    if len(selected)!=1:return {**base,'association':'ambiguous_or_inconsistent_container'}
    identity,delta=selected[0]
    return {**base,'association':'container_localized','unit':'container_property',
            'document_id':identity['document_id'],'candidate_reference_ids':[identity['reference_id']],
            'definite_reference_ids':[identity['reference_id']],
            'physical_line_start':start+delta,'physical_line_end':end+delta,'line_delta':delta}


def file_pass_counterfactual(outcomes,associations):
    """Simulate discarding all failures in files containing a PASS; not a product claim."""
    passed={(r['corpus'],r['path']) for r in outcomes if r['tool']=='trivy' and r['status']=='PASS'}
    by_id={r['outcome_id']:r for r in associations}
    fail=[r for r in outcomes if r['tool']=='trivy' and r['status']=='FAIL']
    kept=[r for r in fail if (r['corpus'],r['path']) not in passed]
    before={x for r in fail for x in by_id[r['outcome_id']]['definite_reference_ids']}
    after={x for r in kept for x in by_id[r['outcome_id']]['definite_reference_ids']}
    return {'baseline_localized_reference_units':len(before),'discarded_native_failures':len(fail)-len(kept),
            'reference_units_lost':len(before-after),'lost_reference_ids':sorted(before-after),
            'interpretation':'Counterfactual file-only PASS filtering; no real filtering action or production prevalence.'}
