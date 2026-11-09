"""Choose development pilot cases from observable input strata, without labels."""
import hashlib
import json


def rank(fid):
    return hashlib.sha256(('triage-pilot-20261012-v1:' + fid).encode()).hexdigest()


def select_pilot(alerts, contexts, budgets, prior_ids):
    ids=[p['finding_id'] for p in alerts]
    if len(ids)!=len(set(ids)) or ids!=[p['finding_id'] for p in contexts] or ids!=[p['finding_id'] for p in budgets]:
        raise ValueError('Pilot inputs not paired')
    groups={};by_id={}
    for a,c,b in zip(alerts,contexts,budgets):
        if not b['alert_inference_eligible'] or not b['context_inference_eligible']:
            continue
        fid=a['finding_id'];native=a['evidence'][0]['content']
        key=(native['tool'],len(c['evidence'])>1,'prior' if fid in prior_ids else 'aigoat')
        groups.setdefault(key,[]).append(fid);by_id[fid]=(a,c,b)
    chosen=[]
    for key,members in sorted(groups.items()):
        fid=min(members,key=rank)
        chosen.append({'finding_id':fid,'tool':key[0],'has_added_context':key[1],
                       'cohort':key[2],'stratum_population':len(members),'selection_rank':rank(fid)})
    def category(fid):
        native=by_id[fid][0]['evidence'][0]['content'];tool=native['tool']
        if native.get('package'):return 'component'
        if tool in ('semgrep','findsecbugs','bandit'):return 'source'
        if tool in ('nuclei','zap','restler'):return 'http'
        if tool in ('checkov','trivy-config','kics','hadolint','zizmor'):return 'declaration'
        return 'other'
    canary=[]
    for name in ('source','component','declaration','http'):
        candidates=[r for r in chosen if category(r['finding_id'])==name]
        if not candidates:raise ValueError('Missing canary input format: '+name)
        # Prefer an enriched example when available, then the fixed opaque hash.
        best=min(candidates,key=lambda r:(not r['has_added_context'],r['selection_rank']))
        canary.append({'finding_id':best['finding_id'],'input_format':name})
    return chosen,canary


def classify_completion(response, packet, validator):
    """Transport/format failures retain; never salvage truncated output."""
    try:
        choices=response['choices']
        if len(choices)!=1:raise ValueError('Unexpected choice count')
        choice=choices[0];message=choice['message']
        if choice['finish_reason']!='stop':raise ValueError('Incomplete completion')
        if message.get('tool_calls') or message.get('function_call'):raise ValueError('Unexpected tool call')
        if message.get('reasoning_content'):raise ValueError('Unexpected reasoning output')
        content=message['content']
        if not isinstance(content,str):raise ValueError('Missing text content')
        return validator(content,packet)
    except (ValueError,KeyError,TypeError,IndexError) as error:
        return {'finding_id':packet['finding_id'],'status':'invalid_completion','action':'retain',
                'effective_action':'retain','error':type(error).__name__+': '+str(error)}
