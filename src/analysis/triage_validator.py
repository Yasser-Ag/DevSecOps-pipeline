"""Frozen decision validator, extracted without changing its function body."""
import json

def validate_decision(text, model_input):
    """Only well-formed dismissals take effect. Never salvage partial JSON."""
    try:
        def unique(pairs):
            row={}
            for key,value in pairs:
                if key in row:raise ValueError('Duplicate response field')
                row[key]=value
            return row
        value=json.loads(text,object_pairs_hook=unique)
        if not isinstance(value,dict) or set(value)!={'finding_id','action','evidence_ids','rationale'}:
            raise ValueError('Unexpected response fields')
        if value['finding_id']!=model_input['finding_id']:raise ValueError('Wrong finding identity')
        if value['action'] not in ('retain','dismiss','abstain'):raise ValueError('Unknown action')
        evidence=value['evidence_ids'];allowed={r['id'] for r in model_input['evidence']}
        if not isinstance(evidence,list) or not all(isinstance(e,str) for e in evidence) or len(set(evidence))!=len(evidence) or not set(evidence)<=allowed:
            raise ValueError('Unsupported evidence reference')
        if value['action']=='dismiss' and not evidence:raise ValueError('Dismissal requires supplied evidence')
        if not isinstance(value['rationale'],str) or not 1<=len(value['rationale'])<=2000:
            raise ValueError('Invalid rationale')
        return {'finding_id':model_input['finding_id'],'status':'completed','action':value['action'],
                'effective_action':'dismiss' if value['action']=='dismiss' else 'retain','response':value}
    except (ValueError,TypeError,KeyError):
        return {'finding_id':model_input['finding_id'],'status':'invalid','action':'retain','effective_action':'retain'}
