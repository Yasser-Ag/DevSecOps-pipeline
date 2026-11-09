"""Typed reference coverage without equating alert counts with distinct cases."""
from collections import Counter,defaultdict
import hashlib
import json


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def identity(prefix,*parts):return prefix+hashlib.sha256(canonical(parts).encode()).hexdigest()[:32]


def index_unique(rows,key):
    result={}
    for row in rows:
        value=row.get(key)
        if not isinstance(value,str) or not value or value in result:raise ValueError('Missing/duplicate '+key)
        result[value]=row
    return result


def validate(references,findings,links,populations):
    refs=index_unique(references,'case_id');alerts=index_unique(findings,'finding_id')
    pops=index_unique(populations,'population');seen=set()
    for row in refs.values():
        if row['population'] not in pops or row['truth'] not in ('positive','negative','unresolved'):
            raise ValueError('Invalid reference scope/truth')
        if not row.get('evidence'):raise ValueError('Reference requires independent evidence')
        if row['unit']!=pops[row['population']]['unit'] or row['endpoint']!=pops[row['population']]['endpoint']:
            raise ValueError('Reference unit/endpoint mismatch')
    for row in alerts.values():
        if row['population'] not in pops or row['native_label'] not in ('true','false','unresolved'):
            raise ValueError('Invalid native finding scope/label')
        key=(row['raw_report_sha256'],row['native_locator'])
        if key in seen:raise ValueError('Native warning was expanded into duplicate decisions')
        seen.add(key)
        if not row.get('stage') or not row.get('evidence'):raise ValueError('Missing finding provenance')
    link_keys=set()
    for row in links:
        if row['finding_id'] not in alerts or row['case_id'] not in refs:raise ValueError('Dangling link')
        key=(row['finding_id'],row['case_id'])
        if key in link_keys:raise ValueError('Duplicate association')
        link_keys.add(key)
        if row['relation'] not in ('supports','contradicts','candidate'):raise ValueError('Unknown relation')
        ref=refs[row['case_id']];finding=alerts[row['finding_id']]
        if ref['population']!=finding['population']:raise ValueError('Cross-population coverage link')
        if row['relation']=='supports' and ref['truth']!='positive':raise ValueError('Cannot cover a negative/unknown case')
        if row['relation']=='contradicts' and ref['truth']!='negative':raise ValueError('Contradiction requires a negative reference')
        if not row.get('evidence'):raise ValueError('Link lacks evidence')
    return refs,alerts,pops


def summarize(references,findings,links,populations):
    refs,alerts,pops=validate(references,findings,links,populations)
    support=defaultdict(set);candidate=defaultdict(set)
    for row in links:
        if row['relation']=='supports':support[row['finding_id']].add(row['case_id'])
        elif row['relation']=='candidate' and refs[row['case_id']]['truth']=='positive':
            candidate[row['finding_id']].add(row['case_id'])
    result=[]
    for name,pop in sorted(pops.items()):
        r=[x for x in refs.values() if x['population']==name]
        f=[x for x in alerts.values() if x['population']==name]
        positive={x['case_id'] for x in r if x['truth']=='positive'}
        covered=set().union(*(support[x['finding_id']] for x in f)) if f else set()
        possible=covered | (set().union(*(candidate[x['finding_id']] for x in f)) if f else set())
        complete=pop['linkage_status']=='qualified'
        stages=sorted({x['stage'] for x in f});ablations=[]
        object_of={x['case_id']:x.get('object_id') for x in r}
        objects={object_of[c] for c in covered if object_of[c] is not None}
        for stage in stages:
            survivors=[x for x in f if x['stage']!=stage]
            kept=set().union(*(support[x['finding_id']] for x in survivors)) if survivors else set()
            kept_objects={object_of[c] for c in kept if object_of[c] is not None}
            ablations.append({'removed_stage':stage,'lost_supported_case_ids':sorted(covered-kept),
                'lost_supported_cases':len(covered-kept),'remaining_supported_cases':len(kept),
                'lost_supported_object_ids':sorted(objects-kept_objects),
                'interpretation':'Report-evidence loss under saved-output removal; not causal operational risk.'})
        result.append({'population':name,'layer':pop['layer'],'cohort':pop['cohort'],'endpoint':pop['endpoint'],'unit':pop['unit'],
            'linkage_status':pop['linkage_status'],'reference_status_counts':dict(Counter(x['truth'] for x in r)),
            'native_warnings':len(f),'native_label_counts':dict(Counter(x['native_label'] for x in f)),
            'supported_positive_cases':len(covered),'positive_reference_cases':len(positive),
            'reference_coverage':len(covered)/len(positive) if complete and positive else None,
            'possible_reference_coverage':len(possible)/len(positive) if complete and positive else None,
            'ratio_scope':'Definite support / fixed positive references; possible bound adds candidate links. Neither is unrestricted scanner recall.' if complete else 'Not computed: reference linkage is incomplete',
            'supported_object_count':len(objects) if objects else None,'stage_removal':ablations,
            'covered_case_ids':sorted(covered),'not_definitely_supported_positive_case_ids':sorted(positive-covered) if complete else None})
    return result
