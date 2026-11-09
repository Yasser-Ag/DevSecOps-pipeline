#!/usr/bin/env python3
"""Reapply frozen grouping comparators to reparsed native observations."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/pipeline'))
from study.final_output_adapter import canonical_content, fixture_identity
from study.final_static_comparators import sast, identities, kubernetes, terraform, K8S_PROFILES, TF_PROFILES
from study.final_context_comparators import crapi_headers
from fetch_external_sources import source_bytes
from replay_dynamic_linking import projection_view
from replay_static_linking import semantic


def read(path):return json.loads(path.read_text())


def run(evidence,static_dirs,dynamic_dirs,cache,output):
    start=time.monotonic()
    context=read(ROOT/'data/references/comparator_context.json')
    sources={path:source_bytes(d,cache,offline=True) for path,d in context['java'].items()}
    k8s={}
    for row in context['kubernetes']:
        data=(ROOT/row['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==row['published_sha256']
        k8s[row['corpus'],row['artifact_path']]=data
    static={}
    for directory in static_dirs:
        assert read(directory/'verification.json')['all_identical'] is True
        for job in read(directory/'comparator_jobs.json'):
            assert job['job_id'] not in static
            static[job['job_id']]=job
    contracts={r['job_id']:r for r in (json.loads(x) for x in (ROOT/'data/references/static_replay_contract.jsonl').read_text().splitlines())}
    dynamic_contracts={r['job_id']:r for r in (json.loads(x) for x in (ROOT/'data/references/dynamic_replay_contract.jsonl').read_text().splitlines())}
    verified_dynamic=set()
    for directory in dynamic_dirs:
        assert read(directory/'verification.json')['all_identical'] is True
        verified_dynamic.update(r['job_id'] for r in read(directory/'links.json'))
    assert verified_dynamic==set(dynamic_contracts)
    output.mkdir(parents=True,exist_ok=False)
    checks=[]
    for block in range(1,6):
        jobs=[r for r in static.values() if r['block']==block]
        reports={}
        for job in jobs:
            if job['profile_id'] not in set(K8S_PROFILES)|set(TF_PROFILES):continue
            contract=contracts[job['job_id']]
            data=(evidence/contract['report']).read_bytes()
            assert hashlib.sha256(data).hexdigest()==contract['published_report_sha256']
            reports[job['profile_id']]=semantic(json.loads(data),contract['work_root'])
        actual={'sast':sast(jobs,sources,context['java_partition']),
                'identity':identities(jobs,context['advisory_aliases'],context['secrets'],context['identity']),
                'kubernetes':kubernetes(jobs,reports,k8s),
                'terraform':terraform(jobs,reports,context['terraform'])}
        conditions={}
        for profile in ('crapi-nuclei-valid-a','crapi-nuclei-invalid'):
            job_id=f'b{block:02d}-{profile}';contract=dynamic_contracts[job_id]
            job={**contract['expected'],'job_id':job_id,'profile_id':profile,'block':block}
            root=evidence/contract['root']
            fixture_data=read(root/'target/fixtures/fixture.json')
            schema=read(root/'target/scanner/openapi.json')
            urls=[s['url'] for s in schema.get('servers',[])]
            if not urls and schema.get('host'):urls=['http://'+schema['host']]
            fixture=fixture_identity('crapi',fixture_data,projection_view(urls))
            trace=[json.loads(x) for x in (root/'target/proxy_logs/requests.jsonl').read_text().splitlines()]
            conditions[profile]=crapi_headers(job,context['crapi_templates'],trace,fixture)
        actual['dast']={'conditions':conditions,'comparison_complete':all(x['comparison_complete'] for x in conditions.values())}
        frozen=read(ROOT/f'data/derived/matching/block{block}.json')['domains']
        for domain,result in actual.items():
            same=result==frozen[domain]['result']
            checks.append({'block':block,'domain':domain,'identical':same})
            if not same:
                (output/'difference.json').write_text(json.dumps({'block':block,'domain':domain,
                    'actual':result,'expected':frozen[domain]['result']},indent=2)+'\n')
                raise ValueError('Grouping replay differs: '+domain)
        # The combined AIGoat comparison remains unavailable: both Nuclei jobs
        # are limited in every block. It is never filled by a partial union.
        limited=[dynamic_contracts[f'b{block:02d}-aigoat-nuclei-{condition}']['expected']['measurement_eligible']
                 for condition in ('valid-alice','invalid')]
        assert limited==[False,False] and frozen['aigoat']['status']=='unavailable'
        checks.append({'block':block,'domain':'aigoat','identical':True,'status':'unavailable'})
        (output/f'block{block}.json').write_text(json.dumps(actual,indent=2)+'\n')
    summary={'blocks':5,'domain_checks':len(checks),'all_identical':True,
             'wall_seconds':time.monotonic()-start,'new_scanner_runs':0}
    (output/'domain_checks.json').write_text(json.dumps(checks,indent=2)+'\n')
    (output/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--static',type=Path,nargs='+',required=True)
    p.add_argument('--dynamic',type=Path,nargs='+',required=True)
    p.add_argument('--source-cache',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.evidence,a.static,a.dynamic,a.source_cache,a.output)
