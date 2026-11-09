#!/usr/bin/env python3
"""Reconstruct supported unions and omissions from verified native-report links."""
import argparse
import csv
import json
from pathlib import Path
import sys
import time
from collections import defaultdict

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/pipeline'))
from study.final_scientific_analysis import coverage_row, population_omissions


def read(path):return json.loads(path.read_text())


def run(static_dirs,dynamic_dirs,output):
    start=time.monotonic()
    bindings=read(ROOT/'config/experiment/analysis_bindings.json')
    profiles={p['profile_id']:p for p in bindings['profiles']}
    populations={p['population']:p for p in bindings['populations']}
    static={c['job_id']:c for c in (json.loads(x) for x in (ROOT/'data/references/static_replay_contract.jsonl').read_text().splitlines())}
    dynamic={c['job_id']:c for c in (json.loads(x) for x in (ROOT/'data/references/dynamic_replay_contract.jsonl').read_text().splitlines())}
    jobs={}
    for directory in static_dirs:
        assert read(directory/'verification.json')['all_identical'] is True
        links=defaultdict(list)
        for row in csv.DictReader((directory/'replayed_links.csv').open()):
            links[row['job_id']].append({k:row[k] for k in ('finding_id','case_id','relation','scope')})
        for check in csv.DictReader((directory/'job_checks.csv').open()):
            assert all(check[k]=='True' for k in ('native_count_identical','status_identical','observations_identical','links_identical'))
            c=static[check['job_id']]
            assert c['job_id'] not in jobs,'Duplicate replay job'
            jobs[c['job_id']]={**{k:c[k] for k in ('job_id','profile_id','block','measurement_eligible','role','native_count')},
                              'observations':c['expected_observations'],'links':links[c['job_id']]}
    for directory in dynamic_dirs:
        assert read(directory/'verification.json')['all_identical'] is True
        for row in read(directory/'links.json'):
            c=dynamic[row['job_id']]
            assert row['job_id'] not in jobs,'Duplicate replay job'
            jobs[row['job_id']]={**row,'role':profiles[row['profile_id']]['role'],
                                  **{k:c['expected'][k] for k in ('native_count','observations','limitations')}}
    assert set(jobs)==set(static)|set(dynamic),'Incomplete replay population'
    rows=[]
    for job in jobs.values():
        for name in profiles[job['profile_id']]['candidate_populations']:
            rows.append(coverage_row(job,populations[name],bindings['references']))
    expected=list(csv.DictReader((ROOT/'data/derived/analysis/coverage_by_profile.csv').open()))
    index={(r['job_id'],r['population']):r for r in expected}
    mismatches=[]
    for row in rows:
        old=index[(row['job_id'],row['population'])]
        for k,v in row.items():
            if isinstance(v,(dict,list)):
                same=json.loads(old[k])==v
            elif v is None:same=old[k]==''
            else:same=old[k]==str(v)
            if not same:mismatches.append({'job_id':row['job_id'],'population':row['population'],'field':k})
    assert len(rows)==len(expected) and not mismatches,'Coverage rows differ'
    omissions=[]
    for block in range(1,6):
        selected=[r for r in rows if r['block']==block]
        for population in bindings['populations']:
            omissions.append(population_omissions(population,selected,bindings['references']))
        sca=[r for r in selected if r['population']=='sca']
        stages={r['profile_id']:('image_scan' if r['profile_id'].endswith('-image') else 'source_sca')
                for r in sca if r['role']!='inventory'}
        omissions.append(population_omissions(populations['sca'],sca,bindings['references'],stages))
    expected_omissions=read(ROOT/'data/derived/analysis/population_and_stage_omissions.json')
    assert omissions==expected_omissions,'Supported unions or omissions differ'
    output.mkdir(parents=True,exist_ok=False)
    (output/'supported_unions_and_omissions.json').write_text(json.dumps(omissions,indent=2)+'\n')
    summary={'scanner_jobs':len(jobs),'coverage_rows':len(rows),'omission_ledgers':len(omissions),
             'all_identical':True,'wall_seconds':time.monotonic()-start,'new_scanner_runs':0}
    (output/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--static',type=Path,nargs='+',required=True)
    parser.add_argument('--dynamic',type=Path,nargs='+',required=True)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();run(a.static,a.dynamic,a.output)
