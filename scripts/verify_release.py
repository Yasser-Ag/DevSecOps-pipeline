#!/usr/bin/env python3
"""Check file identities, study counts and offline reconstruction outputs."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]

def rows(path):return list(csv.DictReader(path.open()))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def check_counts():
    base=ROOT/'data/derived'
    static=rows(base/'static_profiles.csv');dynamic=rows(base/'dynamic_profiles.csv')
    populations=rows(base/'reference_populations.csv')
    assert len(static)==75 and Counter(r['role'] for r in static)=={'D':65,'I':10}
    assert len(dynamic)==18
    assert Counter(r['role_v1_0'] for r in populations)=={'scored':16,'property':2,'descriptive':17}
    assert sum(int(r['catalogue_size']) for r in populations)==338
    assert len(rows(ROOT/'data/references/binding_rules.csv'))==67
    classes=rows(base/'triage_by_class.csv');decisions=rows(base/'triage_decisions.csv')
    assert len(classes)==len(decisions)==12
    index={(r['condition'],r['pass_number']):r for r in decisions}
    for r in classes:
        d=index[r['condition'],r['pass_number']]
        for category,size in [('true_native',62),('false_native',11),('true_literal',15)]:
            assert int(r[category+'_n'])==size
            assert sum(int(r[category+'_'+action]) for action in ['retain','dismiss','abstain','invalid'])==size
        for action in ['retain','dismiss','abstain','invalid']:
            assert int(r['total_'+action])==int(d[action])
        assert sum(int(r[k]) for k in ['Tr','Td','Fr','Fd'])==73
    assert len(rows(base/'reference_review.csv'))==32
    assert len(rows(base/'omissions.csv'))==440
    assert len(rows(base/'invalid_responses.csv'))==34
    preliminary=rows(ROOT/'preliminary/run_metadata.csv')
    assert len(preliminary)==31 and sorted(int(r['run_number']) for r in preliminary)==list(range(1,32))
    return {'static_profiles':75,'static_detector_profiles':65,'static_inventory_profiles':10,
            'dynamic_profiles':18,'reference_populations':35,'reference_records':338,
            'triage_inputs_per_condition':88,'triage_decisions_per_pass':528,
            'model_responses_per_pass':352,'reference_review_propositions':32,
            'binding_rules':67,'preliminary_workflow_runs':31}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--evidence',type=Path)
    p.add_argument('--source-cache',type=Path)
    p.add_argument('--fetch-sources',action='store_true')
    a=p.parse_args()
    if a.output.exists():p.error('Use a new output directory')
    a.output.mkdir(parents=True)
    start=time.monotonic();records=[]
    manifest=ROOT/'config/release_manifest.csv'
    if not manifest.exists():raise ValueError('Release integrity manifest is missing')
    identities=rows(manifest)
    for row in identities:
        file=ROOT/row['path']
        assert file.is_file() and sha(file)==row['sha256'],'Release file identity differs: '+row['path']
        assert file.stat().st_size<50*1024**2,'Repository file exceeds release limit'
    counts=check_counts()
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    def invoke(script,args):
        t=time.monotonic()
        subprocess.run([sys.executable,str(ROOT/'scripts'/script),*map(str,args)],check=True,env=env)
        records.append({'script':script,'wall_seconds':time.monotonic()-t})
    invoke('reproduce_tables.py',['--output',a.output/'tables'])
    expected_tables=list((ROOT/'results/tables').glob('*.csv'))+list((ROOT/'results/supplementary').glob('*.csv'))
    assert len(expected_tables)==24
    for source in expected_tables:
        rebuilt=a.output/'tables'/source.relative_to(ROOT/'results')
        assert source.read_bytes()==rebuilt.read_bytes(),'Table differs: '+source.name
    invoke('reproduce_figures.py',['--output',a.output/'figures'])
    expected_values=list((ROOT/'results/figures').glob('*_values.csv'))
    assert len(expected_values)==5
    for source in expected_values:
        assert source.read_bytes()==(a.output/'figures'/source.name).read_bytes(),'Figure values differ: '+source.name
    replay=False
    if a.evidence:
        if not a.source_cache:p.error('--source-cache is required with --evidence')
        invoke('replay_linking.py',['--evidence',a.evidence,'--source-cache',a.source_cache,'--output',a.output/'linking']+
               (['--fetch-sources'] if a.fetch_sources else []))
        replay=True
    summary={'file_identities_checked':len(identities),'counts':counts,'tables_identical':24,
             'figure_data_files_identical':5,'figures_rendered':6,'level_2_completed':replay,
             'steps':records,'wall_seconds':time.monotonic()-start,'new_experiments':0}
    (a.output/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))

if __name__=='__main__':main()
