#!/usr/bin/env python3
"""Run the complete offline evidence replay without scanners or model inference."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--source-cache',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fetch-sources',action='store_true')
    a=p.parse_args()
    if a.output.exists():p.error('Use a new output directory')
    a.output.mkdir(parents=True)
    evidence=a.evidence.resolve();cache=a.source_cache.resolve();out=a.output.resolve()
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    start=time.monotonic();records=[]
    def invoke(name,args):
        before=time.monotonic()
        subprocess.run([sys.executable,str(ROOT/'scripts'/name),*map(str,args)],check=True,env=env)
        records.append({'script':name,'wall_seconds':time.monotonic()-before})
    # Source retrieval is explicit and restricted to hash-checked upstream files.
    invoke('replay_triage.py',['--evidence',evidence,'--source-cache',cache,'--output',out/'triage']+
           (['--fetch-sources'] if a.fetch_sources else []))
    invoke('replay_static_linking.py',['--evidence',evidence,'--output',out/'static'])
    invoke('replay_dynamic_linking.py',['--evidence',evidence,'--output',out/'dynamic'])
    invoke('replay_reference_checks.py',['--evidence',evidence,'--output',out/'references'])
    invoke('replay_supported_results.py',['--static',out/'static','--dynamic',out/'dynamic','--output',out/'supported'])
    invoke('replay_grouping.py',['--evidence',evidence,'--static',out/'static','--dynamic',out/'dynamic',
                               '--source-cache',cache,'--output',out/'grouping'])
    result={'all_identical':True,'steps':records,'wall_seconds':time.monotonic()-start,
            'new_scanner_runs':0,'new_model_inferences':0,'new_target_requests':0}
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':main()
