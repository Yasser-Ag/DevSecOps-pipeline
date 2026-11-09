#!/usr/bin/env python3
"""Read recorded runtime probes and generation outputs; never contact a target."""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/pipeline'))
from study.final_output_adapter import fixture_identity, generation_observations
from study.final_output_ingress import reference_passed
from study.final_dynamic_projection import rag_reference_observations
from study.dynamic_scan_contract import generation_workload

def read(path):return json.loads(path.read_text())

def run(evidence,output):
    start=time.monotonic()
    references=read(ROOT/'config/experiment/analysis_bindings.json')['references']
    expected=read(ROOT/'data/derived/analysis/target_generation_reference_observations.json')
    rows=[]
    for old in expected:
        root=evidence/'dynamic'/f"block{old['block']}"/'aigoat_generation'/'target/fixtures'
        fixture_data=read(root/'fixture.json')
        before,after=read(root/'before.json'),read(root/'after.json')
        verified=reference_passed(before,'aigoat') and reference_passed(after,'aigoat')
        generation=generation_observations(read(root/'generation.json'),
            [r['id'] for r in generation_workload()],fixture_identity('aigoat',fixture_data))
        observations=rag_reference_observations(references,before,after,fixture_data)
        assert generation==old['generation'],'Generation observations differ'
        assert observations==old['reference_observations'],'Reference observations differ'
        assert verified is old['reference_state_verified'],'Reference status differs'
        rows.append({'job_id':old['job_id'],'generation_requests':len(generation),
                     'reference_observations':len(observations),'all_identical':True})
    assert len(rows)==5
    # Runtime receipts are retained separately from scanner discoveries.
    contracts=[json.loads(x) for x in (ROOT/'data/references/static_replay_contract.jsonl').read_text().splitlines()]
    assert len(contracts)==375 and all(r['runtime_reference_verified'] for r in contracts)
    runtime = evidence/'static/campaign/runtime'
    probes = sorted(runtime.glob('b*/before/*/receipt.json')) + sorted(runtime.glob('b*/after/*/receipt.json'))
    assert len(probes) == 120, 'Expected 12 controls before and after each of five blocks'
    for receipt_path in probes:
        receipt = read(receipt_path)
        probe = read(receipt_path.parent/'probe.json')
        assert receipt['status'] == 'completed'
        assert receipt['assertion']['passed'] is True
        assert probe['returncode'] == 0
    output.mkdir(parents=True,exist_ok=False)
    (output/'generation_checks.json').write_text(json.dumps(rows,indent=2)+'\n')
    result={'generation_jobs':5,'generation_requests':20,'reference_observations':40,
            'recorded_static_runtime_verified':375,'recorded_runtime_probes_checked':120,'all_identical':True,
            'wall_seconds':time.monotonic()-start,'new_target_requests':0}
    (output/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.evidence,a.output)
