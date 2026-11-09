"""Seal the runtime integration without changing any qualified parent package."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'evidence/runtime_integration_2026-10-22'
SOURCES=['study/runtime_block_contract.py','study/final_runtime_ingress.py','engineering/static_runtime_controls.py',
         'engineering/static_campaign_run.py','engineering/test_runtime_integration.py',
         'engineering/runtime_integration_qualification.py','engineering/RUNTIME_INTEGRATION_ACTION_2026-10-22.md',
         'engineering/build_runtime_integration.py','engineering/transport_runtime_integration.py']


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def main():
    p=argparse.ArgumentParser();p.add_argument('--version',type=int,choices=(1,2),default=1);args=p.parse_args()
    protected=json.loads((ROOT/'evidence/final_comparators_2026-10-22/candidate-v1/source_manifest.json').read_text())['files']
    for row in protected:
        path=ROOT/row['path']
        if path.stat().st_size!=row['bytes'] or sha(path)!=row['sha256']:raise ValueError('Protected source changed: '+row['path'])
    package=BASE/('package-v'+str(args.version));package.mkdir(exist_ok=False)
    parent=ROOT/'evidence/final_output_2026-10-22/package-v2'
    mapping={}
    for row in json.loads((parent/'package_manifest.json').read_text())['files']:
        source=parent/row['path']
        if source.stat().st_size!=row['bytes'] or sha(source)!=row['sha256']:raise ValueError('Parent changed')
        mapping[row['path']]=source
    for name in SOURCES:mapping[name]=ROOT/name
    mapping['reference/static_asset_locks.json']=ROOT/'evidence/static_scanner_controller_2026-10-22/ubuntu-preflight-v2/asset_locks.json'
    history=ROOT/'evidence/dynamic_reset_controller_2026-10-22/dynamic-resets-preflight-20261022-04'
    files=['assets-before/image_identities.json','runtime-1/assertions.json','runtime-2/assertions.json']
    for cycle in (1,2):
        for prefix in ('d','c'):
            for i in range(1,7):
                label=f'runtime-{cycle}-{prefix}{i:02d}'
                files += [f'runtime-{cycle}/dser-04-{label}.created.json',f'runtime-{cycle}/dser-04-{label}.final.json',
                          'commands/'+label+'-probe.stdout']
    for name in files:mapping['reference/runtime_history/'+name]=history/name
    records=[]
    for name,source in sorted(mapping.items()):
        if source.is_symlink():raise ValueError('Symbolic package input')
        target=package/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        records.append({'destination':name,'source':source.relative_to(ROOT).as_posix(),
                        'bytes':source.stat().st_size,'sha256':sha(source)})
    write(package/'runtime_integration_sources.json',records)
    write(package/'runtime_integration_scope.json',{'scientific_release':False,'scientific_scans':0,'model_generations':0,
          'unit_tests':96,'qualification_control_probes':24,'final_planned_control_probes':120,
          'parent_manifest_sha256':sha(parent/'package_manifest.json'),'protected_prior_sources':len(protected),
          'static_execution_entrypoint':'engineering/static_campaign_run.py',
          'static_analysis_entrypoint':'study/final_runtime_ingress.py',
          'scope':'Static runtime integration only. Final combined component release remains subsequent.'})
    files=[{'path':p.relative_to(package).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
           for p in sorted(package.rglob('*')) if p.is_file()]
    write(package/'package_manifest.json',{'files':files})
    archive=package.with_suffix('.tar.gz')
    with tarfile.open(archive,'x:gz') as stream:
        for p in sorted(package.rglob('*')):
            if p.is_file():stream.add(p,arcname=p.relative_to(package).as_posix(),recursive=False)
    receipt={'created_utc':datetime.now(timezone.utc).isoformat(),'files':len(files),
             'package_manifest_sha256':sha(package/'package_manifest.json'),'archive_sha256':sha(archive),
             'source_bytes':sum(r['bytes'] for r in files),'archive_bytes':archive.stat().st_size,
             'protected_prior_sources':len(protected),'scientific_release':False}
    write(BASE/(package.name+'.receipt.json'),receipt);print(json.dumps(receipt,indent=2))


if __name__=='__main__':main()
