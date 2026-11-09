"""Synthetic execution-boundary tests; historical probes are never new results."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

from engineering import static_campaign_run as controller
from engineering.static_runtime_controls import RuntimeControls
from engineering.static_scanner_host import write, inventory
from engineering.dynamic_reset_run import PROBE
from study.runtime_block_contract import (CONTROL_SHA256, load_controls, source_bindings,
                                          control_id, schedule as runtime_schedule, validate_container)
from study.final_runtime_ingress import collect_static, verify_block
from study.final_output_ingress import Evidence
from study.final_output_adapter import digest, catalog_entries, static_rows
from study.static_scan_contract import sha, schedule

ROOT = Path(__file__).resolve().parents[1]
HISTORY = ROOT / 'reference/runtime_history'
if not HISTORY.exists():
    HISTORY = ROOT / 'evidence/dynamic_reset_controller_2026-10-22/dynamic-resets-preflight-20261022-04'
CONTROL_FILE = ROOT / 'reference/runtime_controls.json'
if not CONTROL_FILE.exists():
    CONTROL_FILE = ROOT / 'evidence/final_output_2026-10-22/package-v2/reference/runtime_controls.json'
LOCK_FILE = ROOT / 'reference/static_asset_locks.json'
if not LOCK_FILE.exists():
    LOCK_FILE = ROOT / 'evidence/static_scanner_controller_2026-10-22/ubuntu-preflight-v2/asset_locks.json'


def synthetic_phase(root, run_id, controls, locks, block, phase):
    """Rewrap existing raw probes with synthetic identities solely for contract tests."""
    directory = root / 'runtime' / f'b{block}' / phase
    directory.mkdir(parents=True)
    start = time.monotonic_ns()
    images = json.loads((HISTORY / 'assets-before/image_identities.json').read_text())
    images = {r['service']['image']: images[r['service']['image']] for r in controls}
    write(directory / 'images.json', images)
    assertions = {r['case_id']: r for r in json.loads((HISTORY / 'runtime-1/assertions.json').read_text())}
    members = []
    for row in controls:
        case = row['case_id']; base = directory / case; base.mkdir()
        begin = time.monotonic_ns(); identity = control_id(block, phase, case)
        name = 'synthetic-' + identity
        cid = hashlib.sha256((run_id + identity).encode()).hexdigest()
        first = json.loads((HISTORY / 'runtime-1' / ('dser-04-runtime-1-' + case.lower() + '.created.json')).read_text())
        first.update(Id=cid, Name='/' + name)
        first['Config']['Labels'].update({'org.study.run': run_id, 'org.study.runtime': identity, 'org.study.reset': name})
        first['State'].update(Status='created', Running=False)
        last = deepcopy(first); last['State'].update(Status='exited', Running=False, ExitCode=0, OOMKilled=False)
        write(base / 'created.json', first); write(base / 'finished.json', last)
        write(base / 'probe.stdout', assertions[case]['raw'])
        probe_time=time.monotonic_ns()
        write(base / 'probe.json', {'argv':['docker','start','-a',cid], 'returncode':0,
              'started_monotonic_ns':probe_time,'finished_monotonic_ns':probe_time})
        (base / 'probe.stderr').write_text(''); (base / 'resources.jsonl').write_text('')
        remove_time=time.monotonic_ns()
        write(base/'remove.json',{'argv':['docker','rm',cid],'returncode':0,
              'started_monotonic_ns':remove_time,'finished_monotonic_ns':remove_time})
        (base/'remove.stdout').write_text(cid+'\n');(base/'remove.stderr').write_text('')
        write(base/'cleanup-before.json',last)
        receipt = {'id': identity, 'case_id': case, 'run_id': run_id, 'container_name': name, 'container_id': cid,
                   'status':'completed', 'removed':True, 'started_monotonic_ns':begin,
                   'finished_monotonic_ns':time.monotonic_ns(), 'assertion':assertions[case],
                   'evidence_origin':'synthetic_test', 'files':{f.name:sha(f) for f in base.iterdir()}}
        write(base / 'receipt.json', receipt)
        members.append({'case_id':case,'receipt':(base/'receipt.json').relative_to(root).as_posix(), 'sha256':sha(base/'receipt.json')})
    receipt = {'block':block, 'phase':phase, 'run_id':run_id, 'status':'completed', 'control_file_sha256':CONTROL_SHA256,
               'source_bindings':source_bindings(controls, locks), 'started_monotonic_ns':start,
               'finished_monotonic_ns':time.monotonic_ns(), 'controls':members, 'evidence_origin':'synthetic_test'}
    write(directory / 'phase.json', receipt)
    return receipt


class FakeRuntime:
    def __init__(self, root, run_id, controls, locks):
        self.root, self.run_id, self.controls, self.locks = root, run_id, controls, locks
        self.completed, self.calls = 0, []

    def phase(self, block, phase):
        self.calls.append((block, phase))
        value = synthetic_phase(self.root, self.run_id, self.controls, self.locks, block, phase)
        self.completed += 12
        return value


class RuntimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controls = load_controls(CONTROL_FILE)
        cls.original_locks = json.loads(LOCK_FILE.read_text())
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name) / 'run'; cls.base.mkdir()
        cls.run_id = 'synthetic-runtime-integration'
        source = Path(cls.temp.name)/'source'; source.mkdir(); (source/'input.txt').write_text('synthetic input\n')
        cls.locks = {'inputs': {'configuration': cls.original_locks['inputs']['configuration'],
                               'synthetic': [{'source':str(source),'destination':'inputs','files':inventory(source)}]},
                     'runtime':[], 'databases':{}}
        script = "import json,sys;from pathlib import Path;p=Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps([dict(code='DL3002',file=sys.argv[2]+'/docker/d02/Dockerfile',line=2,column=1,message='Last USER is root',level='warning')]))"
        executable = Path(cls.temp.name)/'synthetic-hadolint'
        executable.write_text('#!/usr/bin/env python3\n' + script + '\n'); executable.chmod(0o700)
        p = {'id':'synthetic-hadolint','suite':'synthetic','kind':'native','role':'detector','parser':'hadolint',
             'report':'out/report.json','argv':[str(executable),'{WORK}/out/report.json','{WORK}'],
             'historical_command':[str(executable),'<LAB_ROOT>/evidence/synthetic-historical/out/report.json',
                                   '<LAB_ROOT>/evidence/synthetic-historical'],
             'accepted_exit_codes':[0], 'timeout_seconds':10,'requires':[],'scratch_gib':0,'redacted_secrets':False}
        cls.plan = {'schema':'static-scan-plan-1','repetitions':5,'measurement_reuse':False,
                    'study_model_generations':0,'suites':{'synthetic':{'inputs':[]}},'profiles':[p]}
        cls.runtime = FakeRuntime(cls.base, cls.run_id, cls.controls, cls.locks)
        with patch.object(controller,'sample',return_value={}), patch.object(controller,'isolated_command',side_effect=lambda argv,*a:argv):
            cls.result = controller.execute(cls.plan,cls.locks,cls.base,cls.run_id,[],cls.runtime)
        write(cls.base/'asset_locks.json',cls.locks)
        shutil.copyfile(CONTROL_FILE,cls.base/'runtime_controls.json')
        write(cls.base/'protocol_release.json',{'origin':'synthetic_test','protocol':'v1.0'})
        write(cls.base/'summary.json',{'run_id':cls.run_id,'mode':'execute','assets_preserved':True,
              'package_manifest_sha256':'a'*64, 'protocol_release_sha256':sha(cls.base/'protocol_release.json')})
        cls.contract = {'run_id':cls.run_id, 'profile_ids':[p['id']], 'schedule_digest':digest(schedule(cls.plan)),
                        'package_manifest_sha256':'a'*64, 'asset_locks_sha256':sha(cls.base/'asset_locks.json'),
                        'release_sha256':sha(cls.base/'protocol_release.json'),'runtime_control_sha256':CONTROL_SHA256}
        raw = Path(cls.temp.name)/'historical.json'
        raw.write_text(json.dumps([dict(code='DL3002',file='<LAB_ROOT>/evidence/synthetic-historical/docker/d02/Dockerfile',line=2,column=1,message='Last USER is root',level='warning')]))
        parsed = static_rows(raw,p)
        cls.catalog = catalog_entries(p,parsed,[dict(finding_id='historical',native_locator='/0',population='docker',native_label='true',
                raw_report_sha256=parsed['raw_report_sha256'],evidence=[])],
                [dict(finding_id='historical',case_id='runtime-d02',relation='supports',scope='runtime projection')])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'run'; shutil.copytree(self.base,self.root)

    def collect(self): return collect_static(self.root,self.plan,self.catalog,self.contract)

    def mutate_json(self, relative, fn):
        p=self.root/relative; value=json.loads(p.read_text()); fn(value); write(p,value)

    def test_actual_controller_receipts_reach_ingress(self):
        result = self.collect()
        self.assertTrue(result['runtime_support_complete'])
        self.assertEqual(result['jobs_with_qualified_measurement'],5)
        self.assertEqual([r['bound_assertions'] for r in result['jobs']],[1]*5)
        self.assertEqual(self.result['scanner_invocations'],5)
        self.assertEqual(self.result['runtime_controls_completed'],120)
        self.assertEqual(self.runtime.calls,[(b,p) for b in range(1,6) for p in ('before','after')])

    def test_existing_controller_omitted_reset_flag_would_fail(self):
        before=self.root/'resets/b1-synthetic.json'; value=json.loads(before.read_text()); del value['verified']; write(before,value)
        self.mutate_json('jobs/b1-synthetic-hadolint/prepared.json',lambda r:r.update(reset_sha256=sha(before)))
        result=self.collect()['jobs']
        self.assertFalse(result[0]['measurement_eligible']); self.assertTrue(result[1]['measurement_eligible'])

    def test_missing_after_blocks_only_its_runtime_interpretations(self):
        (self.root/'runtime/b2/after/phase.json').unlink()
        result=self.collect()
        self.assertFalse(result['runtime_support_complete'])
        self.assertEqual([j['bound_assertions'] for j in result['jobs']],[1,0,1,1,1])
        self.assertEqual(result['jobs'][1]['native_count'],1)
        self.assertEqual(result['jobs'][1]['observations'][0]['binding_status'],'runtime_reference_pending')

    def test_copied_phase_cannot_qualify_another_block(self):
        shutil.copyfile(self.root/'runtime/b1/after/phase.json',self.root/'runtime/b2/after/phase.json')
        result=self.collect(); self.assertFalse(result['runtime_blocks'][1]['verified'])
        self.assertIn('Cross-block',result['runtime_blocks'][1]['reason'])

    def test_raw_probe_tampering_rejected_despite_pass_flag(self):
        self.mutate_json('runtime/b1/before/D01/probe.stdout',lambda r:r.update(uid=0))
        result=self.collect(); self.assertFalse(result['runtime_blocks'][0]['verified'])
        self.assertIn('artifact changed',result['runtime_blocks'][0]['reason'])

    def test_after_phase_before_scanners_is_rejected(self):
        self.mutate_json('blocks/b1.json',lambda r:r['scanner_interval'].update(finished_monotonic_ns=10**30))
        self.assertFalse(self.collect()['runtime_blocks'][0]['verified'])

    def test_job_timing_outside_block_rejected(self):
        p=self.root/'jobs/b1-synthetic-hadolint/receipt.json'
        self.mutate_json(p.relative_to(self.root),lambda r:r.update(finished_monotonic_ns=10**30))
        self.mutate_json('blocks/b1.json',lambda r:r['scanner_receipts'][0].update(sha256=sha(p)))
        self.assertFalse(self.collect()['runtime_blocks'][0]['verified'])

    def test_missing_control_cannot_be_scored_as_negative(self):
        self.mutate_json('runtime/b1/after/phase.json',lambda r:r['controls'].pop())
        self.assertFalse(self.collect()['runtime_blocks'][0]['verified'])

    def test_missing_scanner_job_invalidates_complete_block(self):
        self.mutate_json('outcomes.json',lambda r:r.pop(0))
        result=self.collect(); self.assertFalse(result['runtime_blocks'][0]['verified'])
        self.assertIsNone(result['jobs'][0]['native_count'])

    def test_runtime_receipt_identity_bound(self):
        self.mutate_json('runtime/b1/before/D01/receipt.json',lambda r:r.update(removed=False))
        self.assertIn('receipt changed',self.collect()['runtime_blocks'][0]['reason'])

    def test_input_source_hash_cannot_substitute_another_coordinate(self):
        locks=deepcopy(self.original_locks)
        root=next(r for r in locks['inputs']['configuration'] if r['destination']=='reference/scanner-inputs')
        root['files']=[r for r in root['files'] if r['path']!='compose/c01/compose.yaml']
        with self.assertRaisesRegex(ValueError,'coordinate/hash'):
            source_bindings(self.controls,locks)

    def test_runtime_schedule_separate_and_exact(self):
        jobs=runtime_schedule()
        self.assertEqual(len(jobs),120); self.assertEqual(len({r['id'] for r in jobs}),120)
        self.assertEqual(len(schedule(self.plan)),5)

    def test_old_release_cannot_skip_runtime_binding(self):
        package=Path(self.tmp.name)/'package';package.mkdir()
        write(package/'package_manifest.json',{'synthetic':True});write(package/'schedule.json',schedule(self.plan))
        assets=self.root/'asset_locks.json'
        release={'protocol':'v1.0','final_campaign_ready':True,'gates':[{'id':f'G{i}','passed':True} for i in range(1,9)],
                 'static_package_manifest_sha256':sha(package/'package_manifest.json'),'static_assets_sha256':sha(assets),
                 'static_profile_ids':[p['id'] for p in self.plan['profiles']], 'static_schedule_sha256':sha(package/'schedule.json')}
        path=package/'release.json';write(path,release)
        with self.assertRaisesRegex(ValueError,'Runtime control release'):
            controller.require_release(path,package,assets,self.plan)
        release.update(runtime_control_sha256=CONTROL_SHA256,runtime_schedule_digest=digest(runtime_schedule()));write(path,release)
        self.assertEqual(controller.require_release(path,package,assets,self.plan),release)

    def test_inspected_mount_or_image_drift_rejected(self):
        row=self.controls[0]; directory=self.root/'runtime/b1/before'
        info=json.loads((directory/'D01/created.json').read_text())
        image=json.loads((directory/'images.json').read_text())[row['service']['image']]
        self.assertTrue(validate_container(info,row,info['Name'][1:],self.run_id,'b1-before-d01',PROBE,image))
        for mutate in (lambda r:r.update(Image='sha256:'+'a'*64),lambda r:r.update(Mounts=[{'Destination':'/host'}]),
                       lambda r:r['HostConfig'].update(Privileged=True),lambda r:r['HostConfig'].update(NetworkMode='host'),
                       lambda r:r['HostConfig'].update(ReadonlyRootfs=False),lambda r:r['Config'].update(Cmd=['true'])):
            changed=deepcopy(info); mutate(changed)
            with self.assertRaises(ValueError):
                validate_container(changed,row,info['Name'][1:],self.run_id,'b1-before-d01',PROBE,image)

    def test_failed_before_stops_before_first_scanner(self):
        root=Path(self.tmp.name)/'early'; root.mkdir()
        runtime=FakeRuntime(root,self.run_id,self.controls,self.locks)
        with patch.object(runtime,'phase',side_effect=ValueError('essential failed control')), patch.object(controller,'execute_block') as scans:
            with self.assertRaisesRegex(ValueError,'essential'):
                controller.execute(self.plan,self.locks,root,self.run_id,[],runtime)
            scans.assert_not_called()
        self.assertEqual(json.loads((root/'blocks/b1.json').read_text())['status'],'failed')

    def test_failed_after_prevents_next_block(self):
        root=Path(self.tmp.name)/'after-failed'; root.mkdir(); calls=[]
        runtime=FakeRuntime(root,self.run_id,self.controls,self.locks)
        def phase(b,p):
            calls.append((b,p))
            if p=='after': raise ValueError('essential after control')
        with patch.object(runtime,'phase',side_effect=phase), patch.object(controller,'execute_block'):
            with self.assertRaises(ValueError):controller.execute(self.plan,self.locks,root,self.run_id,[],runtime)
        self.assertEqual(calls,[(1,'before'),(1,'after')])

    def test_interrupted_scanner_preserves_failed_block_without_claiming_after(self):
        root=Path(self.tmp.name)/'interrupted'; root.mkdir()
        runtime=FakeRuntime(root,self.run_id,self.controls,self.locks)
        with patch.object(runtime,'phase') as phase, patch.object(controller,'execute_block',side_effect=InterruptedError('stop')):
            with self.assertRaises(InterruptedError):controller.execute(self.plan,self.locks,root,self.run_id,[],runtime)
        phase.assert_called_once_with(1,'before')
        self.assertEqual(json.loads((root/'blocks/b1.json').read_text())['status'],'failed')


class RuntimeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.controls=load_controls(CONTROL_FILE)
        self.locks=json.loads(LOCK_FILE.read_text()); self.row=self.controls[0]
        self.runtime=RuntimeControls(self.root,'synthetic',self.controls,self.locks,[])
        self.image=json.loads((HISTORY/'assets-before/image_identities.json').read_text())[self.row['service']['image']]
        self.info=json.loads((HISTORY/'runtime-1/dser-04-runtime-1-d01.created.json').read_text())
        self.info.update(Name='/dsrt-synthetic-b1-before-d01',Id='a'*64)
        self.info['Config']['Labels'].update({'org.study.run':'synthetic','org.study.runtime':'b1-before-d01',
                                           'org.study.reset':'dsrt-synthetic-b1-before-d01'})
        self.raw=json.loads((HISTORY/'runtime-1/assertions.json').read_text())[0]['raw']
        self.exists=False;self.failure=None;self.calls=[]

    def capture(self, argv, **kw):
        if argv[1:3]==['ps','-a']:
            if '--format' in argv:return self.info['Name'][1:] if self.exists else ''
            return 'f'*64 + ('\n'+'a'*64 if self.exists else '')
        if argv[1]=='inspect':return json.dumps([self.info])
        raise AssertionError(argv)

    def command(self, directory, label, argv, allowed, **kw):
        self.calls.append(list(map(str,argv)))
        if label=='create':self.exists=True
        if label==self.failure:raise RuntimeError('synthetic '+label+' failure')
        if label=='probe':
            self.info['State'].update(Status='exited',Running=False,ExitCode=0,OOMKilled=False)
            return json.dumps(self.raw)
        if label=='remove':self.exists=False
        return ''

    def one(self):
        with patch('engineering.static_runtime_controls.host.capture',side_effect=self.capture), \
             patch.object(self.runtime,'command',side_effect=self.command), \
             patch('engineering.static_runtime_controls.subprocess.run',side_effect=lambda *a,**k:Mock(returncode=0 if self.exists else 1,stdout=json.dumps([self.info]))):
            return self.runtime.one(self.root/'D01',self.row,1,'before',self.image)

    def test_success_removes_only_the_owned_id(self):
        self.one(); self.assertFalse(self.exists)
        self.assertIn(['docker','rm','a'*64],self.calls)
        self.assertFalse(any('f'*64 in c for c in self.calls))

    def test_partially_failed_create_is_cleaned_and_retained_as_failure(self):
        self.failure='create'
        with self.assertRaisesRegex(RuntimeError,'create failure'):self.one()
        self.assertFalse(self.exists)
        r=json.loads((self.root/'D01/receipt.json').read_text())
        self.assertTrue(r['removed']);self.assertEqual(r['status'],'failed')

    def test_probe_failure_preserves_failure_and_cleans(self):
        self.failure='probe'
        with self.assertRaisesRegex(RuntimeError,'probe failure'):self.one()
        self.assertFalse(self.exists)
        self.assertEqual(json.loads((self.root/'D01/receipt.json').read_text())['status'],'failed')

    def test_cleanup_failure_never_produces_success(self):
        self.failure='remove'
        with self.assertRaisesRegex(RuntimeError,'remove failure'):self.one()
        self.assertTrue(self.exists)
        r=json.loads((self.root/'D01/receipt.json').read_text())
        self.assertFalse(r['removed']);self.assertEqual(r['status'],'failed');self.assertIn('cleanup_error',r)

    def test_foreign_labels_are_never_removed(self):
        self.info['Config']['Labels']['org.study.run']='other-project'
        with self.assertRaisesRegex(ValueError,'Refuse ownership'):self.one()
        self.assertFalse(any(c[1]=='rm' for c in self.calls))

    def test_command_interruption_retains_receipt(self):
        directory=self.root/'interrupted';directory.mkdir()
        with patch('engineering.static_runtime_controls.host.sample',side_effect=InterruptedError('host conflict')):
            with self.assertRaises(InterruptedError):
                self.runtime.command(directory,'probe',[sys.executable,'-c','import time; time.sleep(10)'],[],timeout=2)
        r=json.loads((directory/'probe.json').read_text())
        self.assertIsNotNone(r['returncode']);self.assertIn('host conflict',r['error'])


if __name__ == '__main__': unittest.main()
