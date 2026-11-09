"""Receipt-to-analysis boundary tests using explicitly synthetic local records."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from study.final_output_adapter import digest
from study.final_output_ingress import collect_static, collect_dynamic, Evidence, reference_passed, verify_runtime_support
from study.static_scan_contract import schedule, sha
from study.dynamic_execution_contract import native_report


class IngressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        p = {'id': 'secret-gitleaks', 'suite': 'secret', 'kind': 'native', 'role': 'detector',
             'parser': 'gitleaks', 'report': 'report.json', 'argv': ['/fake/scanner'], 'historical_command': ['/fake/scanner'],
             'accepted_exit_codes': [0], 'timeout_seconds': 5, 'requires': [], 'scratch_gib': 0, 'redacted_secrets': False}
        self.plan = {'schema': 'static-scan-plan-1', 'repetitions': 5, 'measurement_reuse': False,
                     'study_model_generations': 0, 'suites': {'secret': {'inputs': []}}, 'profiles': [p]}
        self.put('asset_locks.json', {'inputs': {'secret': []}})
        self.contract = {'profile_ids': ['secret-gitleaks'], 'schedule_digest': digest(schedule(self.plan)),
                         'asset_locks_sha256': sha(self.root/'asset_locks.json'), 'package_manifest_sha256': 'a'*64}
        self.put('summary.json', {'mode': 'execute', 'assets_preserved': True, 'package_manifest_sha256': 'a'*64})
        self.put('work/b1-secret/report.json', [])
        before = {'suite': 'secret', 'fresh_destination': '<LAB_ROOT>/evidence/synthetic/work/b1-secret', 'verified': True}
        self.put('resets/b1-secret.json', before)
        self.put('resets/b1-secret-after.json', {**before, 'verified_after': True})
        self.put('jobs/b1-secret-gitleaks/prepared.json', {
            'reset_sha256': sha(self.root/'resets/b1-secret.json'), 'report': before['fresh_destination']+'/report.json'})
        self.put('jobs/b1-secret-gitleaks/receipt.json', {'status': 'completed'})
        self.outcome = {'job_id': 'b1-secret-gitleaks', 'profile': 'secret-gitleaks', 'block': 1,
                        'status': 'completed', 'effective_status': 'completed', 'native_findings': 0,
                        'raw_sha256': sha(self.root/'work/b1-secret/report.json')}
        self.put('outcomes.json', [self.outcome])

    def put(self, name, value):
        path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True)+'\n')

    def collect(self): return collect_static(self.root, self.plan, [], self.contract)

    def test_valid_empty_report_distinct_from_four_missing_jobs(self):
        result = self.collect()
        self.assertEqual(result['scheduled'], 5)
        self.assertEqual(result['jobs_with_qualified_measurement'], 1)
        self.assertEqual(result['jobs'][0]['detector_count'], 0)
        self.assertTrue(all(r['native_count'] is None for r in result['jobs'][1:]))

    def test_changed_raw_report_is_unavailable(self):
        self.put('work/b1-secret/report.json', {'tampered': True})
        result = self.collect()['jobs'][0]
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['native_count'])

    def test_unverified_after_state_cannot_award_zero(self):
        after = json.loads((self.root/'resets/b1-secret-after.json').read_text()); after['verified_after'] = False
        self.put('resets/b1-secret-after.json', after)
        result = self.collect()['jobs'][0]
        self.assertFalse(result['measurement_eligible'])
        self.assertIsNone(result['detector_count'])

    def test_asset_identity_mismatch_retains_unscored_record(self):
        self.contract['asset_locks_sha256'] = 'b'*64
        result = self.collect()['jobs'][0]
        self.assertFalse(result['measurement_eligible'])
        self.assertIsNone(result['detector_count'])

    def test_duplicate_outcome_rejected(self):
        self.put('outcomes.json', [self.outcome, self.outcome])
        with self.assertRaisesRegex(ValueError, 'Duplicate static outcome'):
            self.collect()

    def test_path_escape_rejected(self):
        with self.assertRaises(ValueError): Evidence(self.root).path('../other-project')

    def test_partial_reference_matrix_rejected(self):
        self.assertFalse(reference_passed({'controls': [{'id':'one','passed': True}]}, 'crapi'))

    def test_duplicate_reference_controls_rejected(self):
        self.assertFalse(reference_passed({'controls': [{'id':'one','passed': True}]*11}, 'crapi'))

    def test_aigoat_ownership_drift_rejected(self):
        value = {'controls': [{'id':str(i),'passed':True} for i in range(13)], 'ownership_unchanged':False}
        self.assertFalse(reference_passed(value, 'aigoat'))

    def test_same_size_wrong_reference_universe_rejected(self):
        self.assertFalse(reference_passed({'controls':[{'id':str(i),'passed':True} for i in range(11)]}, 'crapi'))

    def test_runtime_pass_flag_does_not_override_raw_probe(self):
        controls = [{'case_id': str(i), 'property': 'runtime_uid_zero', 'positive': True} for i in range(12)]
        rows = [{'case_id':str(i), 'property':'runtime_uid_zero', 'expected':True, 'observed':True, 'passed':True,
                 'raw':{'uid':0, 'cap_eff':'0000000000000000'}} for i in range(12)]
        self.assertTrue(verify_runtime_support(controls, rows, rows))
        changed = copy.deepcopy(rows); changed[0]['raw']['uid'] = 1000
        with self.assertRaisesRegex(ValueError, 'assertion differs'):
            verify_runtime_support(controls, rows, changed)


class DynamicIngressTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.job={'id':'b01-aigoat-nuclei-invalid','block':1,'profile_id':'aigoat-nuclei-invalid','kind':'scanner',
                  'reset':'fresh target state before this job'}
        self.put('protocol_release.json',{'synthetic':True})
        self.put('asset_locks.json',{'synthetic':True})
        self.put('assets-before/package_verification.json',{'files':[]})
        self.put('assets-after/package_verification.json',{'files':[]})
        self.contract={'job':self.job,'release_sha256':sha(self.root/'protocol_release.json'),
                       'asset_locks_sha256':sha(self.root/'asset_locks.json'),
                       'package_manifest_sha256':sha(self.root/'assets-before/package_verification.json')}
        self.put('summary.json',{'job':self.job,'mode':'execute','success':True,
                 'protocol_release_sha256':self.contract['release_sha256'],
                 'released_asset_locks_sha256':self.contract['asset_locks_sha256']})
        self.put('target/fixtures/private_fixture.json',{'actors':{'alice':{},'bob':{}},
                 'documents':{'alice':{'id':1},'bob':{'id':2}}})
        ids={o+'-document-'+a+'-L'+str(l) for o in ('alice','bob') for a in ('alice','bob') for l in (0,2)}
        ids|={a+'-'+m for a in ('absent','invalid') for m in ('GET','POST')}|{'public-products'}
        matrix={'controls':[{'id':i,'passed':True} for i in sorted(ids)],'ownership_unchanged':True}
        self.put('target/fixtures/before.json',matrix);self.put('target/fixtures/after.json',matrix)
        self.put('target/scanner/openapi.json',{'servers':[{'url':'http://proxy:8080'}]})
        native={'template-id':'http-missing-security-headers','matcher-name':'x-content-type-options',
                'matched-at':'http://proxy:8080/api/knowledge-base/','info':{'name':'header','severity':'info'},
                'request':'GET /api/knowledge-base/ HTTP/1.1\r\nHost: proxy:8080\r\n\r\n'}
        self.lines('target/scanner/nuclei.jsonl',[native])
        self.put('target/outcome.json',{'status':'completed','native_report':native_report('nuclei',self.root/'target/scanner')})
        self.trace=[{'phase':p,'sequence':i,'forwarded':True,'method':'GET','path':'/api/knowledge-base/',
                    'auth_role':'invalid','status':401,'response_headers':[],'response_sha256':'a'*64}
                    for i,p in enumerate(('before','scanner','after'))]
        self.lines('target/proxy-logs/requests.jsonl',self.trace)
        self.put('target/scanner_trace.json',[self.trace[1]])
        self.refs=[{'case_id':'http-ref','population':'aigoat-http-properties','truth':'positive',
                    'details':{'coordinate':{'resource':'GET /api/knowledge-base/','context':'invalid',
                                              'property':'missing_header:x-content-type-options'}}}]

    def put(self,name,value):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value,sort_keys=True)+'\n')

    def lines(self,name,value):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(''.join(json.dumps(r)+'\n' for r in value))

    def collect(self): return collect_dynamic(self.root,self.contract,self.refs)

    def test_complete_receipts_bind_property_without_assigning_native_truth(self):
        r=self.collect();self.assertTrue(r['measurement_eligible'],r)
        self.assertEqual(len(r['links']),1)
        self.assertEqual(r['observations'][0]['scoped_native_label'],'unresolved')

    def test_changed_native_report_is_not_accepted_under_old_receipt(self):
        self.lines('target/scanner/nuclei.jsonl',[])
        r=self.collect();self.assertFalse(r['measurement_eligible']);self.assertEqual(r['links'],[])

    def test_partial_reference_withholds_links(self):
        self.put('target/fixtures/after.json',{'controls':[],'ownership_unchanged':True})
        r=self.collect();self.assertEqual(r['native_count'],1);self.assertFalse(r['measurement_eligible']);self.assertEqual(r['links'],[])

    def test_execution_package_drift_withholds_measurement(self):
        self.put('assets-after/package_verification.json',{'files':['changed']})
        r=self.collect();self.assertFalse(r['measurement_eligible']);self.assertEqual(r['links'],[])

    def test_full_and_filtered_trace_disagreement_is_not_silently_ignored(self):
        self.trace[1]['auth_role']='alice';self.lines('target/proxy-logs/requests.jsonl',self.trace)
        r=self.collect();self.assertFalse(r['measurement_eligible']);self.assertIn('trace differs',r['reason'])

    def test_unsuccessful_job_cannot_contribute_scientific_links(self):
        p=self.root/'summary.json';data=json.loads(p.read_text());data['success']=False;self.put('summary.json',data)
        r=self.collect();self.assertEqual(r['native_count'],1);self.assertFalse(r['measurement_eligible']);self.assertEqual(r['links'],[])


if __name__ == '__main__': unittest.main()
