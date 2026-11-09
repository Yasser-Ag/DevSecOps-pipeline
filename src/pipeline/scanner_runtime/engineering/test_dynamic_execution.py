"""Failure-sensitive contracts for dynamic execution; fixtures are synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from study.dynamic_execution_contract import (schedule, job, execution_plan, require_release,
                                               native_report, completion, sha)
from engineering.dynamic_execution_run import Controller, private_environment
from engineering.dynamic_job_wrapper import effective_environment


class DynamicExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, value):
        p = self.root / name; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value)); return p

    def release(self):
        self.write('package_manifest.json', {'files': []}); assets = self.write('assets.json', {'runtime': '<MASKED:fixture:127>'})
        return {'protocol_version': '1.0', 'final_ready': True,
                'gates': {'G' + str(i): 'passed' for i in range(1, 9)},
                'dynamic_execution': {'package_manifest_sha256': sha(self.root / 'package_manifest.json'),
                    'asset_locks_sha256': sha(assets), **{k: v for k, v in execution_plan().items() if k.endswith('_sha256')}}}, assets

    def test_schedule_has_five_matched_blocks(self):
        rows = schedule(); self.assertEqual(len(rows), 95); self.assertEqual(len({r['id'] for r in rows}), 95)
        for block in range(1, 6):
            members = [r for r in rows if r['block'] == block]
            self.assertEqual(sum(r['kind'] == 'scanner' for r in members), 18)
            self.assertEqual(sum(r['kind'] == 'target_generation' for r in members), 1)

    def test_unknown_job_rejected(self):
        with self.assertRaises(ValueError): job('historical-scan')

    def test_unreleased_protocol_rejected(self):
        release, assets = self.release(); release['protocol_version'] = '0.8'
        with self.assertRaises(ValueError): require_release(release, self.root, assets)

    def test_release_checks_all_bindings(self):
        release, assets = self.release(); self.assertTrue(require_release(release, self.root, assets))
        for field in ('schedule_sha256', 'profiles_sha256', 'generation_sha256', 'asset_locks_sha256', 'package_manifest_sha256'):
            changed = copy.deepcopy(release); changed['dynamic_execution'][field] = 'changed'
            with self.assertRaises(ValueError): require_release(changed, self.root, assets)
        release['gates']['G3'] = 'pending'
        with self.assertRaises(ValueError): require_release(release, self.root, assets)

    def test_missing_output_is_not_empty(self):
        for tool in ('nuclei', 'zap', 'schemathesis', 'restler'):
            with self.assertRaises((ValueError, FileNotFoundError)): native_report(tool, self.root)

    def test_existing_empty_nuclei_report_is_parseable(self):
        (self.root / 'nuclei.jsonl').touch()
        r = native_report('nuclei', self.root)
        self.assertEqual(r['native_unit_count'], 0)
        self.assertFalse(r['native_units_are_unique_vulnerabilities'])

    def test_malformed_nuclei_report_fails(self):
        (self.root / 'nuclei.jsonl').write_text('{}\n')
        with self.assertRaises(ValueError): native_report('nuclei', self.root)

    def test_zap_keeps_distinct_occurrences(self):
        self.write('zap.json', {'@programName': 'ZAP', 'site': [{'alerts': [{'pluginid': '1', 'instances':
            [{'uri': 'http://proxy:8080/a'}, {'uri': 'http://proxy:8080/b'}]}]}]})
        report = native_report('zap', self.root)
        self.assertEqual(report['native_unit_count'], 2)
        self.assertNotEqual(report['units'][0]['native_pointer'], report['units'][1]['native_pointer'])

    def schema_fixture(self):
        self.write('reports/json-fixture.json', {'complete': True, 'failures': [], 'errors': [], 'stop_reason': 'completed',
                    'operations': {'total': 3, 'selected': 3, 'tested': 3, 'errored': 0, 'skipped': 0}})
        self.write('reports/har-fixture.json', {'log': {'entries': []}})
        (self.root / 'reports/junit-fixture.xml').write_text('<testsuites/>')

    def test_incomplete_schemathesis_rejected(self):
        self.schema_fixture(); path = self.root / 'reports/json-fixture.json'
        raw = json.loads(path.read_text()); raw['complete'] = False; path.write_text(json.dumps(raw))
        with self.assertRaises(ValueError): native_report('schemathesis', self.root)

    def test_time_limited_schemathesis_preserves_limitation(self):
        self.schema_fixture(); path = self.root / 'reports/json-fixture.json'
        raw = json.loads(path.read_text()); raw['stop_reason'] = 'max_time'; path.write_text(json.dumps(raw))
        self.assertIn('native_stop_reason:max_time', native_report('schemathesis', self.root)['limitations'])

    def test_multiple_completion_reports_rejected(self):
        self.schema_fixture(); self.write('reports/json-duplicate.json', {})
        with self.assertRaises(ValueError): native_report('schemathesis', self.root)

    def test_empty_restler_requires_completion_summary(self):
        self.write('Test/RestlerResults/experiment1/logs/testing_summary.json',
                   {'total_requests_sent': {'main_driver': 3}, 'bug_buckets': {}, 'num_sequence_failures': 0})
        self.assertEqual(native_report('restler', self.root)['native_unit_count'], 0)

    def completed(self, trace=None, **kwargs):
        process = kwargs.get('process', {'returncode': 0, 'accounting': {'elapsed_seconds': 1}})
        parsed = kwargs.get('parsed', {'parsed': True, 'limitations': [], 'native_unit_count': 0})
        if trace is None: trace = [{'method': 'GET', 'path': '/ok', 'forwarded': True}]
        return completion('crapi-nuclei-valid-a', process, parsed, trace, [('GET', '/ok')])

    def test_missing_request_trace_fails(self): self.assertEqual(self.completed([])['status'], 'failed')

    def test_only_gate_responses_fail_reach(self):
        r = self.completed([{'method': 'GET', 'path': '/ok', 'forwarded': False, 'gate_reason': 'scope'}])
        self.assertEqual(r['status'], 'failed'); self.assertFalse(r['negative_security_result'])

    def test_partial_reach_does_not_pass(self):
        r = self.completed([{'method': 'GET', 'path': '/other', 'forwarded': True}])
        self.assertEqual(r['status'], 'completed_with_limitations'); self.assertEqual(r['missing_operations'], [('GET', '/ok')])

    def test_transport_errors_cannot_be_zero_detections(self):
        self.assertEqual(self.completed([{'method': 'GET', 'path': '/ok', 'forwarded': True, 'harness_error': 'timeout'}])['status'], 'failed')

    def test_failed_process_keeps_partial_report_but_fails(self):
        r = self.completed(process={'returncode': 137, 'accounting': None})
        self.assertEqual(r['status'], 'failed'); self.assertTrue(r['native_report']['parsed'])

    def test_missing_accounting_is_explicit(self):
        r = self.completed(process={'returncode': 0, 'accounting': None})
        self.assertEqual(r['status'], 'completed_with_limitations')

    def test_wrapper_preserves_nonzero_exit_and_counters(self):
        out = self.root / 'accounting.json'
        spec = self.write('spec.json', {'argv': [sys.executable, '-c', 'raise SystemExit(7)'], 'cwd': str(self.root),
                  'environment': private_environment(self.root), 'accounting_path': str(out), 'container': False})
        wrapper = Path(__file__).with_name('dynamic_job_wrapper.py')
        p = subprocess.run([sys.executable, '-B', str(wrapper), str(spec)], capture_output=True)
        self.assertEqual(p.returncode, 7); raw = json.loads(out.read_text())
        self.assertEqual(raw['returncode'], 7); self.assertGreater(raw['elapsed_seconds'], 0)
        self.assertIsNone(raw['cgroup_after'])

    def test_container_runtime_flags_preserved_without_host_proxy(self):
        inherited = {'PATH': '/venv/bin:/bin', 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT': 'true',
                     'JAVA_HOME': '/jvm', 'ZAP_PATH': '/zap/zap.sh', 'HTTP_PROXY': 'unowned', 'HOME': '/old'}
        spec = {'container': True, 'environment': {'HOME': '/work/home'}}
        result = effective_environment(spec, inherited)
        self.assertEqual(result['DOTNET_SYSTEM_GLOBALIZATION_INVARIANT'], 'true')
        self.assertEqual(result['ZAP_PATH'], '/zap/zap.sh'); self.assertNotIn('HTTP_PROXY', result)
        self.assertEqual(result['HOME'], '/work/home')
        spec['container'] = False
        self.assertNotIn('JAVA_HOME', effective_environment(spec, inherited))

    def test_model_load_failure_does_not_count_four_requests(self):
        controller = Controller.__new__(Controller)
        controller.result = {'target_generation_requests': 0}
        controller.save = lambda: None
        def failed(*args, **kwargs): raise ValueError('Synthetic model load failure')
        controller.run = failed
        with self.assertRaises(ValueError): controller.generate('owned-fixture', self.root)
        self.assertEqual(controller.result['planned_target_generation_requests'], 4)
        self.assertEqual(controller.result['target_generation_requests'], 0)
        self.write('generation.json', [{'id': 'first', 'status': 'running'}])
        with self.assertRaises(ValueError): controller.generate('owned-fixture', self.root)
        self.assertEqual(controller.result['target_generation_requests'], 1)

    def test_container_contract_rejects_other_project_mount(self):
        mounts = ['/owned:/work:rw', '/package:/study:ro']
        item = {'HostConfig': {'PortBindings': {}, 'Privileged': False, 'ReadonlyRootfs': True,
            'NetworkMode': 'scanner', 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
            'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3, 'NanoCpus': 2 * 10**9, 'PidsLimit': 256},
            'Mounts': [{'Type': 'bind', 'Source': '/owned', 'Destination': '/work', 'RW': True},
                       {'Type': 'bind', 'Source': '/package', 'Destination': '/study', 'RW': False}]}
        Controller.validate_container(item, mounts, 'scanner', 'restler')
        item['Mounts'].append({'Type': 'bind', 'Source': '<OTHER_PROJECT_2>', 'Destination': '/foreign', 'RW': False})
        with self.assertRaises(ValueError): Controller.validate_container(item, mounts, 'scanner', 'restler')


if __name__ == '__main__': unittest.main()
