"""Boundary and data-integrity tests for static repetitions; no scanner is launched."""
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study.static_scan_contract import validate, schedule, render, normalize, sha
from engineering.static_scanner_host import inventory, prepare_inputs, verify_inputs, assert_lease, preserved
from engineering.static_scanner_run import scanner_environment, container_argv, validate_container, require_release, execute
from engineering.static_scanner_assets import private_database_bound

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / 'plan.json'
if not PLAN_PATH.exists():
    PLAN_PATH = ROOT / 'evidence/static_scanner_controller_2026-10-22/candidate-v5/plan.json'


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads(PLAN_PATH.read_text())

    def test_all_receipts_have_one_disposition(self):
        retained = [p['historical_receipt']['path'] for p in self.plan['profiles']]
        self.assertEqual(len(retained), len(set(retained)))
        self.assertEqual(len(retained) + len(self.plan['receipt_dispositions']), 205)
        self.assertEqual(len(retained), 75)

    def test_exact_schedule_and_current_block_dependencies(self):
        jobs = schedule(self.plan)
        self.assertEqual(len(jobs), 375)
        done = set()
        for job in jobs:
            self.assertTrue(set(job['requires']) <= done)
            self.assertTrue(all(d.startswith(f"b{job['block']}-") for d in job['requires']))
            done.add(job['job_id'])
        self.assertEqual(len(done), 375)

    def test_measurement_reuse_rejected(self):
        self.plan['measurement_reuse'] = True
        with self.assertRaises(ValueError): validate(self.plan)

    def test_historical_output_rejected(self):
        self.plan['profiles'][0]['argv'].append('<LAB_ROOT>/evidence/old/output.json')
        with self.assertRaises(ValueError): validate(self.plan)

    def test_parent_traversal_rejected(self):
        self.plan['profiles'][0]['report'] = '../another-project/file'
        with self.assertRaises(ValueError): validate(self.plan)

    def test_cycle_rejected(self):
        self.plan['profiles'][0]['requires'] = [self.plan['profiles'][1]['id']]
        self.plan['profiles'][1]['requires'] = [self.plan['profiles'][0]['id']]
        with self.assertRaises(ValueError): validate(self.plan)

    def test_duplicate_profile_rejected(self):
        self.plan['profiles'].append(copy.deepcopy(self.plan['profiles'][0]))
        with self.assertRaises(ValueError): validate(self.plan)

    def test_mutable_image_rejected(self):
        next(p for p in self.plan['profiles'] if p['kind'] == 'container')['image'] = 'kics:latest'
        with self.assertRaises(ValueError): validate(self.plan)

    def test_output_parent_alias_rejected(self):
        next(p for p in self.plan['profiles'] if p['kind'] == 'container')['output_directory'] = '.'
        with self.assertRaises(ValueError): validate(self.plan)

    def test_inventory_does_not_become_security_detector(self):
        self.assertTrue(all(p['role'] == 'inventory' for p in self.plan['profiles'] if p['parser'] == 'syft'))

    def test_render_has_fresh_absolute_roots(self):
        for p in self.plan['profiles']:
            values = render(p, Path('/new/block/suite'), Path('/new/job'))
            self.assertFalse(any('{WORK}' in v or '{PHASE}' in v for v in values))

    def test_unqualified_workflow_selector_not_repeated(self):
        self.assertNotIn('aigoat-checkov-workflow', {p['id'] for p in self.plan['profiles']})
        self.assertIn('aigoat-workflow-checkov-workflow-qualified', {p['id'] for p in self.plan['profiles']})

    def test_disk_bound_excludes_readonly_database_snapshots(self):
        sizes = {'trivy-db': 1400, 'trivy-java': 1500, 'grype': 2200, 'dependency-check': 250}
        self.assertEqual(private_database_bound(self.plan, sizes), 250)
        for profile in self.plan['profiles']:
            if profile['parser'] == 'trivy':
                self.assertIn('--cache-backend', profile['argv'])
                self.assertEqual(profile['argv'][profile['argv'].index('--cache-backend') + 1], 'memory')


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'; self.source.mkdir()
        (self.source / 'Dockerfile').write_text('FROM scratch\n')
        self.locked = [{'source': str(self.source), 'destination': 'inputs', 'files': inventory(self.source)}]

    def test_two_resets_have_identical_bytes_and_distinct_locations(self):
        for name in ('first', 'second'):
            record = prepare_inputs('test', self.locked, self.root / name)
            self.assertFalse(record['prior_reports_copied'])
            verify_inputs(self.locked, self.root / name)
        self.assertEqual(inventory(self.root / 'first/inputs'), inventory(self.root / 'second/inputs'))

    def test_existing_output_refused(self):
        target = self.root / 'existing'; target.mkdir()
        with self.assertRaises(ValueError): prepare_inputs('test', self.locked, target)

    def test_source_byte_drift_refused(self):
        (self.source / 'Dockerfile').write_text('FROM altered\n')
        with self.assertRaises(ValueError): prepare_inputs('test', self.locked, self.root / 'new')

    def test_input_links_refused(self):
        (self.source / 'link').symlink_to(self.source / 'Dockerfile')
        with self.assertRaises(ValueError): inventory(self.source)

    def test_extra_prepared_file_detected(self):
        dest = self.root / 'new'; prepare_inputs('test', self.locked, dest)
        (dest / 'inputs/unexpected').write_text('extra')
        with self.assertRaises(ValueError): verify_inputs(self.locked, dest)

    def test_lease_must_actually_be_held(self):
        path = self.root / 'lease'; path.write_text('')
        with path.open('r+') as handle:
            with self.assertRaises(ValueError): assert_lease(path)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn(handle.fileno(), assert_lease(path))


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        plan = json.loads(PLAN_PATH.read_text())
        self.p = next(p for p in plan['profiles'] if p['kind'] == 'container')
        self.work = Path('/owned/suite')
        r = self.p['container_resources']
        self.info = {'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
            'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'], 'Memory': r['memory_gib'] * 1024**3,
            'MemorySwap': r['memory_gib'] * 1024**3, 'NanoCpus': r['cpus'] * 10**9, 'PidsLimit': r['pids']},
            'Config': {'User': f'{os.getuid()}:{os.getgid()}',
                       'Labels': {'org.study.project': 'devsecops-electronics', 'org.study.run': 'run'}},
            'Mounts': [{'Source': str(self.work / self.p['input_directory']), 'Destination': '/input', 'RW': False, 'Type': 'bind'},
                       {'Source': str(self.work / self.p['output_directory']), 'Destination': '/output', 'RW': True, 'Type': 'bind'}]}

    def test_actual_container_contract(self):
        validate_container(self.info, self.p, self.work, 'run')
        command = container_argv(self.p, self.work, 'run', 'owned', preflight=True)
        self.assertEqual(command[-2:], ['/bin/true', self.p['image']])
        self.assertNotIn('scan', command)

    def test_extra_socket_mount_refused(self):
        self.info['Mounts'].append({'Source': '/var/run/docker.sock', 'Destination': '/socket', 'RW': True, 'Type': 'bind'})
        with self.assertRaises(ValueError): validate_container(self.info, self.p, self.work, 'run')

    def test_wrong_source_mount_refused(self):
        self.info['Mounts'][0]['Source'] = '/other-project'
        with self.assertRaises(ValueError): validate_container(self.info, self.p, self.work, 'run')

    def test_published_port_refused(self):
        self.info['HostConfig']['PortBindings'] = {'8000/tcp': [{'HostPort': '8000'}]}
        with self.assertRaises(ValueError): validate_container(self.info, self.p, self.work, 'run')

    def test_environment_excludes_credentials(self):
        with patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY': '<MASKED:fixture:127>', 'GH_TOKEN': '<MASKED:fixture:127>', 'HTTP_PROXY': '<MASKED:fixture:127>'}):
            env = scanner_environment(Path('/owned/phase'))
        self.assertFalse({'AWS_SECRET_ACCESS_KEY', 'GH_TOKEN', 'HTTP_PROXY'} & env.keys())
        self.assertEqual(env['GRYPE_DB_AUTO_UPDATE'], 'false')

    def test_historical_container_mutation_detected(self):
        before = {'container_config_hashes': {'old': 'hash'}, 'images': ['image'], 'volumes': [], 'networks': [],
                  'registry_sha256': 'registry', 'other_project_paths': {}, 'active_containers': []}
        after = copy.deepcopy(before); after['container_config_hashes']['new'] = 'new'
        self.assertTrue(preserved(before, after))
        after['container_config_hashes']['old'] = 'changed'
        self.assertFalse(preserved(before, after))

    def test_missing_release_blocks_scientific_execution(self):
        with self.assertRaises(ValueError): require_release(None, ROOT, Path('/missing'), {})


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'report.json'

    def test_absent_report_is_not_zero_findings(self):
        with self.assertRaises(FileNotFoundError): normalize(self.path, 'hadolint', 'completed')

    def test_invalid_json_is_not_zero_findings(self):
        self.path.write_text('{broken')
        with self.assertRaises(ValueError): normalize(self.path, 'hadolint', 'completed')

    def test_empty_valid_report_and_failed_process_stay_distinct(self):
        self.path.write_text('[]')
        self.assertEqual(normalize(self.path, 'hadolint', 'completed')['effective_status'], 'completed')
        self.assertEqual(normalize(self.path, 'hadolint', 'failed')['effective_status'], 'failed')

    def test_redacted_secret_has_no_material_hash(self):
        self.path.write_text(json.dumps([{'RuleID': '<MASKED:fixture:127>', 'File': 'config', 'Secret': 'REDACTED'}]))
        finding = normalize(self.path, 'gitleaks', 'completed', redacted_secrets=True)['findings'][0]
        self.assertIsNone(finding['reported_secret_sha256'])
        self.assertTrue(finding['secret_redacted'])


class RepetitionIntegrationTests(unittest.TestCase):
    def test_five_fresh_resets_and_one_malformed_report_remain_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / 'source'; source.mkdir()
            (source / 'Dockerfile').write_text('FROM scratch\n')
            locked = [{'source': str(source), 'destination': 'inputs', 'files': inventory(source)}]
            plan = {'repetitions': 5, 'suites': {'<MASKED:fixture:127>': {}}, 'profiles': [{
                'id': 'fixture-hadolint', 'suite': '<MASKED:fixture:127>', 'kind': 'native', 'requires': [],
                'parser': 'hadolint', 'role': 'detector', 'argv': ['/qualified/hadolint', '{WORK}/inputs/Dockerfile'],
                'report': 'hadolint.stdout', 'accepted_exit_codes': [0], 'timeout_seconds': 10,
                'scratch_gib': 0, 'redacted_secrets': False}]}
            locks = {'inputs': {'<MASKED:fixture:127>': locked}, 'runtime': [], 'databases': {}}
            observed = []
            def fake_measure(argv, phase, *args):
                self.assertFalse((phase / 'receipt.json').exists())
                self.assertEqual(Path(argv[1]).read_text(), 'FROM scratch\n')
                observed.append(phase)
                (phase / 'stdout').write_text('{broken' if len(observed) == 3 else '[]')
                return {'status': 'completed'}
            output = root / 'output'; output.mkdir()
            with patch('engineering.static_scanner_run.sample', return_value={}), \
                    patch('engineering.static_scanner_run.isolated_command', side_effect=lambda argv, *a: argv), \
                    patch('engineering.static_scanner_run.measured', side_effect=fake_measure):
                result = execute(plan, locks, output, '<MASKED:fixture:127>', [])
            self.assertEqual(len(set(observed)), 5)
            self.assertEqual(result['scanner_invocations'], 5)
            self.assertEqual(result['completed_reports'], 4)
            self.assertFalse(result['all_profiles_have_usable_reports'])
            outcomes = json.loads((output / 'outcomes.json').read_text())
            self.assertEqual(outcomes[2]['effective_status'], 'unusable_report')
            self.assertIsNone(outcomes[2]['native_findings'])
            for block in range(1, 6):
                prepared = json.loads((output / 'jobs' / f'b{block}-fixture-hadolint/prepared.json').read_text())
                self.assertEqual(prepared['reset_sha256'], sha(output / 'resets' / f'b{block}-fixture.json'))
                self.assertFalse((output / 'work' / f'b{block}-fixture/inputs').exists())
            self.assertEqual((source / 'Dockerfile').read_text(), 'FROM scratch\n')


if __name__ == '__main__':
    unittest.main()
