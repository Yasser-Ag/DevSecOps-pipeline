"""Source drift, identity, scope and execution-order regressions; no scanners."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study.final_output_adapter import (adapt_static, catalog_entries, digest, fixture_identity,
    generation_observations, historical_work_roots, logical_route, request_coordinate, static_rows)
from study.static_scan_contract import schedule


class StaticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raw = Path(self.tmp.name) / 'old.json'
        self.data = [dict(code='DL3002', file='<LAB_ROOT>/evidence/old/docker/d02/Dockerfile',
                          line=2, column=1, message='Last USER is root', level='warning'),
                     dict(code='DL3002', file='<LAB_ROOT>/evidence/old/docker/d04/Dockerfile',
                          line=5, column=1, message='Last USER is root', level='warning')]
        self.raw.write_text(json.dumps(self.data))
        self.profile = dict(id='configuration-hadolint', parser='hadolint', redacted_secrets=False,
                            role='detector', argv=['/bin/scanner', '{WORK}/docker'],
                            historical_command=['/bin/scanner', '<LAB_ROOT>/evidence/old/docker'])
        parsed = static_rows(self.raw, self.profile)
        old = [dict(finding_id='old-' + str(i), raw_report_sha256=parsed['raw_report_sha256'],
                    native_locator='/' + str(i), population='docker', native_label='unresolved',
                    evidence=[{'path': 'source', 'sha256': 'b'*64}]) for i in range(2)]
        links = [dict(finding_id='old-' + str(i), case_id='case-' + str(i), relation='supports', scope='runtime projection')
                 for i in range(2)]
        self.catalog = catalog_entries(self.profile, parsed, old, links)
        self.context = dict(job_id='b1-configuration-hadolint', block=1,
                            work_root='<LAB_ROOT>/evidence/new/work',
                            input_contract_sha256='a'*64, observed_input_sha256='a'*64,
                            inputs_verified_before=True, inputs_verified_after=True, asset_lock_verified=True,
                            runtime_reference_verified=True, process_status='completed', origin='synthetic_test')

    def fresh(self, transform=None):
        rows = copy.deepcopy(self.data)
        for r in rows:
            r['file'] = r['file'].replace('<LAB_ROOT>/evidence/old', self.context['work_root'])
        if transform:
            rows = transform(rows)
        p = Path(self.tmp.name) / 'new.json'; p.write_text(json.dumps(rows)); return p

    def adapt(self, transform=None):
        return adapt_static(self.fresh(transform), self.profile, self.context, self.catalog)

    def test_reordering_uses_semantics_not_raw_index(self):
        result = self.adapt(lambda rows: list(reversed(rows)))
        self.assertEqual(result['bound_assertions'], 2)
        self.assertEqual(result['observations'][0]['historical_witness_ids'], ['old-1'])
        self.assertEqual(result['links'][0]['case_id'], 'case-1')
        self.assertNotEqual(result['observations'][0]['finding_id'], 'old-1')

    def test_changed_rule_is_not_a_label_match(self):
        def change(rows): rows[0]['code'] = 'DL9999'; return rows
        self.assertEqual(self.adapt(change)['bound_assertions'], 1)

    def test_changed_location_is_not_a_label_match(self):
        def change(rows): rows[0]['line'] = 3; return rows
        self.assertEqual(self.adapt(change)['bound_assertions'], 1)

    def test_changed_claim_is_not_a_label_match(self):
        def change(rows): rows[0]['message'] = 'A different assertion'; return rows
        self.assertEqual(self.adapt(change)['bound_assertions'], 1)

    def test_source_drift_blocks_all_scoring(self):
        self.context['observed_input_sha256'] = 'c'*64
        result = self.adapt()
        self.assertFalse(result['measurement_eligible'])
        self.assertEqual(result['bound_assertions'], 0)
        self.assertIsNone(result['detector_count'])
        self.assertEqual(len(result['observations']), 2)

    def test_asset_drift_blocks_label_reuse(self):
        self.context['asset_lock_verified'] = False
        self.assertEqual(self.adapt()['bound_assertions'], 0)

    def test_failed_execution_is_not_zero(self):
        self.context['process_status'] = 'failed'
        result = self.adapt()
        self.assertEqual(result['native_count'], 2)
        self.assertIsNone(result['detector_count'])
        self.assertEqual(result['bound_assertions'], 0)

    def test_missing_report_is_not_empty(self):
        with self.assertRaises(FileNotFoundError):
            adapt_static(Path(self.tmp.name) / 'absent.json', self.profile, self.context, self.catalog)

    def test_runtime_projection_requires_fresh_reference(self):
        self.context['runtime_reference_verified'] = False
        result = self.adapt()
        self.assertEqual(result['links'], [])
        self.assertTrue(all(r['binding_status'] == 'runtime_reference_pending' for r in result['observations']))

    def test_conflicting_interpretations_abstain(self):
        row = copy.deepcopy(self.catalog[0]); row['links'][0]['case_id'] = 'different-instance'
        self.catalog.append(row)
        result = self.adapt()
        self.assertEqual(result['observations'][0]['binding_status'], 'ambiguous_interpretation')
        self.assertEqual(result['bound_assertions'], 1)

    def test_identical_duplicates_remain_two_native_records(self):
        result = self.adapt(lambda rows: [rows[0], rows[0]])
        self.assertEqual(result['native_count'], 2)
        self.assertEqual(len({r['finding_id'] for r in result['observations']}), 2)
        self.assertEqual(len({e['case_id'] for e in result['links']}), 1)

    def test_cross_profile_catalog_is_rejected(self):
        self.catalog[0]['profile_id'] = 'another-scanner'
        with self.assertRaisesRegex(ValueError, 'Cross-profile'):
            self.adapt()

    def test_replay_does_not_claim_new_measurements(self):
        self.context['origin'] = 'historical_replay'
        self.assertFalse(self.adapt()['new_scientific_measurement'])

    def test_multi_root_classpath_alias(self):
        p = {'argv': ['/bin/jvm', '{WORK}/built:{WORK}/dependencies'],
             'historical_command': ['/bin/jvm', '<LAB_ROOT>/evidence/run/built:<LAB_ROOT>/evidence/run/dependencies']}
        self.assertEqual(historical_work_roots(p), ['<LAB_ROOT>/evidence/run'])

    def test_unrelated_path_prefix_is_preserved(self):
        def change(rows): rows[0]['file'] = rows[0]['file'].replace('/work/', '/work-other/'); return rows
        self.assertEqual(self.adapt(change)['bound_assertions'], 1)


class DynamicTests(unittest.TestCase):
    def setUp(self):
        source = {'a': {'email': 'a@lab', 'vehicles': [{'uuid': 'fresh-a'}]},
                  'b': {'email': 'b@lab', 'vehicles': [{'uuid': 'fresh-b'}]}}
        self.fixture = fixture_identity('crapi', source, ['http://proxy:8080'])
        self.path = '/identity/api/v2/vehicle/fresh-a/location'
        self.native = {'url': 'http://proxy:8080' + self.path, 'method': 'GET'}
        self.trace = [{'forwarded': True, 'method': 'GET', 'path': self.path, 'auth_role': 'b', 'status': 200, 'sequence': 1}]

    def test_fresh_uuid_binds_to_owner_not_old_value(self):
        result = request_coordinate(self.native, self.trace, self.fixture)
        self.assertEqual(result['path'], '/identity/api/v2/vehicle/{owner:a}/location')
        self.assertEqual(result['actor'], 'b')

    def test_ambiguous_authentication_does_not_use_profile_role(self):
        self.trace.append({**self.trace[0], 'auth_role': 'absent', 'status': 401, 'sequence': 2})
        self.assertEqual(request_coordinate(self.native, self.trace, self.fixture)['status'], 'unresolved')

    def test_gated_response_does_not_become_forwarded_evidence(self):
        self.trace[0]['forwarded'] = False
        self.assertEqual(request_coordinate(self.native, self.trace, self.fixture)['status'], 'unresolved')

    def test_foreign_authority_not_equated_to_owned_route(self):
        self.native['url'] = 'http://other.example' + self.path
        self.assertEqual(request_coordinate(self.native, self.trace, self.fixture)['status'], 'unresolved')

    def test_query_is_part_of_request_identity(self):
        self.native['url'] += '?mode=admin'
        self.assertEqual(request_coordinate(self.native, self.trace, self.fixture)['status'], 'unresolved')

    def test_conflicting_native_method_rejected(self):
        self.native['request'] = 'POST ' + self.path + ' HTTP/1.1\r\n\r\n'
        with self.assertRaisesRegex(ValueError, 'Contradictory'):
            request_coordinate(self.native, self.trace, self.fixture)

    def test_absent_trace_is_unknown(self):
        self.assertEqual(request_coordinate(self.native, [], self.fixture)['status'], 'unresolved')

    def test_actors_cannot_share_object(self):
        with self.assertRaises(ValueError):
            fixture_identity('crapi', {'a': {'email': 'a', 'vehicles': [{'uuid': 'same'}]},
                                       'b': {'email': 'b', 'vehicles': [{'uuid': 'same'}]}})

    def test_missing_generation_requests_stay_missing(self):
        fixture = fixture_identity('aigoat', {'actors': {'alice': {}, 'bob': {}},
                                  'documents': {'alice': {'id': 11}, 'bob': {'id': 27}}})
        result = generation_observations([{'id': 'a', 'status': 'running'}], ['a', 'b', 'c', 'd'], fixture)
        self.assertEqual(sum(r['attempted'] for r in result), 1)
        self.assertIsNone(result[1]['marker_emitted'])
        self.assertIsNone(result[0]['non_fallback_reply'])


class ExecutionOrderTests(unittest.TestCase):
    def test_actual_execute_loop_matches_declared_order_without_scanners(self):
        from engineering import static_scanner_run as runner
        plan = {'schema': 'static-scan-plan-1', 'repetitions': 5, 'measurement_reuse': False,
                'study_model_generations': 0, 'suites': {'z': {'inputs': []}, 'a': {'inputs': []}}, 'profiles': []}
        for suite in ('z', 'a'):
            plan['profiles'].append({'id': suite + '-checkov', 'suite': suite, 'kind': 'native', 'role': 'detector',
                'parser': 'checkov', 'report': 'report.stdout', 'argv': ['/fake/scanner'], 'accepted_exit_codes': [0],
                'timeout_seconds': 5, 'requires': [], 'scratch_gib': 0, 'redacted_secrets': False})
        expected = [r['job_id'] for r in schedule(plan)]
        observed = []
        with tempfile.TemporaryDirectory() as tmp:
            def reset(suite, inputs, work): work.mkdir(parents=True); return {'suite': suite, 'verified': True}
            def phase(path): path.mkdir(parents=True)
            def measured(argv, directory, *args):
                observed.append(directory.name); (directory / 'stdout').write_text('{}'); return {'status': 'completed'}
            with patch.object(runner, 'sample'), patch.object(runner, 'prepare_inputs', side_effect=reset), \
                 patch.object(runner, 'verify_inputs'), patch.object(runner, 'phase_directory', side_effect=phase), \
                 patch.object(runner, 'scanner_environment', return_value={}), \
                 patch.object(runner, 'isolated_command', return_value=['never-executed']), \
                 patch.object(runner, 'measured', side_effect=measured), \
                 patch.object(runner, 'normalize', return_value={'effective_status': 'completed', 'findings': []}):
                runner.execute(plan, {'inputs': {'a': [], 'z': []}, 'runtime': [], 'databases': {}}, Path(tmp), 'synthetic-order', [])
        self.assertEqual(observed, expected)
        self.assertEqual(observed[:2], ['b1-a-checkov', 'b1-z-checkov'])


if __name__ == '__main__':
    unittest.main()
