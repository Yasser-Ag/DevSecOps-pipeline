"""Failure-oriented tests of dynamic input, scope and measurement contracts."""
import copy
from email.message import Message
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from study import dynamic_scan_contract as c


def controls(n):
    return [{'id': str(i), 'passed': True, 'response': {'status': 200, 'body_sha256': str(i)},
             'context_signature': [['document', True, None]]} for i in range(n)]


class ContractTests(unittest.TestCase):
    def test_retained_plan_counts_and_independence(self):
        p = c.plan()
        self.assertEqual(len({r['id'] for r in p['profiles']}), 18)
        self.assertEqual(p['planned_native_detector_invocations'], 60)
        self.assertEqual(p['planned_directed_checker_invocations'], 30)
        self.assertEqual(p['planned_target_generations'], 20)
        self.assertFalse(p['protocol_frozen'])

    def test_zap_modes_cannot_be_pooled_as_identical(self):
        crapi = c.profile('crapi-zap-valid-a')
        ai = c.profile('aigoat-zap-valid-alice')
        self.assertEqual(crapi['mode'], 'active_api_scan')
        self.assertEqual(ai['mode'], 'passive_api_import')
        self.assertNotIn('-S', c.scanner_command(crapi['id'], '/zap/wrk', 'http://proxy:8080', 'test')['argv'])
        self.assertIn('-S', c.scanner_command(ai['id'], '/zap/wrk', 'http://proxy:8080', 'test')['argv'])

    def test_nonlocal_proxy_and_credentials_rejected(self):
        for base in ('https://proxy:8080', 'http://example.com:8080', 'http://1.1.1.1:8080',
                     'http://<MASKED:fixture:126>:<MASKED:password:2>@proxy:8080', 'http://proxy:8080/path', 'http://proxy:8080?x=1'):
            with self.subTest(base=base), self.assertRaises(ValueError):
                c.proxy_base(base)
        self.assertEqual(c.proxy_base('http://<MASKED:ip_address:6>:8080'), '<MASKED:ip_address:6>')

    def test_unknown_profile_or_injected_token_rejected(self):
        with self.assertRaises(ValueError):
            c.profile('new-scanner')
        with self.assertRaises(ValueError):
            c.scanner_command('crapi-nuclei-valid-a', '/work', 'http://proxy:8080', 'token\r\nInjected: yes')

    def test_crapi_allows_exact_fixture_routes_and_queries_only(self):
        route = c.LOCATION.format('fixture-uuid')
        for path in (route, route + '?x=1', c.LISTING, c.LOCATION.format(c.MISSING)):
            self.assertTrue(c.permitted('crapi', 'GET', path, b'', {route: 'a'})[0])
        for path in ('/identity/api/auth/login', c.LOCATION.format('other'), 'http://external/' + route,
                     '//external/' + route, route + '#fragment', '/identity/api/v2/vehicle/../auth'):
            self.assertFalse(c.permitted('crapi', 'GET', path, b'', {route: 'a'})[0])

    def test_crapi_mutation_and_body_rejected(self):
        self.assertFalse(c.permitted('crapi', 'POST', c.LISTING, b'{}', {})[0])
        self.assertFalse(c.permitted('crapi', 'GET', c.LISTING, b'{}', {})[0])

    def test_native_crapi_discovery_probes_keep_fixed_upstream_read_only_scope(self):
        for route in ('/', '/identity', '/identity/api/v2/42', '/latest/meta-data/',
                      '/computeMetadata/v1/', '/schemathesis-probe%5C%1B%01', '/actuator/health'):
            self.assertTrue(c.permitted('crapi', 'GET', route, b'', {}, 'crapi_read_only')[0])
        for route in ('http://<MASKED:ip_address:5>/latest/meta-data/', '//example.com/', 'relative', '/x\r\nInjected: yes'):
            self.assertFalse(c.permitted('crapi', 'GET', route, b'', {}, 'crapi_read_only')[0])
        self.assertFalse(c.permitted('crapi', 'POST', c.LISTING, b'{}', {}, 'crapi_read_only')[0])
        self.assertFalse(c.permitted('crapi', 'GET', c.LISTING, b'{}', {}, 'crapi_read_only')[0])
        with self.assertRaises(ValueError):
            c.permitted('aigoat', 'GET', '/api/products/', b'', {}, 'crapi_read_only')

    def test_proxy_handler_forwards_discovery_to_fixed_target_and_records_denial(self):
        from engineering import dynamic_profile_proxy as proxy
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'current.json').write_text(json.dumps({'target': 'crapi', 'scope': 'crapi_read_only',
                'phase': 'discovery-test', 'mode': 'raw', 'max_requests': 128, 'roles': {}, 'route_owners': {}}))
            proxy.COUNTS.clear()
            for route, forwarded in [('/latest/meta-data/', True), ('http://<MASKED:ip_address:5>/latest/meta-data/', False)]:
                handler = proxy.Handler.__new__(proxy.Handler)
                handler.command, handler.path = 'GET', route
                handler.request_version = 'HTTP/1.1'
                handler.headers = Message(); handler.headers['Host'] = 'untrusted.example'
                handler.rfile, handler.wfile = io.BytesIO(), io.BytesIO()
                handler.close_connection = False
                connection = Mock()
                response = connection.getresponse.return_value
                response.status = 200
                response.read.return_value = b'{"<MASKED:fixture:127>":true}'
                response.getheaders.return_value = [('Content-Type', 'application/json')]
                with patch.object(proxy, 'Path', side_effect=lambda value: root / Path(value).name), \
                     patch.object(proxy.http.client, 'HTTPConnection', return_value=connection) as factory:
                    handler.forward()
                    if forwarded:
                        factory.assert_called_once_with('crapi-web', 80, timeout=30)
                        self.assertEqual(connection.request.call_args.args[:2], ('GET', route))
                        self.assertEqual(connection.request.call_args.kwargs['headers']['Host'], 'crapi-web')
                    else:
                        factory.assert_not_called()
                record = json.loads((root / 'requests.jsonl').read_text().splitlines()[-1])
                self.assertIsNone(record['harness_error'])
                self.assertEqual(record['forwarded'], forwarded)
                self.assertEqual(record['status'], 200 if forwarded else 403)

    def test_aigoat_generation_not_in_scanner_scope(self):
        self.assertFalse(c.permitted('aigoat', 'POST', '/api/surfaces/rag.kb/execute', b'{}', {})[0])
        self.assertFalse(c.permitted('aigoat', 'GET', '/api/auth/demo-users/', b'', {})[0])

    def test_aigoat_keeps_bounded_retrieval_settings(self):
        data = {'query': '<MASKED:fixture:127>', 'top_k': 5, 'defense_level': 2, 'hybrid': False}
        self.assertTrue(c.permitted('aigoat', 'POST', '/api/knowledge-base/trace', json.dumps(data).encode(), {})[0])
        for key, value in [('top_k', 6), ('top_k', True), ('defense_level', 3), ('hybrid', True)]:
            changed = {**data, key: value}
            self.assertFalse(c.permitted('aigoat', 'POST', '/api/knowledge-base/trace', json.dumps(changed).encode(), {})[0])

    def test_constructed_gate_only_blocks_cross_user_objects(self):
        route = c.LOCATION.format('one')
        self.assertTrue(c.authorization_gate('GET', route, 'b', {route: 'a'}, 'gated'))
        for mode, actor in [('raw', 'b'), ('gated', 'a'), ('gated', 'invalid'), ('gated', 'absent')]:
            self.assertFalse(c.authorization_gate('GET', route, actor, {route: 'a'}, mode))

    def test_proxy_truncated_matrix_rejected(self):
        rows = controls(13)
        with self.assertRaises(ValueError):
            c.compare_controls('aigoat', rows, rows[:-1])

    def test_proxy_duplicate_ids_rejected(self):
        rows = controls(11); rows[-1] = copy.deepcopy(rows[0])
        with self.assertRaises(ValueError):
            c.compare_controls('crapi', rows, rows)

    def test_proxy_changed_success_bytes_rejected(self):
        a = controls(11); b = copy.deepcopy(a); b[0]['response']['body_sha256'] = 'changed'
        with self.assertRaises(ValueError):
            c.compare_controls('crapi', a, b)

    def test_proxy_changed_context_or_failed_reference_rejected(self):
        a = controls(13)
        for field, value in [('context_signature', []), ('passed', False)]:
            b = copy.deepcopy(a); b[0][field] = value
            with self.assertRaises(ValueError):
                c.compare_controls('aigoat', a, b)

    def test_proxy_scores_not_an_exact_equality_endpoint(self):
        a = controls(13); b = copy.deepcopy(a)
        b[0]['response']['body_sha256'] = 'scores-may-change'
        self.assertTrue(c.compare_controls('aigoat', a, b)['success'])

    def test_empty_or_failed_transport_is_not_a_negative_finding(self):
        with self.assertRaises(ValueError):
            c.transport_completion([], 128)
        result = c.transport_completion([{'harness_error': 'timeout', 'forwarded': False}], 128)
        self.assertEqual(result['effective_transport_status'], 'failed')
        self.assertFalse(result['actual_scope_verified'])

    def test_gate_response_is_a_limit_not_target_security(self):
        result = c.transport_completion([{'gate_reason': 'request_count_budget', 'forwarded': False}], 128)
        self.assertEqual(result['effective_transport_status'], 'completed_with_limitations')
        self.assertFalse(result['gate_responses_are_target_findings'])

    def test_directed_checker_preserves_on_off_and_gate_conditions(self):
        for row in c.profiles():
            if row['tool'] != 'restler':
                continue
            command = c.checker_command(row['id'])
            self.assertEqual('--enable_checkers' in command['argv'], row['checker_enabled'])
            self.assertEqual(command['image'], c.RESTLER)
            self.assertNotIn('20260922', json.dumps(command))

    def test_generated_answers_keep_four_existing_requests(self):
        rows = c.generation_workload()
        self.assertEqual(len(rows), 4)
        self.assertEqual({r['actor'] for r in rows}, {'alice', 'bob'})
        self.assertEqual({r['body']['input']['defense_level'] for r in rows}, {0, 2})
        self.assertFalse(any('expected' in json.dumps(r) for r in rows))
        self.assertEqual({r['owner'] for r in rows}, {'alice'})

    def test_input_projection_contains_no_reference_judgments(self):
        upstream = {'paths': {c.LISTING: {'get': {}}, '/identity/api/v2/vehicle/{vehicleId}/location': {'get': {}}}}
        fixture = {role: {'email': role + '@example.com', 'token': 'token-' + role,
                         'vehicles': [{'uuid': role + '-fixture-uuid'}]} for role in ('a', 'b')}
        for row in c.profiles():
            if row['target'] != 'crapi':
                continue
            result = c.inputs(row['id'], fixture, upstream, 'http://proxy:8080')
            schema = result['openapi.json']
            self.assertEqual(len(schema['paths']), 1 if row['tool'] == 'restler' else 3)
            for forbidden in ('passed', 'expected_access', 'reference_check', 'truth', 'false_positive'):
                self.assertNotIn(forbidden, json.dumps(result))
            if row['tool'] == 'restler':
                self.assertEqual(result['settings.json']['max_sequence_length'], 2)

    def test_target_and_scanner_networks_only_share_the_proxy(self):
        from engineering.dynamic_profile_run import Qualification
        for target in ('crapi', 'aigoat'):
            with tempfile.TemporaryDirectory() as tmp:
                obj = Qualification.__new__(Qualification)
                obj.out = Path(tmp)
                obj.network = lambda name: name
                probe = 'probe' if target == 'crapi' else 'backend'
                config = {'networks': {'default': {'external': True, 'name': 'target'}},
                          'services': {probe: {'networks': ['default'], 'volumes': []}}}
                obj.add_transport(config, obj.out, 'owned', target)
                self.assertEqual(config['services'][probe]['networks'], ['default'])
                self.assertEqual(config['services']['anchor']['networks'], ['scanner'])
                self.assertEqual(set(config['services']['proxy']['networks']), {'default', 'scanner'})
                for name in ('proxy', 'anchor'):
                    service = config['services'][name]
                    self.assertFalse(service.get('ports'))
                    self.assertEqual(service['cap_drop'], ['ALL'])
                    self.assertEqual(service['restart'], 'no')

    def test_root_backend_keeps_private_control_readable_by_proxy_owner(self):
        from engineering.dynamic_profile_probe import write
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'current.json'
            owner = path.parent.stat()
            with patch('os.geteuid', return_value=0), patch('os.chown') as change_owner:
                write(path, {'phase': '<MASKED:fixture:127>'})
            change_owner.assert_called_once_with(path.with_suffix('.json.tmp'), owner.st_uid, owner.st_gid)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.with_suffix('.json.tmp').exists())

    def test_native_argv_replays_prior_wrappers_with_declared_changes_only(self):
        from engineering import api_tool_entrypoint as crapi
        from engineering.aigoat_api import tool as ai
        class Captured(Exception):
            pass
        for row in c.profiles():
            if row['tool'] == 'restler':
                continue
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                (directory / 'authorization.json').write_text('{"token":"test-fixture-token"}')
                captured = []
                def stop(argv, *args, **kwargs):
                    captured.append(argv if isinstance(argv, list) else args[0])
                    raise Captured()
                old = ai if row['target'] == 'aigoat' else crapi
                argv = ['tool.py', '--tool', row['tool'], '--input', tmp, '--base', 'http://audit-proxy:8080']
                with patch.object(sys, 'argv', argv), patch.dict(os.environ, {}, clear=True), \
                     patch('os.execv', side_effect=stop), patch('subprocess.run', side_effect=stop):
                    with self.assertRaises(Captured):
                        old.main()
                observed = [x.replace('/zap/wrk', tmp) for x in captured[0]]
                if row['target'] == 'crapi' and row['tool'] == 'nuclei':
                    i = observed.index('-H')
                    observed[i:i] = ['-config', str(directory / 'nuclei.yml')]
                new = c.scanner_command(row['id'], tmp, 'http://audit-proxy:8080', 'test-fixture-token')
                self.assertEqual(new['argv'], observed, row['id'])


if __name__ == '__main__':
    unittest.main()
