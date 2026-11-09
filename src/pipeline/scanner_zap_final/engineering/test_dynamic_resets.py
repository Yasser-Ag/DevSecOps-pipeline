"""Failure-oriented checks for the dynamic reset boundary and reference semantics."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from study import dynamic_reset_contract as c


def reference(name):
    root = Path(__file__).resolve().parents[1]
    candidates = [root / 'reference' / name,
                  root / 'evidence/dynamic_reset_controller_2026-10-22/package-v1/reference' / name]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        raise FileNotFoundError('Build the package before running integration contract checks')
    return json.loads(path.read_text())


class ResetContractTests(unittest.TestCase):
    def test_untagged_image_resolves_by_exact_digest_without_default_listing(self):
        reference = 'sha256:' + '1' * 64
        observed = {'Id': reference, 'RepoDigests': [], 'Descriptor': {'digest': reference},
                    'Architecture': 'amd64', 'Os': 'linux', 'Config': {}, 'RootFS': {}}
        self.assertEqual(c.image_identity(reference, observed)['Id'], reference)
        with self.assertRaises(ValueError):
            c.image_identity('sha256:' + '2' * 64, observed)
        observed['Architecture'] = 'arm64'
        with self.assertRaises(ValueError):
            c.image_identity(reference, observed)

    def test_repository_manifest_and_image_configuration_are_distinct_identities(self):
        config, manifest = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64
        observed = {'Id': config, 'RepoDigests': ['example/image@' + manifest],
                    'Descriptor': {'digest': manifest}, 'Architecture': 'amd64', 'Os': 'linux'}
        self.assertEqual(c.image_identity('example/image@' + manifest, observed)['Id'], config)

    def test_historical_embedding_and_source_lock_schemas(self):
        locks = reference('aigoat_target_locks.json')
        self.assertIsInstance(locks['embedding_files'], dict)
        self.assertIsInstance(locks['source_files'], list)
        for key in ('embedding_files', 'source_files'):
            self.assertEqual(len(c.lock_rows(locks[key])), len(locks[key]))
        with self.assertRaises(ValueError):
            c.lock_rows({'../other-project': '0' * 64})

    def test_model_alias_is_confined_and_weights_stay_locked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'models'; root.mkdir()
            target = root / ('blobs/sha256-' + c.MODEL_DIGEST)
            target.parent.mkdir(); target.write_text('test-only model manifest')
            alias = root / 'manifests-v2/ollama.com/library/mistral/7b-instruct-v0.3-q4_K_M'
            alias.parent.mkdir(parents=True)
            alias.symlink_to('../../../../blobs/sha256-' + c.MODEL_DIGEST)
            meta = root / 'metadata/sha256-f5074b1221da0f5a2910d33b642efa5b9eb58cfdddca1c79e16d7ad28aa2b31f.json'
            meta.parent.mkdir(); meta.write_text('{}')
            expected = {target.relative_to(root).as_posix(): c.sha(target)}
            self.assertEqual(len(c.model_inventory(root, expected)), 3)
            target.write_text('changed')
            with self.assertRaises(ValueError):
                c.model_inventory(root, expected)
            alias.unlink(); alias.symlink_to(Path(tmp) / 'outside')
            with self.assertRaises(ValueError):
                c.model_inventory(root, expected)

    def test_old_output_is_not_a_permitted_destination(self):
        for value in ['api-development-20260922-02', '../../<OTHER_PROJECT_1>', 'dynamic-resets-preflight-20261022-05']:
            with self.assertRaises(ValueError):
                c.owned_output(c.ROOT / 'evidence' / value)

    def test_existing_output_is_never_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / 'evidence/dynamic-resets-preflight-20261022-01'
            dest.mkdir(parents=True)
            with patch.object(c, 'ROOT', root), self.assertRaises(ValueError):
                c.owned_output(dest)

    def test_crapi_has_no_legacy_ingress_or_state_mount(self):
        template = reference('crapi_compose.json')
        original = copy.deepcopy(template)
        config = c.crapi_profile(template, 'fresh', Path('/new/state'), 'private',
                                 {k: 'fresh-' + k for k in ['chromadb-data', 'mongodb-data', 'postgresql-data', 'mongo-config']})
        self.assertEqual(template, original)
        self.assertEqual(set(config['services']), c.CRAPI_SERVICES)
        self.assertNotIn('20260922', json.dumps(config))
        for value in config['services'].values():
            self.assertFalse(value['ports'])
            self.assertEqual(value['pull_policy'], 'never')
        mounts = config['services']['crapi-identity']['volumes']
        self.assertEqual(mounts[0]['source'], '/new/state/keys')
        self.assertIn('/data/configdb', [m['target'] for m in config['services']['mongodb']['volumes']])

    def test_changed_or_unpinned_target_is_rejected(self):
        for change in [('image', 'crapi:latest'), ('privileged', True), ('volumes',
                      [{'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/socket'}])]:
            template = reference('crapi_compose.json')
            template['services']['crapi-web'][change[0]] = change[1]
            with self.assertRaises(ValueError):
                c.crapi_profile(template, 'x', Path('/new/state'), 'private',
                    {k: k for k in ['chromadb-data', 'mongodb-data', 'postgresql-data', 'mongo-config']})

    def test_model_store_read_only_and_no_frontend(self):
        config = c.aigoat_profile(reference('aigoat_compose.json'), 'fresh', '/fresh/state',
                                 '/fresh/results', '/new/package', 'private')
        self.assertEqual(set(config['services']), {'backend', 'ollama'})
        self.assertEqual(config['services']['ollama']['image'], c.OLLAMA)
        self.assertTrue(all(m.endswith(':ro') for m in config['services']['ollama']['volumes']))
        self.assertNotIn('runtime-03', json.dumps(config))
        self.assertFalse(any(s['ports'] for s in config['services'].values()))

    def test_unsafe_runtime_cases_are_static_only(self):
        row = reference('runtime_controls.json')[-1]
        for case in ['C07', 'C08', 'C09', 'C10', 'C11', 'C12']:
            row['case_id'] = case
            with self.assertRaises(ValueError):
                c.runtime_service(row, 'probe')

    def test_runtime_privilege_or_resource_drift_rejected(self):
        for field, value in [('network_mode', 'host'), ('privileged', True),
                             ('cap_add', ['SYS_ADMIN']), ('volumes', ['/etc:/host']),
                             ('mem_limit', '0'), ('pids_limit', -1)]:
            row = reference('runtime_controls.json')[0]
            row['service'][field] = value
            with self.assertRaises(ValueError):
                c.runtime_service(row, 'probe')

    def test_all_twelve_runtime_profiles_have_bounded_configuration(self):
        rows = reference('runtime_controls.json')
        self.assertEqual(len(rows), 12)
        for row in rows:
            self.assertEqual(c.runtime_service(row, 'probe')['network_mode'], 'none')

    def test_permission_denial_does_not_prove_read_only_rootfs(self):
        row = next(r for r in reference('runtime_controls.json') if r['case_id'] == 'C03')
        with self.assertRaises(ValueError):
            c.runtime_assertion(row, {'cap_eff': '0000000000000000', 'rootfs_writable': False, 'write_errno': 13})
        value = c.runtime_assertion(row, {'cap_eff': '0000000000000000', 'rootfs_writable': False, 'write_errno': 30})
        self.assertTrue(value['passed'])

    def test_unexpected_root_uid_fails_nonroot_control(self):
        row = reference('runtime_controls.json')[0]
        with self.assertRaises(ValueError):
            c.runtime_assertion(row, {'cap_eff': '0000000000000000', 'uid': 0})

    def test_model_tag_name_alone_is_insufficient(self):
        with self.assertRaises(ValueError):
            c.check_model_tags({'models': [{'name': c.MODEL, 'digest': 'changed'}]})
        self.assertFalse(c.check_model_tags({'models': [{'name': c.MODEL, 'digest': c.MODEL_DIGEST}]})['generation_requested'])

    def test_seed_rejects_links_traversal_duplicates_and_other_projects(self):
        for name, kind in [('../<OTHER_PROJECT_1>/result', tarfile.REGTYPE), ('/tmp/state', tarfile.REGTYPE),
                           ('data/link', tarfile.SYMTYPE), ('data/fifo', tarfile.FIFOTYPE),
                           ('models/blob', tarfile.REGTYPE)]:
            member = tarfile.TarInfo(name); member.type = kind
            with self.assertRaises(ValueError):
                c.safe_seed_members([member])
        member = tarfile.TarInfo('data/aigoat.db')
        with self.assertRaises(ValueError):
            c.safe_seed_members([member, member])
        c.safe_seed_members([member])

    def test_signature_requires_all_controls_not_only_successes(self):
        rows = [{'id': str(i), 'status': 200, 'matches_owner': True, 'passed': True} for i in range(11)]
        with self.assertRaises(ValueError):
            c.semantic_signature('crapi', rows[:-1])
        rows[0]['passed'] = False
        with self.assertRaises(ValueError):
            c.semantic_signature('crapi', rows)

    def test_signature_keeps_changed_behavior_but_not_random_body(self):
        rows = [{'id': str(i), 'status': 200, 'matches_owner': True, 'passed': True, 'response': {'uuid': 'a'}} for i in range(11)]
        other = copy.deepcopy(rows)
        other[0]['response']['uuid'] = 'b'
        self.assertEqual(c.semantic_signature('crapi', rows), c.semantic_signature('crapi', other))
        other[0]['status'] = 403
        self.assertNotEqual(c.semantic_signature('crapi', rows), c.semantic_signature('crapi', other))

    def test_reference_client_rejects_external_destinations(self):
        from engineering.dynamic_reset_probe import request
        with self.assertRaises(ValueError):
            request('http://example.com', 'GET', '/')
        with self.assertRaises(ValueError):
            request('http://crapi-web:80', 'GET', '//example.com/')


if __name__ == '__main__':
    unittest.main()
