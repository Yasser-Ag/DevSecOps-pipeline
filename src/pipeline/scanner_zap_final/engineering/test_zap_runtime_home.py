"""Check policy provenance, preservation, and scope before ZAP starts."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from engineering import zap_runtime_home as home


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.spec = {'argv': ['/zap/zap-api-scan.py'], 'container': True, 'cwd': str(self.work)}
        self.source = Path(__file__).resolve().parents[1] / 'reference/zap-api-minimal.policy'

    def test_exact_bundled_policy_is_retained(self):
        with patch.object(home, 'POLICY_SOURCE', self.source):
            result = home.prepare(self.spec)
        self.assertEqual(Path(result['destination']).read_bytes(), self.source.read_bytes())
        self.assertEqual(result['sha256'], home.POLICY_SHA256)

    def test_changed_policy_is_rejected_before_start(self):
        damaged = self.work / 'damaged.policy'; damaged.write_bytes(b'not the bundled rules')
        with patch.object(home, 'POLICY_SOURCE', damaged), self.assertRaises(ValueError):
            home.prepare(self.spec)
        self.assertFalse((self.work / 'zap-policy-seed.json').exists())

    def test_previous_policy_cannot_be_overwritten(self):
        with patch.object(home, 'POLICY_SOURCE', self.source):
            home.prepare(self.spec)
            with self.assertRaises(FileExistsError): home.prepare(self.spec)

    def test_other_tools_do_not_seed_zap(self):
        self.assertIsNone(home.prepare({'argv': ['/usr/local/bin/nuclei']}))
        self.assertEqual(list(self.work.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
