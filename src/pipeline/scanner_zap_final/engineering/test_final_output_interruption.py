"""A started generation request must survive process interruption in the evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from engineering import dynamic_execution_probe as probe
from study.dynamic_scan_contract import generation_workload


class InterruptedGenerationTests(unittest.TestCase):
    def test_started_request_is_persisted_before_blocking_model_response(self):
        class InterruptedOpener:
            def open(self, *args, **kwargs):
                raise KeyboardInterrupt('Synthetic interruption during the first target request')
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            fixture = {'actors': {a: {'token': 'synthetic-' + a} for a in ('alice', 'bob')},
                       'documents': {'alice': {'id': 1, 'marker': 'synthetic-marker'}}}
            model = generation_workload()[0]['model']
            with patch.object(probe, 'model_request', return_value={'body': {'models': [{'name': model}]}}), \
                    patch.object(probe.urllib.request, 'build_opener', return_value=InterruptedOpener()):
                with self.assertRaises(KeyboardInterrupt): probe.generation(out, fixture)
            path = out / 'generation.json'
            self.assertTrue(path.exists(), 'The started request disappeared during interruption')
            rows = json.loads(path.read_text())
            self.assertEqual(len(rows), 1, 'Count actual attempts, not the four planned requests')
            self.assertEqual(rows[0]['id'], generation_workload()[0]['id'])
            self.assertEqual(rows[0]['status'], 'running')
            self.assertIn('started_unix', rows[0])
            self.assertNotIn('marker_emitted', rows[0], 'An interrupted response has no completed outcome')


if __name__ == '__main__': unittest.main()
