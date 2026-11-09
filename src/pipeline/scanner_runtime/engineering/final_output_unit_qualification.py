#!/usr/bin/env python3
"""Run deterministic output-adapter unit checks under the shared host lease."""
import json
from pathlib import Path
import sys
import time
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from engineering import static_scanner_host as host
from study.static_scan_contract import require

TESTS = ['engineering.test_final_output_adapter', 'engineering.test_final_output_ingress',
         'engineering.test_final_dynamic_projection', 'engineering.test_static_scanners',
         'engineering.test_dynamic_execution', 'engineering.test_dynamic_profiles',
         'engineering.test_dynamic_resets', 'engineering.test_final_output_interruption']


def main():
    require(PACKAGE == host.ROOT / 'environment/final-output-adapters-v2', 'Unexpected qualification package')
    host.assert_lease()
    output = host.ROOT / 'evidence/final-output-unit-qualification-20261022-02'
    output.mkdir(mode=0o700, exist_ok=False)
    summary = {'success': False, 'started_utc': host.utc(), 'scientific_scans_or_generations': 0,
               'container_or_network_creations': 0, 'test_modules': TESTS,
               'scope': 'Deterministic unit tests, temporary local fixtures and loopback HTTP fixtures only.'}
    before = None
    try:
        manifest = host.verify_package(PACKAGE)
        host.write(output / 'package_verification_before.json', manifest)
        host.write(output / 'resources_before.json', host.sample())
        before = host.snapshot(); host.write(output / 'host_before.json', before)
        started = time.monotonic()
        suite = unittest.defaultTestLoader.loadTestsFromNames(TESTS)
        with (output / 'unittest.log').open('x') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        summary.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                       skipped=len(result.skipped), test_wall_seconds=time.monotonic() - started)
        require(result.wasSuccessful() and result.testsRun == 147 and not result.skipped, 'Unit qualification failed or incomplete')
        host.write(output / 'package_verification_after.json', host.verify_package(PACKAGE))
        summary['tests_passed'] = True
    except Exception as error:
        summary['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            after = host.snapshot(); host.write(output / 'host_after.json', after)
            host.write(output / 'resources_after.json', host.sample())
            summary['shared_host_preserved'] = bool(before and host.preserved(before, after) and
                set(before['container_config_hashes']) == set(after['container_config_hashes']))
        except Exception as error:
            summary['preservation_error'] = type(error).__name__ + ': ' + str(error)
        summary['success'] = summary.get('tests_passed') is True and summary.get('shared_host_preserved') is True
        summary['finished_utc'] = host.utc()
        host.write(output / 'summary.json', summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary['success'] else 1


if __name__ == '__main__': raise SystemExit(main())
