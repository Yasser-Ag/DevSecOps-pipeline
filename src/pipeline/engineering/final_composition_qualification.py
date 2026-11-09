"""No-scan Ubuntu check of the complete execution/analysis composition."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest
import zipfile

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from engineering import static_scanner_host as host
from study.final_campaign_contract import (composition, verify_package, read, sha, SCANNERS, TRIAGE,
    command_schedule, STATIC_LOCK, DYNAMIC_LOCK, STATIC_LOCK_LOCAL, DYNAMIC_LOCK_LOCAL)

TESTS = ['engineering.test_final_campaign', 'engineering.test_whole_study_bindings', 'study.test_final_comparators']


def dependencies(output):
    tag = f'cp{sys.version_info.major}{sys.version_info.minor}'
    wheels = [p for p in (PACKAGE / 'wheels').glob('*.whl') if tag + '-' in p.name or 'abi3-' in p.name]
    if len(wheels) != 2:
        raise ValueError('Exact compatible analysis wheels unavailable')
    dest = output / 'dependencies'; dest.mkdir()
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as stream:
            for item in stream.infolist():
                name = Path(item.filename)
                if name.is_absolute() or '..' in name.parts or item.file_size > 16 * 1024**2:
                    raise ValueError('Unsafe wheel entry')
            stream.extractall(dest)
    sys.path.insert(0, str(dest))
    return dest, [{'path': p.name, 'sha256': sha(p)} for p in wheels]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--local-output', type=Path)
    args = parser.parse_args(); remote = args.local_output is None
    if remote:
        if PACKAGE.parent != host.ROOT / 'environment' or PACKAGE.name not in ('final-composition-v1', 'final-composition-v2'):
            raise ValueError('Unexpected deployed package')
        host.assert_lease()
        output = host.ROOT / 'evidence' / ('final-composition-qualification-20261023-0' + PACKAGE.name[-1])
        scanners, triage = SCANNERS, TRIAGE
    else:
        output = args.local_output
        scanners, triage = PACKAGE / 'component_fixtures/scanners', PACKAGE / 'component_fixtures/triage'
    output.mkdir(parents=True, exist_ok=False)
    result = {'started_utc': host.utc(), 'success': False, 'remote': remote,
              'scientific_scans': 0, 'model_generations': 0, 'control_probes': 0,
              'protocol_released': False, 'package_manifest_sha256': sha(PACKAGE / 'package_manifest.json')}
    before = None
    try:
        verify_package(PACKAGE)
        if remote:
            before = host.snapshot(); host.write(output / 'host_before.json', before)
            host.write(output / 'resources_before.json', host.sample())
        deps, wheels = dependencies(output)
        host.write(output / 'analysis_dependencies.json', {'wheels': wheels, 'python': sys.version,
                    'platform': platform.platform(), 'installation': 'Offline extraction in this qualification output only'})
        binding = composition(PACKAGE, scanners, triage)
        host.write(output / 'composition.json', binding)
        host.write(output / 'command_schedule_preview.json', command_schedule(host.ROOT / 'environment/final-release-20261023-01'))
        if remote:
            for source, deployed in ((STATIC_LOCK_LOCAL, STATIC_LOCK), (DYNAMIC_LOCK_LOCAL, DYNAMIC_LOCK)):
                if sha(PACKAGE / source) != sha(deployed):
                    raise ValueError('Installed asset lock differs from analyzed reference')
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(deps), 'PYTHONNOUSERSITE': '1'}
        for kind, component in [('scanners', scanners), ('triage', triage)]:
            command = [sys.executable, '-B', str(PACKAGE / 'engineering/final_component_check.py'),
                       '--kind', kind, '--package', str(component), '--composition', str(output / 'composition.json'),
                       '--evaluation', str(PACKAGE)]
            proc = subprocess.run(command, cwd=component, env=env, capture_output=True, text=True, timeout=180)
            (output / (kind + '-schema.stdout')).write_text(proc.stdout)
            (output / (kind + '-schema.stderr')).write_text(proc.stderr)
            if proc.returncode != 0 or not json.loads(proc.stdout)['success']:
                raise ValueError('Installed component schema failed: ' + kind)
        with (output / 'unittest.log').open('x') as log:
            units = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(TESTS))
        result.update(tests=units.testsRun, failures=len(units.failures), errors=len(units.errors), skipped=len(units.skipped))
        if not units.wasSuccessful() or units.testsRun != 52 or units.skipped:
            raise ValueError('Incomplete combined scientific-binding tests')
        from engineering.qualify_fresh_comparators import replay
        inputs, comparisons, audit = replay(PACKAGE)
        host.write(output / 'comparator_replay.json', comparisons)
        host.write(output / 'comparator_audit.json', audit)
        host.write(output / 'replay_source_manifest.json', inputs.manifest())
        import yaml
        from importlib.metadata import version
        host.write(output / 'analysis_versions.json', {n: version(n) for n in ('tree-sitter', 'tree-sitter-java', 'PyYAML', 'psutil')})
        result['historical_replay_checks'] = len(audit['checks'])
        verify_package(PACKAGE); verify_package(scanners); verify_package(triage)
        result['composition_passed'] = True
    except BaseException as error:
        import traceback
        result['error'] = type(error).__name__ + ': ' + str(error)
        (output / 'failure_trace.txt').write_text(traceback.format_exc())
    finally:
        if remote:
            try:
                after = host.snapshot(); host.write(output / 'host_after.json', after)
                host.write(output / 'resources_after.json', host.sample())
                result['shared_host_preserved'] = bool(before and before['container_config_hashes'] == after['container_config_hashes'] and host.preserved(before, after))
            except BaseException as error:
                result['preservation_error'] = str(error)
        result['success'] = result.get('composition_passed') is True and (not remote or result.get('shared_host_preserved') is True)
        result['finished_utc'] = host.utc(); host.write(output / 'summary.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
