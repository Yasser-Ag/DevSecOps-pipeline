"""Bounded Ubuntu integration check: unit tests and 24 safe construction probes."""
import json
from pathlib import Path
import signal
import sys
import time
import unittest

PACKAGE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PACKAGE))
from engineering import static_scanner_host as host
from engineering.static_runtime_controls import RuntimeControls
from engineering.dynamic_reset_run import PROBE
from study.dynamic_reset_contract import require, sha
from study.runtime_block_contract import load_controls, source_bindings, verify_phase
from study.final_output_ingress import Evidence

TESTS=['engineering.test_runtime_integration','engineering.test_static_scanners',
       'engineering.test_final_output_adapter','engineering.test_final_output_ingress']


def check_sources(controls, locks):
    bindings=source_bindings(controls,locks)
    base=next(r['source'] for r in locks['inputs']['configuration'] if r['destination']=='reference/scanner-inputs')
    root=Path(base).resolve();root.relative_to(host.ROOT/'evidence')
    for row in bindings:
        path=root/row['path'];path.resolve().relative_to(root)
        require(not path.is_symlink() and sha(path)==row['source_sha256'],'Runtime source bytes changed')
    return bindings


def main():
    require(PACKAGE.parent==host.ROOT/'environment' and PACKAGE.name in ('runtime-integration-v1','runtime-integration-v2'),
            'Unexpected integration package')
    version=PACKAGE.name[-1]
    def interrupted(signum, frame):raise InterruptedError('Qualification signal '+str(signum))
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(signum,interrupted)
    host.assert_lease()
    output=host.ROOT/'evidence'/('runtime-integration-qualification-20261022-0'+version)
    output.mkdir(mode=0o700,exist_ok=False)
    summary={'started_utc':host.utc(),'success':False,'scientific_scans':0,'model_generations':0,
             'new_control_probes':0,'scope':'Engineering integration only; not a final scientific block.',
             'test_modules':TESTS,'protocol_released':False}
    host.write(output/'summary.json',summary)
    before=None
    try:
        host.write(output/'package_before.json',host.verify_package(PACKAGE))
        host.write(output/'resources_before.json',host.sample())
        before=host.snapshot();host.write(output/'host_before.json',before)
        started=time.monotonic()
        with (output/'unittest.log').open('x') as log:
            result=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(TESTS))
        summary.update(tests=result.testsRun,errors=len(result.errors),failures=len(result.failures),skipped=len(result.skipped),
                       test_seconds=time.monotonic()-started)
        require(result.wasSuccessful() and result.testsRun==96 and not result.skipped,'Incomplete/failed integration tests')
        controls=load_controls(PACKAGE/'reference/runtime_controls.json')
        locks=json.loads((PACKAGE/'reference/static_asset_locks.json').read_text())
        host.write(output/'source_bindings_before.json',check_sources(controls,locks))
        runtime=RuntimeControls(output,output.name,controls,locks,[])
        runtime.phase(1,'before')
        summary['new_control_probes']=runtime.completed;host.write(output/'summary.json',summary)
        # No scanner call belongs between these qualification phases.
        host.sample()
        runtime.phase(1,'after')
        summary['new_control_probes']=runtime.completed
        evidence=Evidence(output)
        phases={p:verify_phase(evidence,controls,1,p,output.name,PROBE) for p in ('before','after')}
        require(phases['before']['assertions']==phases['after']['assertions'],'Construction behavior changed')
        require(not set(phases['before']['container_ids']) & set(phases['after']['container_ids']),'Canary reused a target')
        host.write(output/'phase_verification.json',phases)
        host.write(output/'control_manifest.json',evidence.manifest())
        host.write(output/'source_bindings_after.json',check_sources(controls,locks))
        host.write(output/'package_after.json',host.verify_package(PACKAGE))
        summary['integration_passed']=True
    except BaseException as error:
        summary['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            after=host.snapshot();host.write(output/'host_after.json',after)
            host.write(output/'resources_after.json',host.sample())
            summary['shared_host_preserved']=bool(before and host.preserved(before,after) and
                set(before['container_config_hashes'])==set(after['container_config_hashes']))
        except BaseException as error:
            summary['preservation_error']=type(error).__name__+': '+str(error)
        summary['success']=summary.get('integration_passed') is True and summary.get('shared_host_preserved') is True
        summary['finished_utc']=host.utc();host.write(output/'summary.json',summary)
    print(json.dumps(summary,indent=2),flush=True)
    return 0 if summary['success'] else 1


if __name__=='__main__':raise SystemExit(main())
