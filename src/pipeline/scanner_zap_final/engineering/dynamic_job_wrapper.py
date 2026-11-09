"""Run one exact command and preserve process/cgroup accounting, including failure."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def cgroup():
    root = Path('/sys/fs/cgroup')
    return {name: (root / name).read_text() if (root / name).is_file() else None
            for name in ('cpu.stat', 'memory.current', 'memory.peak', 'memory.events')}


def effective_environment(spec, inherited):
    keys = {'PATH', 'LANG', 'LC_ALL', 'TZ'}
    if spec.get('container'):
        # These values come from the locked image, not a user shell. Removing
        # Alpine's invariant mode makes the pinned RESTler .NET runtime abort.
        keys |= {'DOTNET_RUNNING_IN_CONTAINER', 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT',
                 'JAVA_HOME', 'ZAP_PATH', 'IS_CONTAINERIZED'}
    return {**{k: v for k, v in inherited.items() if k in keys}, **spec['environment']}


def main():
    spec = json.loads(Path(sys.argv[1]).read_text())
    output = Path(spec['accounting_path'])
    if output.exists(): raise FileExistsError('Preserve command accounting')
    result = {'started_unix': time.time(), 'source': 'wait4 plus container cgroup counters when present',
              'cgroup_before': cgroup() if spec.get('container') else None}
    start = time.monotonic()
    os.chdir(spec['cwd'])
    env = effective_environment(spec, os.environ)
    result['effective_environment'] = env
    try:
        from engineering.zap_runtime_home import prepare
        prepare(spec)
        proc = subprocess.Popen(spec['argv'], env=env)
        _, status, u = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        result.update(returncode=proc.returncode, user_cpu_seconds=u.ru_utime,
                      system_cpu_seconds=u.ru_stime, max_rss_kib=u.ru_maxrss,
                      major_page_faults=u.ru_majflt, minor_page_faults=u.ru_minflt,
                      input_blocks=u.ru_inblock, output_blocks=u.ru_oublock)
    except (OSError, ValueError) as error:
        result.update(returncode=127, error=type(error).__name__ + ': ' + str(error))
    finally:
        result.update(elapsed_seconds=time.monotonic() - start, finished_unix=time.time(),
                      cgroup_after=cgroup() if spec.get('container') else None,
                      limits='wait4 max RSS is not simultaneous aggregate memory; container counters include wrapper overhead')
        output.write_text(json.dumps(result, indent=2) + '\n')
    return result['returncode'] if result['returncode'] >= 0 else 128 - result['returncode']


if __name__ == '__main__':
    raise SystemExit(main())
