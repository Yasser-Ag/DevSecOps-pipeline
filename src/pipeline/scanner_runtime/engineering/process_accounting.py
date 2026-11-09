#!/usr/bin/env python3
"""Execute one command and retain Linux wait4 resource counters."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    path = Path(sys.argv[1])
    command = sys.argv[2:]
    started = time.monotonic()
    try:
        proc = subprocess.Popen(command)
    except OSError as error:
        path.write_text(json.dumps({'launch_error': str(error), 'command': command}) + '\n')
        return 127
    _, status, usage = os.wait4(proc.pid, 0)
    proc.returncode = os.waitstatus_to_exitcode(status)
    path.write_text(json.dumps({
        'source': 'Linux wait4; child and waited descendant accounting',
        'child_wall_seconds': time.monotonic() - started,
        'exit_code': proc.returncode, 'user_cpu_seconds': usage.ru_utime,
        'system_cpu_seconds': usage.ru_stime, 'max_rss_kib': usage.ru_maxrss,
        'major_page_faults': usage.ru_majflt, 'minor_page_faults': usage.ru_minflt,
        'filesystem_input_blocks': usage.ru_inblock, 'filesystem_output_blocks': usage.ru_oublock,
        'voluntary_context_switches': usage.ru_nvcsw, 'involuntary_context_switches': usage.ru_nivcsw,
        'limits': 'max RSS is not simultaneous aggregate tree memory; Docker workloads excluded'
    }, indent=2) + '\n')
    return proc.returncode if proc.returncode >= 0 else 128 - proc.returncode


if __name__ == '__main__':
    raise SystemExit(main())
