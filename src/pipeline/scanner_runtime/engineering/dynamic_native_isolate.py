"""Enter an owned scanner network and expose only a private writable work tree.

Invoked after nsenter --net and unshare --mount --pid --fork --mount-proc.
No scanner is allowed to inherit the lab user's Docker supplementary group.
"""
import ctypes
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys


def check(value, message):
    if not value: raise ValueError(message)


def mount(*args):
    subprocess.run(['mount', *map(str, args)], check=True)


def main():
    spec_path = Path(sys.argv[1])
    spec = json.loads(spec_path.read_text())
    work = Path(spec['host_work'])
    root = Path('<LAB_ROOT>/evidence')
    check(os.geteuid() == 0 and os.getpid() == 1, 'Fresh root PID namespace required')
    check(work.is_relative_to(root) and work.resolve() == work and spec_path.is_relative_to(work), 'Unowned work path')
    check(work.parts[len(root.parts)].startswith(('dynamic-execution-preflight-', 'dynamic-final-')), 'Unexpected run')
    check(os.readlink('/proc/self/ns/mnt') != spec['host_mount_ns'], 'Host mount namespace')
    check(os.readlink('/proc/self/ns/net') == spec['scanner_network_ns'] != spec['host_network_ns'], 'Wrong network namespace')
    mount('--make-rprivate', '/')
    mount('--bind', '<USER_HOME>', '<USER_HOME>')
    mount('-o', 'remount,bind,ro', '<USER_HOME>')
    mount('--bind', work, work)
    mount('-o', 'remount,bind,rw', work)
    # Foreign project symlinks resolve to this mount; make it inaccessible here.
    for path in ('<OTHER_PROJECT_2>', '<USER_HOME>/.ssh'):
        if Path(path).exists():
            mount('-t', 'tmpfs', '-o', 'size=1m,mode=000,ro,nosuid,nodev,noexec', 'tmpfs', path)
    mount('-t', 'tmpfs', '-o', 'size=128m,mode=1777,nosuid,nodev', 'tmpfs', '/tmp')
    user = pwd.getpwnam('lab')
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    check(ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) == 0, 'Cannot set no_new_privs')
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    os.execv(sys.executable, [sys.executable, '-B', spec['wrapper'], str(spec_path)])


if __name__ == '__main__':
    main()
