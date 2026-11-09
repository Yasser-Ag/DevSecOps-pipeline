#!/usr/bin/env python3
"""Execute a declared scanner without network access and with read-only inputs.

Called only inside fresh private mount/network namespaces created by unshare.
Mount changes never propagate to the host. Scanner execution drops to lab.
"""
import ctypes
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys


def main():
    job = json.loads(Path(sys.argv[1]).read_text())
    account = pwd.getpwnam("lab")
    if os.getuid() != 0 or Path("/proc/self/ns/net").readlink() == Path("/proc/1/ns/net").readlink():
        raise RuntimeError("A fresh privileged network namespace is required")
    if Path("/proc/self/ns/mnt").readlink() == Path("/proc/1/ns/mnt").readlink():
        raise RuntimeError("A fresh mount namespace is required")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    for name in job["readonly"]:
        path = Path(name)
        if not path.is_absolute() or not path.exists():
            raise ValueError("Invalid read-only input")
        subprocess.run(["mount", "--bind", str(path), str(path)], check=True)
        subprocess.run(["mount", "-o", "remount,bind,ro,nosuid,nodev", str(path)], check=True)
    if job.get("scratch_gib"):
        size = job["scratch_gib"]
        if type(size) is not int or not 1 <= size <= 6:
            raise ValueError("Unqualified temporary-memory budget")
        scratch = Path(job["environment"]["TMPDIR"])
        if scratch != Path(job["cwd"]) / "tmp":
            raise ValueError("Scratch mount escapes the phase directory")
        subprocess.run(["mount", "-t", "tmpfs", "-o",
                        f"size={size}g,uid={account.pw_uid},gid={account.pw_gid},mode=0700,nosuid,nodev,noexec",
                        "tmpfs", str(scratch)], check=True)
    os.setgroups(os.getgrouplist(account.pw_name, account.pw_gid))
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot enable no-new-privileges")
    os.chdir(job["cwd"])
    os.execve(job["argv"][0], job["argv"], job["environment"])


if __name__ == "__main__":
    main()
