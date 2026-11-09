"""Hash native interpreter, installed Python packages and resolved ELF dependencies."""
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engineering import static_scanner_host as host
from study.dynamic_reset_contract import require, sha
from study.dynamic_scan_contract import SCHEMATHESIS


def inventory():
    venv = Path(SCHEMATHESIS).parents[1]
    interpreter = venv / 'bin/python'
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
    code = 'import json,sys,sysconfig;print(json.dumps({"executable":sys.executable,"stdlib":sysconfig.get_path("stdlib"),"version":sys.version}))'
    runtime = json.loads(subprocess.check_output([str(interpreter), '-I', '-B', '-c', code], env=env, text=True))
    roots = [venv, Path(runtime['stdlib'])]
    rows = [{'path': str(p), 'files': host.inventory(p, allow_links=True)} for p in roots]
    binaries = [Path(p) for p in ('/usr/local/bin/nuclei', '/usr/bin/python3', '/usr/bin/nsenter',
                                  '/usr/bin/unshare', '/usr/bin/mount')] + [interpreter]
    elf = set()
    for p in binaries + [p / r['path'] for p, tree in zip(roots, rows) for r in tree['files']
                         if r['path'].endswith('.so') or '.so.' in r['path']]:
        if p.is_file():
            with p.open('rb') as stream:
                if stream.read(4) == b'\x7fELF': elf.add(p.resolve())
    dependencies, logs = set(), []
    for p in sorted(elf):
        proc = subprocess.run(['ldd', str(p)], env=env, capture_output=True, text=True, timeout=15)
        text = proc.stdout + proc.stderr
        require('not found' not in text, 'Missing runtime dependency: ' + str(p))
        logs.append({'path': str(p), 'returncode': proc.returncode, 'output': text})
        for match in re.findall(r'(?:=>\s+|^\s*)(/[^\s()]+)', text, flags=re.MULTILINE):
            dependencies.add(Path(match).resolve())
    identities = [{'path': str(p), 'resolved': str(p.resolve()), 'bytes': p.stat().st_size, 'sha256': sha(p)}
                  for p in sorted(set(binaries) | dependencies)]
    return {'schema': 'dynamic-native-runtime-v1', 'python': runtime, 'trees': rows, 'binaries_and_libraries': identities,
            'ldd_evidence': logs, 'bytecode_policy': 'fresh PYTHONPYCACHEPREFIX and PYTHONDONTWRITEBYTECODE; user site disabled',
            'limitations': 'Installed native runtime identity, not an operating-system reproducibility claim.'}


def verify(expected):
    actual = inventory()
    # ldd addresses vary with ASLR; hash the resolved library files instead.
    keys = ('schema', 'python', 'trees', 'binaries_and_libraries', 'bytecode_policy', 'limitations')
    require({k: actual[k] for k in keys} == {k: expected[k] for k in keys}, 'Native runtime identity drift')
    return {'success': True, 'trees': len(actual['trees']),
            'files': sum(len(x['files']) for x in actual['trees']),
            'binaries_and_libraries': len(actual['binaries_and_libraries'])}
