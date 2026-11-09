#!/usr/bin/env python3
"""Fixed transport for bounded Ubuntu runtime integration (unit tests and safe control probes)."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'evidence/runtime_integration_2026-10-22'
SSH = ['ssh', '-F', '/dev/null', '-i', '<USER_HOME>/.ssh/hetzner_devsecops', '-o', 'BatchMode=yes',
       '-o', 'ConnectTimeout=12', '-o', 'StrictHostKeyChecking=yes', '<MASKED:host_username:1>@<MASKED:ip_address:7>']
REMOTE = '<LAB_ROOT>'
GUARD = ['python3', REMOTE + '/host-control/project_guard.py', 'run', '--']
INSTALL = '''from pathlib import Path
import hashlib,json,sys,tarfile
root=Path('<LAB_ROOT>/environment')
version=sys.argv[2]
if version not in ('1','2'):raise ValueError('Version outside fixed scope')
archive=root/('runtime-integration-v'+version+'.tar.gz');dest=root/('runtime-integration-v'+version)
if archive.exists() or dest.exists():raise ValueError('Preserve existing package')
data=sys.stdin.buffer.read(8*1024**2+1)
if len(data)>8*1024**2 or hashlib.sha256(data).hexdigest()!=sys.argv[1]:raise ValueError('Archive differs')
with archive.open('xb') as f:f.write(data)
with tarfile.open(archive,'r:gz') as stream:
 members=stream.getmembers();names=[m.name for m in members]
 if len(names)!=len(set(names)) or sum(m.size for m in members)>48*1024**2:raise ValueError('Unbounded archive')
 if any(not m.isfile() or Path(m.name).is_absolute() or '..' in Path(m.name).parts for m in members):raise ValueError('Unsafe archive')
 dest.mkdir(mode=0o700)
 for member in members:
  p=dest/member.name;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb') as out:out.write(stream.extractfile(member).read())
manifest=json.loads((dest/'package_manifest.json').read_text())
expected={r['path'] for r in manifest['files']}|{'package_manifest.json'}
if {p.relative_to(dest).as_posix() for p in dest.rglob('*') if p.is_file()}!=expected:raise ValueError('Unexpected file')
for row in manifest['files']:
 p=dest/row['path']
 if p.stat().st_size!=row['bytes'] or hashlib.sha256(p.read_bytes()).hexdigest()!=row['sha256']:raise ValueError('Package drift')
print(json.dumps({'installed':str(dest),'sha256':sys.argv[1],'manifested_files':len(manifest['files'])}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'install', 'test', 'collect', 'manifest'])
    parser.add_argument('--tag', required=True)
    parser.add_argument('--version', type=int, choices=[1, 2], default=1)
    args = parser.parse_args()
    package = REMOTE + '/environment/runtime-integration-v' + str(args.version)
    run = REMOTE + '/evidence/runtime-integration-qualification-20261022-0' + str(args.version)
    if not re.fullmatch('[a-z0-9-]{1,48}', args.tag): raise ValueError('Invalid transport tag')
    prefix = BASE / ('remote-' + args.action + '-' + args.tag)
    if any(prefix.with_suffix(s).exists() for s in ('.json', '.stdout', '.stderr', '.tar.gz')):
        raise FileExistsError('Preserve transport receipt')
    source = None
    if args.action == 'check':
        command = ['python3', REMOTE + '/host-control/project_guard.py', 'check']
    elif args.action == 'install':
        path = BASE / ('package-v' + str(args.version) + '.tar.gz'); data_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        receipt = json.loads((BASE / ('package-v' + str(args.version) + '.receipt.json')).read_text())
        if data_sha != receipt['archive_sha256']: raise ValueError('Local package differs')
        source = path.open('rb'); command = GUARD + ['python3', '-B', '-c', INSTALL, data_sha, str(args.version)]
    elif args.action == 'test':
        command = GUARD + ['python3', '-B', package + '/engineering/runtime_integration_qualification.py']
    elif args.action == 'manifest':
        code = ('from pathlib import Path;import hashlib,json;root=Path(' + repr(run) + ');'
                'print(json.dumps([{\"path\":p.relative_to(root).as_posix(),\"bytes\":p.stat().st_size,'
                '\"sha256\":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(root.rglob(\"*\")) if p.is_file()]))')
        command = ['python3', '-B', '-c', code]
    else:
        command = ['tar', '-C', run, '-czf', '-', '.']
    output = prefix.with_suffix('.tar.gz' if args.action == 'collect' else '.stdout')
    summary = {'action': args.action, 'version': args.version, 'started_utc': datetime.now(timezone.utc).isoformat()}
    try:
        with output.open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
            result = subprocess.run(SSH + [shlex.join(command)], stdin=source, stdout=out, stderr=err, timeout=900)
        summary['returncode'] = result.returncode
    except Exception as error:
        summary.update(returncode=None, error=type(error).__name__ + ': ' + str(error))
    finally:
        if source: source.close()
        summary['finished_utc'] = datetime.now(timezone.utc).isoformat()
        if output.exists(): summary['output_sha256'] = hashlib.sha256(output.read_bytes()).hexdigest()
        prefix.with_suffix('.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary))
    if args.action != 'collect' and output.exists(): print(output.read_text())
    error = prefix.with_suffix('.stderr')
    if error.exists() and error.stat().st_size: print(error.read_text()[-3000:])
    return 0 if summary['returncode'] == 0 else 1


if __name__ == '__main__': raise SystemExit(main())
