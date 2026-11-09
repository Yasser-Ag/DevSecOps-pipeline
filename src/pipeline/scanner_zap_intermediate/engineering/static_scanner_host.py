"""Shared-host lease, preservation and file identity helpers for static scans."""
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess

from study.static_scan_contract import require, sha

ROOT = Path('<LAB_ROOT>')
CONTROL = Path('<OTHER_PROJECT_2>/research-host')


def utc():
    return datetime.now(timezone.utc).isoformat()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def capture(argv, timeout=120):
    return subprocess.check_output([str(a) for a in argv], text=True, timeout=timeout).strip()


def assert_lease(path=CONTROL / 'execution.lock', descriptors=Path('/proc/self/fd')):
    identity = path.stat()
    matching = []
    for item in descriptors.iterdir():
        try:
            info = os.fstat(int(item.name))
            if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                matching.append(int(item.name))
        except (OSError, ValueError):
            pass
    require(matching, 'No inherited shared-host lease')
    with path.open('r+') as independent:
        try:
            fcntl.flock(independent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return matching
        fcntl.flock(independent.fileno(), fcntl.LOCK_UN)
    raise ValueError('Shared-host lease is not held')


def inventory(path, allow_links=False):
    """Retain links explicitly for runtimes; scanner input trees reject links."""
    path = Path(path)
    require(path.exists(), 'Missing asset: ' + str(path))
    require(allow_links or not path.is_symlink(), 'Symbolic input root: ' + str(path))
    rows = []
    for item in ([path] if path.is_file() else sorted(path.rglob('*'))):
        if '__pycache__' in item.parts:
            continue
        relative = '.' if item == path else item.relative_to(path).as_posix()
        if item.is_symlink():
            require(allow_links, 'Symbolic input link: ' + str(item))
            row = {'path': relative, 'kind': 'symlink', 'target': os.readlink(item)}
            if item.is_file():
                row.update(bytes=item.stat().st_size, sha256=sha(item))
            rows.append(row)
        elif item.is_file():
            rows.append({'path': relative, 'kind': 'file', 'bytes': item.stat().st_size, 'sha256': sha(item)})
    return rows


def snapshot():
    ids = capture(['docker', 'ps', '-a', '-q', '--no-trunc']).split()
    containers = json.loads(capture(['docker', 'inspect', *ids])) if ids else []
    import hashlib
    return {'utc': utc(), 'container_config_hashes': {
        c['Id']: hashlib.sha256(json.dumps({k: v for k, v in c.items() if k not in ('State', 'NetworkSettings')},
                                         sort_keys=True).encode()).hexdigest() for c in containers},
        'images': sorted(set(capture(['docker', 'image', 'ls', '-q', '--no-trunc']).split())),
        'volumes': sorted(capture(['docker', 'volume', 'ls', '-q']).split()),
        'networks': sorted(capture(['docker', 'network', 'ls', '-q', '--no-trunc']).split()),
        'registry_sha256': sha(CONTROL / 'projects.json'),
        'active_containers': capture(['docker', 'ps', '-q', '--no-trunc']).split(),
        'other_project_paths': {name: {'resolved': str(Path(name).resolve()), 'allocated_bytes':
            int(capture(['sudo', '-n', 'du', '-sx', '-B1', str(Path(name).resolve())]).split()[0])}
            for name in ('<USER_HOME>/<OTHER_PROJECT_1>', '<USER_HOME>/<OTHER_PROJECT_2>')}}


def preserved(before, after):
    return (all(after['container_config_hashes'].get(k) == v for k, v in before['container_config_hashes'].items())
            and all(before[k] == after[k] for k in ('images', 'volumes', 'networks', 'registry_sha256', 'other_project_paths'))
            and not after['active_containers'])


def sample(allowed=()):
    ids = capture(['docker', 'ps', '-q', '--no-trunc']).split()
    require(not set(ids) - set(allowed), 'Unrelated container became active')
    names = set(capture(['ps', '-eo', 'comm=']).splitlines())
    require(not names & {'Runner.Worker', 'llama-server'}, 'Competing model/runner became active')
    memory = {line.split(':')[0]: int(line.split()[1]) * 1024
              for line in Path('/proc/meminfo').read_text().splitlines() if len(line.split()) >= 2}
    row = {'utc': utc(), 'root_available_bytes': shutil.disk_usage('/').free,
           'host_available_bytes': memory['MemAvailable'], 'active_container_ids': ids}
    require(row['root_available_bytes'] >= 20 * 1024**3, 'Disk reserve reached')
    require(row['host_available_bytes'] >= 2 * 1024**3, 'Memory reserve reached')
    if ids:
        row['container_stats'] = [json.loads(line) for line in capture(
            ['docker', 'stats', '--no-stream', '--format', '{{json .}}', *ids]).splitlines()]
    return row


def prepare_inputs(suite, locked, destination):
    """Copy only locked input artifacts, never prior results or timing receipts."""
    require(not destination.exists(), 'Fresh suite destination required')
    destination.mkdir(parents=True)
    for item in locked:
        source, target = Path(item['source']), destination / item['destination']
        require(inventory(source) == item['files'], 'Input source drift: ' + str(source))
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns('__pycache__'))
        else:
            shutil.copyfile(source, target)
        require(inventory(target) == item['files'], 'Input reset differs: ' + str(target))
    return {'prepared_utc': utc(), 'suite': suite, 'fresh_destination': str(destination),
            'copied_inputs': len(locked), 'copied_bytes': sum(r.get('bytes', 0) for x in locked for r in x['files']),
            'prior_reports_copied': False}


def verify_inputs(locked, destination):
    for item in locked:
        require(inventory(destination / item['destination']) == item['files'], 'Prepared input changed')


def verify_package(package):
    manifest = json.loads((package / 'package_manifest.json').read_text())
    expected = {r['path'] for r in manifest['files']} | {'package_manifest.json'}
    require({p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()} == expected, 'Package allowlist differs')
    for row in manifest['files']:
        path = package / row['path']
        require(not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'Package identity drift')
    return manifest
