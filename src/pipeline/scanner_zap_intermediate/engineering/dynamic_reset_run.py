"""Sequential Ubuntu reset qualification. No scanner run or model generation action."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time
import traceback

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from study.dynamic_reset_contract import (ROOT, AIGOAT, PYTHON, require, sha, owned_output,
    crapi_profile, aigoat_profile, runtime_service, runtime_assertion, safe_seed_members, lock_rows, image_identity)
from engineering import static_scanner_host as host

PROBE = '''import json,os
from pathlib import Path
s={l.split(':')[0]:l.split(':')[1].strip() for l in Path('/proc/self/status').read_text().splitlines() if ':' in l}
err=None
try:
 Path('/tmp/reset-probe').write_text('<MASKED:fixture:127>');Path('/tmp/reset-probe').unlink();writable=True
except OSError as e:err=e.errno;writable=False
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'no_new_privs':int(s['NoNewPrivs']), 'cap_eff':s['CapEff'],'rootfs_writable':writable,'write_errno':err}))'''


def load(name):
    return json.loads((PACKAGE / name).read_text())


class Qualification:
    def __init__(self, out):
        self.out = owned_output(out)
        self.out.mkdir(mode=0o700)
        self.before = host.snapshot()
        require(not self.before['active_containers'], 'A workload is already running')
        host.write(self.out / 'host_before.json', self.before)
        self.result = {'started_utc': host.utc(), 'success': False, 'scope': 'engineering_reset_qualification',
                       'scanner_invocations': 0, 'generations': 0, 'cycles': []}
        self.owned, self.networks, self.volumes = {}, [], []
        self.samples = 0
        self.child = None
        self.started = time.monotonic()
        self.cycle_started = None

    def save(self):
        host.write(self.out / 'summary.json', self.result)
        host.write(self.out / 'owned_resources.json', {'containers': self.owned, 'networks': self.networks, 'volumes': self.volumes})

    def sample(self):
        require(time.monotonic() - self.started < 3000, 'Qualification time budget exhausted')
        if self.cycle_started is not None:
            require(time.monotonic() - self.cycle_started < 1800, 'Cycle time budget exhausted')
        value = host.sample(self.owned)
        with (self.out / 'resources.jsonl').open('a') as stream:
            stream.write(json.dumps(value) + '\n')
        self.samples += 1

    def run(self, label, argv, timeout=300, allowed=(0,)):
        started = time.monotonic()
        record = {'argv': [str(a) for a in argv], 'started_utc': host.utc(), 'timeout_seconds': timeout}
        target = self.out / 'commands' / label
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.with_suffix('.json').exists(), 'Preserve command receipt')
        with target.with_suffix('.stdout').open('xb') as stdout, target.with_suffix('.stderr').open('xb') as stderr:
            process = subprocess.Popen(record['argv'], stdout=stdout, stderr=stderr, start_new_session=True,
                                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.child = process
            try:
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        raise TimeoutError(label)
                    self.sample()
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        pass
                record['returncode'] = process.returncode
            except BaseException as error:
                record['error'] = type(error).__name__ + ': ' + str(error)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                record['returncode'] = process.returncode
                raise
            finally:
                self.child = None
                record.update(finished_utc=host.utc(), elapsed_seconds=time.monotonic() - started)
                host.write(target.with_suffix('.json'), record)
        require(record['returncode'] in allowed, 'Command failed: ' + label)
        return target.with_suffix('.stdout').read_text()

    def verify_assets(self, phase):
        evidence = self.out / ('assets-' + phase)
        evidence.mkdir()
        host.write(evidence / 'package_verification.json', host.verify_package(PACKAGE))
        reference = load('reference/crapi_source.json')
        source = ROOT / 'targets/crapi'
        require(host.capture(['git', '-C', source, 'rev-parse', 'HEAD']) == reference['commit'], 'crAPI commit drift')
        for item in reference['files']:
            require(sha(source / item['path']) == item['sha256'], 'crAPI source drift: ' + item['path'])
        for item in reference['builds']:
            manifest = json.loads(Path(item['path']).read_text())
            require(manifest['success'] and manifest['source_commit'] == reference['commit'] and
                    manifest['runtime_image'] == item['runtime_image'], 'crAPI build identity drift')
        ai_files = load('reference/aigoat_files.json')
        for item in ai_files.values():
            require(sha(item['path']) == item['sha256'], 'AIGoat seed/config drift')
        locks = load('reference/aigoat_target_locks.json')
        for key, directory in [('source_files', AIGOAT / 'source' / ('AIGoat-' + locks['source_commit'])),
                               ('embedding_files', AIGOAT / 'embedding')]:
            for item in lock_rows(locks[key]):
                require(sha(directory / item['path']) == item['sha256'], 'AIGoat source/embedding drift')
        # Existing model blobs may be root-owned; this read-only verifier has one fixed root.
        code = """import json,pathlib,sys
sys.path.insert(0,sys.argv[1])
from study.dynamic_reset_contract import model_inventory
r=pathlib.Path('<LAB_ROOT>/environment/aigoat-qualification-20261012-01/state/models/models')
expected=json.loads((pathlib.Path(sys.argv[1])/'reference/aigoat_model_files.json').read_text())
print(json.dumps(model_inventory(r,expected)))"""
        model_files = json.loads(host.capture(['sudo', '-n', 'python3', '-B', '-c', code, PACKAGE], timeout=180))
        if phase == 'after':
            require(model_files == json.loads((self.out / 'assets-before/model_files_verified.json').read_text()),
                    'Model weights or runtime metadata changed during qualification')
        host.write(evidence / 'model_files_verified.json', model_files)
        images = {v['image'] for k, v in load('reference/crapi_compose.json')['services'].items()
                  if k not in {'lab-ingress', 'audit-proxy'}}
        from study.dynamic_reset_contract import BACKEND, OLLAMA
        images |= {PYTHON, BACKEND, OLLAMA}
        images |= {row['service']['image'] for row in load('reference/runtime_controls.json')}
        rows = {}
        for image in sorted(images):
            value = json.loads(host.capture(['docker', 'image', 'inspect', image]))[0]
            rows[image] = image_identity(image, value)
        if phase == 'after':
            require(rows == json.loads((self.out / 'assets-before/image_identities.json').read_text()),
                    'Resolved input image identities changed')
        host.write(evidence / 'image_identities.json', rows)
        self.sample()

    def network(self, name):
        known = host.capture(['docker', 'network', 'ls', '--format', '{{.Name}}']).split()
        require(name not in known, 'Existing network name')
        identity = host.capture(['docker', 'network', 'create', '--internal', '--label',
                                 'org.study.reset=' + self.out.name, name])
        self.networks.append({'id': identity, 'name': name})
        self.save()
        inspected = json.loads(host.capture(['docker', 'network', 'inspect', identity]))[0]
        host.write(self.out / ('network-' + name + '.json'), inspected)
        require(inspected['Internal'] and inspected['Id'] == identity, 'Unexpected target network')
        return name

    def volume(self, name):
        require(name not in host.capture(['docker', 'volume', 'ls', '-q']).split(), 'Existing volume name')
        identity = host.capture(['docker', 'volume', 'create', '--label', 'org.study.reset=' + self.out.name, name])
        require(identity == name, 'Unexpected volume identity')
        self.volumes.append(name)
        self.save()
        return name

    def compose_create(self, label, config, directory):
        path = directory / (label + '.compose.json')
        require(not path.exists(), 'Preserve previous target configuration')
        host.write(path, config)
        names = [c['container_name'] for c in config['services'].values()]
        existing = set(host.capture(['docker', 'ps', '-a', '--format', '{{.Names}}']).split())
        require(not existing.intersection(names), 'Container name already exists')
        argv = ['docker', 'compose', '-p', config['name'], '-f', path]
        try:
            self.run(label + '-create', argv + ['create', '--pull', 'never'], timeout=240)
        finally:
            # A failed compose create may still have made some containers. Discover
            # only reserved names and reject any pre-existing ID before recording.
            for name in names:
                process = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True)
                if process.returncode:
                    continue
                item = json.loads(process.stdout)[0]
                require(item['Id'] not in self.before['container_config_hashes'], 'Existing container cannot be owned')
                require(item['Config']['Labels'].get('org.study.project') == 'devsecops-electronics', 'Ownership label differs')
                require(not item['HostConfig'].get('PortBindings'), 'Unexpected published port')
                require(not item['HostConfig'].get('Privileged'), 'Unexpected privilege')
                self.owned[item['Id']] = name
                host.write(directory / (name + '.created.json'), item)
                self.save()
        return argv, {key: next(i for i, n in self.owned.items() if n == cfg['container_name'])
                      for key, cfg in config['services'].items()}

    def cleanup(self, directory):
        """Delete only exact newly created IDs after recording state and logs."""
        errors = []
        for identity, name in list(self.owned.items()):
            try:
                item = json.loads(host.capture(['docker', 'inspect', identity]))[0]
                host.write(directory / (name + '.final.json'), item)
                for suffix, command in [('stdout', ['docker', 'logs', identity]),
                                        ('stop', ['docker', 'stop', '-t', '10', identity])]:
                    p = subprocess.run(command, capture_output=True, timeout=90)
                    (directory / (name + '.' + suffix + '.log')).write_bytes(p.stdout + p.stderr)
                    require(p.returncode == 0, 'Container capture/stop failed')
                require(identity not in self.before['container_config_hashes'], 'Refuse old container removal')
                host.capture(['docker', 'rm', '-v', identity], timeout=120)
                del self.owned[identity]
            except Exception as error:
                errors.append(str(error))
        for volume in list(self.volumes):
            try:
                require(volume not in self.before['volumes'], 'Refuse old volume removal')
                host.capture(['docker', 'volume', 'rm', volume], timeout=120)
                self.volumes.remove(volume)
            except Exception as error:
                errors.append(str(error))
        for network in list(self.networks):
            try:
                require(network['id'] not in self.before['networks'], 'Refuse old network removal')
                host.capture(['docker', 'network', 'rm', network['id']], timeout=120)
                self.networks.remove(network)
            except Exception as error:
                errors.append(str(error))
        self.save()
        require(not errors, 'Owned cleanup failed: ' + '; '.join(errors))

    def keys(self, state):
        source = ROOT / 'targets/crapi'
        commit = load('reference/crapi_source.json')['commit']
        names = host.capture(['git', '-C', source, 'ls-tree', '-r', '--name-only', commit, '--', 'deploy/docker/keys']).splitlines()
        require(names, 'Missing crAPI key seed')
        rows = []
        for name in names:
            rel = Path(name).relative_to('deploy/docker/keys')
            require('..' not in rel.parts, 'Invalid seed key path')
            payload = subprocess.check_output(['git', '-C', str(source), 'show', commit + ':' + name])
            require(payload == (source / name).read_bytes(), 'Working key seed differs from pinned commit')
            target = state / 'keys' / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            rows.append({'path': str(rel), 'sha256': sha(target), 'bytes': len(payload)})
        host.write(state / 'key_seed.json', rows)

    def crapi(self, number):
        label = 'crapi-' + str(number)
        directory = self.out / label
        directory.mkdir()
        state, fixtures = directory / 'state', directory / 'fixtures'
        fixtures.mkdir()
        self.keys(state)
        name = 'dser-' + self.out.name[-2:] + '-' + label
        try:
            network = self.network(name)
            volumes = {v: self.volume(name + '-' + v) for v in
                       ('chromadb-data', 'mongodb-data', 'postgresql-data', 'mongo-config')}
            config = crapi_profile(load('reference/crapi_compose.json'), name, state, network, volumes)
            config['services']['probe'] = {'image': PYTHON, 'container_name': name + '-probe',
                'labels': {'org.study.project': 'devsecops-electronics', 'org.study.reset': name},
                'command': ['sleep', 'infinity'], 'networks': ['default'], 'user': str(os.getuid()) + ':' + str(os.getgid()),
                'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                'mem_limit': '128m', 'cpus': 1, 'pids_limit': 32, 'pull_policy': 'never', 'restart': 'no',
                'volumes': [str(PACKAGE) + ':/study:ro', str(fixtures) + ':/evidence:rw']}
            argv, ids = self.compose_create(label, config, directory)
            self.run(label + '-start', argv + ['up', '-d', '--no-recreate', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '300'], timeout=360)
            self.run(label + '-reference', ['docker', 'exec', ids['probe'], 'python3', '-B',
                     '/study/engineering/dynamic_reset_probe.py', 'crapi', '--output', '/evidence'], timeout=240)
            summary = json.loads((fixtures / 'summary.json').read_text())
            self.result['cycles'].append({'family': 'crapi', 'cycle': number, 'summary': summary,
                                          'fresh_volumes': list(volumes.values()), 'directory': label})
        finally:
            self.cleanup(directory)

    def aigoat(self, number):
        label = 'aigoat-' + str(number)
        directory = self.out / label
        directory.mkdir()
        state, fixtures = directory / 'state', directory / 'fixtures'
        state.mkdir()
        fixtures.mkdir()
        seed = load('reference/aigoat_files.json')['seed']
        with tarfile.open(seed['path'], 'r:gz') as archive:
            members = archive.getmembers()
            safe_seed_members(members)
            for member in members:
                target = state / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('xb') as stream:
                        stream.write(archive.extractfile(member).read())
        before = host.inventory(state)
        require(len(before) == 1 and before[0]['path'] == 'data/aigoat.db', 'Expected only the original SQLite seed')
        host.write(directory / 'seed.json', {'source': seed, 'reset_files': before, 'chroma_present_before_start': False})
        # Same root-owned target data as the previously qualified backend, scoped
        # exclusively to this newly created state directory.
        host.capture(['sudo', '-n', 'chown', '-R', '0:0', state / 'data'])
        name = 'dser-' + self.out.name[-2:] + '-' + label
        try:
            network = self.network(name)
            config = aigoat_profile(load('reference/aigoat_compose.json'), name, state, fixtures, PACKAGE, network)
            argv, ids = self.compose_create(label, config, directory)
            self.run(label + '-start', argv + ['up', '-d', '--no-recreate', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '180'], timeout=240)
            self.run(label + '-reference', ['docker', 'exec', ids['backend'], 'python', '-B',
                     '/study/engineering/dynamic_reset_probe.py', 'aigoat', '--output', '/evidence'], timeout=900)
            summary = json.loads((fixtures / 'summary.json').read_text())
            self.result['cycles'].append({'family': 'aigoat', 'cycle': number, 'summary': summary,
                                          'seed_sha256': seed['sha256'], 'directory': label})
        finally:
            self.cleanup(directory)
            # Allow private local collection without changing any earlier evidence.
            host.capture(['sudo', '-n', 'chown', '-R', str(os.getuid()) + ':' + str(os.getgid()), directory])

    def runtime(self, number):
        directory = self.out / ('runtime-' + str(number))
        directory.mkdir()
        assertions = []
        for row in load('reference/runtime_controls.json'):
            label = 'runtime-' + str(number) + '-' + row['case_id'].lower()
            name = 'dser-' + self.out.name[-2:] + '-' + label
            cfg = runtime_service(row, name)
            cfg['command'] = ['python', '-c', PROBE]
            try:
                argv, ids = self.compose_create(label, {'name': name, 'services': {'probe': cfg}}, directory)
                raw = self.run(label + '-probe', ['docker', 'start', '-a', ids['probe']], timeout=60)
                state = json.loads(host.capture(['docker', 'inspect', ids['probe']]))[0]['State']
                require(state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled'], 'Runtime probe failed')
                value = json.loads(raw)
                assertions.append({**runtime_assertion(row, value), 'raw': value})
            finally:
                self.cleanup(directory)
        host.write(directory / 'assertions.json', assertions)
        self.result['cycles'].append({'family': 'runtime', 'cycle': number, 'controls': len(assertions),
                                      'assertions': assertions, 'directory': directory.name})

    def execute(self):
        try:
            self.verify_assets('before')
            for family in ('runtime', 'crapi', 'aigoat'):
                for number in (1, 2):
                    self.cycle_started = time.monotonic()
                    getattr(self, family)(number)
                    self.cycle_started = None
                    self.sample()
                    self.save()
                    print(json.dumps({'completed': family, 'cycle': number, 'utc': host.utc()}), flush=True)
                rows = [r for r in self.result['cycles'] if r['family'] == family]
                if family != 'runtime':
                    require(rows[0]['summary']['signature'] == rows[1]['summary']['signature'], 'Reset behavior differs: ' + family)
                else:
                    require(rows[0]['assertions'] == rows[1]['assertions'], 'Runtime controls differ across resets')
            self.verify_assets('after')
            self.result['success'] = True
        except Exception as error:
            self.result['error'] = type(error).__name__ + ': ' + str(error)
            (self.out / 'failure_trace.txt').write_text(traceback.format_exc())
        finally:
            after = host.snapshot()
            host.write(self.out / 'host_after.json', after)
            self.result['preservation_passed'] = host.preserved(self.before, after)
            self.result['success'] &= self.result['preservation_passed']
            self.result.update(finished_utc=host.utc(), host_samples=self.samples,
                               existing_containers=len(self.before['container_config_hashes']))
            self.save()
        print(json.dumps({k: v for k, v in self.result.items() if k != 'cycles'}), flush=True)
        return 0 if self.result['success'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    host.assert_lease()
    raise SystemExit(Qualification(ROOT / 'evidence' / args.run_id).execute())


if __name__ == '__main__':
    main()
