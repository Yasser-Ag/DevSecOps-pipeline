"""Qualify new proxy/input bindings using the already qualified fresh reset primitives."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import tarfile
import time
import traceback
import sys

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from engineering import dynamic_reset_run as reset
from engineering import static_scanner_host as host
from study.dynamic_reset_contract import (ROOT, PYTHON, require, crapi_profile, aigoat_profile,
                                          safe_seed_members, image_identity, sha)
from study.dynamic_scan_contract import ZAP, RESTLER


class Qualification(reset.Qualification):
    def __init__(self, out):
        require(out.parent == ROOT / 'evidence' and re.fullmatch(r'dynamic-profiles-preflight-20261022-0[12]', out.name),
                'Output outside the two-attempt engineering action')
        require(not out.exists() and out.parent.resolve() == out.parent, 'Preserve previous evidence')
        self.out = out
        out.mkdir(mode=0o700)
        self.before = host.snapshot()
        require(not self.before['active_containers'], 'Other workload is active')
        host.write(out / 'host_before.json', self.before)
        self.result = {'started_utc': host.utc(), 'success': False, 'scope': 'dynamic_proxy_and_input_qualification',
                      'scanner_invocations': 0, 'generations': 0, 'cycles': []}
        self.owned, self.networks, self.volumes = {}, [], []
        self.samples, self.child = 0, None
        self.started, self.cycle_started = time.monotonic(), None

    def verify_assets(self, phase):
        super().verify_assets(phase)
        extra = {}
        for image in (ZAP, RESTLER):
            extra[image] = image_identity(image, json.loads(host.capture(['docker', 'image', 'inspect', image]))[0])
        for name, row in reset.load('reference/dynamic_tool_locks.json')['tools'].items():
            require(sha(row['path']) == row['sha256'], 'Dynamic tool launcher changed: ' + name)
            extra[name] = row
        if phase == 'after':
            require(extra == json.loads((self.out / 'assets-before/dynamic_tools.json').read_text()), 'Dynamic tools changed')
        host.write(self.out / ('assets-' + phase) / 'dynamic_tools.json', extra)

    def add_transport(self, config, directory, name, target):
        scanner_net = self.network(name + '-scanner')
        config['networks']['scanner'] = {'external': True, 'name': scanner_net}
        for child in ('control', 'proxy-logs'):
            (directory / child).mkdir()
        host.write(directory / 'control/current.json', {'target': target, 'phase': 'startup', 'mode': 'raw',
            'max_requests': 128, 'roles': {}, 'route_owners': {}})
        target_network = next(k for k in config['networks'] if k != 'scanner')
        common = {'image': PYTHON, 'pull_policy': 'never', 'restart': 'no', 'read_only': True,
            'user': str(os.getuid()) + ':' + str(os.getgid()), 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'pids_limit': 32, 'cpus': 1,
            'labels': {'org.study.project': 'devsecops-electronics', 'org.study.qualification': self.out.name}}
        config['services']['proxy'] = {**common, 'container_name': name + '-proxy',
            'networks': {target_network: {'aliases': ['proxy', 'authorization-proxy', 'audit-proxy']},
                         'scanner': {'aliases': ['proxy', 'authorization-proxy', 'audit-proxy']}},
            'volumes': [str(PACKAGE) + ':/study:ro', str(directory / 'control') + ':/control:ro',
                        str(directory / 'proxy-logs') + ':/logs:rw'],
            'command': ['python3', '-B', '/study/engineering/dynamic_profile_proxy.py'],
            'healthcheck': {'test': ['CMD', 'python3', '-c', "import socket;socket.create_connection(('127.0.0.1',8080),2).close()"],
                            'interval': '2s', 'timeout': '3s', 'retries': 10}}
        config['services']['anchor'] = {**common, 'container_name': name + '-anchor', 'networks': ['scanner'],
                                      'command': ['sleep', 'infinity']}
        probe = 'probe' if target == 'crapi' else 'backend'
        config['services'][probe]['volumes'].append(str(directory / 'control') + ':/control:rw')

    def network_check(self, label, config, ids, directory, target):
        service = 'crapi-web' if target == 'crapi' else 'backend'
        inspected = json.loads(host.capture(['docker', 'inspect', ids[service]]))[0]
        addresses = [v['IPAddress'] for v in inspected['NetworkSettings']['Networks'].values()]
        require(len(addresses) == 1, 'Target must have only the target network')
        target_ip = addresses[0]
        proxy = json.loads(host.capture(['docker', 'inspect', ids['proxy']]))[0]
        anchor = json.loads(host.capture(['docker', 'inspect', ids['anchor']]))[0]
        require(len(proxy['NetworkSettings']['Networks']) == 2 and len(anchor['NetworkSettings']['Networks']) == 1,
                'Unexpected scanner network connectivity')
        port = 80 if target == 'crapi' else 8000
        code = """import json,socket,sys
s=socket.create_connection(('proxy',8080),3);s.close()
blocked=False
try:
 s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2);s.close()
except OSError:blocked=True
print(json.dumps({'proxy_reachable':True,'direct_target_blocked':blocked,'target_ip':sys.argv[1]}))
if not blocked:raise SystemExit(1)
"""
        raw = self.run(label + '-scanner-network', ['docker', 'exec', ids['anchor'], 'python3', '-c', code, target_ip, str(port)], timeout=15)
        host.write(directory / 'scanner_network.json', json.loads(raw))

    def crapi(self):
        label = 'crapi'
        directory = self.out / label
        directory.mkdir()
        state, fixtures = directory / 'state', directory / 'fixtures'
        fixtures.mkdir()
        self.keys(state)
        name = 'dsep-' + self.out.name[-2:] + '-crapi'
        try:
            network = self.network(name)
            volumes = {v: self.volume(name + '-' + v) for v in
                       ('chromadb-data', 'mongodb-data', 'postgresql-data', 'mongo-config')}
            config = crapi_profile(reset.load('reference/crapi_compose.json'), name, state, network, volumes)
            config['services']['probe'] = {'image': PYTHON, 'container_name': name + '-probe',
                'labels': {'org.study.project': 'devsecops-electronics'}, 'command': ['sleep', 'infinity'],
                'networks': ['default'], 'user': str(os.getuid()) + ':' + str(os.getgid()), 'read_only': True,
                'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'cpus': 1,
                'pids_limit': 32, 'pull_policy': 'never', 'restart': 'no',
                'volumes': [str(PACKAGE) + ':/study:ro', str(fixtures) + ':/evidence:rw']}
            self.add_transport(config, directory, name, label)
            argv, ids = self.compose_create(label, config, directory)
            self.run(label + '-start', argv + ['up', '-d', '--no-recreate', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '300'], timeout=360)
            self.run(label + '-reference-setup', ['docker', 'exec', ids['probe'], 'python3', '-B',
                '/study/engineering/dynamic_reset_probe.py', label, '--output', '/evidence'], timeout=240)
            self.network_check(label, config, ids, directory, label)
            self.run(label + '-profiles', ['docker', 'exec', ids['probe'], 'python3', '-B',
                '/study/engineering/dynamic_profile_probe.py', label], timeout=240)
            self.result['cycles'].append({'family': label, 'directory': label,
                'summary': json.loads((fixtures / 'dynamic_profile_summary.json').read_text())})
        finally:
            self.cleanup(directory)

    def aigoat(self):
        label = 'aigoat'
        directory = self.out / label
        directory.mkdir()
        state, fixtures = directory / 'state', directory / 'fixtures'
        state.mkdir()
        fixtures.mkdir()
        seed = reset.load('reference/aigoat_files.json')['seed']
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
        require(len(before) == 1 and before[0]['path'] == 'data/aigoat.db', 'Unexpected reset content')
        host.write(directory / 'seed.json', {'source': seed, 'reset_files': before})
        host.capture(['sudo', '-n', 'chown', '-R', '0:0', state / 'data'])
        name = 'dsep-' + self.out.name[-2:] + '-aigoat'
        try:
            network = self.network(name)
            config = aigoat_profile(reset.load('reference/aigoat_compose.json'), name, state, fixtures, PACKAGE, network)
            self.add_transport(config, directory, name, label)
            argv, ids = self.compose_create(label, config, directory)
            self.run(label + '-start', argv + ['up', '-d', '--no-recreate', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '180'], timeout=240)
            self.run(label + '-reference-setup', ['docker', 'exec', ids['backend'], 'python', '-B',
                '/study/engineering/dynamic_reset_probe.py', label, '--output', '/evidence'], timeout=900)
            self.network_check(label, config, ids, directory, label)
            self.run(label + '-profiles', ['docker', 'exec', ids['backend'], 'python', '-B',
                '/study/engineering/dynamic_profile_probe.py', label], timeout=240)
            self.result['cycles'].append({'family': label, 'directory': label,
                'summary': json.loads((fixtures / 'dynamic_profile_summary.json').read_text())})
        finally:
            self.cleanup(directory)
            host.capture(['sudo', '-n', 'chown', '-R', str(os.getuid()) + ':' + str(os.getgid()), directory])

    def execute(self):
        try:
            self.verify_assets('before')
            for target in ('crapi', 'aigoat'):
                self.cycle_started = time.monotonic()
                getattr(self, target)()
                self.cycle_started = None
                self.save()
                print(json.dumps({'completed': target, 'utc': host.utc()}), flush=True)
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
        print(json.dumps(self.result), flush=True)
        return 0 if self.result['success'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    host.assert_lease()
    def interrupted(signum, frame):
        raise RuntimeError('Qualification interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(Qualification(ROOT / 'evidence' / args.run_id).execute())


if __name__ == '__main__':
    main()
