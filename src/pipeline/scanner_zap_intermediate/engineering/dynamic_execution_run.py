"""Sequential fresh-target dynamic execution, gated by an exact protocol release.

Preflight uses only a synthetic HTTP server, namespace/container canaries and
an offline grammar compile. It does not scan crAPI/AIGoat or generate answers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from engineering import static_scanner_host as host
from engineering import dynamic_reset_run as reset
from engineering.dynamic_profile_run import Qualification as ProxyQualification
from engineering.dynamic_profile_probe import write
from engineering import dynamic_execution_assets as assets
from study.dynamic_reset_contract import ROOT, PYTHON, require, sha, crapi_profile, aigoat_profile, safe_seed_members
from study.dynamic_scan_contract import ZAP, RESTLER, SCHEMATHESIS, profile, inputs, scanner_command, checker_command, LOCATION
from study.dynamic_execution_contract import job, execution_plan, require_release, native_report, completion
from study.api_references import ownership, bearer_digest


def load(path):
    return json.loads(Path(path).read_text())


def private_environment(directory):
    d = Path(directory)
    return {'HOME': str(d / 'home'), 'XDG_CACHE_HOME': str(d / 'cache'), 'XDG_CONFIG_HOME': str(d / 'config'),
            'TMPDIR': '/tmp', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
            'PYTHONPYCACHEPREFIX': str(d / 'cache/pycache'), 'GOMAXPROCS': '2', 'OMP_NUM_THREADS': '2',
            'OPENBLAS_NUM_THREADS': '2', 'NO_COLOR': '1', 'LANG': 'C.UTF-8'}


class Controller(ProxyQualification):
    def __init__(self, out, mode, job_id=None, locks=None, release=None):
        require(out.parent == ROOT / 'evidence' and out.parent.resolve() == out.parent, 'Unowned output root')
        if mode == 'preflight':
            require(re.fullmatch(r'dynamic-execution-preflight-20261022-0[12]', out.name), 'Preflight outside two-attempt action')
        else:
            require(re.fullmatch(r'dynamic-final-[a-z0-9-]{1,100}', out.name), 'Invalid final run identity')
            self.job = job(job_id)
            require_release(load(release), PACKAGE, locks)
            assets.verify(load(locks))
        require(not out.exists(), 'Preserve existing evidence')
        self.out, self.mode, self.locks = out, mode, locks
        out.mkdir(mode=0o700)
        self.before = host.snapshot()
        require(not self.before['active_containers'], 'Other workload is active')
        host.write(out / 'host_before.json', self.before)
        self.result = {'started_utc': host.utc(), 'success': False, 'mode': mode,
                       'scope': 'engineering_canaries' if mode == 'preflight' else 'released_final_dynamic_job',
                       'job': None if mode == 'preflight' else self.job,
                       'scanner_invocations': 0, 'target_generation_requests': 0, 'cycles': []}
        if mode == 'execute':
            host.write(out / 'protocol_release.json', load(release))
            self.result['protocol_release_sha256'] = sha(release)
            self.result['released_asset_locks_sha256'] = sha(locks)
        self.owned, self.networks, self.volumes = {}, [], []
        self.samples, self.child = 0, None
        self.started, self.cycle_started = time.monotonic(), None
        self.name = 'dsex-' + hashlib.sha256(out.name.encode()).hexdigest()[:12]

    def sample(self):
        require(time.monotonic() - self.started < (1200 if self.mode == 'preflight' else 3600), 'Action time budget exhausted')
        ids = host.capture(['docker', 'ps', '-q', '--no-trunc']).split()
        require(not set(ids) - self.owned.keys(), 'Unrelated container became active')
        # Accept a target Ollama process only when its cgroup belongs to an owned ID.
        for line in host.capture(['ps', '-eo', 'pid=,comm=']).splitlines():
            pid, name = line.split(None, 1)
            if name not in ('Runner.Worker', 'llama-server', 'ollama'): continue
            try: cg = Path('/proc', pid, 'cgroup').read_text()
            except FileNotFoundError: continue
            require(any(i in cg for i in self.owned), 'Unrelated inference/runner process became active')
        memory = {line.split(':')[0]: int(line.split()[1]) * 1024
                  for line in Path('/proc/meminfo').read_text().splitlines() if len(line.split()) >= 2}
        row = {'utc': host.utc(), 'root_available_bytes': shutil.disk_usage('/').free,
               'host_available_bytes': memory['MemAvailable'], 'active_container_ids': ids}
        if self.child is not None:
            processes = []
            for path in Path('/proc').glob('[0-9]*/stat'):
                try:
                    fields = path.read_text().rsplit(')', 1)[1].split()
                    if int(fields[2]) == self.child.pid:
                        processes.append({'pid': int(path.parent.name), 'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE')})
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
            row['command_group'] = {'leader': self.child.pid, 'processes': processes,
                                    'aggregate_rss_bytes': sum(p['rss_bytes'] for p in processes),
                                    'scope': 'sampled host command group; container workload measured by its own cgroup'}
        require(row['root_available_bytes'] >= 20 * 1024**3, 'Disk reserve reached')
        require(row['host_available_bytes'] >= 2 * 1024**3, 'Memory reserve reached')
        row['container_cgroups'] = {}
        if ids:
            for item in json.loads(host.capture(['docker', 'inspect', *ids])):
                pid = item['State']['Pid']
                try:
                    cg = next(l[3:] for l in Path('/proc', str(pid), 'cgroup').read_text().splitlines() if l.startswith('0::'))
                    root = Path('/sys/fs/cgroup') / cg.lstrip('/')
                    row['container_cgroups'][item['Id']] = {n: (root / n).read_text()
                        for n in ('cpu.stat', 'memory.current', 'memory.peak', 'memory.events') if (root / n).exists()}
                except (FileNotFoundError, StopIteration):
                    row['container_cgroups'][item['Id']] = {'unavailable': 'process ended during sample'}
        with (self.out / 'resources.jsonl').open('a') as stream: stream.write(json.dumps(row) + '\n')
        self.samples += 1

    def run(self, label, argv, timeout=300, allowed=(0,)):
        started = time.monotonic()
        path = self.out / 'commands' / label
        path.parent.mkdir(parents=True, exist_ok=True)
        require(not path.with_suffix('.json').exists(), 'Preserve command receipt')
        record = {'argv': list(map(str, argv)), 'started_utc': host.utc(), 'timeout_seconds': timeout}
        with path.with_suffix('.stdout').open('xb') as stdout, path.with_suffix('.stderr').open('xb') as stderr:
            proc = subprocess.Popen(record['argv'], stdout=stdout, stderr=stderr, start_new_session=True,
                                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.child = proc
            try:
                while proc.poll() is None:
                    require(time.monotonic() - started <= timeout, 'Command timeout: ' + label)
                    self.sample()
                    try: proc.wait(timeout=1)
                    except subprocess.TimeoutExpired: pass
                record['returncode'] = proc.returncode
            except BaseException as error:
                record['error'] = type(error).__name__ + ': ' + str(error)
                if proc.poll() is None:
                    # Namespace commands contain root descendants; kill only this new process group.
                    subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(proc.pid)], capture_output=True, timeout=15)
                    try: proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        subprocess.run(['sudo', '-n', 'kill', '-KILL', '--', '-' + str(proc.pid)], capture_output=True, timeout=15)
                        proc.wait(timeout=10)
                record['returncode'] = proc.returncode
                raise
            finally:
                self.child = None
                record.update(finished_utc=host.utc(), elapsed_seconds=time.monotonic() - started)
                host.write(path.with_suffix('.json'), record)
        require(record['returncode'] in allowed, 'Command failed: ' + label)
        return path.with_suffix('.stdout').read_text()

    def measured(self, label, command, work, base, ids, tool, compile=False, canary=False):
        """Use identical wrappers and limits for canaries and real scanner jobs."""
        require(self.mode == 'execute' or canary or compile, 'Scientific command blocked in preflight')
        work.mkdir(exist_ok=True)
        for child in ('home', 'cache', 'config'): (work / child).mkdir(exist_ok=True)
        container = tool in ('zap', 'restler')
        inner = Path('/zap/wrk') if tool == 'zap' else Path('/work') if container else work
        spec = {'argv': command['argv'], 'cwd': str(inner), 'container': container,
                'environment': {**private_environment(inner), **command.get('environment_additions', {})},
                'accounting_path': str(inner / (label + '-accounting.json'))}
        if not container:
            anchor = json.loads(host.capture(['docker', 'inspect', ids['anchor']]))[0]
            pid = anchor['State']['Pid']; require(pid > 0, 'Scanner anchor is stopped')
            spec.update(host_work=str(work), wrapper=str(PACKAGE / 'engineering/dynamic_job_wrapper.py'),
                        host_mount_ns=os.readlink('/proc/self/ns/mnt'), host_network_ns=os.readlink('/proc/self/ns/net'),
                        scanner_network_ns=host.capture(['sudo', '-n', 'readlink', '/proc/' + str(pid) + '/ns/net']))
            spec['environment']['PATH'] = '/usr/local/bin:/usr/bin:/bin'
            write(work / (label + '-spec.json'), spec)
            argv = ['sudo', '-n', 'nsenter', '--target', str(pid), '--net', '--', 'unshare', '--mount', '--pid',
                    '--fork', '--mount-proc', '--kill-child=SIGKILL', '--', 'python3', '-B',
                    PACKAGE / 'engineering/dynamic_native_isolate.py', work / (label + '-spec.json')]
            owned_id = None
        else:
            write(work / (label + '-spec.json'), spec)
            image = ZAP if tool == 'zap' else RESTLER
            network = 'none' if compile else next(n['name'] for n in self.networks if n['name'].endswith('-scanner'))
            name = self.name + '-' + label
            mounts = [str(PACKAGE) + ':/study:ro', str(work) + ':' + str(inner) + ':rw']
            if tool == 'restler' and not compile and not canary:
                mounts.append(str(work.parent / 'compile/Compile') + ':/grammar:ro')
            argv = ['docker', 'create', '--name', name, '--pull', 'never', '--network', network,
                    '--label', 'org.study.project=devsecops-electronics', '--label', 'org.study.execution=' + self.out.name,
                    '--user', str(os.getuid()) + ':' + str(os.getgid()), '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges=true', '--read-only', '--cpus', '2',
                    '--memory', '3g' if tool == 'zap' else '2g', '--memory-swap', '3g' if tool == 'zap' else '2g',
                    '--pids-limit', '256', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777',
                    '--workdir', str(inner), '--entrypoint', 'python3']
            for mount in mounts: argv += ['-v', mount]
            argv += [image, '-B', '/study/engineering/dynamic_job_wrapper.py', str(inner / (label + '-spec.json'))]
            owned_id = host.capture(argv)
            require(owned_id not in self.before['container_config_hashes'], 'Refuse existing container')
            self.owned[owned_id] = name; self.save()
            inspection = json.loads(host.capture(['docker', 'inspect', owned_id]))[0]
            host.write(work / (label + '-container.json'), inspection)
            self.validate_container(inspection, mounts, network, tool)
            argv = ['docker', 'start', '-a', owned_id]
        try:
            self.run(label, argv, timeout=command['timeout_seconds'], allowed=tuple(range(256)))
        finally:
            if owned_id:
                # Stopping the CLI is not equivalent to stopping its container.
                host.capture(['docker', 'stop', '-t', '5', owned_id], timeout=45)
        record = load(self.out / 'commands' / (label + '.json'))
        counters = work / (label + '-accounting.json')
        record['accounting'] = load(counters) if counters.exists() else None
        if container:
            final = json.loads(host.capture(['docker', 'inspect', owned_id]))[0]
            host.write(work / (label + '-container-final.json'), final)
            record['container_state'] = final['State']
            record['returncode'] = final['State']['ExitCode']
        host.write(work / (label + '-execution.json'), record)
        return record

    @staticmethod
    def validate_container(item, mounts, network, tool):
        config = item['HostConfig']
        expected = {tuple(v.rsplit(':', 2)) for v in mounts}
        actual = {(v['Source'], v['Destination'], 'rw' if v['RW'] else 'ro') for v in item['Mounts'] if v['Type'] == 'bind'}
        require(actual == expected, 'Unexpected scanner mount')
        require(not config.get('PortBindings') and not config['Privileged'] and config['ReadonlyRootfs'], 'Unsafe scanner container')
        require(config['NetworkMode'] == network and config['CapDrop'] == ['ALL'] and
                any('no-new-privileges' in v for v in config['SecurityOpt']), 'Scanner namespace/capability drift')
        memory = (3 if tool == 'zap' else 2) * 1024**3
        require(config['Memory'] == config['MemorySwap'] == memory and config['NanoCpus'] == 2 * 10**9 and
                config['PidsLimit'] == 256, 'Scanner resource budget drift')

    def state(self, target, directory):
        state, fixture = directory / 'state', directory / 'fixtures'
        fixture.mkdir()
        name = self.name
        network = self.network(name + '-target')
        if target == 'crapi':
            self.keys(state)
            volumes = {v: self.volume(name + '-' + v) for v in ('chromadb-data', 'mongodb-data', 'postgresql-data', 'mongo-config')}
            config = crapi_profile(reset.load('reference/crapi_compose.json'), name, state, network, volumes)
            config['services']['probe'] = {'image': PYTHON, 'container_name': name + '-probe',
                'labels': {'org.study.project': 'devsecops-electronics'}, 'command': ['sleep', 'infinity'],
                'networks': ['default'], 'user': str(os.getuid()) + ':' + str(os.getgid()), 'read_only': True,
                'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'memswap_limit': '128m',
                'cpus': 1, 'pids_limit': 32, 'pull_policy': 'never', 'restart': 'no',
                'volumes': [str(PACKAGE) + ':/study:ro', str(fixture) + ':/evidence:rw']}
        else:
            state.mkdir()
            seed = reset.load('reference/aigoat_files.json')['seed']
            with tarfile.open(seed['path'], 'r:gz') as archive:
                members = archive.getmembers(); safe_seed_members(members)
                for member in members:
                    path = state / member.name
                    if member.isdir(): path.mkdir(parents=True, exist_ok=True)
                    else:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        with path.open('xb') as stream: stream.write(archive.extractfile(member).read())
            host.write(directory / 'seed.json', {'source': seed, 'reset_files': host.inventory(state)})
            host.capture(['sudo', '-n', 'chown', '-R', '0:0', state / 'data'])
            config = aigoat_profile(reset.load('reference/aigoat_compose.json'), name, state, fixture, PACKAGE, network)
        self.add_transport(config, directory, name, target)
        argv, ids = self.compose_create('target', config, directory)
        self.run('target-start', argv + ['up', '-d', '--no-recreate', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '300'], timeout=360)
        probe = ids['probe' if target == 'crapi' else 'backend']
        python = 'python3' if target == 'crapi' else 'python'
        self.run('fixture-setup', ['docker', 'exec', probe, python, '-B',
                 '/study/engineering/dynamic_reset_probe.py', target, '--output', '/evidence'], timeout=900)
        if target == 'aigoat':
            host.capture(['sudo', '-n', 'chown', '-R', str(os.getuid()) + ':' + str(os.getgid()), fixture])
        self.network_check('target', config, ids, directory, target)
        proxy = json.loads(host.capture(['docker', 'inspect', ids['proxy']]))[0]
        scanner_network = next(n['name'] for n in self.networks if n['name'].endswith('-scanner'))
        base = 'http://' + proxy['NetworkSettings']['Networks'][scanner_network]['IPAddress'] + ':8080'
        return fixture, ids, base

    def control(self, target, fixture, phase, mode='raw', scope='<MASKED:fixture:127>', maximum=128):
        actors = fixture if target == 'crapi' else fixture['actors']
        roles = {bearer_digest(v['token']): k for k, v in actors.items()}
        invalid = 'invalid-development-token' if target == 'crapi' else 'invalid-aigoat-qualification-token'
        roles[bearer_digest(invalid)] = 'invalid'
        routes = {LOCATION.format(v): k for k, v in ownership(fixture).items()} if target == 'crapi' else {}
        write(self.out / 'target/control/current.json', {'target': target, 'phase': phase, 'mode': mode,
              'scope': scope, 'max_requests': maximum, 'roles': roles, 'route_owners': routes})

    def reference(self, target, ids, fixture, name, mode):
        self.control(target, fixture, name, mode)
        self.run('reference-' + name, ['docker', 'exec', ids['probe' if target == 'crapi' else 'backend'],
            'python3' if target == 'crapi' else 'python', '-B', '/study/engineering/dynamic_execution_probe.py',
            'reference', '--target', target, '--name', name, '--mode', mode], timeout=240)

    def final_job(self, directory):
        generator = self.job['kind'] == 'target_generation'
        row = {'target': 'aigoat'} if generator else profile(self.job['profile_id'])
        fixture_path, ids, base = self.state(row['target'], directory)
        fixture = load(fixture_path / 'private_fixture.json')
        mode = row.get('mode') if row.get('tool') == 'restler' else 'raw'
        self.reference(row['target'], ids, fixture, 'before', mode)
        if generator:
            self.generate(ids['backend'], fixture_path)
            result = {'cases': load(fixture_path / 'generation.json'), 'scope': 'bounded target answers; not scanner findings'}
        else:
            source = reset.load('reference/crapi_upstream.json') if row['target'] == 'crapi' else load(fixture_path / 'upstream_openapi.json')
            work = directory / 'scanner'; work.mkdir()
            values = inputs(row['id'], fixture, source, base)
            values['template.yaml'] = (PACKAGE / 'reference/http-missing-security-headers.yaml').read_text()
            for name, value in values.items():
                if isinstance(value, str): (work / name).write_text(value); (work / name).chmod(0o600)
                else: write(work / name, value)
            initial = host.inventory(work); host.write(directory / 'input_manifest.json', initial)
            if row['tool'] == 'restler':
                compile_dir = directory / 'compile'; compile_dir.mkdir()
                shutil.copyfile(work / 'openapi.json', compile_dir / 'openapi.json')
                binding = checker_command(row['id'])
                compiled = self.measured('compile', {'argv': binding['compile_argv'], 'timeout_seconds': 180,
                     'environment_additions': binding['environment_additions']}, compile_dir, base, ids, 'restler', compile=True)
                require(compiled['returncode'] == 0 and all((compile_dir / 'Compile' / n).is_file()
                        for n in ('grammar.py', 'dict.json')), 'Fresh grammar compile failed')
                host.write(directory / 'grammar_manifest.json', host.inventory(compile_dir / 'Compile'))
            else:
                binding = scanner_command(row['id'], '/zap/wrk' if row['tool'] == 'zap' else str(work),
                                           base, values['authorization.json']['token'])
            self.control(row['target'], fixture, 'scanner', mode, row['transport_scope'], row['request_budget'])
            self.result['scanner_invocations'] += 1; self.save()
            process = self.measured('scanner', binding, work, base, ids, row['tool'])
            for item in initial: require(sha(work / item['path']) == item['sha256'], 'Scanner changed supplied input')
            try: report = native_report(row['tool'], work)
            except (ValueError, KeyError, OSError, TypeError) as error:
                report = {'parsed': False, 'error': type(error).__name__ + ': ' + str(error), 'native_unit_count': None}
            trace = [json.loads(line) for line in (directory / 'proxy-logs/requests.jsonl').read_text().splitlines()
                     if json.loads(line).get('phase') == 'scanner']
            expected = [(method.upper(), path) for path, methods in values['openapi.json']['paths'].items()
                        for method in methods if method.lower() in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options')]
            result = completion(row['id'], process, report, trace, expected)
            host.write(directory / 'scanner_trace.json', trace)
        self.reference(row['target'], ids, fixture, 'after', mode)
        host.write(directory / 'outcome.json', result)
        self.result['outcome'] = result

    def generate(self, backend, fixture_path):
        self.result['planned_target_generation_requests'] = 4
        try:
            self.run('target-generation', ['docker', 'exec', backend, 'python', '-B',
                 '/study/engineering/dynamic_execution_probe.py', 'generation', '--target', 'aigoat', '--name', 'generation'], timeout=1100)
        finally:
            path = fixture_path / 'generation.json'
            self.result['target_generation_requests'] = len(load(path)) if path.exists() else 0
            self.save()

    def preflight(self, directory):
        fixture = directory / 'fixtures'; fixture.mkdir()
        network = self.network(self.name + '-target')
        config = {'name': self.name, 'networks': {'default': {'external': True, 'name': network}}, 'services': {}}
        common = {'image': PYTHON, 'pull_policy': 'never', 'restart': 'no', 'read_only': True,
                  'user': str(os.getuid()) + ':' + str(os.getgid()), 'cap_drop': ['ALL'],
                  'security_opt': ['no-new-privileges:true'], 'mem_limit': '128m', 'memswap_limit': '128m',
                  'cpus': 1, 'pids_limit': 32, 'labels': {'org.study.project': 'devsecops-electronics'}, 'networks': ['default']}
        config['services']['crapi-web'] = {**common, 'container_name': self.name + '-mock',
            'volumes': [str(PACKAGE) + ':/study:ro'], 'command': ['python3', '-B', '/study/engineering/dynamic_execution_canary.py', 'server'],
            'healthcheck': {'test': ['CMD', 'python3', '-c', "import socket;socket.create_connection(('127.0.0.1',80),1).close()"],
                            'interval': '2s', 'timeout': '3s', 'retries': 10}}
        config['services']['probe'] = {**common, 'container_name': self.name + '-probe', 'command': ['sleep', 'infinity'], 'volumes': []}
        self.add_transport(config, directory, self.name, 'crapi')
        argv, ids = self.compose_create('synthetic', config, directory)
        self.run('synthetic-start', argv + ['up', '-d', '--no-recreate', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '45'], timeout=60)
        self.network_check('synthetic', config, ids, directory, 'crapi')
        proxy = json.loads(host.capture(['docker', 'inspect', ids['proxy']]))[0]
        anchor = json.loads(host.capture(['docker', 'inspect', ids['anchor']]))[0]
        network = next(n['name'] for n in self.networks if n['name'].endswith('-scanner'))
        base = 'http://' + proxy['NetworkSettings']['Networks'][network]['IPAddress'] + ':8080'
        write(directory / 'control/current.json', {'target': 'crapi', 'phase': 'canary', 'mode': 'raw', 'scope': 'crapi_read_only',
              'max_requests': 32, 'roles': {}, 'route_owners': {}})
        tests = []
        for tool in ('schemathesis', 'zap', 'restler'):
            work = directory / tool; work.mkdir()
            inner = '/zap/wrk' if tool == 'zap' else '/work'
            python = str(Path(SCHEMATHESIS).parent / 'python') if tool == 'schemathesis' else 'python3'
            script = str(PACKAGE / 'engineering/dynamic_execution_canary.py') if tool == 'schemathesis' else '/study/engineering/dynamic_execution_canary.py'
            command = {'argv': [python, '-B', script, 'client', '--base', base, '--work', str(work) if tool == 'schemathesis' else inner,
                        '--native' if tool == 'schemathesis' else '--container'], 'timeout_seconds': 60}
            result = self.measured('canary-' + tool, command, work, base, ids, tool, canary=True)
            require(result['returncode'] == 0 and result['accounting'], 'Canary or accounting failed')
            observation = load(work / 'canary.json')
            require(all(observation['checks'].values()), 'Canary contract failed')
            tests.append({'tool': tool, 'checks': observation['checks'], 'accounting': result['accounting']})
        compile_dir = directory / 'compile'; compile_dir.mkdir()
        write(compile_dir / 'openapi.json', {'swagger': '2.0', 'info': {'title': 'Synthetic lifecycle control', 'version': '1'},
              'host': 'authorization-proxy:8080', 'basePath': '/', 'schemes': ['http'],
              'paths': {'/ok': {'get': {'responses': {'200': {'description': 'Synthetic control'}}}}}})
        result = self.measured('compile', {'argv': ['/RESTler/restler/Restler', 'compile', '--api_spec', '/work/openapi.json'],
            'timeout_seconds': 180, 'environment_additions': {'RESTLER_TELEMETRY_OPTOUT': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
            'DOTNET_CLI_HOME': '/tmp'}}, compile_dir, base, ids, 'restler', compile=True)
        require(result['returncode'] == 0 and all((compile_dir / 'Compile' / n).is_file() for n in ('grammar.py', 'dict.json')),
                'Offline synthetic grammar compile failed')
        host.write(directory / 'preflight_checks.json', {'canaries': tests, 'offline_compile': True,
                   'compiled_files': host.inventory(compile_dir / 'Compile'), 'scanner_invocations': 0, 'generations': 0})
        self.result.update(canaries=3, offline_compilations=1, scientific_execution=False)

    def execute(self):
        directory = self.out / 'target'; directory.mkdir()
        try:
            self.verify_assets('before')
            locked = assets.inventory() if self.mode == 'preflight' else load(self.locks)
            host.write(self.out / 'asset_locks.json', locked)
            if self.mode == 'preflight': self.preflight(directory)
            else: self.final_job(directory)
            self.verify_assets('after')
            host.write(self.out / 'runtime_after.json', assets.verify(locked))
            self.result['success'] = True
        except Exception as error:
            self.result['error'] = type(error).__name__ + ': ' + str(error)
            (self.out / 'failure_trace.txt').write_text(traceback.format_exc())
        finally:
            try: self.cleanup(directory)
            except Exception as error:
                self.result.update(success=False, cleanup_error=str(error))
            host.capture(['sudo', '-n', 'chown', '-R', str(os.getuid()) + ':' + str(os.getgid()), directory])
            after = host.snapshot(); host.write(self.out / 'host_after.json', after)
            self.result['preservation_passed'] = host.preserved(self.before, after)
            self.result['success'] &= self.result['preservation_passed']
            self.result.update(finished_utc=host.utc(), host_samples=self.samples,
                               existing_containers=len(self.before['container_config_hashes']))
            self.save()
        print(json.dumps(self.result), flush=True)
        return 0 if self.result['success'] else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['preflight', 'execute'])
    p.add_argument('--run-id', required=True)
    p.add_argument('--job-id')
    p.add_argument('--asset-locks', type=Path)
    p.add_argument('--release', type=Path)
    args = p.parse_args()
    host.assert_lease()
    require(args.mode == 'preflight' or args.job_id and args.asset_locks and args.release, 'Final bindings are required')
    def interrupted(signum, frame): raise RuntimeError('Interrupted: ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(Controller(ROOT / 'evidence' / args.run_id, args.mode, args.job_id, args.asset_locks, args.release).execute())


if __name__ == '__main__':
    main()
