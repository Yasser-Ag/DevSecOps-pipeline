"""Owned, sequential construction checks; never a vulnerability scanner."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from engineering import static_scanner_host as host
from engineering.dynamic_reset_run import PROBE
from study.dynamic_reset_contract import require, runtime_service, runtime_assertion, image_identity, sha
from study.runtime_block_contract import CONTROL_SHA256, control_id, source_bindings, validate_container


class RuntimeControls:
    def __init__(self, output, run_id, controls, locks, owned):
        self.output, self.run_id, self.controls, self.owned = Path(output), run_id, controls, owned
        self.bindings = source_bindings(controls, locks)
        self.completed = 0

    def command(self, directory, label, argv, allowed, timeout=120):
        """Time complete commands; sample host/containers separately from scanners."""
        record = {'argv': [str(a) for a in argv], 'started_utc': host.utc(),
                  'started_monotonic_ns': time.monotonic_ns(), 'timeout_seconds': timeout}
        target = directory / (label + '.json')
        require(not target.exists(), 'Preserve runtime command receipt')
        proc = None
        try:
            with (directory / (label + '.stdout')).open('xb') as out, (directory / (label + '.stderr')).open('xb') as err:
                proc = subprocess.Popen(record['argv'], stdout=out, stderr=err, start_new_session=True)
                while proc.poll() is None:
                    require((time.monotonic_ns() - record['started_monotonic_ns']) / 1e9 < timeout, 'Runtime command timeout')
                    sample = host.sample([*self.owned, *allowed])
                    sample['elapsed_seconds'] = (time.monotonic_ns() - record['started_monotonic_ns']) / 1e9
                    with (directory / 'resources.jsonl').open('a') as stream:
                        stream.write(json.dumps(sample, sort_keys=True) + '\n')
                    try:
                        proc.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                record['returncode'] = proc.returncode
            require(proc.returncode == 0, 'Runtime command failed: ' + label)
        except BaseException as error:
            record['error'] = type(error).__name__ + ': ' + str(error)
            if proc is not None and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=5)
            record['returncode'] = proc.returncode if proc is not None else None
            raise
        finally:
            record.update(finished_utc=host.utc(), finished_monotonic_ns=time.monotonic_ns())
            record['elapsed_seconds'] = (record['finished_monotonic_ns'] - record['started_monotonic_ns']) / 1e9
            host.write(target, record)
        return (directory / (label + '.stdout')).read_text()

    def one(self, directory, row, block, phase, image):
        identity = control_id(block, phase, row['case_id'])
        name = 'dsrt-' + self.run_id + '-' + identity
        directory.mkdir()
        record = {'id': identity, 'case_id': row['case_id'], 'run_id': self.run_id,
                  'container_name': name, 'status': 'running', 'removed': False,
                  'started_utc': host.utc(), 'started_monotonic_ns': time.monotonic_ns()}
        record_path = directory / 'receipt.json'
        host.write(record_path, record)
        (directory / 'resources.jsonl').touch(exist_ok=False)
        cfg = runtime_service(row, name)
        cfg['command'] = ['python', '-c', PROBE]
        cfg['labels'].update({'org.study.run': self.run_id, 'org.study.runtime': identity})
        config = {'name': name, 'services': {'probe': cfg}}
        host.write(directory / 'compose.json', config)
        existing = set(host.capture(['docker', 'ps', '-a', '--format', '{{.Names}}']).split())
        require(name not in existing, 'Runtime container name already exists')
        existing_ids = set(host.capture(['docker', 'ps', '-a', '-q', '--no-trunc']).split())
        cid = None
        failure = None
        try:
            try:
                self.command(directory, 'create', ['docker','compose','-p',name,'-f',directory/'compose.json',
                                                  'create','--pull','never'], [])
            finally:
                # A failed create can leave a container. Claim only this reserved name,
                # new ID and exact run/control labels; never perform global cleanup.
                observed = subprocess.run(['docker','inspect',name], capture_output=True, text=True, timeout=30)
                if observed.returncode == 0:
                    first = json.loads(observed.stdout)[0]
                    labels = first['Config'].get('Labels', {})
                    require(first['Id'] not in existing_ids and labels.get('org.study.run') == self.run_id and
                            labels.get('org.study.runtime') == identity, 'Refuse ownership of an existing/foreign container')
                    cid = first['Id']; record['container_id'] = cid
                    host.write(directory / 'created.json', first)
                    host.write(record_path, record)
            require(cid is not None, 'Runtime container not created')
            validate_container(first, row, name, self.run_id, identity, PROBE, image)
            require(first['State']['Status'] == 'created' and not first['State']['Running'], 'Runtime target is not fresh')
            raw = self.command(directory, 'probe', ['docker','start','-a',cid], [cid], timeout=60)
            last = json.loads(host.capture(['docker','inspect',cid]))[0]
            host.write(directory / 'finished.json', last)
            validate_container(last, row, name, self.run_id, identity, PROBE, image)
            state = last['State']
            require(state['Status'] == 'exited' and not state['Running'] and state['ExitCode'] == 0 and not state['OOMKilled'],
                    'Runtime probe did not exit normally')
            value = json.loads(raw)
            record['assertion'] = {**runtime_assertion(row, value), 'raw': value}
            record['status'] = 'completed'
        except BaseException as error:
            failure = error
            record.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        finally:
            try:
                if cid is not None:
                    info = json.loads(host.capture(['docker','inspect',cid]))[0]
                    labels = info['Config'].get('Labels', {})
                    require(info['Id'] == cid and cid not in existing_ids and
                            labels.get('org.study.run') == self.run_id and labels.get('org.study.runtime') == identity,
                            'Refuse foreign runtime cleanup')
                    host.write(directory / 'cleanup-before.json', info)
                    if info['State']['Running']:
                        self.command(directory, 'stop', ['docker','stop','-t','5',cid], [cid], timeout=30)
                    self.command(directory, 'remove', ['docker','rm',cid], [cid])
                    require(cid not in host.capture(['docker','ps','-a','-q','--no-trunc']).split(), 'Runtime container remains')
                    record['removed'] = True
            except BaseException as error:
                record.update(status='failed', cleanup_error=type(error).__name__ + ': ' + str(error))
                failure = failure or error
            record.update(finished_utc=host.utc(), finished_monotonic_ns=time.monotonic_ns())
            record['elapsed_seconds'] = (record['finished_monotonic_ns'] - record['started_monotonic_ns']) / 1e9
            record['files'] = {p.name: sha(p) for p in sorted(directory.iterdir()) if p.is_file() and p != record_path}
            host.write(record_path, record)
        if failure is not None:
            raise failure
        self.completed += 1
        return {'case_id': row['case_id'], 'receipt': record_path.relative_to(self.output).as_posix(), 'sha256': sha(record_path)}

    def phase(self, block, phase):
        host.assert_lease(); host.sample(self.owned)
        directory = self.output / 'runtime' / f'b{block}' / phase
        directory.mkdir(parents=True, exist_ok=False)
        record = {'block': block, 'phase': phase, 'run_id': self.run_id, 'status': 'running',
                  'control_file_sha256': CONTROL_SHA256, 'source_bindings': self.bindings,
                  'started_utc': host.utc(), 'started_monotonic_ns': time.monotonic_ns(), 'controls': [],
                  'measurement_scope': 'Reference construction overhead including image verification, create, probe, inspection, cleanup and monitoring; not scanner cost. Samples are not exact peak container memory.'}
        host.write(directory / 'phase.json', record)
        try:
            images = {}
            for image in sorted({r['service']['image'] for r in self.controls}):
                images[image] = json.loads(host.capture(['docker','image','inspect',image]))[0]
                image_identity(image, images[image])
            host.write(directory / 'images.json', images)
            for row in self.controls:
                require((time.monotonic_ns() - record['started_monotonic_ns']) / 1e9 <= 900,
                        'Runtime phase exceeded its 15-minute bound')
                host.assert_lease(); host.sample(self.owned)
                record['controls'].append(self.one(directory / row['case_id'], row, block, phase, images[row['service']['image']]))
                host.write(directory / 'phase.json', record)
            record['status'] = 'completed'
        except BaseException as error:
            record.update(status='failed', error=type(error).__name__ + ': ' + str(error))
            raise
        finally:
            record.update(finished_utc=host.utc(), finished_monotonic_ns=time.monotonic_ns())
            record['elapsed_seconds'] = (record['finished_monotonic_ns'] - record['started_monotonic_ns']) / 1e9
            host.write(directory / 'phase.json', record)
        return record
