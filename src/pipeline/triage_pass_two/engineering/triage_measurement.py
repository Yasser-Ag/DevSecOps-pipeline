"""Linux process/container observations for the bounded offline pilot."""
from pathlib import Path
import threading
import time


def process_memory(pid):
    fields = dict(line.split(':', 1) for line in Path('/proc/' + str(pid) + '/status').read_text().splitlines())
    return {'rss_kib': int(fields['VmRSS'].split()[0]),
            'high_water_rss_kib': int(fields['VmHWM'].split()[0])}


def cgroup_memory(root=Path('/sys/fs/cgroup')):
    return {name: int((root/filename).read_text().strip()) for name, filename in
            [('current_bytes', 'memory.current'), ('peak_bytes', 'memory.peak'),
             ('swap_current_bytes', 'memory.swap.current')]}


class RequestMemory:
    """Sample a request, propagating observer errors rather than hiding gaps."""
    def __init__(self, pid, interval=0.25, reader=None):
        self.pid = pid; self.interval = interval
        self.reader = reader or self._read
        self.samples = []; self.error = None; self.event = threading.Event()

    def _read(self):
        return {'server': process_memory(self.pid), 'cgroup': cgroup_memory()}

    def take(self):
        self.samples.append({'elapsed_seconds': time.monotonic()-self.start, **self.reader()})

    def _run(self):
        try:
            while not self.event.wait(self.interval):
                self.take()
        except Exception as error:
            self.error = error

    def __enter__(self):
        self.start = time.monotonic(); self.take()
        self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()
        return self

    def __exit__(self, kind, value, traceback):
        self.event.set(); self.thread.join(timeout=5)
        if self.thread.is_alive(): raise RuntimeError('Memory observer did not stop')
        if self.error is not None: raise RuntimeError('Memory observer failed') from self.error
        self.take()
        return False

    def summary(self):
        if not self.samples: raise ValueError('No memory observations')
        return {'interval_seconds': self.interval, 'samples': len(self.samples),
                'sampled_peak_server_rss_kib': max(s['server']['rss_kib'] for s in self.samples),
                'sampled_peak_cgroup_current_bytes': max(s['cgroup']['current_bytes'] for s in self.samples),
                'scope': 'Observed request peaks; process high-water and cgroup peak fields are lifetime counters.'}
