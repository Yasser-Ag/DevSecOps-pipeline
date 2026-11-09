"""Synthetic engineering traffic and isolation assertions; no security finding."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import urllib.request


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = json.dumps({'synthetic': True, 'path': self.path, 'host': self.headers.get('Host')}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *args): pass


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['server', 'client'])
    p.add_argument('--base'); p.add_argument('--work', type=Path)
    p.add_argument('--native', action='store_true'); p.add_argument('--container', action='store_true')
    args = p.parse_args()
    if args.action == 'server':
        HTTPServer(('0.0.0.0', 80), Handler).serve_forever(); return
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(args.base + '/.well-known/lifecycle-canary', timeout=10) as response:
        body = json.load(response)
    (args.work / 'private-write.txt').write_text('synthetic control\n')
    state = {s.split(':')[0]: s.split(':', 1)[1].strip() for s in Path('/proc/self/status').read_text().splitlines() if ':' in s}
    checks = {'nonroot': os.geteuid() == 1000, 'no_new_privileges': state['NoNewPrivs'] == '1',
              'capabilities_dropped': int(state['CapEff'], 16) == 0, 'private_write': True,
              'fixed_upstream_get': body == {'synthetic': True, 'path': '/.well-known/lifecycle-canary', 'host': 'crapi-web'}}
    if args.native:
        checks['no_supplementary_groups'] = not os.getgroups()
        for name, path in [('foreign_project_hidden', '<OTHER_PROJECT_2>'), ('ssh_hidden', '<USER_HOME>/.ssh')]:
            try: list(Path(path).iterdir()); blocked = False
            except (PermissionError, FileNotFoundError): blocked = True
            checks[name] = blocked
        try:
            Path('<USER_HOME>/.dynamic-forbidden-canary').write_text('unexpected'); readonly = False
        except OSError: readonly = True
        checks['home_read_only'] = readonly
        checks['schemathesis_runtime_available'] = bool(importlib.metadata.version('schemathesis'))
        checks['private_python_cache'] = str(args.work) in os.environ['PYTHONPYCACHEPREFIX']
    result = {'checks': checks, 'uid': os.getuid(), 'groups': os.getgroups(), 'body': body,
              'mount_namespace': os.readlink('/proc/self/ns/mnt'), 'network_namespace': os.readlink('/proc/self/ns/net')}
    (args.work / 'canary.json').write_text(json.dumps(result, indent=2) + '\n')
    if not all(checks.values()): raise SystemExit(1)


if __name__ == '__main__': main()
