"""Fixed-upstream bounded recorder shared by the new dynamic profile bindings."""
import base64
from collections import Counter
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.dynamic_scan_contract import permitted, authorization_gate

HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te',
       'trailer', 'transfer-encoding', 'upgrade'}
LOCK = threading.Lock()
SERIAL = threading.Semaphore(1)
COUNTS = Counter()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 30

    def forward(self):
        started = time.monotonic()
        record = {'method': self.command, 'path': self.path, 'forwarded': False, 'harness_error': None}
        connection = None
        try:
            control = json.loads(Path('/control/current.json').read_text())
            target, phase = control['target'], control['phase']
            if target not in ('crapi', 'aigoat') or not 1 <= control['max_requests'] <= 4096:
                raise ValueError('Invalid proxy control')
            auth = self.headers.get('Authorization', '')
            digest = hashlib.sha256(auth.encode()).hexdigest()
            actor = control['roles'].get(digest, 'other' if auth else 'absent')
            with LOCK:
                COUNTS[phase] += 1
                count = COUNTS[phase]
            record.update(phase=phase, sequence=count, auth_sha256=digest, auth_role=actor)
            lengths = self.headers.get_all('Content-Length', [])
            length = int(lengths[0]) if len(lengths) == 1 else 0
            if len(lengths) > 1 or length < 0 or length > 16384 or self.headers.get('Transfer-Encoding'):
                self.close_connection = True
                body = b''
                allowed, reason = False, 'request_framing_or_body_budget'
            else:
                body = self.rfile.read(length) if length else b''
                allowed, reason = permitted(target, self.command, self.path, body, control['route_owners'], control.get('scope', '<MASKED:fixture:127>'))
            if count > control['max_requests']:
                allowed, reason = False, 'request_count_budget'
            record.update(request_body_base64=base64.b64encode(body).decode(),
                          request_body_sha256=hashlib.sha256(body).hexdigest(), gate_reason=reason)
            if not allowed:
                status = 429 if reason == 'request_count_budget' else 403
                data = json.dumps({'qualification_gate': reason}).encode()
                headers = [('Content-Type', 'application/json'), ('X-Study-Gate', reason)]
            elif target == 'crapi' and authorization_gate(self.command, self.path, actor, control['route_owners'], control['mode']):
                status, data = 403, b'{"error":"ownership_gate_denied"}'
                headers = [('Content-Type', 'application/json')]
                record['constructed_authorization_control'] = True
            else:
                with SERIAL:
                    upstream, port = ('crapi-web', 80) if target == 'crapi' else ('backend', 8000)
                    headers_in = {k: v for k, v in self.headers.items()
                                  if k.lower() not in HOP | {'host', 'content-length', 'accept-encoding'}}
                    headers_in.update(Host='crapi-web' if target == 'crapi' else 'backend:8000', **{'Accept-Encoding': 'identity'})
                    connection = http.client.HTTPConnection(upstream, port, timeout=30)
                    connection.request(self.command, self.path, body=body or None, headers=headers_in)
                    response = connection.getresponse()
                    maximum = 4 * 1024**2 if target == 'crapi' else 1024**2
                    data = response.read(maximum + 1)
                    if len(data) > maximum:
                        raise ValueError('Response exceeds recording budget')
                    status = response.status
                    headers = [(k, v) for k, v in response.getheaders() if k.lower() not in HOP | {'content-length'}]
                    record['forwarded'] = True
            record.update(status=status, response_headers=headers, response_bytes=len(data),
                          response_sha256=hashlib.sha256(data).hexdigest(), response_body_base64=base64.b64encode(data).decode())
            self.send_response_only(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(data)
        except Exception as error:
            record['harness_error'] = type(error).__name__ + ': ' + str(error)
            try:
                self.send_error(502, 'Study transport error')
            except OSError:
                pass
        finally:
            if connection:
                connection.close()
            record['elapsed_seconds'] = time.monotonic() - started
            with LOCK:
                with Path('/logs/requests.jsonl').open('a') as stream:
                    stream.write(json.dumps(record, sort_keys=True) + '\n')

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = forward

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    http.server.ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
