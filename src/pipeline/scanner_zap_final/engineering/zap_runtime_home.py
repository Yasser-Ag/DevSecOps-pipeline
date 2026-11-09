"""Seed the private ZAP home from the policy already bundled in its pinned image."""
import hashlib
import json
from pathlib import Path

POLICY_SOURCE = Path('<USER_HOME>/.ZAP/policies/API-Minimal.policy')
POLICY_SHA256 = '029a8670ff8f78a5a2af027c3667bf25500c6e2bed7996644a35f9e147144520'


def prepare(spec):
    if spec.get('argv', [None])[0] != '/zap/zap-api-scan.py':
        return None
    work = Path(spec['cwd'])
    if not spec.get('container') or not work.is_absolute() or work.is_symlink():
        raise ValueError('Invalid ZAP private work directory')
    if POLICY_SOURCE.is_symlink():
        raise ValueError('Unexpected symbolic policy source')
    data = POLICY_SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != POLICY_SHA256:
        raise ValueError('Bundled ZAP policy differs from pinned-image evidence')
    destination = work / 'home/.ZAP/policies/API-Minimal.policy'
    if not destination.resolve().is_relative_to(work.resolve()):
        raise ValueError('ZAP policy destination escapes the private work directory')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(data)
    receipt = {'source': str(POLICY_SOURCE), 'destination': str(destination),
               'sha256': POLICY_SHA256, 'bytes': len(data),
               'role': 'Unchanged bundled scan policy; no downloaded or custom rules.'}
    with (work / 'zap-policy-seed.json').open('x') as stream:
        json.dump(receipt, stream, indent=2); stream.write('\n')
    return receipt
