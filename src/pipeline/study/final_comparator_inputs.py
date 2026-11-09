"""Verified comparator reference context, separate from detector report ingestion."""
import hashlib
import json
from pathlib import Path

from study.final_output_adapter import require, logical_route
from study.identity_matching import advisory_aliases


PLAN = 'evidence/final_output_2026-10-22/package-v2/plan.json'
PROTECTED = 'evidence/final_output_2026-10-22/candidate-v1/source_manifest.json'
BINDINGS = 'data/references/bindings.json'
AIGOAT_STATIC = ('aigoat-checkov-docker-original', 'aigoat-checkov-docker-deployment',
    'aigoat-trivy-config-original', 'aigoat-trivy-config-deployment', 'aigoat-kics-compose',
    'aigoat-compose-kics-compose-deployment-qualified')
AIGOAT_DYNAMIC = ('aigoat-nuclei-valid-alice', 'aigoat-nuclei-invalid',
                  'aigoat-zap-valid-alice', 'aigoat-zap-invalid')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Inputs:
    """Bind all accessed files and verify the existing source/input contracts."""
    def __init__(self, root):
        self.root = Path(root).resolve(); self.files = {}
        protected = self.json(PROTECTED)
        for row in protected:
            path = self.bind(row['path'])
            require(sha(path) == row['sha256'] and path.stat().st_size == row['bytes'],
                    'Protected source changed: ' + row['path'])
        self.protected_count = len(protected)
        self.plan = self.json(PLAN)
        self.verified_inputs = {}
        for suite, definition in self.plan['suites'].items():
            for row in definition['local_input_hashes']:
                local = definition['source_directory'] + '/' + row['path']
                if suite == 'aigoat' and row['path'].startswith('source/'):
                    local = ('evidence/aigoat_static_2026-10-12/package-v2/targets/aigoat/source/'
                             'AIGoat-e1c538badb93c6c1c2307096ab5d709a9ee0fe55/' + row['path'].removeprefix('source/'))
                path = self.bind(local)
                require(sha(path) == row['sha256'] and path.stat().st_size == row['bytes'],
                        'Frozen static source changed: ' + row['path'])
                self.verified_inputs[(suite, row['path'])] = path
        # Matrix/split assets originate in a separate immutable controller
        # package. Their remote lock, rather than the report-directory listing,
        # binds the complete 40-file source population.
        locks = self.json('evidence/static_scanner_controller_2026-10-22/ubuntu-preflight-v2/asset_locks.json')
        for item in locks['inputs']['k8s-scope']:
            if item['destination'] not in ('inputs/matrix', 'inputs/split'): continue
            for row in item['files']:
                if row['kind'] != 'file': continue
                relative = item['destination'] + '/' + row['path']
                path = self.bind('evidence/configuration_matching_2026-09-22/package-v2/' + relative)
                require(sha(path) == row['sha256'] and path.stat().st_size == row['bytes'],
                        'Kubernetes matrix/split differs from qualified remote asset lock')
                self.verified_inputs[('k8s-scope', relative)] = path

    def bind(self, name):
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe evidence path')
        path = (self.root / relative).resolve()
        require(path.is_relative_to(self.root) and path.is_file(), 'Missing/outside evidence: ' + str(relative))
        self.files[str(relative)] = {'path': str(relative), 'sha256': sha(path), 'bytes': path.stat().st_size}
        return path

    def json(self, name):
        return json.loads(self.bind(name).read_text())

    def references(self):
        selection = self.json('evidence/matching_development_2026-09-22/inputs/sast/development_selection.json')['cases']
        java = {}
        for row in selection:
            path = self.verified_inputs[('java', 'scanner-inputs/java/' + row['source_path'])]
            require(sha(path) == row['source_sha256'], 'Java reference/source mismatch')
            java[row['source_path'].removeprefix('src/main/java/')] = path.read_bytes()
        secret = {name.removeprefix('reference/scanner-inputs/'): path
                  for (suite, name), path in self.verified_inputs.items()
                  if suite == 'configuration' and name.startswith('reference/scanner-inputs/secrets/')}
        identity = self.json('evidence/identity_development_2026-09-22/analysis-v1/references.json')['nodes']
        authority_root = 'evidence/identity_development_2026-09-22/inputs-v1/primary_sources'
        authority = [self.json(str(p.relative_to(self.root))) for p in sorted((self.root / authority_root).glob('GHSA-*.json'))]
        aliases = advisory_aliases(authority)
        require(aliases == self.json('evidence/identity_development_2026-09-22/analysis-v1/advisory_aliases.json'),
                'Authority-derived advisory aliases changed')
        k8s = {}
        for (suite, path), source in self.verified_inputs.items():
            if suite == 'infrastructure':
                for corpus in ('controls','originals'):
                    prefix = 'reference/scanner-inputs/' + corpus + '/kubernetes/'
                    if path.startswith(prefix) and path.endswith('.yaml'):
                        k8s[(corpus, path.removeprefix(prefix))] = source.read_bytes()
            if suite == 'k8s-scope':
                for corpus in ('matrix','split'):
                    prefix = 'inputs/' + corpus + '/'
                    if path.startswith(prefix) and path.endswith('.yaml'):
                        k8s[(corpus, path.removeprefix(prefix))] = source.read_bytes()
        tf = self.json('evidence/workflow_iac_matching_2026-09-23/development-analysis-v3/registry.json')['terraform']
        for row in tf:
            path = self.verified_inputs[('infrastructure', 'reference/scanner-inputs/' + row['path'])]
            require(sha(path) == row['source_sha256'], 'Terraform source/reference mismatch')
        templates = self.json('evidence/matching_development_2026-09-22/analysis-development/dast_references.json')
        old = self.json('evidence/api_development_2026-09-22/attempt-02/behavior_reference.json')
        fixture = {'route_aliases': {'/identity/api/v2/vehicle/'+uuid+'/location':
                    '/identity/api/v2/vehicle/{owner:'+actor+'}/location' for actor, uuid in old['objects'].items()}}
        templates = [{k: v for k, v in row.items() if k not in ('independent_evidence','property_absent','allowed_statuses')}
                     | {'path': logical_route(row['path'], fixture)} for row in templates]
        # Historical truth/status are deliberately absent from dynamic templates.
        refs = self.json(BINDINGS)['references']
        return {'java': java, 'java_partition': 'owasp-development:' + selection[0]['commit'],
                'secrets': secret, 'identity': identity, 'aliases': aliases, 'kubernetes': k8s,
                'terraform': tf, 'crapi_templates': templates, 'references': refs}

    def manifest(self):
        return {'files': sorted(self.files.values(), key=lambda r: r['path']),
                'protected_sources_verified': self.protected_count,
                'role': 'Evaluation reference inputs; never mount into a triage model container.'}
