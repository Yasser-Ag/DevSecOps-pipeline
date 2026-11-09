"""Construct documented declaration controls without using detector labels."""
import argparse
import copy
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import yaml


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def effective_contents(workflow, job):
    value = job['permissions'] if 'permissions' in job else workflow.get('permissions')
    if value == 'write-all': return 'write'
    if value == 'read-all': return 'read'
    if isinstance(value, dict): return value.get('contents', 'none')
    return None


def effective_nonroot(pod, container):
    local = container.get('securityContext') or {}
    parent = pod.get('securityContext') or {}
    return local['runAsNonRoot'] if 'runAsNonRoot' in local else parent.get('runAsNonRoot')


def unrestricted_ssh(rule):
    transport = str(rule['protocol'])
    permits = transport in ('-1', 'all') or (transport in ('tcp', '6') and rule['from_port'] <= 22 <= rule['to_port'])
    networks = [ipaddress.ip_network(x) for x in rule.get('cidr_blocks', []) + rule.get('ipv6_cidr_blocks', [])]
    return permits and any(n.prefixlen == 0 for n in networks)


def generate(out, snapshot, sources):
    out.mkdir(parents=True, exist_ok=False)
    inputs = out/'scanner-inputs'; controls = inputs/'controls'; originals = inputs/'originals'
    cases, files = [], []
    def store(relative, text, role):
        p = inputs/relative; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
        files.append({'path': relative, 'sha256': sha(p), 'bytes': p.stat().st_size, 'role': role})
        return p
    def add(identifier, path, resource, prop, value, positive, **other):
        cases.append({'case_id': identifier, 'path': str(path.relative_to(inputs)), 'source_sha256': sha(path),
                      'resource': resource, 'property': prop, 'reference_value': value, 'positive': positive,
                      'reference_status': 'unknown' if positive is None else 'independent_declaration', **other})
    for i, (top, local) in enumerate([('read-all', None), ('write-all', None), ('write-all', {'contents':'read'}),
                                     ('read-all', {'contents':'write'}), ('read-all', {'contents':'write'}), ('write-all', {})], 1):
        job = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'echo development'}]}
        if local is not None: job['permissions'] = local
        jobs = {'alpha': job}
        if i == 5: jobs['bravo'] = copy.deepcopy(job)
        doc = {'name': f'w{i:02d}', 'on': 'workflow_dispatch', 'permissions': top, 'jobs': jobs}
        path = store(f'controls/workflow/.github/workflows/w{i:02d}.yml', yaml.safe_dump(doc, sort_keys=False), 'constructed')
        for name, entry in jobs.items():
            value = effective_contents(doc, entry)
            add(f'W{i:02d}-{name}', path, 'jobs.'+name, 'declared_contents_write', value, value == 'write',
                assumptions='workflow_dispatch; declared precedence before external organizational restrictions')

    specs = [('t01', 22, ['0.0.0.0/0'], []), ('t02', 22, ['10.12.0.0/16'], []),
             ('t03', 80, ['0.0.0.0/0'], []), ('t04a', 22, ['0.0.0.0/0'], []),
             ('t04b', 22, ['0.0.0.0/0'], []), ('t05', 22, [], ['::/0']), ('t06', 22, [], ['fd00::/64'])]
    blocks, rules = [], []
    for name, port, ipv4, ipv6 in specs:
        rule = {'protocol': 'tcp', 'from_port': port, 'to_port': port, 'cidr_blocks': ipv4, 'ipv6_cidr_blocks': ipv6}
        block = f'resource "aws_security_group" "{name}" {{\n  name = "development-{name}"\n  description = "Static development control"\n  vpc_id = "vpc-development"\n  ingress {{\n    description = "Declared ingress"\n'
        block += ''.join('    '+key+' = '+json.dumps(value)+'\n' for key,value in rule.items())
        blocks.append(block+'  }\n}\n'); rules.append((name, rule))
    path = store('controls/terraform/main.tf', '\n'.join(blocks), 'constructed')
    for name, rule in rules:
        add(name.upper(), path, 'aws_security_group.'+name, 'declared_unrestricted_tcp_22', rule, unrestricted_ssh(rule),
            assumptions='Literal inline rule only; no Terraform apply, network route or effective AWS state')

    image = 'python@sha256:0495f5559318affa673172ec7e35cd0a5213e4aaf4c76d0a66554c0af97b157e'
    for i in range(1, 11):
        sc = {'allowPrivilegeEscalation': False, 'privileged': False, 'readOnlyRootFilesystem': True,
              'capabilities': {'drop':['ALL']}, 'seccompProfile': {'type':'RuntimeDefault'}}
        container = {'name': 'alpha', 'image': image, 'securityContext': sc,
                     'resources': {'requests': {'cpu':'10m','memory':'32Mi'}, 'limits': {'cpu':'100m','memory':'64Mi'}}}
        pod = {'automountServiceAccountToken':False, 'containers':[container], 'securityContext':{'runAsNonRoot':True}}
        if i == 2: sc['runAsNonRoot'] = False
        if i in (3,4): pod['securityContext']['runAsNonRoot'] = False
        if i == 3: sc['runAsNonRoot'] = True
        if i == 5:
            sc['runAsNonRoot'] = False; other = copy.deepcopy(container); other['name'] = 'bravo'; pod['containers'].append(other)
        if i == 6: pod['securityContext'] = {}
        if i == 8: sc['privileged'] = True
        if i == 10: sc['readOnlyRootFilesystem'] = False
        doc = {'apiVersion':'v1', 'kind':'Pod', 'metadata':{'name':f'k{i:02d}', 'namespace':'development'}, 'spec':pod}
        path = store(f'controls/kubernetes/k{i:02d}.yaml', yaml.safe_dump(doc, sort_keys=False), 'constructed')
        for index, entry in enumerate(pod['containers']):
            prop = 'declared_nonroot_enforcement_disabled' if i <= 6 else 'declared_privileged' if i <= 8 else 'declared_writable_rootfs'
            value = effective_nonroot(pod, entry) if i <= 6 else entry['securityContext']['privileged'] if i <= 8 else entry['securityContext']['readOnlyRootFilesystem']
            positive = None if value is None else value if i in (7,8) else not value
            add(f'K{i:02d}-{entry["name"]}', path, f'Pod/development/k{i:02d}/containers/{entry["name"]}', prop, value, positive,
                container_index=index, assumptions='Declared field only; no actual UID, cluster admission or effective runtime claim')

    upstream = json.loads(snapshot.read_text()); original_rows = []
    for name, repo in upstream['targets'].items():
        for item in repo['files']:
            rel = item['path']
            if hashlib.sha256(item['text'].encode()).hexdigest() != item['sha256']:
                raise ValueError('Upstream byte identity mismatch')
            if rel.startswith('.github/workflows/'):
                dest = f'originals/workflow/{name}/{rel}'
            elif name == 'terragoat' and rel.endswith('.tf'):
                dest = 'originals/terraform/'+rel
            elif name == 'kubernetes-goat' and rel.startswith('scenarios/'):
                dest = 'originals/kubernetes/'+rel
            else:
                dest = 'licenses/'+name+'/'+rel
            path = store(dest, item['text'], 'unmodified_upstream')
            original_rows.append({'path':str(path.relative_to(inputs)), 'upstream_path':rel, 'repository':name,
                                  'commit':repo['commit'], 'sha256':item['sha256'], 'labels':'not_adjudicated'})
    shutil.copytree(sources, out/'primary_sources')
    manifest = {'schema_version':'infrastructure-development-1','created_before_scans_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'cases':cases,'files':files,'upstream':original_rows,'generator_sha256':sha(Path(__file__)),
        'source_snapshot_sha256':sha(snapshot), 'sources':[{'path':p.name,'sha256':sha(p)} for p in sorted(sources.iterdir())],
        'limits':['Constructed controls are development-only, not independent applications.',
                  'Literal declaration truth does not establish deployment, exploitability or live credentials.',
                  'Original source findings remain unadjudicated; unsupported properties stay visible.']}
    (out/'reference_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--snapshot',type=Path,required=True);p.add_argument('--sources',type=Path,required=True)
    a=p.parse_args();m=generate(a.output,a.snapshot,a.sources);print(json.dumps({'cases':len(m['cases']),'files':len(m['files']),'upstream_files':len(m['upstream'])}))
