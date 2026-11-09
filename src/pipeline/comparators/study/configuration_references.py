"""Describe source properties independently of scanner findings.

These are syntax/property references, not exploitability or effective-runtime
labels. Legacy counts and terminology are retained separately for comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import yaml


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker_instructions(text):
    result, pending, first = [], '', None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not pending and (not line or line.startswith('#')):
            continue
        if first is None:
            first = number
        continued = line.endswith('\\')
        pending += line[:-1].rstrip() + ' ' if continued else line
        if continued:
            continue
        match = re.match(r'^([A-Za-z]+)\s+(.*)$', pending)
        if not match:
            raise ValueError('Unsupported Dockerfile instruction at line ' + str(first))
        if '<<' in match[2]:
            raise ValueError('Docker heredoc requires a dedicated parser')
        result.append({'instruction': match[1].upper(), 'argument': match[2], 'line': first})
        pending, first = '', None
    if pending:
        raise ValueError('Unterminated Dockerfile continuation')
    return result


def pod_spec(doc):
    kind = doc.get('kind')
    if kind == 'Pod': return doc.get('spec', {})
    if kind in {'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job'}:
        return doc.get('spec', {}).get('template', {}).get('spec', {})
    if kind == 'CronJob':
        return doc.get('spec', {}).get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
    return None


def source_references(root, revision):
    root = Path(root)
    rows = []
    def add(path, resource, prop, state, explanation):
        rel = path.relative_to(root).as_posix()
        identity = {'revision': revision, 'artifact': rel, 'resource': resource, 'property': prop}
        cid = 'crapi-source:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
        rows.append({'case_id': cid, 'reference_type': 'configuration_source_property',
                     'unit': 'property_at_source_resource', 'identity': identity,
                     'property_holds': bool(state), 'source_sha256': sha(path),
                     'evidence': explanation, 'evidence_status': 'independent_source_parse',
                     'scanner_used_as_oracle': False, 'effective_runtime': 'not_validated',
                     'vulnerability_or_exploitability': 'not_inferred'})
    for path in sorted(root.glob('services/*/Dockerfile')):
        instructions = docker_instructions(path.read_text())
        starts = [i for i, x in enumerate(instructions) if x['instruction'] == 'FROM']
        if not starts: raise ValueError('Dockerfile has no FROM')
        final = instructions[starts[-1]:]
        for instr, prop in [('USER', 'final_stage_explicit_user_absent'), ('HEALTHCHECK', 'final_stage_explicit_healthcheck_absent')]:
            occurrences = [i['line'] for i in final if i['instruction'] == instr]
            add(path, 'final-stage', prop, not occurrences,
                {'instruction_lines': occurrences, 'final_from_line': final[0]['line'],
                 'limit': 'Local final-stage declaration only; inherited image values and deployment overrides not evaluated.'})
        aliases = set()
        for i, item in enumerate(instructions):
            if item['instruction'] != 'FROM': continue
            parts = item['argument'].split()
            image = next((p for p in parts if not p.startswith('--')), None)
            if not image: raise ValueError('Missing FROM image')
            external = image.lower() != 'scratch' and image.lower() not in aliases
            if external:
                add(path, 'FROM:' + str(item['line']), 'external_base_reference_without_digest', '@sha256:' not in image,
                    {'line': item['line'], 'image_reference': image})
            if len(parts) >= 3 and parts[-2].upper() == 'AS': aliases.add(parts[-1].lower())
    for path in sorted(root.glob('deploy/k8s/base/*/*.yaml')):
        docs = list(yaml.safe_load_all(path.read_text()))
        for index, doc in enumerate(docs):
            if not isinstance(doc, dict) or not doc.get('kind'): continue
            resource = f"document:{index}:{doc['kind']}:{doc.get('metadata', {}).get('name', '')}"
            if doc['kind'] not in {'Kustomization', 'Namespace', 'ClusterRole', 'ClusterRoleBinding', 'PersistentVolume', 'CustomResourceDefinition'}:
                add(path, resource, 'explicit_metadata_namespace_absent', not doc.get('metadata', {}).get('namespace'),
                    {'field': 'metadata.namespace', 'limit': 'kubectl namespace, kustomize transformation and admission not evaluated.'})
            spec = pod_spec(doc)
            if spec is not None:
                for section in ('containers', 'initContainers'):
                    for c in spec.get(section, []):
                        unit = resource + ':' + section + ':' + c.get('name', '')
                        image = c.get('image', '')
                        add(path, unit, 'image_explicit_latest_tag', image.endswith(':latest'), {'image_reference': image})
                        add(path, unit, 'pod_and_container_security_context_absent',
                            not spec.get('securityContext') and not c.get('securityContext'),
                            {'limit': 'Absence of local declarations only; no inferred effective UID or privilege.'})
                        for kind in ('requests', 'limits'):
                            for item in ('cpu', 'memory'):
                                state = item in (c.get('resources', {}).get(kind) or {})
                                add(path, unit, f'resource_{kind}_{item}_declared', state,
                                    {'field': f'{section}.resources.{kind}.{item}', 'limit': 'Presence does not establish an adequate value.'})
            if doc['kind'] == 'ConfigMap':
                for key, value in (doc.get('data') or {}).items():
                    if re.search(r'password|secret|token|api_key', str(key), re.I):
                        add(path, resource + ':data:' + str(key), 'sensitive_named_key_has_nonempty_value',
                            value is not None and str(value).strip() != '',
                            {'key': str(key), 'value_sha256': hashlib.sha256(str(value).encode()).hexdigest(),
                             'limit': 'Key-name heuristic labels a source property; credential validity or disclosure is not established.'})
    for path in sorted(root.glob('.github/workflows/*.yml')):
        doc = yaml.safe_load(path.read_text())
        for job_id, job in (doc.get('jobs') or {}).items():
            for index, step in [('job', job), *list(enumerate(job.get('steps', [])))]:
                uses = step.get('uses')
                if not uses or uses.startswith('./'): continue
                pinned = bool(re.search(r'@[0-9a-fA-F]{40}$', uses)) or '@sha256:' in uses
                add(path, f'job:{job_id}:step:{index}', 'external_action_reference_unpinned', not pinned,
                    {'uses': uses, 'limit': 'Reference immutability, not evidence of a compromised action.'})
    return rows


def legacy_count_replay(root, legacy):
    """Recompute the documented lexical scopes without executing shell text."""
    root = Path(root)
    docker = sorted(root.glob('services/*/Dockerfile'))
    k8s = sorted(root.glob('deploy/k8s/base/*/*.yaml'))
    workload = [p for p in k8s if p.name in {'deployment.yaml', 'statefulset.yaml'}]
    workflows = sorted(root.glob('.github/workflows/*.yml'))
    def rel(paths): return [p.relative_to(root).as_posix() for p in paths]
    affected = {
        'A2-01': rel(p for p in docker if not re.search(r'^USER ', p.read_text(), re.M)),
        'A2-02': rel(p for p in docker if 'HEALTHCHECK' not in p.read_text()),
        'A2-03': rel(p for p in docker if any('@sha256:' not in s for s in p.read_text().splitlines() if s.startswith('FROM'))),
        'A2-04': rel(p for p in workload if 'securityContext' not in p.read_text()),
        'A2-05': rel(p for p in k8s if re.search(r'image:.*:latest', p.read_text())),
        'A2-06': rel(p for p in k8s if 'namespace:' not in p.read_text()),
        'A2-07': [], 'A2-08': [],
        'A2-09': rel(p for p in workflows if re.search(r'uses: [^@]+@[^ ]+', p.read_text()))}
    config = root / 'deploy/k8s/base/chatbot/config.yaml'
    docs = list(yaml.safe_load_all(config.read_text()))
    data = {k: v for d in docs if isinstance(d, dict) for k, v in (d.get('data') or {}).items()}
    if any(re.search(r'password', str(k), re.I) and v for k, v in data.items()):
        affected['A2-07'] = [config.relative_to(root).as_posix()]
    if any(re.search(r'API_KEY|TOKEN', str(k)) for k in data):
        affected['A2-08'] = [config.relative_to(root).as_posix()]
    detail = [{'id': r['id'], 'recorded_count': r['expected_count'],
               'observed_lexical_artifact_count': len(affected[r['id']]),
               'artifacts': affected[r['id']]} for r in legacy['weaknesses']]
    return {'families': detail, 'recorded_total_field': legacy['total_affected_artifacts'],
            'recorded_family_sum': sum(r['expected_count'] for r in legacy['weaknesses']),
            'observed_sum_with_overlap': sum(len(v) for v in affected.values()),
            'observed_unique_paths': len(set().union(*map(set, affected.values()))),
            'interpretation': 'Lexical legacy-scope replay only; totals are not validated vulnerability counts. A2-07/08 use bounded key/value source checks, not the broad legacy grep.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--legacy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    legacy = yaml.safe_load(args.legacy.read_text())
    rows = source_references(args.root, legacy['commit'])
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'source_properties.jsonl').write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows))
    result = legacy_count_replay(args.root, legacy)
    result.update(source_property_records=len(rows), purpose='reference_development_not_final_labels',
                  legacy_source_sha256=sha(args.legacy))
    (args.output / 'legacy_reconciliation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'families'}, indent=2))

if __name__ == '__main__': main()
