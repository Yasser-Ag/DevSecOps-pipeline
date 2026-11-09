"""Reconcile saved AIGoat observations with source and pre-scan HTTP properties.

All generated labels describe declared/observed properties. They are evaluation
data, not inference packets or final security TP/FP judgments.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import yaml

from study.aigoat_references import Builder as EvidenceReader, pointer, require
from study.configuration_matching import UniqueLoader
from study.coverage_registry import canonical, identity, summarize, validate

STATIC = 'evidence/aigoat_static_2026-10-12/'
API = 'evidence/aigoat_api_2026-10-12/run-02/'
BASE = 'evidence/aigoat_reference_2026-10-12/development-v1/'
HERE = 'evidence/aigoat_linkage_2026-10-12/'
SOURCE = STATIC + 'run01/inputs/'
HEADER_NAMES = (
    'content-security-policy', 'cross-origin-embedder-policy',
    'cross-origin-opener-policy', 'cross-origin-resource-policy',
    'permissions-policy', 'referrer-policy', 'strict-transport-security',
    'x-content-type-options', 'x-frame-options', 'x-permitted-cross-domain-policies',
    'content-type',
)
DOCKER_RULES = {
    'CKV_DOCKER_3': 'missing_user_instruction', 'DS-0002': 'missing_user_instruction',
    'CKV_DOCKER_2': 'missing_healthcheck_instruction', 'DS-0026': 'missing_healthcheck_instruction',
}
COMPOSE_RULES = {
    'ce76b7d0-9e77-464d-b86f-c5c48e03e22d': 'missing_cap_drop',
    '610e266e-6c12-4bca-9925-1ed0cd29742b': 'missing_security_opt',
    '698ed579-b239-4f8f-a388-baa4bcb13ef8': 'missing_healthcheck',
    '451d79dc-0588-476a-ad03-3c7f0320abb3': 'published_on_wildcard_interface',
}
SHARED = '8c978947-0ff6-485c-b0c2-0bfca6026466'
SENSITIVE = '1c1325ff-831d-43a1-973e-839ae57dfcc0'
FIELDS = ('scope', 'artifact', 'resource', 'property', 'context')
SOURCE_POP = 'aigoat-declared-properties'
HTTP_POP = 'aigoat-http-properties'


def docker_properties(text):
    """Bounded instruction parser; never infer base-image or process state."""
    instructions = []
    pending = ''
    for physical in text.splitlines():
        line = physical.strip()
        if not line or line.startswith('#'):
            if re.match(r'#\s*escape\s*=\s*`', line):
                raise ValueError('Unsupported Dockerfile escape directive')
            continue
        require('<<' not in line, 'Heredoc needs an explicit parser qualification')
        pending += line[:-1] + ' ' if line.endswith('\\') else line
        if line.endswith('\\'):
            continue
        match = re.match(r'^([A-Za-z]+)\s+(.+)$', pending)
        require(match is not None, 'Unparsed Dockerfile instruction')
        instructions.append((match.group(1).upper(), match.group(2)))
        pending = ''
    require(not pending and any(op == 'FROM' for op, _ in instructions), 'Incomplete Dockerfile')
    names = [op for op, _ in instructions]
    return {'missing_user_instruction': 'USER' not in names,
            'missing_healthcheck_instruction': 'HEALTHCHECK' not in names}, instructions


def mounts(service):
    result = []
    for index, volume in enumerate(service.get('volumes') or []):
        if isinstance(volume, str):
            parts = volume.split(':')
            require(len(parts) in (2, 3), 'Unsupported mount syntax')
            source, target = parts[:2]
            mode = parts[2] if len(parts) == 3 else 'rw'
            kind = 'bind' if source.startswith(('/', '.')) else 'volume'
            readonly = 'ro' in mode.split(',')
        elif isinstance(volume, dict):
            source, target, kind = volume.get('source'), volume['target'], volume['type']
            require(kind in ('bind', 'volume') and isinstance(source, str), 'Unsupported mount type')
            readonly = volume.get('read_only', False)
            require(type(readonly) is bool, 'Ambiguous mount read_only')
        else:
            raise ValueError('Unsupported volume declaration')
        result.append({'index': index, 'source': source, 'target': target,
                       'kind': kind, 'read_only': readonly})
    return result


def named_consumers(compose):
    result = {name: set() for name in (compose.get('volumes') or {})}
    for service, value in compose['services'].items():
        for mount in mounts(value):
            if mount['kind'] == 'volume':
                result.setdefault(mount['source'], set()).add(service)
    return {name: sorted(users) for name, users in sorted(result.items())}


def compose_properties(service):
    wildcard = False
    for port in service.get('ports') or []:
        if isinstance(port, dict):
            interface = port.get('host_ip', '')
        elif isinstance(port, str):
            value = port.split('/')[0]
            if value.startswith('['):
                interface = value.split(']', 1)[0][1:]
            else:
                fields = value.split(':')
                require(len(fields) <= 3, 'Ambiguous port syntax')
                interface = fields[0] if len(fields) == 3 else ''
        elif isinstance(port, int):
            interface = ''
        else:
            raise ValueError('Unsupported port declaration')
        wildcard |= interface in ('', '0.0.0.0', '::')
    for key in ('read_only', 'privileged'):
        require(key not in service or type(service[key]) is bool, 'Ambiguous Compose boolean')
    return {'missing_cap_drop': 'cap_drop' not in service,
            'missing_security_opt': 'security_opt' not in service,
            'missing_healthcheck': 'healthcheck' not in service,
            'published_on_wildcard_interface': wildcard,
            'explicit_privileged': service.get('privileged') is True,
            'read_only_not_explicit_true': service.get('read_only') is not True,
            'explicit_host_network': service.get('network_mode') == 'host'}


def coordinate(scope, artifact, resource, prop, context=''):
    return dict(zip(FIELDS, (scope, artifact, resource, prop, context)))


def key(row):
    return canonical([row.get(name) for name in FIELDS])


def docker_path(native, view):
    path = native.get('path') or ''
    absolute = '<LAB_ROOT>/evidence/aigoat-static-20261012-01/inputs/' + view + '/docker/'
    path = path.removeprefix(absolute)
    require(re.fullmatch(r'(backend|frontend|ollama)/Dockerfile', path) is not None,
            'Ambiguous Dockerfile native path')
    return view + '/docker/' + path


def observed_coordinate(profile, row):
    """Use native fields and invocation metadata only, with no reference input."""
    name = profile['id']; rule = row.get('native_rule')
    if name.startswith(('checkov-docker-', 'trivy-config-')) and rule in DOCKER_RULES:
        view = 'original' if name.endswith('original') else 'deployment'
        path = docker_path(row, view)
        return coordinate('dockerfile', path, 'file', DOCKER_RULES[rule])
    if name.startswith('kics-compose'):
        view = 'deployment' if 'deployment' in name else 'original'
        artifact = 'compose/' + view
        resource = row.get('resource') or ''
        service = re.fullmatch(r'services\.([^.]+)(?:\.(ports|volumes))?', resource)
        require(service is not None, 'Unqualified Compose resource coordinate')
        if rule in COMPOSE_RULES:
            return coordinate('compose_service', artifact, service.group(1), COMPOSE_RULES[rule])
        if rule == SHARED:
            match = re.fullmatch(r'Volume ([^ ]+) created and shared between containers', row.get('actual_value', ''))
            require(match is not None, 'Unknown volume-sharing message variant')
            return coordinate('named_volume', artifact, match.group(1), 'at_least_two_service_consumers')
        if rule == SENSITIVE:
            match = re.fullmatch(r'There is a sensitive directory \((.+)\) mounted as a volume', row.get('actual_value', ''))
            require(match is not None, 'Unknown host-mount message variant')
            return coordinate('bind_mount', artifact, service.group(1) + ':' + match.group(1), 'literal_source_under_home')
    if profile.get('api'):
        url = row.get('url'); method = row.get('method')
        request = row.get('request') or ''
        if request:
            first = request.splitlines()[0]
            match = re.fullmatch(r'([A-Z]+) ([^ ]+) HTTP/[0-9.]+', first)
            require(match is not None, 'Unparsed native HTTP request line')
            require(method is None or method == match.group(1), 'Conflicting native HTTP method')
            require(url is not None and urlsplit(match.group(2)).path == urlsplit(url).path,
                    'Native HTTP request/URL paths disagree')
            method = match.group(1)
        if not url or not method:
            return None
        parsed = urlsplit(url)
        require(not parsed.query and not parsed.fragment, 'Unqualified API query identity')
        resource = method + ' ' + parsed.path
        context = profile['auth_role']
        if profile['tool'] == 'nuclei' and rule == 'http-missing-security-headers':
            prop = 'missing_header:' + row['matcher'].lower()
        elif profile['tool'] == 'zap' and rule == '10021':
            prop = 'missing_header:x-content-type-options'
        elif profile['tool'] == 'zap' and rule == '100000' and row.get('native_alert_ref') == '100000-1':
            prop = 'response_is_4xx'
        else:
            return None
        return coordinate('http_response', 'api-state:aigoat-api-20261012-02', resource, prop, context)
    return None


def groups(observables, method):
    """Every group preserves its complete membership; unknowns abstain."""
    out = defaultdict(list)
    for row in observables:
        if row.get('coordinate') is None:
            group = 'singleton:' + row['finding_id']
        elif method == 'competent_exact':
            group = key(row['coordinate'])
        elif method == 'coarse_property':
            c = row['coordinate']; group = canonical([c['scope'], c['property']])
        else:
            raise ValueError('Unknown matcher')
        out[group].append(row['finding_id'])
    return [sorted(values) for _, values in sorted(out.items())]


def retention(observables, links):
    support = defaultdict(set)
    for row in links:
        if row['relation'] == 'supports': support[row['finding_id']].add(row['case_id'])
    ids = {row['finding_id'] for row in observables}
    covered = set().union(*(support[i] for i in ids)) if ids else set()
    result = []
    for method in ('coarse_property', 'competent_exact'):
        buckets = groups(observables, method)
        require([i for bucket in buckets for i in bucket].__len__() == len(ids), 'Dropped/duplicated group membership')
        for policy in ('all_members', 'lexically_first_representative'):
            kept = {i for bucket in buckets for i in (bucket if policy == 'all_members' else bucket[:1])}
            retained = set().union(*(support[i] for i in kept)) if kept else set()
            result.append({'method': method, 'reporting_policy': policy, 'groups': len(buckets),
                           'input_findings': len(ids), 'retained_findings': len(kept),
                           'input_supported_cases': len(covered), 'retained_supported_cases': len(retained),
                           'lost_supported_case_ids': sorted(covered-retained),
                           'scope': 'Saved-output property support; representative policy is a counterfactual, not a model decision.'})
    return result


class Builder(EvidenceReader):
    def __init__(self, root):
        super().__init__(root)
        self.references = []; self.observations = []; self.reference_by_key = {}
        self.byte_cache = {}; self.json_cache = {}

    def data(self, relative):
        if relative not in self.byte_cache:
            self.byte_cache[relative] = super().data(relative)
        return self.byte_cache[relative]

    def read(self, relative):
        if relative not in self.json_cache:
            self.json_cache[relative] = json.loads(self.data(relative))
        return self.json_cache[relative]

    def lines(self, path):
        return [json.loads(line) for line in self.data(path).decode().splitlines()]

    def ev(self, path, location='', **extras):
        # JSONL evidence uses a one-based physical line coordinate.
        if location.startswith('line:'):
            row = int(location[5:]); require(row > 0, 'Invalid JSONL line')
            require(row <= len(self.data(path).decode().splitlines()), 'JSONL line outside evidence')
            return {'path': path, 'sha256': self.inputs[path]['sha256'], 'pointer': location, **extras}
        self.data(path)
        if location and path.endswith('.json'):
            pointer(self.read(path), location)
        return {'path': path, 'sha256': self.inputs[path]['sha256'], 'pointer': location, **extras}

    def add_reference(self, coord, value, evidence, details):
        require(type(value) is bool, 'Property truth requires a boolean')
        pop = HTTP_POP if coord['scope'] == 'http_response' else SOURCE_POP
        k = key(coord); require(k not in self.reference_by_key, 'Duplicate reference coordinate')
        row = {'case_id': identity('case-', 'aigoat-properties-v1', k), 'population': pop,
               'unit': 'artifact_context_property', 'endpoint': 'specified literal or observed property',
               'truth': 'positive' if value else 'negative', 'object_id': identity('object-', coord['scope'], coord['artifact'], coord['resource']),
               'family_id': 'aigoat-development', 'evidence': evidence,
               'details': {'coordinate': coord, 'value': value, 'selection': 'development_after_outcome_access',
                           'coauthor_review': 'pending', 'scanner_used_as_oracle': False,
                           'security_consequence': 'not_established', **details}}
        self.references.append(row); self.reference_by_key[k] = row

    def verify_collections(self):
        lock = self.read(HERE + 'input_locks.json')
        for row in lock['files']:
            require(hashlib.sha256(self.data(row['path'])).hexdigest() == row['sha256'], 'Locked input changed: ' + row['path'])
        for prefix in (STATIC+'run01/', STATIC+'run02/', STATIC+'run03/', API):
            manifest = self.read(prefix+'collection_manifest.json')
            for row in manifest['files']:
                data = self.data(prefix+row['path'])
                require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'Collection changed')
        base = self.read(BASE+'manifest.json')
        for row in base['outputs']:
            require(hashlib.sha256(self.data(BASE+row['path'])).hexdigest() == row['sha256'], 'Prior reference release changed')
        selected = self.read(STATIC+'run01/input_manifest.json')['selected_configurations']
        for row in selected:
            require(hashlib.sha256(self.data(SOURCE+row['path'])).hexdigest() == row['sha256'], 'Configuration input changed')
        sources = self.read(HERE+'sources/manifest.json')
        for row in sources['sources']:
            require(hashlib.sha256(self.data(HERE+'sources/'+row['path'])).hexdigest() == row['sha256'], 'Primary source snapshot changed')

    def build_source_references(self):
        for view, names in [('original', ('backend', 'frontend')), ('deployment', ('backend', 'frontend', 'ollama'))]:
            for name in names:
                artifact = view+'/docker/'+name+'/Dockerfile'; path = SOURCE+artifact
                data = self.data(path).decode(); properties, instructions = docker_properties(data)
                for prop, value in properties.items():
                    self.add_reference(coordinate('dockerfile', artifact, 'file', prop), value,
                        [self.ev(path)], {'instruction_names': [i[0] for i in instructions],
                        'scope_limit': 'Literal whole-file declaration only; no inherited image or effective process property.'})
        for view, path in [('original', SOURCE+'compose/original/docker-compose.yml'),
                           ('deployment', STATIC+'run03/inputs/docker-compose.yml')]:
            text = self.data(path).decode(); document = yaml.load(text, Loader=UniqueLoader)
            if view == 'deployment':
                require(document == self.read(SOURCE+'compose/deployment/docker-compose.yaml'), 'Compose representations differ')
            artifact = 'compose/'+view
            for service, values in sorted(document['services'].items()):
                for prop, value in compose_properties(values).items():
                    self.add_reference(coordinate('compose_service', artifact, service, prop), value,
                        [self.ev(path, yaml_pointer='/services/'+service)], {'scope_limit': 'Declaration only; no effective host exposure or privilege inferred.'})
                for mount in mounts(values):
                    if mount['kind'] != 'bind': continue
                    resource = service+':'+mount['source']
                    self.add_reference(coordinate('bind_mount', artifact, resource, 'literal_source_under_home'),
                        mount['source'] == '/home' or mount['source'].startswith('/home/'),
                        [self.ev(path, yaml_pointer='/services/'+service+'/volumes/'+str(mount['index']))],
                        {'mount': mount, 'scope_limit': 'Literal /home prefix, not sensitivity, write access or exploitability.'})
            for volume, consumers in named_consumers(document).items():
                self.add_reference(coordinate('named_volume', artifact, volume, 'at_least_two_service_consumers'),
                    len(consumers) >= 2, [self.ev(path)], {'declared_consumers': consumers,
                    'scope_limit': 'Only services in this single Compose declaration; outside consumers unknown.'})

    def build_http_references(self):
        path = API+'proxy-logs/requests.jsonl'; grouped = defaultdict(list)
        for index, row in enumerate(self.lines(path), 1):
            if row['phase'] != 'reference-proxy': continue
            require(row['forwarded'] and not row['harness_error'], 'Independent HTTP probe failed')
            require(row['status'] in (200, 401), 'Unqualified reference response')
            resource = row['method']+' '+urlsplit(row['path']).path
            grouped[(resource, row['auth_role'])].append((index, row))
        for (resource, role), rows in sorted(grouped.items()):
            observed = [{name.lower() for name, value in row['response_headers']} for _, row in rows]
            require(all(names == observed[0] for names in observed), 'Varying headers within reference context')
            statuses = {row['status'] for _, row in rows}
            require(len(statuses) == 1, 'Varying status within reference context')
            evidence = [self.ev(path, 'line:'+str(index)) for index, _ in rows]
            for header in HEADER_NAMES:
                self.add_reference(coordinate('http_response', 'api-state:aigoat-api-20261012-02', resource,
                                   'missing_header:'+header, role), header not in observed[0], evidence,
                                   {'reference_status': next(iter(statuses)), 'header': header,
                                    'scope_limit': 'Header presence in this exact pre-scan route/role context; not a security requirement.'})
            self.add_reference(coordinate('http_response', 'api-state:aigoat-api-20261012-02', resource,
                               'response_is_4xx', role), 400 <= next(iter(statuses)) < 500, evidence,
                               {'reference_status': next(iter(statuses)), 'scope_limit': 'HTTP response class, not failure of authorization.'})

    def import_findings(self):
        findings = []; observables = []; links = []; profiles = []
        for run in ('01', '02', '03'):
            prefix = STATIC+'run'+run+'/'; summary = self.read(prefix+'summary.json')
            for profile in summary['profiles']:
                if profile['id'] != 'checkov-workflow':
                    profiles.append((prefix, {**profile, 'tool': profile['parser'], 'api': False}, prefix+profile['report']))
        for profile in self.read(API+'summary.json')['profiles']:
            profiles.append((API, {**profile, 'api': True}, API+profile['raw_report']))
        unlinked = Counter()
        for prefix, profile, raw_path in profiles:
            norm_path = prefix+profile['id']+'.normalized.json'; normalized = self.read(norm_path)
            raw_bytes = self.data(raw_path); raw_sha = hashlib.sha256(raw_bytes).hexdigest()
            require(raw_sha == normalized['raw_report_sha256'], 'Native report identity changed')
            raw = [json.loads(line) for line in raw_bytes.decode().splitlines() if line.strip()] if profile['tool'] == 'nuclei' else json.loads(raw_bytes)
            for index, native in enumerate(normalized['findings']):
                loc = native['native_locator']; pointer(raw, loc)
                fid = identity('finding-', raw_sha, loc)
                coord = observed_coordinate(profile, native)
                pop = (HTTP_POP if profile['api'] else SOURCE_POP) if coord else 'aigoat-unresolved:'+profile['tool']
                public_fields = {k: native[k] for k in ('native_rule','message','description','severity','cwes','path','line_start','line_end','resource','url','method','matcher','native_alert_ref') if k in native}
                native_evidence = [self.ev(norm_path, '/findings/'+str(index)), self.ev(raw_path)]
                row = {'finding_id': fid, 'source_finding_id': native.get('finding_id'), 'population': pop,
                       'tool': profile['tool'], 'profile': profile['id'], 'stage': 'api' if profile['api'] else ('configuration' if coord else profile['tool']),
                       'native_label': 'unresolved', 'native_fields': public_fields, 'raw_report_sha256': raw_sha,
                       'native_locator': loc, 'evidence': native_evidence,
                       'label_scope': 'Security correctness not adjudicated; source/HTTP property links are separate.'}
                findings.append(row)
                observable = {'finding_id': fid, 'tool': profile['tool'], 'profile': profile['id'],
                              'native_rule': native.get('native_rule'), 'coordinate': coord,
                              'method_basis': ('normalized_native_field' if native.get('method') else
                                               'native_request_line' if profile['api'] and native.get('request') else None)}
                observables.append(observable)
                ref = self.reference_by_key.get(key(coord)) if coord else None
                if ref:
                    relation = 'supports' if ref['truth'] == 'positive' else 'contradicts'
                    links.append({'finding_id': fid, 'case_id': ref['case_id'], 'relation': relation,
                                  'evidence': native_evidence + ref['evidence'],
                                  'scope': 'Projection to specified literal/observed property only; not automatic native TP/FP.',
                                  'coauthor_review': 'pending'})
                else:
                    unlinked['missing_exact_reference_context' if coord else 'outside_property_adjudication_scope'] += 1
        return findings, observables, links, profiles, dict(unlinked)

    def build(self, output):
        output = Path(output); require(not output.exists(), 'Preserve existing release')
        self.verify_collections()
        self.build_source_references(); self.build_http_references()
        findings, observables, links, profiles, unlinked = self.import_findings()
        refs = self.lines(BASE+'evaluation/references.jsonl')
        previous = self.lines(BASE+'evaluation/native_findings.jsonl')
        old_links = self.lines(BASE+'evaluation/links.jsonl')
        populations = list(self.read(BASE+'evaluation/populations.json'))
        require((len(refs),len(previous),len(old_links)) == (192,314,144), 'Prior development baseline changed')
        new_pops = sorted({f['population'] for f in findings} | {SOURCE_POP, HTTP_POP})
        for name in new_pops:
            populations.append({'population':name,'cohort':'AIGoat observed development artifacts/contexts',
                                'layer':'api' if name == HTTP_POP else 'aigoat',
                                'unit':'artifact_context_property','endpoint':'specified literal or observed property',
                                'linkage_status':'partial_property_adjudication'})
        combined = (refs+self.references, previous+findings, old_links+links, populations)
        validate(*combined)
        coverage = summarize(*combined)
        old_coverage = self.read(BASE+'coverage_by_population.json')
        require([r for r in coverage if r['population'] in {p['population'] for p in self.read(BASE+'evaluation/populations.json')}] == old_coverage,
                'Historical coverage changed')
        comparisons = retention([o for o in observables if o['coordinate']], links)
        require(all(not r['lost_supported_case_ids'] for r in comparisons if r['reporting_policy']=='all_members'), 'Member preservation failed')
        output.mkdir(parents=True); (output/'evaluation').mkdir(); (output/'matching').mkdir()
        def write(rel, data, jsonl=False):
            text = ''.join(canonical(r)+'\n' for r in data) if jsonl else json.dumps(data,indent=2,sort_keys=True)+'\n'
            (output/rel).write_text(text)
        for name, rows in [('references',combined[0]),('native_findings',combined[1]),('links',combined[2])]:
            original = self.data(BASE+'evaluation/'+name+'.jsonl')
            additions = rows[{'references':len(refs),'native_findings':len(previous),'links':len(old_links)}[name]:]
            (output/'evaluation'/ (name+'.jsonl')).write_bytes(original + ''.join(canonical(r)+'\n' for r in additions).encode())
        write('evaluation/populations.json',populations)
        write('property_references.jsonl',self.references,True); write('property_links.jsonl',links,True)
        write('matching/observables.jsonl',observables,True); write('matching/retention.json',comparisons)
        write('coverage_by_population.json',coverage)
        summary = {'phase':'post_outcome_development_property_linkage','remote_actions':False,'scanners_invoked':False,'models_invoked':False,
                   'native_observations_imported':len(findings),'source_profiles':len(profiles),'new_reference_properties':len(self.references),
                   'property_links':len(links),'relation_counts':dict(Counter(r['relation'] for r in links)),
                   'new_reference_truth_counts':dict(Counter(r['truth'] for r in self.references)),
                   'new_native_label_counts':dict(Counter(r['native_label'] for r in findings)),
                   'unlinked_native_reasons':unlinked,'combined_references':len(combined[0]),'combined_native_findings':len(combined[1]),
                   'combined_links':len(combined[2]),'coauthor_review':'pending','rag_scanner_coverage':None,'final_scientific_result':False,
                   'limits':['Property absence/presence is not exploitability or universal security correctness.',
                             'All new native security labels remain unresolved; contradicted projections are not automatically false alerts.',
                             'No inference or matcher receives reference labels, case IDs or oracle responses.',
                             'No cross-role or cross-route substitution for missing independent HTTP references.',
                             'Same source family, observed development reports and partial linkage; no inferential statistics or general recall.',
                             'Coarse grouping is an ablation; both member-preserving methods retain all known support.',
                             'Representative selection is a diagnostic reporting policy, not a measured LLM action.']}
        write('summary.json',summary)
        with (output/'coauthor_review.csv').open('w',newline='') as stream:
            fields=['case_id','scope','artifact','resource','property','context','proposed_property_truth','linked_findings','proposed_relations','first_judgment','reviewer','review_date','rationale','adjudication']
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
            for ref in self.references:
                matched=[r for r in links if r['case_id']==ref['case_id']]
                writer.writerow({'case_id':ref['case_id'],**ref['details']['coordinate'],'proposed_property_truth':ref['truth'],
                                 'linked_findings':';'.join(r['finding_id'] for r in matched),'proposed_relations':';'.join(r['relation'] for r in matched)})
        outputs=[{'path':str(p.relative_to(output)),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                 for p in sorted(output.rglob('*')) if p.is_file()]
        write('manifest.json',{'inputs':sorted(self.inputs.values(),key=lambda r:r['path']),'outputs':outputs,'evaluation_only':True,
                              'contract':'study/AIGOAT_LINKAGE_CONTRACT.md','coauthor_review':'pending'})
        print(json.dumps(summary,indent=2))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();Builder(args.root).build(args.output)


if __name__=='__main__':main()
