"""Bounded declaration identities and explicit matching-loss diagnostics."""
from collections import defaultdict
from itertools import combinations
import json
import re

import yaml


class UniqueBaseLoader(yaml.BaseLoader):
    """Reject ambiguous mappings instead of silently keeping their last key."""
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if len(set(keys)) != len(keys): raise ValueError('Duplicate YAML key')
        return super().construct_mapping(node, deep=deep)


def declared_contents(workflow, job):
    """Return declaration precedence, without claiming live token capability."""
    origin = 'job' if 'permissions' in job else 'workflow' if 'permissions' in workflow else 'unspecified'
    value = job.get('permissions') if origin == 'job' else workflow.get('permissions')
    if value in ('read-all', 'write-all'):
        return value.split('-')[0], origin
    if isinstance(value, dict):
        answer = value.get('contents', 'none')
        return (answer if answer in ('read', 'write', 'none') else None), origin
    return None, origin


def workflow_document(text):
    # BaseLoader preserves the YAML 1.2 key "on" rather than YAML 1.1 boolean True.
    doc = yaml.load(text, Loader=UniqueBaseLoader)
    if not isinstance(doc, dict) or not isinstance(doc.get('jobs'), dict):
        raise ValueError('Unsupported workflow structure')
    return doc


def route_value(doc, route):
    value = doc
    for entry in route:
        if set(entry) == {'Key'} and isinstance(value, dict): value = value[entry['Key']]
        elif set(entry) == {'Index'} and isinstance(value, list):
            index = entry['Index']
            if not isinstance(index, int) or index < 0: raise ValueError('Invalid route index')
            value = value[index]
        else: raise ValueError('Unsupported symbolic route')
    return value


def route_context(route):
    tokens = [p.get('Key', p.get('Index')) for p in route]
    if len(tokens) >= 2 and tokens[0] == 'jobs':
        if len(tokens) >= 4 and tokens[2] == 'steps': return 'step', tokens[1], tokens[3]
        return 'job', tokens[1], None
    return 'workflow', None, None


def route_byte_span(text, route):
    """Independent YAML node envelope including a mapping key and its value."""
    node = yaml.compose(text, Loader=UniqueBaseLoader)
    first = node.start_mark.index
    for entry in route:
        if set(entry) == {'Key'} and isinstance(node, yaml.MappingNode):
            pairs = [(k,v) for k,v in node.value if k.value == entry['Key']]
            if len(pairs) != 1: raise ValueError('Ambiguous or missing YAML node')
            key,node = pairs[0]; first = key.start_mark.index
        elif set(entry) == {'Index'} and isinstance(node,yaml.SequenceNode):
            if entry['Index'] < 0: raise ValueError('Invalid YAML index')
            node = node.value[entry['Index']]; first = node.start_mark.index
        else: raise ValueError('Unsupported node route')
    return len(text[:first].encode()),len(text[:node.end_mark.index].encode())


def kics_resource(search_key):
    match = re.fullmatch(r'(aws_security_group(?:_rule)?)\[([^\[\]]+)\]\.ingress(?:\[(\d+)\])?', search_key)
    if not match: raise ValueError('Unsupported selected KICS identity')
    return match[1]+'.'+match[2], int(match[3]) if match[3] is not None else None


def literal_rule(text):
    """Decode only a supplied, bounded literal ingress body, never arbitrary HCL."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != 'ingress {' or lines[-1].strip() != '}':
        raise ValueError('Expected exact ingress span')
    content = '\n'.join(lines[1:-1]); result = {}
    pattern = re.compile(r'\s*([a-z_][a-z0-9_]*)\s*=\s*')
    decoder = json.JSONDecoder(); position = 0
    while content[position:].strip():
        match = pattern.match(content, position)
        if not match: raise ValueError('Unsupported ingress expression')
        key = match[1]
        if key in result: raise ValueError('Duplicate ingress attribute')
        value, used = decoder.raw_decode(content[match.end():])
        if '${' in json.dumps(value) or '%{' in json.dumps(value): raise ValueError('Unresolved ingress expression')
        result[key] = value; position = match.end()+used
    if not {'protocol','from_port','to_port'} <= result.keys(): raise ValueError('Incomplete ingress')
    if not set(result) <= {'protocol','from_port','to_port','cidr_blocks','ipv6_cidr_blocks','description'}:
        raise ValueError('Unsupported ingress attribute')
    return result


def pair_diagnostics(rows, key_fields):
    """Pair errors against independently supplied reference IDs; no pooling of corpora."""
    groups = defaultdict(list)
    for row in rows:
        if not row.get('reference_id'): raise ValueError('Unresolved identity cannot be scored')
        groups[tuple(row[k] for k in key_fields)].append(row)
    same_predicted = set()
    for group in groups.values():
        same_predicted.update(tuple(sorted((a['observation_id'], b['observation_id']))) for a,b in combinations(group,2))
    truth = {tuple(sorted((a['observation_id'], b['observation_id']))) for a,b in combinations(rows,2)
             if a['reference_id'] == b['reference_id']}
    if len({r['observation_id'] for r in rows}) != len(rows): raise ValueError('Duplicate observation')
    return {'observations':len(rows),'reference_instances':len({r['reference_id'] for r in rows}),
            'groups':len(groups),'true_same_pairs':len(truth),'correct_same_pairs':len(truth & same_predicted),
            'false_merge_pairs':len(same_predicted-truth),'false_split_pairs':len(truth-same_predicted),
            'member_preserving_instances':len({r['reference_id'] for group in groups.values() for r in group})}


def pass_suppression(positive_references, outcomes, keys):
    """An explicitly counterfactual policy, not an implementation of any scanner."""
    passed = {tuple(row[k] for k in keys) for row in outcomes if row['status'] == 'PASSED'}
    return sorted(row['reference_id'] for row in positive_references if tuple(row[k] for k in keys) in passed)
