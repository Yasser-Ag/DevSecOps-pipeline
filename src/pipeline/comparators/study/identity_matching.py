"""Observable identity keys and loss-aware reporting; no oracle labels are read."""
from collections import defaultdict
import itertools
import math
import re

from study.matching_baselines import canonical, fingerprint, group_keys, score_pairs


def advisory_aliases(records):
    """Accept explicit GHSA/CVE identity statements from the advisory authority."""
    aliases = {}
    for record in records:
        ghsa, cve = record.get('ghsa_id'), record.get('cve_id')
        if not re.fullmatch(r'GHSA-[a-z0-9-]+', ghsa or '') or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve or ''):
            raise ValueError('Missing advisory authority identity')
        if record.get('withdrawn_at'):
            raise ValueError('Withdrawn advisory requires separate adjudication')
        identifiers = {(x['type'], x['value']) for x in record.get('identifiers', [])}
        if ('GHSA', ghsa) not in identifiers or ('CVE', cve) not in identifiers:
            raise ValueError('Authority identity fields disagree')
        for name in (ghsa, cve):
            if name in aliases and aliases[name] != cve:
                raise ValueError('Conflicting advisory aliases')
            aliases[name] = cve
    return aliases


def relative_location(path, prefixes):
    """Strip only declared scan roots; never suffix-match or collapse traversal."""
    if not isinstance(path, str) or not path or '\\' in path:
        raise ValueError('Missing or unsupported path')
    candidates = set()
    for prefix in prefixes:
        if path.startswith(prefix):
            relative = path[len(prefix):]
            parts = relative.split('/')
            if relative and all(x not in ('', '.', '..') for x in parts):
                candidates.add(relative)
    if len(candidates) != 1:
        raise ValueError('Missing or ambiguous declared scan root: ' + path)
    return candidates.pop()


def identity_key(feature, method):
    """Each comparator has an explicit unit and a common population partition."""
    prefix = [feature.get('partition'), feature.get('family')]
    if not all(isinstance(x, str) and x for x in prefix):
        return None
    fields = {
        'component_literal': ('purl', 'reported_advisory'),
        'component_alias': ('purl', 'canonical_advisory'),
        'artifact_occurrence': ('purl', 'canonical_advisory', 'artifact', 'path'),
        'secret_path': ('artifact', 'path'),
        'secret_bytes': ('file_sha256',),
        'secret_key': ('public_der_sha256',),
        'configuration_resource': ('artifact', 'path', 'resource', 'property', 'context'),
    }
    if method not in fields:
        raise ValueError('Unknown identity method')
    values = [feature.get(k) for k in fields[method]]
    if any(not isinstance(x, str) or not x for x in values):
        return None
    return fingerprint(prefix + values)


def make_groups(features, method):
    rows = []
    for feature in features:
        key = identity_key(feature, method)
        rows.append({'finding_id': feature['observation_id'], 'key': key,
                     'status': 'supported' if key is not None else 'unsupported'})
    return group_keys(rows)


def pair_audit(features, assignments, method, unit):
    """Exhaustive within-partition pairs; assignments belong only to the scorer."""
    ids = [r['observation_id'] for r in features]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate observation identity')
    keys = {r['observation_id']: identity_key(r, method) for r in features}
    relations = []
    for left, right in itertools.combinations(features, 2):
        if (left['partition'], left['family']) != (right['partition'], right['family']):
            continue
        a, b = assignments.get(left['observation_id']), assignments.get(right['observation_id'])
        av, bv = (a or {}).get(unit), (b or {}).get(unit)
        known = av is not None and bv is not None
        relations.append({'left': left['observation_id'], 'right': right['observation_id'],
                          'relation': ('same' if av == bv else 'different') if known else 'unknown',
                          'evidence_ids': sorted(set((a or {}).get('evidence_ids', []) +
                                                     (b or {}).get('evidence_ids', []))) or ['unresolved-reference']})
    return score_pairs(relations, keys)


def reporting_effect(features, assignments, method, unit, limit=100000):
    """Replay an explicitly destructive one-representative reporting policy.

    Loss refers to reference units absent from the report, not repaired flaws.
    Unknown keys are retained individually. All representative choices are
    enumerated within a fixed bound; no favorable ordering is selected.
    """
    grouped = make_groups(features, method)
    groups = [g['members'] for g in grouped['groups']]
    groups += [[i] for i in grouped['unresolved_finding_ids']]
    refs = {r['observation_id']: (assignments.get(r['observation_id']) or {}).get(unit)
            for r in features}
    baseline = {v for v in refs.values() if v is not None}
    member_units = {refs[i] for group in groups for i in group if refs[i] is not None}
    total = math.prod(len(g) for g in groups)
    result = {'method': method, 'unit': unit, 'observations': len(features),
              'report_groups': len(groups), 'baseline_reference_units': len(baseline),
              'unresolved_reference_observations': sum(v is None for v in refs.values()),
              'unsupported_keys_retained': len(grouped['unresolved_finding_ids']),
              'member_preserving_units_lost': len(baseline - member_units), 'representative_combinations': total,
              'interpretation': 'Counterfactual report visibility, not security improvement or LLM filtering.'}
    if total > limit:
        result['representative_status'] = 'enumeration_limit'
        return result
    losses = []
    for representatives in itertools.product(*groups):
        retained = {refs[i] for i in representatives if refs[i] is not None}
        losses.append(len(baseline - retained))
    result.update(representative_status='exhaustive',
                  representative_units_lost_min=min(losses, default=0),
                  representative_units_lost_max=max(losses, default=0))
    return result


def stage_effect(features, assignments, method, unit):
    """Compare marginal fingerprint coverage with independently assigned units."""
    stages = sorted({r['stage'] for r in features})
    def observed(rows):
        keys = set()
        truth = set()
        for row in rows:
            oid = row['observation_id']
            key = identity_key(row, method)
            # Missing features are never treated as the same unknown object.
            keys.add(key if key is not None else 'unsupported:' + oid)
            ref = (assignments.get(oid) or {}).get(unit)
            if ref is not None:
                truth.add(ref)
        return keys, truth
    all_keys, all_truth = observed(features)
    effects = []
    for stage in stages:
        keys, truth = observed([r for r in features if r['stage'] != stage])
        effects.append({'stage': stage, 'fingerprint_groups_lost': len(all_keys - keys),
                        'reference_units_lost': len(all_truth - truth)})
    return {'method': method, 'unit': unit, 'stages': effects,
            'interpretation': 'Coverage of the declared unit, not operational stage dispensability.'}
