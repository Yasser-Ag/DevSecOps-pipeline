"""Independently recompute ledger counts without importing the analysis scorer.

This audit checks evidence custody, the narrow Semgrep interpretation overlay,
reference-supported unions, paired output omissions, and scoped triage counts.
It does not certify novelty, external validity or journal acceptance.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import json
from pathlib import Path
import resource
import statistics
import traceback

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / 'evidence/final_static_campaign_2026-10-23'
BINDINGS = ROOT / 'data/references/bindings.json'
CONDITIONS = {'B0': 'B0', 'B1': 'B1', 'qwen35-9b-q4km/alert_only': 'Q-A',
              'qwen35-9b-q4km/context': 'Q-C', 'gemma4-e4b-qat-q40/alert_only': 'G-A',
              'gemma4-e4b-qat-q40/context': 'G-C'}


def require(test, message):
    if not test: raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024**2), b''): h.update(chunk)
    return h.hexdigest()


def read(path):
    with Path(path).open() as stream: return json.load(stream)


def lines(path):
    with Path(path).open() as stream: return [json.loads(line) for line in stream if line.strip()]


def rows(path):
    with Path(path).open(newline='') as stream: return list(csv.DictReader(stream))


def check_manifest(root, entries):
    require(len(entries) == len({r['path'] for r in entries}), 'Duplicate manifest entry')
    for row in entries:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe manifest path')
        path = root / relative
        require(not path.is_symlink() and path.is_file(), 'Missing or symbolic input')
        require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'Manifest mismatch: ' + str(path))


def check_overlay(original, overlay, catalog):
    """Check each repaired assertion directly against both immutable records."""
    jobs = {j['job_id']: j for j in original}
    entries = {c['historical_finding_id']: c for c in catalog if c['profile_id'] == 'java-semgrep'}
    count = 0
    require(len(overlay['jobs']) == 5, 'Unexpected overlay size')
    for patch in overlay['jobs']:
        old, new = jobs[patch['job_id']], patch['corrected_job']
        require(old['profile_id'] == new['profile_id'] == 'java-semgrep', 'Overlay scope changed')
        allowed = {'observations', 'links', 'bound_assertions', 'analysis_correction_scope'}
        require({k:v for k,v in old.items() if k not in allowed} ==
                {k:v for k,v in new.items() if k not in allowed}, 'Unrelated job fields changed')
        old_obs = {o['finding_id']: o for o in old['observations']}
        require(set(old_obs) == {o['finding_id'] for o in new['observations']}, 'Native identity set changed')
        expected_links = []
        seen = set()
        for fresh in new['observations']:
            before = old_obs[fresh['finding_id']]
            permitted = {'population', 'scoped_native_label', 'historical_witness_ids', 'binding_status', 'analysis_correction'}
            require({k:v for k,v in before.items() if k not in permitted} ==
                    {k:v for k,v in fresh.items() if k not in permitted}, 'Raw observation changed')
            historical = fresh['historical_witness_ids']
            require(len(historical) == 1 and historical[0] not in seen, 'Ambiguous catalog binding')
            seen.add(historical[0]); entry = entries[historical[0]]
            compared = dict(before['native_content'])
            require(compared['native_rule'] == 'home.lab.' + entry['content']['native_rule'], 'Unexpected alias')
            compared['native_rule'] = entry['content']['native_rule']
            require(compared == entry['content'], 'A non-prefix field differs')
            require(fresh['population'] == entry['population'] and
                    fresh['scoped_native_label'] == entry['scoped_native_label'], 'Interpretation changed')
            expected_links.extend({**e, 'finding_id': fresh['finding_id']} for e in entry['links'])
            count += 1
        actual_links = [{k:v for k,v in e.items() if k != 'binding_evidence'} for e in new['links']]
        normalize = lambda values: sorted(json.dumps(e, sort_keys=True) for e in values)
        require(normalize(actual_links) == normalize(expected_links), 'Links differ from catalog')
        require(seen == set(entries), 'Catalog repair not bijective')
        jobs[patch['job_id']] = new
    require(count == 80, 'Missing repaired assertion')
    return jobs


def audit_coverage(analysis, jobs, bindings):
    refs = {r['case_id']: r for r in bindings['references']}
    routes = {p['profile_id']: p for p in bindings['profiles']}
    observations = rows(analysis / 'coverage_by_profile.csv')
    expected_keys = {(j['job_id'], p) for j in jobs.values()
                     for p in routes[j['profile_id']]['candidate_populations']}
    require(len(observations) == len(expected_keys) == 490, 'Coverage ledger cardinality differs')
    seen, supported, eligible = set(), {}, {}
    for row in observations:
        key = (row['job_id'], row['population']); require(key not in seen and key in expected_keys, 'Coverage row identity')
        seen.add(key); job = jobs[row['job_id']]; profile = routes[job['profile_id']]
        usable = job['measurement_eligible'] and profile['role'] != 'inventory'
        require((row['measurement_eligible'] == 'True') == usable, 'Eligibility changed')
        require(row['profile_recall'] == '', 'Unqualified recall introduced')
        require(row['limitations'] == json.dumps(job.get('limitations', []), sort_keys=True), 'Limitation lost')
        sets = {'supports': set(), 'contradicts': set()}
        for edge in job['links'] if usable else []:
            ref = refs[edge['case_id']]
            if ref['population'] != row['population'] or edge['relation'] not in sets: continue
            require(ref['truth'] == ('positive' if edge['relation'] == 'supports' else 'negative'), 'Truth relation mismatch')
            sets[edge['relation']].add(edge['case_id'])
        for relation, field in [('supports', 'supported_positive'), ('contradicts', 'contradicted_negative')]:
            require(row[field + '_cases'] == (json.dumps(sorted(sets[relation])) if usable else ''), 'Coverage witness mismatch')
            require(row[field + '_count'] == (str(len(sets[relation])) if usable else ''), 'Coverage count mismatch')
        k = (int(row['block']), row['population'], row['profile_id'])
        supported[k] = sets['supports']; eligible[k] = usable
    omissions = read(analysis / 'population_and_stage_omissions.json')
    for item in omissions:
        if item['block'] is None:
            require(not item['qualified_profile_union'] and not item['full_comparison_available'], 'Empty population misrepresented')
            continue
        members = {k[2]: v for k,v in supported.items() if k[:2] == (item['block'], item['population'])
                   and eligible[k]}
        union = set().union(*members.values())
        require(set(item['qualified_profile_union']) == union, 'Population union mismatch')
        for contrast in item['comparisons']:
            retained = set().union(*(v for profile,v in members.items() if profile not in contrast['omitted_profiles']))
            require(set(contrast['lost_case_ids']) == union - retained, 'Omission witnesses differ')
            require((contrast['supported_before'], contrast['supported_after'], contrast['lost_count']) ==
                    (len(union), len(retained), len(union-retained)), 'Omission count differs')
            objects = {refs[c]['object_id'] for c in union if refs[c].get('object_id')}
            remaining = {refs[c]['object_id'] for c in retained if refs[c].get('object_id')}
            require(contrast['lost_object_count'] == (len(objects-remaining) if objects else None), 'Object loss differs')
    return len(observations), len(omissions)


def audit_triage(analysis, bindings, passes):
    endpoints = {e['finding_id']: e for e in bindings['triage_clusters']}
    reported = rows(analysis / 'triage_summary.csv')
    expected = {}
    for block in passes:
        directory = 'triage_single_pass_2026-10-24/scientific-audit-v2' if block == 1 else 'triage_second_pass_2026-10-24/scientific-audit-v1'
        decisions = lines(ROOT / 'evidence' / directory / 'decisions.jsonl')
        require(len(decisions) == 528, 'Incomplete decision universe')
        require(len({(r['condition'], r['finding_id']) for r in decisions}) == 528, 'Duplicate decision')
        for raw_condition, condition in CONDITIONS.items():
            subset = [d for d in decisions if d['condition'] == raw_condition]
            require({d['finding_id'] for d in subset} == set(endpoints), 'Paired inputs changed')
            for domain in ('inherited_native_assertion', 'literal_declaration_assertion'):
                group = [d for d in subset if endpoints[d['finding_id']]['evaluation_domain'] == domain]
                truth = lambda d: endpoints[d['finding_id']]['endpoint_truth']
                removed = lambda d: d['status'] == 'completed' and d['action'] == 'dismiss'
                require(all((d['effective_action'] == 'dismiss') == removed(d) for d in group), 'Invalid/abstained output removed')
                before = set().union(*(set(endpoints[d['finding_id']]['positive_support_case_ids']) for d in group))
                after = set().union(*(set(endpoints[d['finding_id']]['positive_support_case_ids']) for d in group if not removed(d)))
                counts = {'observations':len(group), 'true_total':sum(truth(d)=='true' for d in group),
                    'false_total':sum(truth(d)=='false' for d in group),
                    'dismissed_true':sum(truth(d)=='true' and removed(d) for d in group),
                    'dismissed_false':sum(truth(d)=='false' and removed(d) for d in group),
                    'invalid':sum(d['status']!='completed' for d in group),
                    'abstain':sum(d['status']=='completed' and d['action']=='abstain' for d in group),
                    'positive_cases_before':len(before), 'positive_cases_after':len(after),
                    'lost_positive_cases':len(before-after)}
                expected[(block,condition,domain)] = counts
    require(len(reported) == len(expected), 'Triage summaries missing/duplicated')
    for row in reported:
        key = (int(row['block']),row['condition'],row['evaluation_domain'])
        require(key in expected, 'Unexpected summary')
        require(all(int(row[k]) == v for k,v in expected.pop(key).items()), 'Triage count differs')
    require(not expected, 'Missing triage summary')
    return 528 * len(passes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    analysis, output = args.analysis.resolve(), args.output.resolve()
    analysis.relative_to(ROOT/'evidence'); output.relative_to(ROOT/'evidence')
    output.mkdir(parents=True, exist_ok=False)
    result = {'success':False,'started_utc':datetime.now(timezone.utc).isoformat(),
              'scope':'Independent evidence and primary-count audit; no publication-readiness verdict.'}
    try:
        resource.setrlimit(resource.RLIMIT_AS,(5*1024**3,5*1024**3))
        check_manifest(analysis,read(analysis/'output_manifest.json'))
        source_manifest = read(analysis/'input_manifest.json')
        check_manifest(ROOT,source_manifest)
        result['verified_input_files'] = len(source_manifest)
        result['analysis_output_manifest_sha256'] = sha(analysis/'output_manifest.json')
        summary = read(analysis/'summary.json'); require(summary['success'], 'Unsuccessful analysis')
        bindings = read(BINDINGS)
        original = read(STATIC/'audit-v1/ingress.json')['jobs']
        catalog = read(ROOT/'static_assertion_catalog.json')
        jobs = check_overlay(original,read(analysis/'semgrep_binding_overlay.json'),catalog)
        for entry in source_manifest:
            if entry['path'].startswith('evidence/final_dynamic_campaign_2026-10-23/block-audit-') and entry['path'].endswith('-ingress.json'):
                job = read(ROOT/entry['path'])
                if job['profile_id'] not in {p['profile_id'] for p in bindings['profiles']}: continue
                require(job['job_id'] not in jobs, 'Duplicate final job'); jobs[job['job_id']] = job
        require(len(jobs)==465,'Incomplete static/dynamic scanner set')
        result['coverage_rows'], result['omission_ledgers'] = audit_coverage(analysis,jobs,bindings)
        result['triage_decisions'] = audit_triage(analysis,bindings,summary['triage_passes'])
        costs = read(STATIC/'audit-v1/invocation_costs.json')
        reported = rows(analysis/'static_profile_cost_summary.csv')
        grouped = defaultdict(list)
        for c in costs: grouped[jobs[c['job_id']]['profile_id']].append(c['wall_seconds'])
        require(len(reported)==len(grouped)==75,'Cost profile universe changed')
        for r in reported:
            vals = grouped[r['profile_id']]
            require(int(r['repetitions']) == len(vals) == 5,'Incorrect cost repetitions')
            for key,value in [('median',statistics.median(vals)),('min',min(vals)),('max',max(vals))]:
                require(float(r['wall_seconds_'+key])==value,'Cost summary differs')
        snapshot = output/'source_snapshot'
        for row in source_manifest:
            if row['path'].startswith(('engineering/','study/')) and row['path'].endswith('.py'):
                target=snapshot/row['path']; target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT/row['path']).read_bytes())
        target=snapshot/'engineering'/Path(__file__).name; target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(Path(__file__).read_bytes())
        result.update(success=True,repaired_semgrep_assertions=80,verified_final_scanner_jobs=len(jobs),
                      static_cost_profiles=75,maximum_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except Exception as error:
        result['error']=type(error).__name__+': '+str(error)
        (output/'failure_trace.txt').write_text(traceback.format_exc())
    result['finished_utc']=datetime.now(timezone.utc).isoformat()
    (output/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    manifest=[{'path':p.relative_to(output).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
              for p in sorted(output.rglob('*')) if p.is_file()]
    (output/'output_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__': raise SystemExit(main())
