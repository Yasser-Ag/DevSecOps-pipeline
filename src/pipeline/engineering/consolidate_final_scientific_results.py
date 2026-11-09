"""Build a versioned local result ledger from audited experimental evidence.

This program never starts a scanner, a model or a remote command. Existing
evidence is read-only. Use a new output directory for every analysis revision.
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
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from study.final_scientific_analysis import (CONDITIONS, canonical_condition, coverage_row,
    digest, paired_decisions, population_omissions, reconcile_semgrep, require, score_pass)
from study.whole_study_contract import validate_bindings

STATIC = ROOT / 'evidence/final_static_campaign_2026-10-23'
DYNAMIC = ROOT / 'evidence/final_dynamic_campaign_2026-10-23'
SCANNERS = ROOT / 'evidence/runtime_integration_2026-10-22/package-v1'
BINDINGS = ROOT / 'data/references/bindings.json'
BINDINGS_SHA = '05ad1853da236dbabf0aea3811c2e0937e4f0130d4482753f122e58d348e4806'
STATIC_INGRESS_SHA = '5b086a9479ba6be812fc7aa6c3c7aa4fb6ab7ddfe1f3563626476d50ad2d84ad'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4*1024**2), b''): h.update(chunk)
    return h.hexdigest()


class Sources:
    def __init__(self): self.files = {}

    def bind(self, path, expected=None):
        path = Path(path)
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
        require(not path.is_symlink(), 'Symbolic source')
        record = {'path': relative, 'sha256': sha(path), 'bytes': path.stat().st_size}
        require(expected is None or record['sha256'] == expected, 'Source identity changed: ' + relative)
        require(relative not in self.files or self.files[relative] == record, 'Source changed during analysis')
        self.files[relative] = record
        return path

    def read(self, path, expected=None):
        with self.bind(path, expected).open() as stream: return json.load(stream)

    def lines(self, path, expected=None):
        with self.bind(path, expected).open() as stream: return [json.loads(x) for x in stream if x.strip()]

    def verify_manifest(self, root, rows):
        require(len(rows) == len({r['path'] for r in rows}), 'Duplicate source manifest path')
        for row in rows:
            relative = Path(row['path'])
            require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe source manifest path')
            path = self.bind(root / relative, row['sha256'])
            require(path.stat().st_size == row['bytes'], 'Source size differs')


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def table(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with Path(path).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v
                             for k, v in row.items()})


def static_data(sources, output):
    audit = sources.read(STATIC / 'audit-v1/summary.json')
    require(audit['success'] and audit['qualified_static_measurements'] == 375, 'Static audit incomplete')
    collection = sources.read(STATIC / 'audit-v1/ingress.json', STATIC_INGRESS_SHA)
    require(collection['assets_verified'] and collection['runtime_support_complete'], 'Static support failed')
    sources.verify_manifest(STATIC / 'static-scanners-final-20261023-01', collection['source_manifest'])
    package = sources.read(SCANNERS / 'package_manifest.json',
        '06e60151cacc46b6bb57d39db4dda1292ce76f586ede82ebbe7e8c5df8e5e662')
    packaged = {r['path']: r for r in package['files']}
    catalog = sources.read(SCANNERS / 'reference/static_assertion_catalog.json',
                           packaged['reference/static_assertion_catalog.json']['sha256'])
    selected = [r for r in catalog if r['profile_id'] == 'java-semgrep']
    require(len(selected) == 16, 'Semgrep catalog universe changed')
    # Ensure the original rule asset identity is bound by the execution package.
    release = ROOT / 'evidence/final_release_2026-10-23/release-v1'
    manifest = sources.read(release / 'release_manifest.json',
        '9513881a86942faea8fc66a4960dd12b077e9304770820e3a55f1c8d066234c1')
    bound = next(r for r in manifest['files'] if r['path'] == 'composition.json')
    composition = sources.read(release / 'composition.json', bound['sha256'])
    sources.read(STATIC / 'static-scanners-final-20261023-01/asset_locks.json',
                 composition['static']['asset_locks_sha256'])
    plan = sources.read(SCANNERS / 'plan.json', packaged['plan.json']['sha256'])
    profile = next(p for p in plan['profiles'] if p['id'] == 'java-semgrep')
    require(profile['argv'][profile['argv'].index('--config')+1] ==
            profile['historical_command'][profile['historical_command'].index('--config')+1],
            'Semgrep configuration asset differs')
    patches = []
    for i, job in enumerate(collection['jobs']):
        if job['profile_id'] != 'java-semgrep': continue
        fixed, changes = reconcile_semgrep(job, selected)
        require(len(changes) == len(job['observations']) == 16, 'Semgrep repair is not complete')
        require(Counter(c['label'] for c in changes) == Counter({'true': 6, 'false': 4, 'unresolved': 6}),
                'Inherited labels differ from the frozen scoped catalog')
        require(len({c['historical_finding_id'] for c in changes}) == 16, 'Non-bijective repair')
        patches.append({'job_id': job['job_id'], 'before_job_digest': digest(job),
                        'after_job_digest': digest(fixed), 'changes': changes, 'corrected_job': fixed})
        collection['jobs'][i] = fixed
    require(len(patches) == 5, 'Missing Semgrep block')
    write(output / 'semgrep_binding_overlay.json', {
        'original_ingress_sha256': STATIC_INGRESS_SHA,
        'scope': 'Post-execution analysis correction after outcome inspection; no raw report, reference label or experiment changed.',
        'jobs': patches})
    costs = sources.read(STATIC / 'audit-v1/invocation_costs.json')
    return collection, costs, plan


def dynamic_data(sources):
    closed = sources.read(DYNAMIC / 'completion-v1/summary.json')
    require(closed['status'] == 'completed_and_audited' and closed['completed_jobs'] == 95, 'Dynamic campaign incomplete')
    jobs, costs, generation, runs = [], [], [], defaultdict(dict)
    for bound in closed['block_audits']:
        path = ROOT / bound['path']
        audit = sources.read(path, bound['sha256'])
        require(audit['success'] and audit['block_complete'], 'Dynamic block incomplete')
        for row in audit['jobs']:
            job = sources.read(path.parent / (row['job_id'] + '-ingress.json'))
            root = DYNAMIC / 'runs' / row['run_id']
            sources.bind(root / 'summary.json', row['summary_sha256'])
            sources.verify_manifest(root, job['source_manifest'])
            require(job['job_id'] == row['job_id'] and job['measurement_eligible'] == row['measurement_eligible'],
                    'Ingress/audit identity or qualification differs')
            if row['kind'] == 'target_generation':
                generation.append(job)
            else:
                jobs.append(job)
                runs[job['block']][job['profile_id']] = {'root': str(root), 'contract': row['contract']}
            for phase, value in row['costs'].items():
                costs.append({'job_id': row['job_id'], 'block': audit['block'], 'phase': phase,
                              'profile_id': job['profile_id'], 'wall_seconds': value['elapsed_seconds'],
                              'measurement_scope': 'Recorded command interval for this phase; other phases excluded.'})
    require(len(jobs) == 90 and len(generation) == 5, 'Dynamic job universe differs')
    return jobs, costs, generation, runs


def summarize_triage(rows):
    summaries = []
    for condition in CONDITIONS:
        for domain in ('inherited_native_assertion', 'literal_declaration_assertion'):
            selected = [r for r in rows if r['condition'] == condition and r['evaluation_domain'] == domain]
            summaries.append({'condition': condition, 'block': selected[0]['block'], 'evaluation_domain': domain,
                **{k: sum(r[k] for r in selected) for k in ('observations','true_total','false_total','dismissed_true','dismissed_false')},
                'invalid': sum(len(r['invalid_ids']) for r in selected),
                'abstain': sum(len(r['abstained_ids']) for r in selected),
                'positive_cases_before': sum(len(r['positive_cases_before']) for r in selected),
                'positive_cases_after': sum(len(r['positive_cases_after']) for r in selected),
                'lost_positive_cases': sum(len(r['lost_positive_case_ids']) for r in selected),
                'scope': 'Counts for the fixed selected cohort only; distinct endpoint domains remain separate.'})
    return summaries


def triage_data(sources, output, bindings, passes):
    pass_decisions, summaries, condition_costs = {}, [], []
    for block in passes:
        base = ROOT / ('evidence/triage_single_pass_2026-10-24' if block == 1 else 'evidence/triage_second_pass_2026-10-24')
        audit_dir = base / ('scientific-audit-v2' if block == 1 else 'scientific-audit-v1')
        audit = sources.read(audit_dir / 'summary.json')
        require(audit['success'] and audit['measurement_policy_audit_complete'] and audit['original_block'] == block,
                'Triage raw replay has not passed')
        decisions = sources.lines(audit_dir / 'decisions.jsonl', audit['decisions_sha256'])
        measurements = sources.lines(audit_dir / 'measurements.jsonl', audit['measurements_sha256'])
        rows, sensitivity, grouped = score_pass(bindings['triage_clusters'], decisions)
        table(output / f'triage_pass_{block}_by_population.csv', rows)
        write(output / f'triage_pass_{block}_source_sensitivity.json', sensitivity)
        summaries.extend(summarize_triage(rows)); pass_decisions[block] = grouped
        contrasts = []
        packets = {r['finding_id']: r for r in sources.lines(base / 'package-v1/inputs/context.jsonl')}
        for left, right in bindings['analysis']['primary_contrasts']:
            pairs = paired_decisions(grouped[left], grouped[right])
            for pair in pairs:
                pair['additional_context_available'] = len(packets[pair['finding_id']]['evidence']) > 1
            contrasts.append({'left': left, 'right': right, 'pairs': pairs})
        write(output / f'triage_pass_{block}_paired_contrasts.json', contrasts)
        for condition in CONDITIONS:
            measures = [m for m in measurements if not m['synthetic'] and
                        canonical_condition(m['model'] + '/' + m['condition']) == condition]
            if not measures: continue
            condition_costs.append({'block': block, 'condition': condition, 'requests': len(measures),
                'request_seconds_sum': sum(m['request_seconds'] for m in measures),
                'request_seconds_median': statistics.median(m['request_seconds'] for m in measures),
                'decision_interval_seconds_sum': sum(m['decision_interval_seconds'] for m in measures),
                'server_cpu_seconds_sum': sum(m['server_cpu_seconds'] for m in measures),
                'sampled_peak_server_rss_kib': max(m['sampled_peak_server_rss_kib'] for m in measures),
                'sampled_peak_cgroup_current_bytes': max(m['sampled_peak_cgroup_current_bytes'] for m in measures),
                'scope': 'Scientific request intervals only; startup/warmup/container overhead reported separately.'})
        write(output / f'triage_pass_{block}_phase_costs.json', audit['phases'])
    table(output / 'triage_summary.csv', summaries)
    table(output / 'triage_request_costs.csv', condition_costs)
    if 1 in pass_decisions and 2 in pass_decisions:
        repeated = [{'condition': c, 'pairs': paired_decisions(pass_decisions[1][c], pass_decisions[2][c])}
                    for c in CONDITIONS]
        write(output / 'triage_repeatability.json', repeated)
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--triage-passes', type=int, nargs='+', choices=(1,2), default=[1])
    args = parser.parse_args()
    output = args.output.resolve(); output.relative_to((ROOT / 'evidence').resolve())
    output.mkdir(parents=True, exist_ok=False)
    sources = Sources()
    result = {'success': False, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'new_scans': 0, 'new_model_calls': 0, 'new_annotations': 0,
              'scope': 'Post-execution descriptive analysis. Scientific novelty and submission readiness are not certified.'}
    try:
        resource.setrlimit(resource.RLIMIT_AS, (5*1024**3, 5*1024**3))
        for p in (Path(__file__), ROOT/'study/final_scientific_analysis.py',
                  ROOT/'engineering/test_final_scientific_analysis.py', ROOT/'study/whole_study_contract.py'):
            sources.bind(p)
        bindings = sources.read(BINDINGS, BINDINGS_SHA)
        result['frozen_universe'] = validate_bindings(bindings)
        collection, static_costs, plan = static_data(sources, output)
        print('Static inputs verified; five exact Semgrep binding overlays derived.', flush=True)
        dynamic, dynamic_costs, generation, runs = dynamic_data(sources)
        write(output / 'dynamic_run_inputs.json', {str(k): v for k,v in runs.items()})
        write(output / 'target_generation_reference_observations.json', generation)
        all_jobs = collection['jobs'] + dynamic
        rows = []
        routes = {p['profile_id']: p for p in bindings['profiles']}
        pops = {p['population']: p for p in bindings['populations']}
        for job in all_jobs:
            require(job['profile_id'] in routes, 'Unregistered profile')
            # A missing role in a limited dynamic collection is recovered only
            # from the frozen route, never from observed output success.
            job.setdefault('role', routes[job['profile_id']]['role'])
            for pop in routes[job['profile_id']]['candidate_populations']:
                rows.append(coverage_row(job, pops[pop], bindings['references']))
        table(output / 'coverage_by_profile.csv', rows)
        omissions = []
        recorded_stages = defaultdict(set)
        for r in bindings['native_observations']: recorded_stages[r['profile_id']].add(r['stage'])
        for block in range(1,6):
            selected = [r for r in rows if r['block'] == block]
            for pop in bindings['populations']:
                omissions.append(population_omissions(pop, selected, bindings['references']))
            sca_rows = [r for r in selected if r['population'] == 'sca']
            # Profiles without historical findings have no supported case to
            # add, but their known profile role still determines this grouping.
            sca_stages = {r['profile_id']: ('image_scan' if r['profile_id'].endswith('-image') else 'source_sca')
                          for r in sca_rows if r['role'] != 'inventory'}
            for profile, stage in sca_stages.items():
                require(not recorded_stages[profile] or recorded_stages[profile] == {stage}, 'Frozen SCA stage differs')
            omissions.append(population_omissions(pops['sca'], sca_rows, bindings['references'], sca_stages))
        write(output / 'population_and_stage_omissions.json', omissions)
        table(output / 'population_coverage.csv', [
            {k: r[k] for k in ('block','population','unit','grouping','catalog_positive_count',
                              'qualified_profile_union_count','full_comparison_available','unavailable_profiles',
                              'normalized_population_eligible')} for r in omissions if r['grouping']=='profile'])
        table(output / 'profile_omissions.csv', [
            {'population': r['population'],'block': r['block'],'grouping':r['grouping'],
             'full_comparison_available':r['full_comparison_available'],**v}
            for r in omissions for v in r['comparisons']])
        # Keep every invocation, including inventories and limited dynamic jobs.
        table(output / 'static_invocation_costs.csv', static_costs)
        table(output / 'dynamic_phase_costs.csv', dynamic_costs)
        aggregated = []
        by_profile = defaultdict(list)
        for r in static_costs:
            profile = next(j['profile_id'] for j in collection['jobs'] if j['job_id'] == r['job_id'])
            by_profile[profile].append(r)
        for profile, values in sorted(by_profile.items()):
            aggregated.append({'profile_id':profile,'repetitions':len(values),
                'wall_seconds_median':statistics.median(v['wall_seconds'] for v in values),
                'wall_seconds_min':min(v['wall_seconds'] for v in values),
                'wall_seconds_max':max(v['wall_seconds'] for v in values),
                'measurement_scope':values[0]['measurement_scope']})
        table(output / 'static_profile_cost_summary.csv', aggregated)
        summaries = triage_data(sources, output, bindings, sorted(set(args.triage_passes)))
        result.update(success=True, static_jobs=len(collection['jobs']), dynamic_scanner_jobs=len(dynamic),
            dynamic_strictly_eligible=sum(j['measurement_eligible'] for j in dynamic),
            coverage_profile_population_rows=len(rows), semgrep_corrected_assertions=80,
            triage_passes=sorted(set(args.triage_passes)),
            open_scope_limits=['No pooled cross-population recall.',
                'Per-profile recall requires a separate validated case-applicability denominator.',
                'Thirty dynamic jobs retain frozen limitations; their coverage is unavailable.',
                'Complete six-domain matching consolidation is a separate output.',
                'Observed output omissions are not measured end-to-end runtime savings.',
                'Development exposure and sparse negative references limit generalization.'],
            maximum_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        print(json.dumps({'triage_counts':summaries,'static_jobs':len(collection['jobs'])}), flush=True)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        (output / 'failure_trace.txt').write_text(traceback.format_exc())
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    write(output / 'input_manifest.json', sorted(sources.files.values(), key=lambda r:r['path']))
    result['input_manifest_sha256'] = sha(output / 'input_manifest.json')
    write(output / 'summary.json', result)
    manifest = [{'path':p.relative_to(output).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
                for p in sorted(output.iterdir()) if p.is_file()]
    write(output / 'output_manifest.json', manifest)
    print(json.dumps(result, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__': raise SystemExit(main())
