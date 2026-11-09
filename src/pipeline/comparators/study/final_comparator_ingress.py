"""Connect qualified execution collections to block-specific comparator results."""
import json
from pathlib import Path

from study.final_comparator_inputs import AIGOAT_STATIC, AIGOAT_DYNAMIC, sha
from study.final_output_adapter import require, fixture_identity
from study.final_output_ingress import collect_dynamic
from study.final_static_comparators import sast, identities, kubernetes, terraform, checked_raw, K8S_PROFILES, TF_PROFILES
from study.final_context_comparators import crapi_headers, aigoat


class Collected:
    """Reread only files bound by the successful output-ingress collection."""
    def __init__(self, root, manifest):
        self.root = Path(root).resolve()
        self.expected = {r['path']: r for r in manifest}
        require(len(self.expected) == len(manifest), 'Duplicate collected evidence path')

    def path(self, name):
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe collected path')
        path = (self.root / relative).resolve()
        require(path.is_relative_to(self.root) and name in self.expected, 'Unbound comparator evidence')
        row = self.expected[name]
        require(sha(path) == row['sha256'] and path.stat().st_size == row['bytes'], 'Evidence changed after ingress')
        return path

    def read(self, name): return json.loads(self.path(name).read_text())


def compare_block(static_root, static_collection, dynamic_runs, inputs, block):
    """Evaluation-only entry point; receives ingress receipts, never historical analyses.

dynamic_runs: mapping from profile ID to {root, contract}, for this one block.
Missing/invalid domains remain unavailable with no numerical substitute. Their
native collections remain in the output, including every unscored observation.
"""
    require(type(block) is int and 1 <= block <= 5, 'Invalid scanner repetition block')
    refs = inputs.references()
    source = Collected(static_root, static_collection['source_manifest'])
    jobs = [j for j in static_collection['jobs'] if j['block'] == block]
    raw_reports, report_errors = {}, {}
    for job in jobs:
        if job['profile_id'] not in set(K8S_PROFILES) | set(TF_PROFILES): continue
        if job.get('measurement_eligible') is not True: continue
        try:
            before, after = (source.read(p) for p in job['reset_evidence'])
            require(before['fresh_destination'] == after['fresh_destination'] and before.get('verified') is True
                    and after.get('verified_after') is True, 'Comparator input reset changed')
            raw_reports[job['profile_id']] = checked_raw(job, source.path(job['raw_report']),
                                                       [(before['fresh_destination'], '<WORK>')])
        except (ValueError, KeyError, OSError, TypeError) as error:
            report_errors[job['profile_id']] = type(error).__name__ + ': ' + str(error)
    dynamic_jobs, contexts, dynamic_errors = [], {}, {}
    for profile in (*AIGOAT_DYNAMIC, 'crapi-nuclei-valid-a', 'crapi-nuclei-invalid'):
        if profile not in dynamic_runs:
            dynamic_errors[profile] = 'Missing dynamic run'; continue
        entry = dynamic_runs[profile]
        try:
            contract = entry['contract']
            require(contract['job']['profile_id'] == profile and contract['job']['block'] == block,
                    'Cross-profile/block dynamic contract')
            job = collect_dynamic(entry['root'], contract, references=refs['references'])
            dynamic_jobs.append(job)
            require(job['measurement_eligible'] is True, 'Dynamic receipt is not measurement eligible')
            evidence = Collected(entry['root'], job['source_manifest'])
            private = evidence.read('target/fixtures/private_fixture.json')
            schema = evidence.read('target/scanner/openapi.json')
            urls = [r['url'] for r in schema.get('servers', [])]
            if not urls and schema.get('host'): urls = ['http://' + schema['host']]
            fixture = fixture_identity('aigoat' if profile.startswith('aigoat-') else 'crapi', private, urls)
            trace = [json.loads(line) for line in evidence.path('target/proxy-logs/requests.jsonl').read_text().splitlines()]
            contexts[profile] = (trace, fixture)
        except (ValueError, KeyError, OSError, TypeError) as error:
            dynamic_errors[profile] = type(error).__name__ + ': ' + str(error)
    domains = {}
    def record(name, operation):
        try: domains[name] = {'status': 'complete', 'result': operation()}
        except (ValueError, KeyError, OSError, TypeError) as error:
            domains[name] = {'status': 'unavailable', 'result': None, 'reason': type(error).__name__ + ': ' + str(error)}
    record('sast', lambda: sast(jobs, refs['java'], refs['java_partition']))
    record('identity', lambda: identities(jobs, refs['aliases'], refs['secrets'], refs['identity']))
    record('kubernetes', lambda: kubernetes(jobs, raw_reports, refs['kubernetes']))
    record('terraform', lambda: terraform(jobs, raw_reports, refs['terraform']))
    record('aigoat', lambda: aigoat(jobs + dynamic_jobs, refs['references'],
                                  {p: contexts[p] for p in AIGOAT_DYNAMIC}, (*AIGOAT_STATIC, *AIGOAT_DYNAMIC)))
    def dast():
        profiles = ('crapi-nuclei-valid-a', 'crapi-nuclei-invalid')
        from study.final_static_comparators import selected_jobs
        selected = selected_jobs(dynamic_jobs, profiles)
        result = {j['profile_id']: crapi_headers(j, refs['crapi_templates'], *contexts[j['profile_id']]) for j in selected}
        return {'conditions': result, 'comparison_complete': all(r['comparison_complete'] for r in result.values())}
    record('dast', dast)
    for name in ('dast','aigoat'):
        if domains[name]['status'] == 'complete' and not domains[name]['result']['comparison_complete']:
            domains[name]['status'] = 'incomplete_reference'
    return {'block': block, 'domains': domains, 'report_errors': report_errors, 'dynamic_errors': dynamic_errors,
        'complete': all(d['status'] == 'complete' for d in domains.values()),
        'static_collection_jobs': [j['job_id'] for j in jobs], 'dynamic_collections': dynamic_jobs,
        'reference_manifest': inputs.manifest(),
        'scope': 'Six distinct comparator domains; no pooled accuracy/recall, no new annotations, no cross-block pairs.'}
