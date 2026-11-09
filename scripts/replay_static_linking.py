#!/usr/bin/env python3
"""Parse masked native reports and reapply the frozen assertion catalogue."""
import argparse
from collections import defaultdict
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/pipeline'))
from study.final_output_adapter import static_rows, digest, TRANSIENT_TOP, assertion_key


def semantic(value, root):
    if isinstance(value, str):
        return re.sub(re.escape(root) + r'(?=/|$)', lambda _: '<WORK>', value)
    if isinstance(value, list):
        return [semantic(v, root) for v in value]
    if isinstance(value, dict):
        return {k:semantic(v, root) for k,v in value.items()}
    return value


def identity(job, profile, original_hash, locator):
    return 'native-' + digest([job, profile, original_hash, locator])


def run(evidence, output, limit=None, blocks=None, profile_ids=None):
    start = time.monotonic()
    plan = json.loads((ROOT / 'config/plan.json').read_text())
    profiles = {p['id']:p for p in plan['profiles']}
    catalogue = json.loads((evidence / 'static_assertion_catalog.json').read_text())
    catalogs = defaultdict(lambda: defaultdict(list))
    for entry in catalogue:
        # Signatures change when a path or a credential is masked. The retained
        # original signature is provenance, not the public comparison signature.
        catalogs[entry['profile_id']][digest(entry['content'])].append(entry)
    contracts = [json.loads(line) for line in
                 (ROOT / 'data/references/static_replay_contract.jsonl').read_text().splitlines()]
    if blocks:
        contracts = [c for c in contracts if c['block'] in blocks]
    if profile_ids:
        contracts = [c for c in contracts if c['profile_id'] in profile_ids]
        if {c['profile_id'] for c in contracts} != set(profile_ids):
            raise ValueError('Unknown requested static profile')
    if limit is not None:
        contracts = contracts[:limit]
    checks, links, comparator_jobs = [], [], []
    comparator_profiles = {'java-semgrep','java-findsecbugs',
        'sca-grype-filesystem','sca-trivy-rootfs','sca-dependency-check',
        'sca-grype-image','sca-trivy-image','configuration-gitleaks','configuration-trivy-secret',
        'k8s-scope-matrix-trivy','k8s-scope-matrix-checkov','k8s-scope-split-trivy'}
    comparator_profiles |= {f'infrastructure-{corpus}-{tool}-{layer}'
        for corpus in ('controls','originals') for layer in ('kubernetes','terraform')
        for tool in (('trivy','checkov') if layer=='kubernetes' else ('trivy','checkov','kics'))}
    for contract in contracts:
        profile = profiles[contract['profile_id']]
        report = evidence / contract['report']
        if hashlib.sha256(report.read_bytes()).hexdigest() != contract['published_report_sha256']:
            raise ValueError('Published native report identity mismatch')
        parsed = static_rows(report, profile, contract['status'])
        actual_observations, actual_links, detailed = [], [], []
        candidates = catalogs[profile['id']]
        for row in parsed['findings']:
            content = semantic({k:v for k,v in row.items() if k not in TRANSIENT_TOP}, contract['work_root'])
            matches = candidates.get(digest(content), [])
            corrected = False
            # Same recorded prefix alias used in the final analysis.
            if profile['id'] == 'java-semgrep' and not matches:
                rule = content.get('native_rule', '')
                if rule.startswith('home.lab.devsecops_access.environment.scanner-assets-20260921-01.semgrep.'):
                    compared = deepcopy(content)
                    compared['native_rule'] = rule[len('home.lab.'):]
                    matches = candidates.get(digest(compared), [])
                    corrected = bool(matches)
            interpretations = {assertion_key(entry) for entry in matches}
            runtime_ok = not any(e['population'] == 'docker' for e in matches) or contract['runtime_reference_verified']
            bound = contract['measurement_eligible'] and len(interpretations) == 1 and runtime_ok
            if corrected:
                bound = bound and len(matches) == 1
            native_id = identity(contract['job_id'], profile['id'], contract['original_report_sha256'], row['native_locator'])
            actual_observations.append({
                'native_locator':row['native_locator'],
                'population':matches[0]['population'] if bound else None,
                'scoped_native_label':matches[0]['scoped_native_label'] if bound else 'unresolved',
                'binding_status':('bound_exact_assertion_after_rule_prefix_alias' if corrected and bound else
                                  'bound_identical_assertion' if bound else
                                  'ambiguous_interpretation' if len(interpretations)>1 else 'unadjudicated'),
                'historical_witness_ids':sorted(e['historical_finding_id'] for e in matches) if bound else []})
            if profile['id'] in comparator_profiles:
                detailed.append({'finding_id':native_id, 'native_content':content,
                                 **actual_observations[-1]})
            if bound:
                actual_links.extend({'finding_id':native_id, **{k:e[k] for k in ('case_id','relation','scope')}}
                                    for e in matches[0]['links'])
        key = lambda r: json.dumps(r, sort_keys=True)
        observations_equal = actual_observations == contract['expected_observations']
        links_equal = sorted(actual_links,key=key) == sorted(contract['expected_links'],key=key)
        check = {'job_id':contract['job_id'], 'profile':profile['id'], 'block':contract['block'],
                 'native_count':len(parsed['findings']),
                 'native_count_identical':len(parsed['findings']) == contract['native_count'],
                 'status_identical':parsed['effective_status'] == contract['status'],
                 'observations_identical':observations_equal, 'links_identical':links_equal,
                 'supported_links':sum(e['relation']=='supports' for e in actual_links)}
        checks.append(check)
        if profile['id'] in comparator_profiles:
            comparator_jobs.append({'job_id':contract['job_id'],'profile_id':profile['id'],
                'block':contract['block'],'status':contract['status'],
                'measurement_eligible':contract['measurement_eligible'],
                'raw_report_sha256':contract['original_report_sha256'],
                'native_count':len(parsed['findings']),'observations':detailed,'links':actual_links})
        links.extend({'job_id':contract['job_id'],'profile':profile['id'],'block':contract['block'],**r}
                     for r in actual_links)
        if len(checks) % 75 == 0:
            print(json.dumps({'jobs_replayed':len(checks),'completed_block':contract['block']}),flush=True)
    output.mkdir(parents=True,exist_ok=False)
    (output/'comparator_jobs.json').write_text(json.dumps(comparator_jobs,indent=2)+'\n')
    for name,rows in [('job_checks.csv',checks),('replayed_links.csv',links)]:
        if rows:
            with (output/name).open('w',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    summary={'jobs_checked':len(checks), 'all_identical':all(all(r[k] for k in
             ('native_count_identical','status_identical','observations_identical','links_identical')) for r in checks),
             'new_scanner_runs':0,'wall_seconds':time.monotonic()-start}
    (output/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))
    return summary


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--limit',type=int)
    parser.add_argument('--blocks',type=int,nargs='+',choices=range(1,6))
    parser.add_argument('--profiles',nargs='+')
    args=parser.parse_args()
    result=run(args.evidence,args.output,args.limit,args.blocks,args.profiles)
    raise SystemExit(0 if result['all_identical'] else 1)
