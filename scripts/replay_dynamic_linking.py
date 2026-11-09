#!/usr/bin/env python3
"""Reparse saved dynamic reports and recheck the frozen reference projections."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src/pipeline'))
from study.api_native_reports import parse_api_report
from study.dynamic_execution_contract import native_report
from study.dynamic_scan_contract import profile as get_profile
from study.final_output_adapter import digest, fixture_identity, logical_route, request_coordinate
from study.final_output_ingress import reference_passed
from study.final_dynamic_projection import http_projection, authorization_projection, rag_reference_observations


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


ORIGIN_ALIASES = read(ROOT/'config/projection_origin_aliases.json')


def projection_view(value):
    """Give opaque origin labels URI syntax without recovering any host value."""
    if isinstance(value,str):
        for label,origin in ORIGIN_ALIASES.items():value=value.replace(label,origin)
        return value
    if isinstance(value,list):return [projection_view(v) for v in value]
    if isinstance(value,dict):return {k:projection_view(v) for k,v in value.items()}
    return value


def reparse(directory, profile, contract, trace, fixture):
    parsed = native_report(profile['tool'], directory)
    identities = {r['path']:r for r in contract['reports']}
    assert {r['path'] for r in parsed['reports']} == set(identities), 'Native report set differs'
    for row in parsed['reports']:
        assert row['sha256'] == identities[row['path']]['published_sha256'], 'Native report bytes differ'
    records = []
    if profile['tool'] == 'restler':
        for native in parsed['units']:
            records.append((identities[native['native_path']]['original_sha256'], '/',
                            {'unit':'native_bug_bucket', **native}))
    else:
        report = parsed['reports'][0]
        original_sha = identities[report['path']]['original_sha256']
        normalized = parse_api_report(directory/report['path'], profile['tool'], 'completed')
        for row in normalized['findings']:
            # Identity uses the original report digest, whose published copy has
            # just been verified separately. Content always comes from that copy.
            row['finding_id'] = f"{profile['tool']}:{original_sha[:16]}:{row['native_index']}"
            records.append((original_sha, row['native_locator'], row))
    observations = []
    for original_sha, pointer, native in records:
        if profile['tool'] == 'restler':
            coordinate = {'status':'bucket_coordinate_only', 'method':native['reported_method'],
                          'path':logical_route(projection_view(native['reported_endpoint']), fixture),
                          'requires':'Fresh independent shadow-user response evidence; stored replay is not the oracle.'}
        else:
            coordinate = request_coordinate(projection_view(native), projection_view(trace), fixture)
        observations.append({'finding_id':'native-'+digest([contract['job_id'],profile['id'],original_sha,pointer]),
                             'profile_id':profile['id'],'job_id':contract['job_id'],'block':contract['block'],
                             'raw_report_sha256':original_sha,'native_locator':pointer,'native_content':native,
                             'coordinate':coordinate,'scoped_native_label':'unresolved'})
    return observations, parsed['limitations']


def run(evidence, output, blocks=None):
    started = time.monotonic()
    references = read(ROOT/'config/inputs/whole_study_references.json')
    owners = read(ROOT/'data/references/authorization_owner_references.json')
    contracts = [json.loads(x) for x in (ROOT/'data/references/dynamic_replay_contract.jsonl').read_text().splitlines()]
    if blocks:contracts = [c for c in contracts if c['block'] in blocks]
    checks, linked = [], []
    output.mkdir(parents=True, exist_ok=False)
    for contract in contracts:
        root = evidence/contract['root']
        for file in contract['files']:
            assert sha(root/file['path']) == file['published_sha256'], 'Published input identity differs'
        profile = get_profile(contract['profile_id'])
        summary, outcome = read(root/'summary.json'), read(root/'target/outcome.json')
        fixture_data = read(root/'target/fixtures/fixture.json')
        before, after = read(root/'target/fixtures/before.json'), read(root/'target/fixtures/after.json')
        schema = read(root/'target/scanner/openapi.json')
        base_urls = [r['url'] for r in schema.get('servers',[])]
        if not base_urls and schema.get('host'):base_urls = ['http://'+schema['host']]
        fixture = fixture_identity(profile['target'],fixture_data,projection_view(base_urls))
        trace = read(root/'target/scanner_trace.json')
        observations, limitations = reparse(root/'target/scanner',profile,contract,trace,fixture)
        reference_ok = reference_passed(before,profile['target']) and reference_passed(after,profile['target'])
        eligible = outcome.get('status') == 'completed' and reference_ok and not limitations
        actual = {'native_count':len(observations),'measurement_eligible':eligible,
                  'reference_state_verified':reference_ok, 'limitations':limitations,
                  'status':outcome.get('status','unavailable'),'observations':observations}
        if eligible:
            full_trace = [json.loads(x) for x in (root/'target/proxy_logs/requests.jsonl').read_text().splitlines()]
            assert [r for r in full_trace if r.get('phase')=='scanner'] == trace, 'Filtered trace differs'
            projections = []
            for observation in observations:
                if profile['target']=='aigoat':
                    result = http_projection(observation,references,full_trace,fixture)
                elif profile['tool']=='restler':
                    result = authorization_projection(observation,owners,full_trace,fixture,fixture_data,
                                                      body_digest_field='published_response_sha256')
                else:
                    result = {'status':'native_only','links':[],
                              'reason':'Generic native alerts have no whole-warning truth label.'}
                projections.append({'finding_id':observation['finding_id'],**result})
            actual['reference_projections'] = projections
            if profile['target']=='aigoat':
                actual['reference_observations'] = rag_reference_observations(references,before,after,fixture_data)
        if summary.get('success') is not True:actual['measurement_eligible']=False
        actual['links'] = [e for p in actual.get('reference_projections',[]) for e in p['links']] if actual['measurement_eligible'] else []
        differences = [k for k,v in contract['expected'].items() if actual.get(k)!=v]
        check = {'job_id':contract['job_id'],'profile':profile['id'],'block':contract['block'],
                 'native_count':len(observations),'eligible':actual['measurement_eligible'],
                 'supported_links':sum(e['relation']=='supports' for e in actual['links']),
                 'identical':not differences,'different_fields':';'.join(differences)}
        checks.append(check)
        linked.append({'job_id':contract['job_id'],'profile_id':profile['id'],'block':contract['block'],
                       'measurement_eligible':actual['measurement_eligible'],'links':actual['links']})
        if differences:
            (output/'difference.json').write_text(json.dumps({'job_id':contract['job_id'],
                'fields':differences,'actual':{k:actual.get(k) for k in differences},
                'expected':{k:contract['expected'][k] for k in differences}},indent=2)+'\n')
            raise ValueError('Dynamic replay mismatch: '+contract['job_id']+' '+','.join(differences))
    with (output/'job_checks.csv').open('w',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=list(checks[0]));writer.writeheader();writer.writerows(checks)
    (output/'links.json').write_text(json.dumps(linked,indent=2)+'\n')
    summary = {'jobs':len(checks),'all_identical':True,'eligible_jobs':sum(r['eligible'] for r in checks),
               'new_scanner_executions':0,'wall_seconds':time.monotonic()-started}
    (output/'verification.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--blocks',type=int,nargs='+')
    args=parser.parse_args()
    run(args.evidence,args.output,args.blocks)
