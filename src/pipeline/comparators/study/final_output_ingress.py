"""Connect final execution receipts to typed output adapters, without execution."""
import json
from pathlib import Path

from study.final_output_adapter import (adapt_dynamic, adapt_static, digest, fixture_identity,
                                        generation_observations, require)
from study.static_scan_contract import schedule, sha
from study.dynamic_scan_contract import profile as dynamic_profile, generation_workload
from study.dynamic_reset_contract import runtime_assertion
from study.final_dynamic_projection import (http_projection, authorization_projection,
                                             rag_reference_observations)


class Evidence:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.files = {}

    def path(self, relative):
        path = self.root / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'Unsafe evidence path')
        path.resolve().relative_to(self.root)
        require(not path.is_symlink(), 'Symbolic evidence file')
        return path

    def bind(self, relative):
        p = self.path(relative)
        row = {'path': relative, 'sha256': sha(p), 'bytes': p.stat().st_size}
        require(relative not in self.files or self.files[relative] == row, 'Evidence changed during collection')
        self.files[relative] = row
        return p

    def read(self, relative, optional=False):
        p = self.path(relative)
        if optional and not p.exists():
            return None
        return json.loads(self.bind(relative).read_text())

    def lines(self, relative):
        return [json.loads(x) for x in self.bind(relative).read_text().splitlines() if x.strip()]

    def manifest(self):
        for p in list(self.files): self.bind(p)
        return sorted(self.files.values(), key=lambda r: r['path'])


def verify_runtime_support(controls, before, after):
    require(len(controls) == 12, 'Unexpected safe control universe')
    expected = {r['case_id']: r for r in controls}
    require(len(expected) == 12, 'Duplicate control identity')
    signatures = []
    for phase in (before, after):
        require(len(phase) == 12 and {r['case_id'] for r in phase} == set(expected), 'Incomplete runtime evidence')
        rows = []
        for r in phase:
            actual = runtime_assertion(expected[r['case_id']], r['raw'])
            require(all(r.get(k) == v for k, v in actual.items()), 'Runtime receipt contradicts raw probe')
            rows.append(actual)
        signatures.append(sorted(rows, key=lambda r: r['case_id']))
    require(signatures[0] == signatures[1], 'Runtime reference drift')
    return True


def collect_static(root, plan, catalog, contract, runtime_support=False):
    evidence = Evidence(root)
    summary = evidence.read('summary.json', optional=True) or {}
    locks = evidence.read('asset_locks.json', optional=True)
    records = evidence.read('outcomes.json', optional=True) or []
    outcomes = {r['job_id']: r for r in records}
    require(len(outcomes) == len(records), 'Duplicate static outcome')
    jobs = schedule(plan)
    require(set(outcomes) <= {j['job_id'] for j in jobs}, 'Outcome outside static schedule')
    require(contract['profile_ids'] == [p['id'] for p in plan['profiles']], 'Static profile contract mismatch')
    require(contract['schedule_digest'] == digest(jobs), 'Static schedule contract mismatch')
    asset_ok = (locks is not None and sha(evidence.path('asset_locks.json')) == contract['asset_locks_sha256']
                and summary.get('assets_preserved') is True and summary.get('mode') == 'execute'
                and summary.get('package_manifest_sha256') == contract['package_manifest_sha256'])
    profiles = {p['id']: p for p in plan['profiles']}
    result = []
    for job in jobs:
        row = outcomes.get(job['job_id'])
        record = {'job_id': job['job_id'], 'profile_id': job['profile'], 'block': job['block'],
                  'native_count': None, 'measurement_eligible': False, 'observations': [], 'links': []}
        if row is None or row.get('status') == 'not_run':
            record.update(status='not_run', reason='No completed execution receipt' if row is None else row.get('reason'))
            result.append(record); continue
        p = profiles[job['profile']]
        work = 'work/b' + str(job['block']) + '-' + p['suite']
        phase = 'jobs/' + job['job_id']
        reset = 'resets/b' + str(job['block']) + '-' + p['suite']
        try:
            before = evidence.read(reset + '.json')
            after = evidence.read(reset + '-after.json')
            prepared = evidence.read(phase + '/prepared.json')
            receipt = evidence.read(phase + '/receipt.json')
            raw_name = work + '/' + p['report']
            raw = evidence.bind(raw_name)
            require(row.get('raw_sha256') == sha(raw), 'Raw report differs from execution receipt')
            require(prepared['reset_sha256'] == sha(evidence.path(reset + '.json')), 'Reset receipt identity differs')
            require(prepared['report'] == before['fresh_destination'] + '/' + p['report'], 'Prepared report is not in owned work directory')
            require(after['fresh_destination'] == before['fresh_destination'], 'Reset destination changed')
            require(before['fresh_destination'].endswith('/' + work), 'Unexpected reset path')
            require(receipt['status'] == row['status'], 'Process/outcome status disagreement')
            input_digest = digest(locks['inputs'][p['suite']]) if locks else 'unavailable'
            context = {'job_id': job['job_id'], 'block': job['block'], 'work_root': before['fresh_destination'],
                       'input_contract_sha256': input_digest, 'observed_input_sha256': input_digest,
                       'inputs_verified_before': before.get('verified') is True,
                       'inputs_verified_after': after.get('verified_after') is True,
                       'asset_lock_verified': asset_ok, 'runtime_reference_verified': runtime_support is True,
                       'process_status': receipt['status'], 'origin': 'fresh_execution'}
            adapted = adapt_static(raw, p, context, [x for x in catalog if x['profile_id'] == p['id']])
            require(adapted['status'] == row.get('effective_status'), 'Native report status differs from receipt')
            require(adapted['native_count'] == row.get('native_findings'), 'Native count differs from receipt')
            record.update(adapted, reset_evidence=[reset + '.json', reset + '-after.json'],
                          process_receipt=phase + '/receipt.json', raw_report=raw_name)
        except (ValueError, KeyError, TypeError, OSError) as error:
            record.update(status='unavailable', reason=type(error).__name__ + ': ' + str(error),
                          native_count=None, measurement_eligible=False, observations=[], links=[])
        result.append(record)
    return {'kind': 'static_output_collection', 'jobs': result, 'scheduled': len(jobs),
            'jobs_with_qualified_measurement': sum(r['measurement_eligible'] for r in result),
            'assets_verified': asset_ok, 'source_manifest': evidence.manifest(),
            'scope': 'Frozen static assertion interpretation; unmatched outputs remain unadjudicated.'}


def reference_passed(value, target):
    if not isinstance(value, dict) or not isinstance(value.get('controls'), list):
        return False
    rows = value['controls']
    if target == 'crapi':
        expected = {a + '-location-' + o for a in ('a', 'b', 'absent', 'invalid') for o in ('a', 'b')}
        expected |= {'a-own-list', 'b-own-list', 'missing-object'}
    elif target == 'aigoat':
        expected = {o + '-document-' + a + '-L' + str(l) for o in ('alice', 'bob')
                    for a in ('alice', 'bob') for l in (0, 2)}
        expected |= {a + '-' + m for a in ('absent', 'invalid') for m in ('GET', 'POST')} | {'public-products'}
    else:
        return False
    return (len(rows) == len(expected) and all(isinstance(r, dict) for r in rows) and
            {r.get('id') for r in rows} == expected and all(r.get('passed') is True for r in rows) and
            (target != 'aigoat' or value.get('ownership_unchanged') is True))


def collect_dynamic(root, contract, references=(), reference_by_owner=None):
    evidence = Evidence(root)
    summary = evidence.read('summary.json')
    job = summary['job']
    require(job == contract['job'], 'Dynamic job differs from campaign schedule')
    require(summary['mode'] == 'execute', 'Qualification output is not a final job')
    require(summary['protocol_release_sha256'] == contract['release_sha256'], 'Dynamic release differs')
    require(summary['released_asset_locks_sha256'] == contract['asset_locks_sha256'], 'Dynamic assets differ')
    result = {'job_id': job['id'], 'profile_id': job['profile_id'], 'block': job['block'],
              'measurement_eligible': False, 'native_count': None, 'observations': []}
    try:
        evidence.bind('protocol_release.json')
        require(sha(evidence.path('protocol_release.json')) == contract['release_sha256'], 'Copied release differs')
        locks = evidence.bind('asset_locks.json')
        require(sha(locks) == contract['asset_locks_sha256'], 'Copied dynamic assets differ')
        for phase in ('before', 'after'):
            evidence.bind('assets-' + phase + '/package_verification.json')
            require(sha(evidence.path('assets-' + phase + '/package_verification.json')) ==
                    contract['package_manifest_sha256'], 'Dynamic execution package differs')
        fixture_data = evidence.read('target/fixtures/private_fixture.json')
        before = evidence.read('target/fixtures/before.json', optional=True)
        after = evidence.read('target/fixtures/after.json', optional=True)
        outcome = evidence.read('target/outcome.json', optional=True) or {}
        if job['kind'] == 'target_generation':
            fixture = fixture_identity('aigoat', fixture_data)
            rows = evidence.read('target/fixtures/generation.json', optional=True) or []
            expected = [r['id'] for r in generation_workload()]
            result.update(role='target_behavior_not_scanner_or_triage',
                          generation=generation_observations(rows, expected, fixture), status='collected',
                          reference_state_verified=reference_passed(before, 'aigoat') and reference_passed(after, 'aigoat'))
            if result['reference_state_verified']:
                result['reference_observations'] = rag_reference_observations(references, before, after, fixture_data)
        else:
            p = dynamic_profile(job['profile_id'])
            schema = evidence.read('target/scanner/openapi.json')
            base_urls = [r['url'] for r in schema.get('servers', [])]
            if not base_urls and schema.get('host'):
                base_urls = ['http://' + schema['host']]
            fixture = fixture_identity(p['target'], fixture_data, base_urls)
            trace = evidence.read('target/scanner_trace.json')
            context = {'job_id': job['id'], 'block': job['block'],
                       'process_status': 'completed' if outcome.get('status') == 'completed' else 'failed',
                       'reference_before_passed': reference_passed(before, p['target']),
                       'reference_after_passed': reference_passed(after, p['target'])}
            adapted = adapt_dynamic(evidence.path('target/scanner'), p, context, trace, fixture)
            require(adapted['reports'] == outcome.get('native_report', {}).get('reports'),
                    'Dynamic raw reports differ from execution receipt')
            require(adapted['native_count'] == outcome.get('native_report', {}).get('native_unit_count'),
                    'Dynamic native count differs from execution receipt')
            for report in adapted['reports']:
                evidence.bind('target/scanner/' + report['path'])
            result.update(adapted, status=outcome.get('status', 'unavailable'))
            # Use independently recorded reference phases for property projections.
            # Scanner-phase traces qualify only the explicitly scoped shadow check.
            if result['measurement_eligible']:
                full_trace = evidence.lines('target/proxy-logs/requests.jsonl')
                require([r for r in full_trace if r.get('phase') == 'scanner'] == trace,
                        'Filtered scanner trace differs from complete request trace')
                projections = []
                for observation in result['observations']:
                    if p['target'] == 'aigoat':
                        projected = http_projection(observation, references, full_trace, fixture)
                    elif p['tool'] == 'restler':
                        projected = authorization_projection(observation, reference_by_owner or {}, full_trace, fixture, fixture_data)
                    else:
                        projected = {'status': 'native_only', 'links': [],
                                     'reason': 'Generic native alerts have no whole-warning truth label.'}
                    projections.append({'finding_id': observation['finding_id'], **projected})
                result['reference_projections'] = projections
                if p['target'] == 'aigoat':
                    result['reference_observations'] = rag_reference_observations(references, before, after, fixture_data)
        if summary.get('success') is not True:
            result['measurement_eligible'] = False
            result['incomplete_job'] = summary.get('error', 'Execution did not finish successfully')
    except (ValueError, KeyError, TypeError, OSError) as error:
        result.update(status='unavailable', reason=type(error).__name__ + ': ' + str(error), measurement_eligible=False)
    result['links'] = [link for row in result.get('reference_projections', []) for link in row['links']] if result['measurement_eligible'] else []
    result['source_manifest'] = evidence.manifest()
    return result
