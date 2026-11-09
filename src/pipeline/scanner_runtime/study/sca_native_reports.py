"""Preserve native component and advisory observations without declaring truth."""
import hashlib
import json
from pathlib import Path


def rows(value, label):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise ValueError('Expected object list: ' + label)
    return value


def required(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError('Missing string: ' + key)
    return value


def trivy(report):
    if report.get('SchemaVersion') != 2:
        raise ValueError('Unsupported or incomplete Trivy report')
    omitted = 'Results' not in report
    if omitted and not (report.get('ArtifactName') and report.get('ArtifactType')
                        and (report.get('Trivy') or {}).get('Version') and report.get('CreatedAt')):
        raise ValueError('Missing Trivy results and completion metadata')
    components, findings = [], []
    for i, result in enumerate(rows(report.get('Results', []), 'Results')):
        target = required(result, 'Target')
        for j, item in enumerate(rows(result.get('Packages', []), 'Packages')):
            components.append({'native_locator': f'/Results/{i}/Packages/{j}',
                'native_id': item.get('ID'), 'name': item.get('Name'), 'version': item.get('Version'),
                'purls': [item['Identifier']['PURL']] if (item.get('Identifier') or {}).get('PURL') else [],
                'locations': [{'path': p} for p in item.get('FilePath', '').split('\n') if p],
                'target': target, 'ecosystem': result.get('Type'), 'native': item})
        for j, item in enumerate(rows(result.get('Vulnerabilities', []), 'Vulnerabilities')):
            findings.append({'native_locator': f'/Results/{i}/Vulnerabilities/{j}',
                'advisory_id': required(item, 'VulnerabilityID'),
                'reported_related_ids': item.get('VendorIDs', []),
                'package': {'name': required(item, 'PkgName'), 'version': item.get('InstalledVersion'),
                    'purls': [item['PkgIdentifier']['PURL']] if (item.get('PkgIdentifier') or {}).get('PURL') else [],
                    'locations': [{'path': item['PkgPath']}] if item.get('PkgPath') else [],
                    'native_id': (item.get('PkgIdentifier') or {}).get('UID')},
                'target': target, 'ecosystem': result.get('Type'),
                'reported_fix': item.get('FixedVersion'), 'reported_status': item.get('Status'),
                'suppressed': False, 'native': item})
    return components, findings, {'source': {k: report.get(k) for k in
        ('ArtifactID','ArtifactName','ArtifactType','Metadata','Trivy')},
        'results_field_omitted': omitted,
        'coverage_limit': 'No reported analyzable results; zero reported findings does not establish eligible case coverage.' if omitted else None,
        'inventory_scope': 'Only explicit Packages entries; omission is not package absence.',
        'reported_errors': [], 'report_status': 'completed'}


def syft(report):
    if not isinstance(report.get('source'), dict) or not isinstance(report.get('schema'), dict):
        raise ValueError('Incomplete Syft source/schema')
    components = []
    for i, item in enumerate(rows(report.get('artifacts'), 'artifacts')):
        components.append({'native_locator': f'/artifacts/{i}', 'native_id': required(item,'id'),
            'name': required(item,'name'), 'version': item.get('version'),
            'purls': [item['purl']] if item.get('purl') else [],
            'locations': item.get('locations', []), 'ecosystem': item.get('type'), 'native': item})
    return components, [], {'source': report['source'], 'schema': report['schema'],
        'relationships': report.get('artifactRelationships', []), 'descriptor': report.get('descriptor'),
        'inventory_scope': 'Reported SBOM artifacts; no vulnerability labels inferred.',
        'reported_errors': [], 'report_status': 'completed'}


def grype(report):
    if not isinstance(report.get('descriptor'), dict) or not isinstance(report.get('source'), dict):
        raise ValueError('Incomplete Grype descriptor/source')
    findings = []
    for field in ('matches', 'ignoredMatches'):
        values = report.get(field, []) if field != 'matches' else report.get(field)
        for i, entry in enumerate(rows(values, field)):
            match = entry.get('match', entry)
            vulnerability, artifact = match.get('vulnerability'), match.get('artifact')
            if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
                raise ValueError('Incomplete Grype match')
            related = rows(match.get('relatedVulnerabilities', []), 'relatedVulnerabilities')
            locator = f'/{field}/{i}' + ('/match' if 'match' in entry else '')
            findings.append({'native_locator': locator,
                'advisory_id': required(vulnerability,'id'),
                'reported_related_ids': [required(v,'id') for v in related],
                'package': {'native_id': artifact.get('id'), 'name': required(artifact,'name'),
                    'version': artifact.get('version'), 'purls': [artifact['purl']] if artifact.get('purl') else [],
                    'locations': artifact.get('locations', [])},
                'ecosystem': artifact.get('type'), 'reported_fix': vulnerability.get('fix'),
                'reported_status': (vulnerability.get('fix') or {}).get('state'),
                'suppressed': field == 'ignoredMatches', 'native': entry})
    status = (report['descriptor'].get('db') or {}).get('status')
    error = (report['descriptor'].get('db') or {}).get('error')
    invalid_status = (status.get('valid') is not True if isinstance(status, dict)
                      else status not in (None, 'valid'))
    problems = [x for x in [error, status if invalid_status else None] if x]
    return [], findings, {'source': report['source'], 'descriptor': report['descriptor'],
        'inventory_scope': 'Matches only; consume the paired Syft SBOM for full reported inventory.',
        'reported_errors': problems, 'report_status': 'completed_with_limitations' if problems else 'completed'}


def dependency_check(report):
    if not isinstance(report.get('scanInfo'), dict) or 'reportSchema' not in report:
        raise ValueError('Incomplete Dependency-Check report')
    components, findings = [], []
    errors = list(report['scanInfo'].get('analysisExceptions') or [])
    for i, item in enumerate(rows(report.get('dependencies'), 'dependencies')):
        packages = rows(item.get('packages', []), 'packages')
        package = {'native_id': item.get('sha256'), 'name': item.get('fileName'), 'version': None,
            'purls': [p['id'] for p in packages if p.get('id','').startswith('pkg:')],
            'locations': [{'path': required(item,'filePath')}],
            'related_dependencies': item.get('relatedDependencies', [])}
        components.append({'native_locator': f'/dependencies/{i}', **package,
                           'native': item, 'ecosystem': 'not_inferred'})
        errors.extend(item.get('analysisExceptions') or [])
        for field in ('vulnerabilities', 'suppressedVulnerabilities'):
            for j, vuln in enumerate(rows(item.get(field, []), field)):
                findings.append({'native_locator': f'/dependencies/{i}/{field}/{j}',
                    'advisory_id': required(vuln,'name'), 'reported_related_ids': [],
                    'package': package, 'ecosystem': 'not_inferred', 'reported_fix': None,
                    'reported_status': None, 'suppressed': field == 'suppressedVulnerabilities',
                    'native': vuln})
    return components, findings, {'source': report.get('projectInfo'), 'scanInfo': report['scanInfo'],
        'report_schema': report['reportSchema'], 'reported_errors': errors,
        'inventory_scope': 'Reported dependencies including related dependencies; candidate package IDs retained.',
        'report_status': 'completed_with_limitations' if errors else 'completed'}


def parse_sca_report(path, tool, execution_status):
    allowed = {'completed','completed_with_limitations','failed','timed_out','interrupted','unsupported','not_run'}
    if execution_status not in allowed:
        raise ValueError('Unknown execution status')
    raw = Path(path).read_bytes(); report = json.loads(raw)
    if not isinstance(report, dict):
        raise ValueError('Expected report object')
    parsers = {'trivy':trivy, 'syft':syft, 'grype':grype, 'dependency-check':dependency_check}
    if tool not in parsers:
        raise ValueError('Unsupported SCA parser')
    components, findings, diagnostic = parsers[tool](report)
    digest = hashlib.sha256(raw).hexdigest()
    for kind, items in [('component',components),('finding',findings)]:
        for i, row in enumerate(items):
            row.update({kind+'_id': f'{tool}:{digest[:16]}:{kind}:{i}',
                        'raw_report_sha256': digest, 'truth': 'not_adjudicated'})
    return {'schema_version': 'native-sca-1', 'tool': tool, 'raw_report_sha256': digest,
        'execution_status': execution_status,
        'effective_status': diagnostic['report_status'] if execution_status == 'completed' else execution_status,
        'components': components, 'findings': findings, 'diagnostics': diagnostic,
        'contract': 'Native observations preserved; no deduplication, oracle labels or inferred exploitability.'}
