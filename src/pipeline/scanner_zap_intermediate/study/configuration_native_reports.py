"""Retain native secret/configuration findings without reference-label access."""
import hashlib
import json
from pathlib import Path

from study.native_reports import _required, _rows


def gitleaks(report):
    findings = []
    for i, r in enumerate(_rows(report, 'Gitleaks root')):
        findings.append({'native_rule': _required(r, 'RuleID'), 'path': _required(r, 'File'),
            'line_start': r.get('StartLine'), 'line_end': r.get('EndLine'),
            'column_start': r.get('StartColumn'), 'column_end': r.get('EndColumn'),
            'native_id': r.get('Fingerprint'), 'message': r.get('Description'),
            'entropy': r.get('Entropy'), 'commit': r.get('Commit'), 'tags': r.get('Tags'),
            'reported_secret_sha256': hashlib.sha256(r['Secret'].encode()).hexdigest() if isinstance(r.get('Secret'), str) else None,
            'native_locator': f'/{i}', 'location_basis': 'reported_secret_span'})
    return findings, {'report_status': 'completed', 'coverage_evidence': 'requires_execution_log_and_input_manifest'}


def hadolint(report):
    findings = []
    for i, r in enumerate(_rows(report, 'Hadolint root')):
        findings.append({'native_rule': _required(r, 'code'), 'path': _required(r, 'file'),
            'line_start': r.get('line'), 'line_end': r.get('line'), 'column_start': r.get('column'),
            'message': r.get('message'), 'severity': r.get('level'),
            'native_locator': f'/{i}', 'location_basis': 'reported_dockerfile_instruction'})
    return findings, {'report_status': 'completed', 'coverage_evidence': 'requires_execution_log_and_input_manifest'}


def trivy(report, kind):
    if not isinstance(report, dict) or report.get('SchemaVersion') != 2 or not report.get('ArtifactName'):
        raise ValueError('Missing Trivy schema/artifact metadata')
    if kind not in ('secret', 'misconfig'):
        raise ValueError('Unknown Trivy configuration kind')
    findings, inventories = [], []
    for group, block in enumerate(_rows(report.get('Results', []), 'Trivy Results')):
        target = _required(block, 'Target')
        key = 'Secrets' if kind == 'secret' else 'Misconfigurations'
        rows = _rows(block.get(key) or [], key)
        inventories.append({'target': target, 'class': block.get('Class'), 'type': block.get('Type'),
                            'misconf_summary': block.get('MisconfSummary'), 'native_rows': len(rows)})
        for i, r in enumerate(rows):
            if kind == 'misconfig' and r.get('Status') not in ('FAIL', 'PASS', 'EXCEPTION'):
                raise ValueError('Missing/unknown Trivy configuration status')
            if kind == 'misconfig' and r['Status'] != 'FAIL':
                continue
            cause = r.get('CauseMetadata') or {}
            findings.append({'native_rule': _required(r, 'RuleID' if kind == 'secret' else 'ID'),
                'native_secondary_id': r.get('AVDID'), 'path': target,
                'line_start': r.get('StartLine') if kind == 'secret' else cause.get('StartLine'),
                'line_end': r.get('EndLine') if kind == 'secret' else cause.get('EndLine'),
                'resource': cause.get('Resource'), 'cause': cause if kind == 'misconfig' else None,
                'message': r.get('Title'), 'severity': r.get('Severity'),
                'description': r.get('Description'), 'resolution': r.get('Resolution'),
                'references': r.get('References'), 'status': r.get('Status'),
                'native_locator': f'/Results/{group}/{key}/{i}',
                'location_basis': 'reported_secret_span' if kind == 'secret' else 'reported_config_resource'})
    return findings, {'report_status': 'completed', 'inventories': inventories,
        'results_present': 'Results' in report, 'coverage_evidence': 'requires_execution_log_and_input_manifest'}


def kics(report):
    if not isinstance(report, dict) or not isinstance(report.get('queries'), list):
        raise ValueError('Missing KICS queries')
    if not isinstance(report.get('files_scanned'), int):
        raise ValueError('Missing KICS scan coverage')
    findings = []
    for group, query in enumerate(_rows(report['queries'], 'KICS queries')):
        for i, row in enumerate(_rows(query.get('files'), 'KICS query files')):
            findings.append({'native_rule': _required(query, 'query_id'),
                'path': _required(row, 'file_name'), 'line_start': row.get('line'), 'line_end': row.get('line'),
                'message': query.get('query_name'), 'severity': query.get('severity'),
                'platform': query.get('platform'), 'category': query.get('category'),
                'resource': row.get('search_key'), 'issue_type': row.get('issue_type'),
                'expected_value': row.get('expected_value'), 'actual_value': row.get('actual_value'),
                'similarity_id': row.get('similarity_id'), 'native_locator': f'/queries/{group}/files/{i}',
                'location_basis': 'reported_config_search_key'})
    diagnostics = {k: v for k, v in report.items() if k != 'queries'}
    failed = report.get('files_failed_to_scan', 0) or report.get('queries_failed_to_execute', 0) or report.get('queries_failed_to_compute_similarity_id', 0)
    diagnostics['report_status'] = 'completed_with_limitations' if failed else 'completed'
    return findings, diagnostics


def parse_configuration_report(path, tool, execution_status):
    if execution_status not in {'completed', 'completed_with_limitations', 'failed', 'timed_out', 'interrupted', 'not_run'}:
        raise ValueError('Unknown execution status')
    raw = Path(path).read_bytes(); digest = hashlib.sha256(raw).hexdigest(); document = json.loads(raw)
    if tool == 'gitleaks': rows, diagnostics = gitleaks(document)
    elif tool == 'hadolint': rows, diagnostics = hadolint(document)
    elif tool in ('trivy-secret', 'trivy-config'): rows, diagnostics = trivy(document, 'secret' if tool.endswith('secret') else 'misconfig')
    elif tool == 'kics': rows, diagnostics = kics(document)
    else: raise ValueError('Unknown configuration adapter')
    for i, row in enumerate(rows):
        row.update(native_index=i, finding_id=f'{tool}:{digest[:16]}:{i}', tool=tool,
                   raw_report_sha256=digest, truth='not_adjudicated', cwes=[])
    return {'schema_version': 'configuration-findings-1', 'tool': tool,
        'raw_report': str(path), 'raw_report_sha256': digest, 'execution_status': execution_status,
        'effective_status': diagnostics['report_status'] if execution_status == 'completed' else execution_status,
        'findings': rows, 'diagnostics': diagnostics,
        'contract': 'Native occurrences retained; rule IDs and file overlap do not assign truth or object identity.'}
