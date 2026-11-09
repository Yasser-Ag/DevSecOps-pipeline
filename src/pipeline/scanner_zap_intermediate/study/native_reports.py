"""Parse native findings without deduplication, truth labels or CWE guessing."""
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def _rows(value, name):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise ValueError('Expected object list: ' + name)
    return value


def _cwes(value):
    if value is None: return []
    if isinstance(value, (int, str)): value = [value]
    if not isinstance(value, list): raise ValueError('Invalid CWE metadata')
    found = set()
    for x in value:
        if isinstance(x, int) and not isinstance(x, bool) and x > 0: found.add('CWE-' + str(x))
        elif isinstance(x, str):
            found.update('CWE-' + str(int(n)) for n in re.findall(r'\bCWE[-_](\d+)\b', x, flags=re.I))
    return sorted(found)


def _required(row, field):
    value = row.get(field)
    if not isinstance(value, str) or not value.strip(): raise ValueError('Missing string: ' + field)
    return value


def semgrep(report):
    if not isinstance(report, dict) or 'results' not in report or 'errors' not in report:
        raise ValueError('Incomplete Semgrep report')
    parsed = []
    errors = _rows(report['errors'], 'errors')
    for i, r in enumerate(_rows(report['results'], 'results')):
        extra = r.get('extra') or {}
        start, end = r.get('start') or {}, r.get('end') or {}
        if not isinstance(start.get('line'), int) or start['line'] < 1:
            raise ValueError('Invalid Semgrep source location')
        parsed.append({'native_index': i, 'native_rule': _required(r, 'check_id'),
            'native_id': extra.get('fingerprint') if extra.get('fingerprint') != 'requires login' else None,
            'path': _required(r, 'path'), 'line_start': start['line'], 'line_end': end.get('line'),
            'cwes': _cwes((extra.get('metadata') or {}).get('cwe')),
            'message': extra.get('message'), 'severity': extra.get('severity'),
            'native_locator': f'/results/{i}', 'location_basis': 'reported_source_span'})
    return parsed, {'reported_errors': errors, 'reported_paths': report.get('paths'),
                    'skipped_rules': report.get('skipped_rules'),
                    'report_status': 'completed_with_limitations' if errors else 'completed'}


def findsecbugs(text):
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper(): raise ValueError('XML entities not allowed')
    root = ET.fromstring(text)
    if root.tag != 'BugCollection': raise ValueError('Not a SpotBugs collection')
    patterns = {x.get('type'): x.get('cweid') for x in root.findall('BugPattern')}
    parsed = []
    for i, bug in enumerate(root.findall('BugInstance')):
        rule = bug.get('type')
        if not rule: raise ValueError('Missing bug type')
        candidates = bug.findall('SourceLine')
        loc = next((x for x in candidates if x.get('primary') == 'true'), None)
        if loc is None and candidates: loc = candidates[0]
        cls = bug.find('Class'); method = bug.find('Method')
        if loc is None and cls is not None: loc = cls.find('SourceLine')
        cwe = bug.get('cweid') or patterns.get(rule)
        parsed.append({'native_index': i, 'native_rule': rule, 'native_id': bug.get('instanceHash'),
            'path': loc.get('sourcepath') if loc is not None else None,
            'line_start': int(loc.get('start')) if loc is not None and loc.get('start', '').isdigit() else None,
            'line_end': int(loc.get('end')) if loc is not None and loc.get('end', '').isdigit() else None,
            'class_name': cls.get('classname') if cls is not None else None,
            'method': method.get('name') if method is not None else None,
            'signature': method.get('signature') if method is not None else None,
            'cwes': _cwes(int(cwe)) if cwe and cwe.isdigit() else [],
            'message': bug.findtext('LongMessage'), 'severity': bug.get('priority'),
            'native_category': bug.get('category'),
            'native_locator': f'/BugCollection/BugInstance[{i + 1}]',
            'location_basis': 'bytecode_report_source_mapping'})
    errors = root.find('Errors')
    missing = [x.text for x in errors.findall('MissingClass')] if errors is not None else []
    detail = [ET.tostring(x, encoding='unicode') for x in errors.findall('Error')] if errors is not None else []
    attributes = errors.attrib if errors is not None else {}
    counted_errors = any(int(attributes.get(key, '0')) > 0
                         for key in ('errors', 'missingClasses'))
    summary = root.find('FindBugsSummary')
    return parsed, {'missing_classes': missing, 'reported_errors': detail,
                    'error_attributes': attributes,
                    'analysis_summary': summary.attrib if summary is not None else {},
                    'analyzed_classes': [x.attrib for x in root.findall('.//ClassStats')],
                    'report_status': 'completed_with_limitations' if missing or detail or counted_errors else 'completed'}


def checkov(report):
    # The installed CLI emits this summary-only object when no input resource is
    # collected (for example, a workflow outside .github/workflows). It is not a
    # clean scan and must not become an eligible zero-detection observation.
    empty_fields = ('passed', 'failed', 'skipped', 'parsing_errors', 'resource_count')
    if isinstance(report, dict) and 'results' not in report and 'resource_count' in report:
        if (any(type(report.get(k)) is not int or report[k] != 0 for k in empty_fields)
                or not isinstance(report.get('checkov_version'), str) or not report['checkov_version']):
            raise ValueError('Unqualified Checkov summary-only report')
        return [], {'reported_errors': [], 'skipped_checks': [], 'summaries': [report],
                    'input_collection_empty': True, 'eligible_detection_observation': False,
                    'report_status': 'completed_with_limitations',
                    'scope': 'No collected resource; this report cannot establish case coverage or a clean target.'}
    reports = report if isinstance(report, list) else [report]
    if not reports: raise ValueError('Empty report list does not establish a completed scan')
    parsed, errors, summaries, skipped = [], [], [], []
    for group, block in enumerate(reports):
        if not isinstance(block, dict) or not isinstance(block.get('results'), dict):
            raise ValueError('Incomplete Checkov report')
        result = block['results']
        for field in ('failed_checks', 'passed_checks', 'skipped_checks', 'parsing_errors'):
            if field not in result or not isinstance(result[field], list): raise ValueError('Missing Checkov result list: ' + field)
        errors.extend(result['parsing_errors']); skipped.extend(result['skipped_checks'])
        summaries.append(block.get('summary'))
        for i, r in enumerate(_rows(result['failed_checks'], 'failed_checks')):
            if (r.get('check_result') or {}).get('result') != 'FAILED': raise ValueError('Unexpected check status in failed list')
            lines = r.get('file_line_range') or []
            parsed.append({'native_index': len(parsed), 'native_rule': _required(r, 'check_id'),
                'native_id': None, 'path': r.get('file_abs_path') or r.get('file_path'),
                'reported_relative_path': r.get('file_path'), 'resource': r.get('resource'),
                'framework': block.get('check_type'), 'line_start': lines[0] if lines else None,
                'line_end': lines[-1] if lines else None, 'cwes': [],
                'message': r.get('check_name'), 'severity': r.get('severity'),
                'evaluated_keys': (r.get('check_result') or {}).get('evaluated_keys'),
                'native_locator': (f'/{group}' if isinstance(report, list) else '') + f'/results/failed_checks/{i}',
                'location_basis': 'reported_resource_and_span'})
    return parsed, {'reported_errors': errors, 'skipped_checks': skipped, 'summaries': summaries,
                    'report_status': 'completed_with_limitations' if errors or skipped else 'completed'}


def parse_report(path, tool, execution_status):
    if execution_status not in {'completed', 'completed_with_limitations', 'failed', 'timed_out', 'interrupted', 'unsupported', 'not_run'}:
        raise ValueError('Unknown execution status')
    p = Path(path)
    raw = p.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if tool == 'semgrep': rows, diagnostic = semgrep(json.loads(raw))
    elif tool == 'findsecbugs': rows, diagnostic = findsecbugs(raw.decode())
    elif tool == 'checkov': rows, diagnostic = checkov(json.loads(raw))
    else: raise ValueError('Unsupported native parser')
    for r in rows:
        r.update(finding_id=f'{tool}:{digest[:16]}:{r["native_index"]}', tool=tool,
                 raw_report_sha256=digest, truth='not_adjudicated')
    effective = (execution_status if execution_status != 'completed' else diagnostic['report_status'])
    return {'schema_version': 'native-findings-2', 'tool': tool,
            'raw_report': str(p), 'raw_report_sha256': digest,
            'execution_status': execution_status, 'effective_status': effective,
            'findings': rows, 'diagnostics': diagnostic,
            'contract': 'All native findings retained without deduplication; no reference labels consulted.'}
