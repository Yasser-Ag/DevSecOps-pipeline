"""Bind currently installed inputs/rules/databases to the retained static recipes."""
import json
from pathlib import Path
import re

from engineering.static_scanner_host import ROOT, capture, inventory, utc
from study.static_scan_contract import require, sha

DATABASES = {
    'grype': ROOT / 'environment/grype-db-20260922-01',
    'trivy-db': ROOT / 'environment/scanner-assets-20260921-01/trivy/db',
    'trivy-java': ROOT / 'environment/scanner-assets-20260921-01/trivy/java-db',
    'dependency-check': ROOT / 'environment/dependency-check-20260922-02/data',
}


def private_database_bound(plan, sizes):
    needs = [0]
    for profile in plan['profiles']:
        if '{PHASE}/database-copies/trivy' in profile['argv']:
            needs.append(sizes['trivy-db'] + sizes['trivy-java'])
        if '{PHASE}/database-copies/dependency-check' in profile['argv']:
            needs.append(sizes['dependency-check'])
    return max(needs)


def runtime_roots(plan):
    roots = {ROOT / 'environment/toolset-20260922-01/jdk',
             ROOT / 'environment/toolset-20260922-01/spotbugs/spotbugs-4.10.4',
             ROOT / 'environment/toolset-20260922-01/findsecbugs',
             ROOT / 'environment/dependency-check-20260922-01/dependency-check',
             ROOT / 'environment/scanner-assets-20260921-01/semgrep/owasp-top-ten.yaml'}
    for profile in plan['profiles']:
        if profile['kind'] != 'native':
            continue
        entry = Path(profile['argv'][0])
        require(entry.is_file(), 'Missing scanner executable: ' + str(entry))
        roots.add(entry)
        resolved = entry.resolve()
        if resolved.name in ('semgrep', 'checkov', 'bandit'):
            roots.add(resolved.parents[1])
    return sorted(roots)


def qualify(plan):
    for path, expected in plan['historical_file_hashes'].items():
        require(Path(path).is_file() and sha(path) == expected, 'Historical asset changed: ' + path)
    inputs = {}
    for key, suite in plan['suites'].items():
        rows, flattened = [], {}
        for item in suite['inputs']:
            files = inventory(item['source'])
            rows.append({**item, 'files': files})
            for f in files:
                path = item['destination'] if f['path'] == '.' else item['destination'] + '/' + f['path']
                flattened[path] = f
        for expected in suite['local_input_hashes']:
            current = flattened.get(expected['path'])
            require(current is not None and all(current.get(k) == expected[k] for k in ('bytes', 'sha256')),
                    'Retained/local input differs: ' + key + '/' + expected['path'])
        inputs[key] = rows
    runtime = [{'source': str(p), 'resolved': str(p.resolve()), 'files': inventory(p, allow_links=True)} for p in runtime_roots(plan)]
    databases = {k: {'source': str(p), 'files': inventory(p)} for k, p in DATABASES.items()}
    image_ids = set()
    for profile in plan['profiles']:
        if profile['kind'] == 'container':
            image_ids.add(profile['image'])
        for arg in profile['argv']:
            image_ids.update(re.findall(r'(?:^|docker:)(sha256:[a-f0-9]{64})$', arg))
    images = {}
    for image in sorted(image_ids):
        info = json.loads(capture(['docker', 'image', 'inspect', image]))[0]
        require(info['Id'] == image, 'Image ID differs')
        images[image] = {k: info[k] for k in ('Id', 'RootFS', 'Architecture', 'Os', 'Size')}
    max_inputs = max(sum(f.get('bytes', 0) for item in rows for f in item['files']) for rows in inputs.values())
    db_sizes = {k: sum(f.get('bytes', 0) for f in item['files']) for k, item in databases.items()}
    return {'schema': 'static-assets-1', 'qualified_utc': utc(), 'inputs': inputs, 'runtime': runtime,
            'databases': databases, 'images': images,
            'capacity': {'largest_suite_input_bytes': max_inputs, 'database_bytes': db_sizes,
                         'max_private_database_bytes': private_database_bound(plan, db_sizes),
                         'temporary_memory_filesystem_max_gib': 6,
                         'retained_evidence_allowance_bytes': 1024**3},
            'scope': 'Current installed bytes, checked against available retained input hashes; not a new vulnerability evaluation.'}


def verify_locked(locks, include_inputs=True):
    for row in locks['runtime']:
        require(str(Path(row['source']).resolve()) == row['resolved'] and
                inventory(row['source'], allow_links=True) == row['files'], 'Runtime changed: ' + row['source'])
    for row in locks['databases'].values():
        require(inventory(row['source']) == row['files'], 'Database changed: ' + row['source'])
    if include_inputs:
        for rows in locks['inputs'].values():
            for row in rows:
                require(inventory(row['source']) == row['files'], 'Source input changed: ' + row['source'])
    for image, expected in locks['images'].items():
        actual = json.loads(capture(['docker', 'image', 'inspect', image]))[0]
        require({k: actual[k] for k in expected} == expected, 'Image changed')
