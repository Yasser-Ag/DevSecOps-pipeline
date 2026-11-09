"""Replay the frozen six-domain comparators on collected final evidence.

No scientific rule is modified. A domain that lacks qualified inputs remains
unavailable. The only input overlay is the separately documented exact Semgrep
rule-prefix binding repair; original observations and raw files are preserved.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import resource
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
QUALIFIED = ROOT / 'evidence/final_composition_2026-10-23/package-v2'
STATIC = ROOT / 'evidence/final_static_campaign_2026-10-23'
sys.path.insert(0, str(QUALIFIED))
from study.final_campaign_contract import verify_package
from study.final_comparator_inputs import Inputs
from study.final_comparator_ingress import compare_block
from engineering.final_composition_qualification import dependencies


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024**2), b''): h.update(chunk)
    return h.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    analysis, output = args.analysis.resolve(), args.output.resolve()
    analysis.relative_to(ROOT / 'evidence'); output.relative_to(ROOT / 'evidence')
    output.mkdir(parents=True, exist_ok=False)
    result = {'success': False, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'blocks': [], 'new_scans': 0, 'new_model_calls': 0,
              'scope': 'Unchanged frozen domain comparators on all collected final blocks; no pooled accuracy.'}
    sources = {}

    def read(path, expected=None):
        path = Path(path); actual = sha(path)
        require(expected is None or actual == expected, 'Input identity differs: ' + str(path))
        relative = path.relative_to(ROOT).as_posix()
        row = {'path': relative, 'sha256': actual, 'bytes': path.stat().st_size}
        require(relative not in sources or sources[relative] == row, 'Input changed during replay')
        sources[relative] = row
        with path.open() as stream: return json.load(stream)

    try:
        resource.setrlimit(resource.RLIMIT_AS, (5 * 1024**3, 5 * 1024**3))
        require(read(analysis / 'summary.json')['success'] is True, 'Analysis input incomplete')
        manifest = read(analysis / 'output_manifest.json')
        for row in manifest:
            p = Path(row['path'])
            require(not p.is_absolute() and '..' not in p.parts, 'Unsafe output path')
            require(sha(analysis / p) == row['sha256'] and (analysis / p).stat().st_size == row['bytes'],
                    'Consolidated artifact changed')
        verify_package(QUALIFIED, '4579ba6ad6ec0b432725a94f4452f67aea70e60380b22158efb4dbba7a79b9e2')
        _, result['qualified_analysis_wheels'] = dependencies(output)
        original = STATIC / 'audit-v1/ingress.json'
        collection = read(original, '5b086a9479ba6be812fc7aa6c3c7aa4fb6ab7ddfe1f3563626476d50ad2d84ad')
        overlay = read(analysis / 'semgrep_binding_overlay.json')
        require(overlay['original_ingress_sha256'] == sha(original), 'Overlay source differs')
        patches = {p['job_id']: p for p in overlay['jobs']}
        require(len(patches) == 5, 'Incomplete or duplicate overlay')
        replaced = set()
        for index, job in enumerate(collection['jobs']):
            if job['job_id'] not in patches: continue
            patch = patches[job['job_id']]
            require(job['profile_id'] == 'java-semgrep', 'Cross-profile overlay')
            require(digest(job) == patch['before_job_digest'], 'Original job differs')
            require(digest(patch['corrected_job']) == patch['after_job_digest'], 'Corrected job differs')
            collection['jobs'][index] = patch['corrected_job']; replaced.add(job['job_id'])
        require(replaced == set(patches), 'Unused overlay job')
        runs = read(analysis / 'dynamic_run_inputs.json')
        require(set(runs) == {'1', '2', '3', '4', '5'}, 'Dynamic blocks differ')
        inputs = Inputs(QUALIFIED)
        for block in range(1, 6):
            report = compare_block(STATIC / 'static-scanners-final-20261023-01', collection,
                                   runs[str(block)], inputs, block)
            write(output / f'block-{block:02d}.json', report)
            statuses = {name: domain['status'] for name, domain in report['domains'].items()}
            result['blocks'].append({'block': block, 'domains': statuses,
                'unavailable_reasons': {name: domain.get('reason') for name, domain in report['domains'].items()
                                        if domain['status'] != 'complete'}})
            print(json.dumps(result['blocks'][-1]), flush=True)
            # The historical qualification limits are retained, never bypassed.
            require(all(statuses[name] == 'complete' for name in ('sast', 'identity', 'kubernetes', 'terraform')),
                    'Previously qualified static domain regressed')
            require(not report['report_errors'], 'Static raw evidence failed replay')
        result['success'] = True
        result['complete_all_domains'] = all(all(v == 'complete' for v in b['domains'].values()) for b in result['blocks'])
        result['maximum_process_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        (output / 'failure_trace.txt').write_text(traceback.format_exc())
    snapshot = output / 'source_snapshot'; snapshot.mkdir()
    (snapshot / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    write(output / 'input_manifest.json', sorted(sources.values(), key=lambda r: r['path']))
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    write(output / 'summary.json', result)
    write(output / 'output_manifest.json', [{'path': p.relative_to(output).as_posix(), 'sha256': sha(p),
            'bytes': p.stat().st_size} for p in sorted(output.rglob('*')) if p.is_file()])
    print(json.dumps(result, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__': raise SystemExit(main())
