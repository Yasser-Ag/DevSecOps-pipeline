#!/usr/bin/env python3
"""Reapply the frozen validator to recorded responses; never run a model."""
import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

from fetch_external_sources import canonical, reconstruct

ROOT = Path(__file__).resolve().parents[1]


def load_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--source-cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fetch-sources', action='store_true',
                        help='Allow retrieval of pinned source files, not scanner or model execution')
    args = parser.parse_args()
    start = time.monotonic()
    # This frozen validator has no dependency on source parsing.
    validator_file = ROOT / 'src/analysis/triage_validator.py'
    spec = importlib.util.spec_from_file_location('triage_validator', validator_file)
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    packet_manifest = list(csv.DictReader((ROOT / 'data/derived/triage_packet_manifest.csv').open()))
    expected = {(int(r['pass']), r['condition'], r['finding_id']): r for r in packet_manifest}
    results, packet_checks = [], []
    for number in (1, 2):
        base = args.evidence / 'triage' / f'pass{number}'
        packets = {}
        for condition in ('alert_only', 'context'):
            for value in load_rows(base / 'packets' / (condition + '.jsonl')):
                packet = reconstruct(value, args.source_cache, offline=not args.fetch_sources)
                key = number, condition, packet['finding_id']
                same = digest(packet) == expected[key]['published_reconstructed_sha256']
                if not same:
                    raise ValueError('Public packet reconstruction identity mismatch')
                packets[condition, packet['finding_id']] = packet
                packet_checks.append({'pass': number, 'condition': condition,
                                      'finding_id': packet['finding_id'], 'identical': same})
        for model in ('qwen35_9b_q4km', 'gemma4_e4b_qat_q40'):
            directory = base / 'recordings' / f'b{number}_{model}'
            for stored in load_rows(directory / 'decisions.jsonl'):
                if stored.get('synthetic'):
                    continue
                packet = packets[stored['condition'], stored['finding_id']]
                request_id = stored['request_id'].replace('-', '_')
                response = json.loads((directory / (request_id + '_response.raw')).read_text())
                text = response['choices'][0]['message']['content']
                replayed = validator.validate_decision(text, packet)
                if replayed != stored['decision']:
                    raise ValueError('Complete validator output differs from the recorded decision')
                results.append({'pass': number, 'model': model, 'condition': stored['condition'],
                                'finding_id': stored['finding_id'], 'request_id': stored['request_id'],
                                'identical': True, 'status': replayed['status'],
                                'action': replayed['action'], 'effective_action': replayed['effective_action']})
    if len(packet_checks) != 352 or len(results) != 704:
        raise ValueError('Unexpected recorded triage population')
    args.output.mkdir(parents=True, exist_ok=False)
    for name, rows in [('packet_checks.csv', packet_checks), ('validator_checks.csv', results)]:
        with (args.output / name).open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
    summary = {'packets': len(packet_checks), 'responses': len(results), 'all_identical': True,
               'new_model_inferences': 0, 'wall_seconds': time.monotonic() - start}
    (args.output / 'verification.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
