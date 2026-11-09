#!/usr/bin/env python3
"""Export paper tables from preserved derived data without rerunning experiments."""
from collections import defaultdict
import argparse
import csv
import json
from pathlib import Path
import shutil
import time

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return list(csv.DictReader((ROOT / 'data/derived' / name).open()))


def write(path, rows, fields=None):
    if not rows:
        raise ValueError('An empty table is not a reconstructed result: ' + path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def export(output):
    start = time.monotonic()
    files = []
    direct = {
        'static_profiles.csv': ('supplementary/S1_static_profiles.csv', 75),
        'dynamic_profiles.csv': ('supplementary/S2_dynamic_profiles.csv', 18),
        'grouping.csv': ('supplementary/S3_grouping.csv', 300),
        'os_advisories.csv': ('supplementary/S5_os_advisories.csv', 12),
        'reference_review.csv': ('supplementary/S6_reference_review.csv', 32),
        'triage_cost.csv': ('supplementary/S8_triage_cost.csv', 12),
        'measure_definitions.csv': ('tables/table04_measures.csv', 19),
        'ci_workflow_audit.csv': ('tables/table05_ci_workflow_audit.csv', 7),
        'sca_occurrences.csv': ('tables/table06_sca_occurrences.csv', 6),
        'triage_decisions.csv': ('tables/table07_triage_decisions.csv', 12),
        'reference_populations.csv': ('tables/table_a1_reference_populations.csv', 35),
    }
    for source, (destination, count) in direct.items():
        data = read(source)
        if len(data) != count:
            raise ValueError('Source row count changed: ' + source)
        write(output / destination, data)
        files.append({'output': destination, 'source': 'data/derived/' + source, 'rows': count,
                      'operation': 'copy_cells_without_numeric_conversion'})
    # Retain every per-block omission record; do not average distinct observations.
    grouped = defaultdict(list)
    for row in read('omissions.csv'):
        grouped[row['population'], row['omission_level'], row['omitted']].append(row)
    omissions = []
    for key, members in sorted(grouped.items()):
        members.sort(key=lambda row: int(row['block']))
        if [r['block'] for r in members] != ['1', '2', '3', '4', '5']:
            raise ValueError('Missing or duplicated omission block')
        scientific_fields = [k for k in members[0] if k not in {'block', 'source'}]
        same = all(all(row[k] == members[0][k] for k in scientific_fields) for row in members)
        record = {k: members[0][k] for k in scientific_fields}
        record.update(blocks='1;2;3;4;5', identical_on_five_blocks=str(same).lower(),
                      blockwise_observations=json.dumps(members, separators=(',', ':'), ensure_ascii=False))
        omissions.append(record)
    if len(omissions) != 88:
        raise ValueError('Expected 88 omission comparisons')
    write(output / 'supplementary/S4_omissions.csv', omissions)
    files.append({'output': 'supplementary/S4_omissions.csv', 'source': 'data/derived/omissions.csv',
                  'rows': 88, 'operation': 'group_five_blocks_preserve_all_440_records'})
    decisions = [{'record_type': 'class_decisions', **r} for r in read('triage_by_class.csv')]
    invalid = [{'record_type': 'invalid_response', **r} for r in read('invalid_responses.csv')]
    if len(decisions) != 12 or len(invalid) != 34:
        raise ValueError('Unexpected triage records')
    write(output / 'supplementary/S7_triage_decisions_and_invalid.csv', decisions + invalid)
    files.append({'output': 'supplementary/S7_triage_decisions_and_invalid.csv',
                  'source': 'data/derived/triage_by_class.csv;data/derived/invalid_responses.csv',
                  'rows': 46, 'operation': 'typed_union_without_value_changes'})
    rules_source = ROOT / 'data/references/binding_rules.csv'
    rules = list(csv.DictReader(rules_source.open()))
    if len(rules) != 67:
        raise ValueError('The protocol reference rules must have 67 rows')
    for destination in ['supplementary/S9_binding_rules.csv', 'tables/table_a2_binding_rules.csv']:
        write(output / destination, rules)
        files.append({'output': destination, 'source': 'data/references/binding_rules.csv',
                      'rows': 67, 'operation': 'copy_cells_without_numeric_conversion'})
    cost = read('triage_cost.csv')
    write(output / 'tables/table08_triage_cost.csv', cost)
    files.append({'output': 'tables/table08_triage_cost.csv', 'source': 'data/derived/triage_cost.csv',
                  'rows': len(cost), 'operation': 'copy_cells_without_numeric_conversion'})
    for name in ['closest_studies', 'analyzed_material', 'scanner_versions', 'human_checks', 'practitioner_checklist']:
        source = ROOT / 'data/derived' / (name + '.csv')
        if name in {'closest_studies','practitioner_checklist'}:
            number = {'closest_studies':'01','practitioner_checklist':'10'}[name]
            source = ROOT / 'data/editorial' / ('table'+number+'_'+name+'.csv')
        if source.exists():
            number = {'closest_studies': '01', 'analyzed_material': '02', 'scanner_versions': '03',
                      'human_checks': '09', 'practitioner_checklist': '10'}[name]
            destination = 'tables/table' + number + '_' + name + '.csv'
            data = list(csv.DictReader(source.open()))
            write(output / destination, data)
            files.append({'output': destination, 'source': str(source.relative_to(ROOT)),
                          'rows': len(data), 'operation': 'copy_cells_without_numeric_conversion'})
    editorial = ROOT / 'data/editorial/table_b1_model_deployments.csv'
    destination='tables/table_b1_model_deployments.csv'
    shutil.copyfile(editorial,output/destination)
    files.append({'output':destination,'source':str(editorial.relative_to(ROOT)),'rows':len(list(csv.DictReader(editorial.open()))),'operation':'verbatim_article_table'})
    shutil.copyfile(ROOT/'data/editorial/table10_note.md',output/'tables/table10_note.md')
    preliminary = ROOT / 'preliminary/preliminary_observations.csv'
    if preliminary.exists():
        data = list(csv.DictReader(preliminary.open()))
        for number, sections in [('c1', {'failed_runs'}), ('c2', {'run31_stages', 'image_database_drift'})]:
            selected = [r for r in data if r.get('section') in sections]
            sources='preliminary/preliminary_observations.csv'
            if number=='c1':
                runs=list(csv.DictReader((ROOT/'preliminary/run_metadata.csv').open()))
                assert len(runs)==31 and sorted(int(r['run_number']) for r in runs)==list(range(1,32))
                selected=[{'record_type':'workflow_run',**r,'source':f'preliminary/run_metadata.csv:{i}'}
                          for i,r in enumerate(runs,2)]+[{'record_type':'recorded_failure',**r} for r in selected]
                stages=list(csv.DictReader((ROOT/'preliminary/stage_counts.csv').open()))
                assert [r['stage'] for r in stages]==['sast','sca','secrets','iac','image','dast']
                selected += [{'record_type':'scanner_stage','stage_order':i,**r,
                              'source':f'preliminary/stage_counts.csv:{i+1}'} for i,r in enumerate(stages,1)]
                sources+=';preliminary/run_metadata.csv;preliminary/stage_counts.csv;preliminary/pipeline.yml.disabled'
            if selected:
                destination = 'tables/table_' + number + '_preliminary.csv'
                write(output / destination, selected)
                files.append({'output': destination, 'source': sources,
                              'rows': len(selected), 'operation': 'select_recorded_sections'})
    write(output / 'table_provenance.csv', files)
    return {'tables_exported': len(files), 'new_measurements': 0, 'wall_seconds': time.monotonic() - start}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('Use an empty output directory')
    summary = export(args.output)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
