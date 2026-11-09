"""Audit typed Kubernetes associations and bounded precedence diagnostics."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from study.configuration_matching import (registry_for_text,documents,trivy_outcomes,
    checkov_outcomes,associate,file_pass_counterfactual)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text())
def write(path,data):path.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')


def analyze(inputs,run,out):
    if out.exists():raise FileExistsError('Analysis output already exists')
    for row in read(inputs/'inputs_manifest.json')['files']:
        p=Path(row['path'])
        if p.is_absolute() or '..' in p.parts:raise ValueError('Invalid input path')
        if sha(inputs/p)!=row['sha256'] or (inputs/p).stat().st_size!=row['bytes']:raise ValueError('Input changed')
    manifest=read(run/'manifest.json')
    if not manifest.get('scans_completed'):raise ValueError('Diagnostic scans incomplete')
    for label in ('matrix-trivy','matrix-checkov','split-trivy'):
        phase=read(run/(label+'.manifest.json'))
        if phase['outcome']!='completed':raise ValueError('Missing completed diagnostic phase')
        raw=run/(label+'.json' if 'trivy' in label else label+'.stdout')
        if sha(raw)!=manifest['reports'][label]['sha256']:raise ValueError('Native report changed')
    prior=inputs/'prior'
    roots={'controls':prior/'reference/scanner-inputs/controls/kubernetes',
           'originals':prior/'reference/scanner-inputs/originals/kubernetes',
           'matrix':inputs/'matrix','split':inputs/'split'}
    registry={'objects':[],'identities':[],'references':[],
              'source_roots':{k:str(v.relative_to(inputs)) for k,v in roots.items()}}
    for corpus,root in roots.items():
        for path in sorted(root.rglob('*.yaml')):
            result=registry_for_text(path.read_text(),str(path.relative_to(root)),corpus)
            for key in ('objects','identities','references'):registry[key].extend(result[key])
    by_ref={r['reference_id']:r for r in registry['references']}
    if len(by_ref)!=len(registry['references']):raise ValueError('Duplicate independent identity')
    reference=read(inputs/'diagnostic_reference.json')
    matrix_ids=[r for r in registry['identities'] if r['corpus']=='matrix']
    for case in reference['probes']:
        selected=[r for r in matrix_ids if r['path']==Path(case['path']).name and r['container_name']=='subject']
        if len(selected)!=1:raise ValueError('Missing subject reference')
        row=by_ref[selected[0]['reference_id']]
        if row['effective_runAsNonRoot'] is not case['effective_value'] or row['guard_not_declared_true'] is not case['guard_not_declared_true']:
            raise ValueError('Generated precedence table disagrees with independent source reader')
    for split in reference['splits']:
        original=documents((roots['originals']/split['original_path']).read_text(),split['original_path'])
        old=next(d for d in original if d['document_index']==split['document_index'])
        new=documents((inputs/split['path']).read_text(),split['path'])[0]
        if old['object']!=new['object']:raise ValueError('Isolated object changed semantics')
    outcomes=[];sources=[]
    for corpus in ('controls','originals','matrix','split'):
        for tool in ('trivy','checkov'):
            if corpus=='split' and tool=='checkov':continue
            if corpus in ('controls','originals'):
                p=prior/(f'{corpus}-{tool}-kubernetes.'+('json' if tool=='trivy' else 'stdout'))
                phase=read(prior/f'{corpus}-{tool}-kubernetes.manifest.json')
                if phase['outcome']!='completed':raise ValueError('Original scan not completed')
            else:p=run/(f'{corpus}-{tool}.'+('json' if tool=='trivy' else 'stdout'))
            rows=(trivy_outcomes if tool=='trivy' else checkov_outcomes)(read(p),corpus)
            for row in rows:row['raw_report_sha256']=sha(p)
            outcomes.extend(rows);sources.append({'corpus':corpus,'tool':tool,'sha256':sha(p),'selected_outcomes':len(rows)})
    associations=[associate(r,registry['identities'],registry['objects']) for r in outcomes]
    oracle_validation=[]
    for outcome,link in zip(outcomes,associations):
        if outcome['status'] not in ('FAIL','FAILED'):continue
        for rid in link['definite_reference_ids']:
            oracle_validation.append({'outcome_id':outcome['outcome_id'],'reference_id':rid,
                'guard_not_declared_true':by_ref[rid]['guard_not_declared_true'],
                'actual_runtime_uid':by_ref[rid]['actual_runtime_uid']})
    matrix=[]
    for case in reference['probes']:
        for tool in ('trivy','checkov'):
            selected=[r for r in outcomes if r['corpus']=='matrix' and r['tool']==tool and r['path']==Path(case['path']).name]
            statuses={r['status'] for r in selected};statuses={dict(PASSED='PASS',FAILED='FAIL').get(s,s) for s in statuses}
            observed='FAIL' if 'FAIL' in statuses else 'PASS' if statuses=={'PASS'} else 'not_reported_or_other'
            in_scope=case['trivy_0012_in_scope' if tool=='trivy' else 'checkov_23_in_scope']
            # Published rule-source applicability is separate from emitted PASS rows.
            agreement=(observed==('FAIL' if case['guard_not_declared_true'] else 'PASS')) if in_scope and observed in ('PASS','FAIL') else None
            matrix.append({'case_id':case['id'],'tool':tool,'container_type':case['container_type'],
                'pod_value':case['pod_value'],'container_value':case['container_value'],
                'reference_guard_not_true':case['guard_not_declared_true'],'in_declared_rule_scope':in_scope,
                'native_status':observed,'scored_agreement':agreement,'outcome_ids':[r['outcome_id'] for r in selected]})
    split_outcomes=[r for r in outcomes if r['corpus']=='split'];split_records=[]
    for part in reference['splits']:
        rows=[r for r in split_outcomes if r['path']==Path(part['path']).name]
        split_records.append({**part,'rule_statuses':[r['status'] for r in rows],
                              'outcome_ids':[r['outcome_id'] for r in rows]})
    original_out=[r for r in outcomes if r['corpus']=='originals']
    original_links=[a for r,a in zip(outcomes,associations) if r['corpus']=='originals']
    original_ids=[r for r in registry['identities'] if r['corpus']=='originals']
    summary={'purpose':'Post-outcome Kubernetes identity and rule qualification',
        'input_manifest_sha256':sha(inputs/'inputs_manifest.json'),'analysis_source_sha256':sha(Path(__file__)),
        'source_reports':sources,'reference_counts':dict(Counter(r['corpus'] for r in registry['identities'])),
        'original_workloads':sum(r['corpus']=='originals' and r['workload'] for r in registry['objects']),
        'original_objects':sum(r['corpus']=='originals' for r in registry['objects']),
        'original_guard_not_true':sum(by_ref[r['reference_id']]['guard_not_declared_true'] for r in original_ids),
        'association_counts':dict(Counter(a['association'] for a in associations)),
        'original_association_counts':dict(Counter(a['association'] for a in original_links)),
        'source_coordinate_policy':'Version-gated Trivy 0.74.0 YAML parser offsets; raw coordinates preserved.',
        'original_coordinate_adjustments':[
            {'outcome_id':a['outcome_id'],'line_delta':a['line_delta'],
             'physical_line_start':a['physical_line_start'],'physical_line_end':a['physical_line_end']}
            for a in original_links if a.get('line_delta',0)!=0],
        'matrix_summary':{t:{'scored':sum(r['tool']==t and r['scored_agreement'] is not None for r in matrix),
            'disagreements':sum(r['tool']==t and r['scored_agreement'] is False for r in matrix),
            'outside_rule_scope':sum(r['tool']==t and not r['in_declared_rule_scope'] for r in matrix)} for t in ('trivy','checkov')},
        'original_file_pass_counterfactual':file_pass_counterfactual(original_out,original_links),
        'split_rule_outcomes':[{k:r[k] for k in ('original_path','document_index','kind','rule_statuses')} for r in split_records],
        'limits':['Known outcomes guided this bounded diagnosis; not held-out performance.',
            'Missing declared non-root enforcement does not prove a running UID of zero.',
            'Checkov also accepts positive runAsUser; the comparison matrix fixes that field absent.',
            'Trivy source excludes ephemeral containers; Checkov root rule iterates ordinary containers only.',
            'Absent/multi-document PASS identity is not transferred to container properties.',
            'Source-coordinate adaptation was added after two v1 associations failed; v1 evidence is retained.',
            'Seven source workloads and constructed variants are not independent production applications.',
            'No live admission/runtime, new vulnerability, general accuracy or methodological superiority is claimed.']}
    out.mkdir(parents=True)
    for name,data in [('analysis',summary),('registry',registry),('outcomes',outcomes),('associations',associations),
                      ('localized_failure_reference_checks',oracle_validation),('matrix',matrix),('split_audit',split_records)]:
        write(out/(name+'.json'),data)
    return summary
