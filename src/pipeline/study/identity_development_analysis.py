"""Replay independently evidenced identities at explicitly different units.

Reference construction and observable extraction are separate functions.
Only scoring receives both. This is post-outcome development, not a blind test.
"""
import argparse
import hashlib
import json
from pathlib import Path

from study.configuration_development_cases import inspect_key
from study.configuration_development_analysis import stage_scope, validate_runtime
from study.configuration_native_reports import parse_configuration_report
from study.configuration_references import docker_instructions
from study.identity_matching import (advisory_aliases, relative_location,
    pair_audit, reporting_effect, stage_effect)
from study.matching_baselines import fingerprint
from study.sca_native_reports import parse_sca_report
from study.sca_references import inspect_jar


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text())
def write(path, data):path.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')


def verify_inputs(inputs):
    manifest=read(inputs/'inputs_manifest.json');seen=set()
    for r in manifest['files']:
        p=Path(r['path'])
        if p.is_absolute() or '..' in p.parts or r['path'] in seen:raise ValueError('Unsafe/duplicate input')
        seen.add(r['path'])
        if sha(inputs/p)!=r['sha256'] or (inputs/p).stat().st_size!=r['bytes']:
            raise ValueError('Changed input: '+r['path'])
    return manifest


def build_references(inputs):
    """Use source bytes and pre-existing independent checks, never report fields."""
    sca=inputs/'sca';cfg=inputs/'configuration'
    sm=read(sca/'reference_manifest.json');cm=read(cfg/'reference/reference_manifest.json')
    if not read(sca/'manifest.json')['success'] or not read(cfg/'manifest.json')['success']:
        raise ValueError('Incomplete earlier development run')
    image=read(sca/'image_byte_verification.json')
    expected={x['image_path']:x['sha256'] for x in sm['occurrences']}
    if image['expected_sha256']!=expected or image['verified_files']!=len(expected):
        raise ValueError('Preserved image byte-verification receipt mismatch')
    nodes=[];edges=[];lookups={'sca':{},'secret':{},'docker':{}}
    for case in sm['cases']:
        c=case['release_identity']['coordinates']
        source=sca/'vendor_sources'/Path(case['source']['retained_path']).name
        if sha(source)!=case['source']['sha256']:raise ValueError('Vendor reference changed')
        for occ in [r for r in sm['occurrences'] if r['purl']==case['purl']]:
            path=sca/'build-context/scanner-inputs'/occ['occurrence_id']
            if sha(path)!=occ['sha256'] or sha(path)!=case['artifact_sha256']:
                raise ValueError('Release bytes disagree')
            if inspect_jar(path,c['groupId'],c['artifactId'],c['version'])!=case['release_identity']:
                raise ValueError('Embedded release coordinates disagree')
            object_id='component-advisory:'+fingerprint([occ['sha256'],case['advisory_id']])
            pair=[]
            for view, location in [('source',occ['occurrence_id']),('image',occ['image_path'])]:
                oid='sca-occurrence:'+fingerprint([view,location,case['advisory_id']])
                evidence=['sca/reference_manifest.json','sca/build-context/scanner-inputs/'+occ['occurrence_id'],
                          'sca/vendor_sources/'+source.name]
                if view=='image':evidence.append('sca/image_byte_verification.json')
                node={'id':oid,'family':'sca','artifact':view,'path':location,
                      'object':object_id,'occurrence':oid,'positive':case['advisory_version_affected'],
                      'purl':case['purl'],'advisory':case['advisory_id'],'bytes_sha256':occ['sha256'],
                      'evidence_ids':evidence,'scope':'Named vendor version predicate; runtime exploitation unassessed.'}
                lookups['sca'][(view,location,case['advisory_id'])]=node;nodes.append(node);pair.append(oid)
            edges.append({'left':pair[0],'right':pair[1],'relation':'copied_into_image',
                          'equal_occurrence':False,'same_component_advisory':True,
                          'evidence_ids':['sca/image_byte_verification.json','sca/reference_manifest.json']})
    for case in cm['secrets']:
        path=cfg/'reference/scanner-inputs'/case['path'];parsed=inspect_key(path)
        if sha(path)!=case['sha256'] or parsed['public_der_sha256']!=case['key_identity']:
            raise ValueError('Independent key identity mismatch')
        if (parsed['parse_exit_code']==0)!=case['positive']:raise ValueError('Private-material presence mismatch')
        oid='private-occurrence:'+case['path']
        node={'id':oid,'family':'secret','artifact':'source','path':case['path'],
              'object':('key:'+case['key_identity']) if case['positive'] else None,
              'occurrence':oid if case['positive'] else None,'positive':case['positive'],
              'evidence_ids':['configuration/reference/reference_manifest.json',
                              'configuration/reference/scanner-inputs/'+case['path']],
              'scope':'Parseable private material; no registered credential or exposure claim.'}
        lookups['secret'][case['path']]=node;nodes.append(node)
    public=inspect_key(cfg/'reference/scanner-inputs/secrets/s05.pem',public=True)
    if public['public_der_sha256']!=read(cfg/'reference/construction/public-control.json')['public_der_sha256']:
        raise ValueError('Public control changed')
    edges.append({'left':'private-occurrence:secrets/s01.pem','right':'private-occurrence:secrets/s05.pem',
                  'relation':'shares_public_key','equal_private_material':False,
                  'evidence_ids':['configuration/reference/construction/public-control.json']})
    for case in cm['docker']:
        name=case['case_id'].lower();probe=read(cfg/(name+'-probe.stdout'))
        container=read(cfg/(name+'.container.json'))
        if not isinstance(container,dict):raise ValueError('Expected retained container inspect object')
        if sha(cfg/'reference/scanner-inputs'/case['path'])!=case['sha256']:raise ValueError('Docker source changed')
        validate_runtime(case,{'probe':probe},container)
        node={'id':'final-process:'+case['path'],'family':'docker','path':case['path'],
              'positive':probe['uid']==0,'runtime_uid':probe['uid'],
              'evidence_ids':['configuration/'+name+'-probe.stdout','configuration/'+name+'.container.json',
                              'configuration/reference/scanner-inputs/'+case['path']],
              'scope':'Observed default process UID in the bounded isolated probe.'}
        lookups['docker'][case['path']]=node;nodes.append(node)
    return {'nodes':nodes,'edges':edges,'image_check':'Previously recorded export verification, not a fresh image export.'},lookups


def component_locations(package):
    locations=[r['path'] for r in package.get('locations',[]) if r.get('path')]
    for related in package.get('related_dependencies',[]):
        if related.get('isVirtual') or not related.get('sha256') or related['sha256']!=package.get('native_id'):
            raise ValueError('Related dependency lacks matching byte identity')
        if not related.get('filePath'):raise ValueError('Missing related dependency path')
        locations.append(related['filePath'])
    return sorted(set(locations))


def extract_observables(inputs):
    """Read native reports, source context and authority aliases; never oracle labels."""
    authority=[read(p) for p in sorted((inputs/'primary_sources').glob('GHSA-*.json'))]
    aliases=advisory_aliases(authority)
    features=[];excluded=[];contexts=[];reports=[]
    sca=inputs/'sca';cfg=inputs/'configuration'
    for name in ('grype-filesystem','trivy-rootfs','dependency-check','grype-image','trivy-image'):
        tool='dependency-check' if name=='dependency-check' else name.split('-')[0]
        raw=sca/('dependency-check-report/dependency-check-report.json' if name=='dependency-check' else name+'.json')
        phase=read(sca/(name+'.manifest.json'))
        parsed=parse_sca_report(raw,tool,phase['outcome'])
        stored=read(sca/(name+'.normalized.json'))
        if parsed['raw_report_sha256']!=stored['raw_report_sha256'] or parsed['findings']!=stored['findings']:
            raise ValueError('SCA parser replay changed')
        if parsed['effective_status']!='completed':raise ValueError('Incomplete detector condition')
        view='image' if name.endswith('-image') else 'source'
        reports.append({'profile':name,'native_findings':len(parsed['findings']),'raw_sha256':sha(raw)})
        prefixes=['','/'] if tool!='dependency-check' else [
            '<LAB_ROOT>/evidence/sca-development-20260922-01/build-context/scanner-inputs/',
            '<LAB_ROOT>/evidence/sca-development-20260922-02/build-context/scanner-inputs/']
        for finding in parsed['findings']:
            advisory=aliases.get(finding['advisory_id']);purls=finding['package']['purls']
            if advisory is None or len(purls)!=1 or finding['suppressed']:
                excluded.append({'finding_id':finding['finding_id'],'profile':name,'reason':'outside_named_advisories_or_ambiguous_or_suppressed'})
                continue
            locations=component_locations(finding['package'])
            if not locations:raise ValueError('Selected finding has no supported location')
            for path in locations:
                relative=relative_location(path,prefixes)
                features.append({'observation_id':finding['finding_id']+':location:'+fingerprint(relative),
                    'finding_id':finding['finding_id'],'partition':'sca-development-fixed-release','family':'sca',
                    'profile':name,'stage':'image_scan' if view=='image' else 'source_sca',
                    'artifact':view,'path':relative,'purl':purls[0],
                    'reported_advisory':finding['advisory_id'],'canonical_advisory':advisory,
                    'raw_report_sha256':parsed['raw_report_sha256'],'native_locator':finding['native_locator']})
    for name in ('gitleaks','trivy-secret','hadolint','trivy-config'):
        raw=cfg/(name+'.json' if name!='hadolint' else 'hadolint.stdout')
        phase=read(cfg/(name+'.manifest.json'))
        parsed=parse_configuration_report(raw,name,phase['outcome'])
        stored=read(cfg/(name+'.normalized.json'))
        if parsed['findings']!=stored['findings'] or parsed['raw_report_sha256']!=stored['raw_report_sha256']:
            raise ValueError('Configuration parser replay changed')
        if parsed['effective_status']!='completed':raise ValueError('Incomplete detector condition')
        reports.append({'profile':name,'native_findings':len(parsed['findings']),'raw_sha256':sha(raw)})
        family='secret' if name in ('gitleaks','trivy-secret') else 'docker'
        kind='secrets' if family=='secret' else 'docker'
        prefixes=[''] if name.startswith('trivy') else [
            '<LAB_ROOT>/evidence/configuration-development-20260922-01/reference/scanner-inputs/'+kind+'/',
            '<LAB_ROOT>/evidence/configuration-development-20260922-02/reference/scanner-inputs/'+kind+'/']
        for finding in parsed['findings']:
            allowed={'gitleaks':'private-key','trivy-secret':'private-key','hadolint':'DL3002','trivy-config':'DS-0002'}
            if finding['native_rule']!=allowed[name]:
                excluded.append({'finding_id':finding['finding_id'],'profile':name,'reason':'outside_selected_property'});continue
            path=kind+'/'+relative_location(finding['path'],prefixes)
            source=cfg/'reference/scanner-inputs'/path
            row={'observation_id':finding['finding_id'],'finding_id':finding['finding_id'],
                 'partition':family+'-development-fixed-source','family':family,'profile':name,
                 'stage':'secret_scan' if family=='secret' else 'dockerfile_scan',
                 'artifact':'source','path':path,'raw_report_sha256':parsed['raw_report_sha256'],
                 'native_locator':finding['native_locator']}
            if family=='secret':
                row.update(file_sha256=sha(source), public_der_sha256=inspect_key(source)['public_der_sha256'])
                features.append(row)
            else:
                text=source.read_text();start=finding.get('line_start');end=finding.get('line_end')
                scope=stage_scope(text,start,end)
                instructions=docker_instructions(text)
                if scope=='unknown' and sum(x['instruction']=='FROM' for x in instructions)==1:
                    scope='single_stage_rule_without_span'
                row.update(source_scope=scope,native_rule=finding['native_rule'],line=start)
                contexts.append(row)
    return features,contexts,reports,excluded,aliases


def assign_references(features,lookups):
    assignments={}
    for row in features:
        if row['family']=='sca':
            node=lookups['sca'].get((row['artifact'],row['path'],row['canonical_advisory']))
            if node and node['purl']!=row['purl']:raise ValueError('Native component identity disagrees with independent bytes')
        else:node=lookups['secret'].get(row['path'])
        if node is None:
            assignments[row['observation_id']]={'object':None,'occurrence':None,'evidence_ids':[]}
        else:
            assignments[row['observation_id']]={k:node[k] for k in ('object','occurrence','evidence_ids')}
            assignments[row['observation_id']]['reference_id']=node['id']
            assignments[row['observation_id']]['positive']=node['positive']
            # Negative controls never create coverage of affected/material units.
            if not node['positive']:
                assignments[row['observation_id']].update(object=None,occurrence=None)
    return assignments


def run_analysis(inputs,out):
    if out.exists():raise FileExistsError('Preserve existing analysis')
    manifest=verify_inputs(inputs)
    registry,lookups=build_references(inputs)
    features,contexts,reports,excluded,aliases=extract_observables(inputs)
    assignments=assign_references(features,lookups)
    pairs={};effects=[];stages=[]
    for family,methods in [('sca',('component_literal','component_alias','artifact_occurrence')),
                           ('secret',('secret_path','secret_bytes','secret_key'))]:
        selected=[r for r in features if r['family']==family]
        for method in methods:
            for unit in ('object','occurrence'):
                pairs[family+':'+method+':'+unit]=pair_audit(selected,assignments,method,unit)
                effects.append({'family':family,**reporting_effect(selected,assignments,method,unit)})
                if family=='sca':stages.append(stage_effect(selected,assignments,method,unit))
    context_audit=[]
    for row in contexts:
        ref=lookups['docker'][row['path']]
        admissible=row['source_scope'] in ('final_stage','single_stage_rule_without_span')
        context_audit.append({**row,'reference_id':ref['id'],'runtime_uid':ref['runtime_uid'],
            'evidence_ids':ref['evidence_ids'],'file_only_projection_to_final_root_would_agree':ref['positive'],
            'context_aware_projection': 'eligible_for_independent_runtime_check' if admissible else 'abstain_nonfinal_or_ambiguous',
            'scope':'Projection error does not establish that the original native warning is a false positive.'})
    summary={'purpose':'Post-outcome identity and decision development; selected controls only',
        'inputs_manifest_sha256':sha(inputs/'inputs_manifest.json'),
        'source_sha256':sha(Path(__file__)),'reports':reports,
        'reference_nodes':len(registry['nodes']),'reference_edges':len(registry['edges']),
        'observations_by_family':{f:sum(x['family']==f for x in features) for f in ('sca','secret')},
        'selected_native_findings':len({x['finding_id'] for x in features}),
        'excluded_native_findings':len(excluded),'docker_root_observations':len(contexts),
        'pair_counts':{k:v['counts'] for k,v in pairs.items()},'reporting_effects':effects,'stage_effects':stages,
        'docker_file_only_projection_disagreements':sum(not x['file_only_projection_to_final_root_would_agree'] for x in context_audit),
        'docker_context_aware_abstentions':sum(x['context_aware_projection'].startswith('abstain') for x in context_audit),
        'limits':['Constructed controls selected and methods developed after outcome access; no confirmatory inference.',
            'Pairs and artifact copies are dependent, not independent vulnerabilities/applications.',
            'The same component may legitimately be one object and multiple remediation locations.',
            'A member-preserving competent baseline loses no locations in this reporting replay.',
            'Key-object equality is an OpenSSL-backed construction check, not novel cryptographic inference.',
            'Stage effects concern artifact-view coverage; they do not establish runtime risk or stage dispensability.',
            'No LLM, false-positive reduction, real remediation or full-pipeline performance is evaluated.']}
    out.mkdir(parents=True)
    for name,data in [('references',registry),('observables',features),('reference_assignments',assignments),
                      ('pair_audit',pairs),('context_audit',context_audit),('excluded',excluded),
                      ('advisory_aliases',aliases),('analysis',summary)]:write(out/(name+'.json'),data)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=run_analysis(a.inputs,a.output)
    print(json.dumps({k:r[k] for k in ('reference_nodes','reference_edges','observations_by_family','selected_native_findings',
        'excluded_native_findings','docker_root_observations','docker_file_only_projection_disagreements')}))
