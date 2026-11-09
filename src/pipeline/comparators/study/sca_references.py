"""Create bounded development references from release bytes and vendor advisories."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

SELECTION = [
    ('org.apache.logging.log4j','log4j-core','2.14.1','CVE-2021-44228',True,'log4j'),
    ('org.apache.logging.log4j','log4j-core','2.17.1','CVE-2021-44228',False,'log4j'),
    ('org.apache.logging.log4j','log4j-api','2.14.1','CVE-2021-44228',False,'log4j'),
    ('org.apache.commons','commons-text','1.9','CVE-2022-42889',True,'commons-text'),
    ('org.apache.commons','commons-text','1.10.0','CVE-2022-42889',False,'commons-text'),
]
SOURCES = {'log4j': 'https://logging.apache.org/security.html#CVE-2021-44228',
           'commons-text': 'https://commons.apache.org/proper/commons-text/security.html'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inspect_jar(path, group, artifact, version):
    """Check exact release identity, independently of scanner metadata."""
    locator = f'META-INF/maven/{group}/{artifact}/pom.properties'
    with zipfile.ZipFile(path) as jar:
        text = jar.read(locator).decode('utf-8')
        values = {}
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith(('#','!')):
                continue
            key, value = line.split('=',1)
            if key in values:
                raise ValueError('Duplicate release property')
            values[key] = value
        if values != {'groupId':group,'artifactId':artifact,'version':version}:
            raise ValueError('Embedded release coordinates disagree')
        licenses = [n for n in jar.namelist() if n.upper().startswith('META-INF/LICENSE')]
        if not licenses:
            raise ValueError('License entry missing')
        return {'coordinates': values, 'pom_properties_entry': locator,
                'pom_properties_sha256': hashlib.sha256(text.encode()).hexdigest(),
                'license_entries': licenses}


def prepare(inputs, output):
    output.mkdir(parents=True,exist_ok=False)
    fixtures = output/'scanner-inputs'; fixtures.mkdir()
    cases, occurrences, sources = [], [], {}
    shutil.copytree(inputs/'vendor_sources',output/'vendor_sources')
    for name, url in SOURCES.items():
        path = inputs/'vendor_sources'/f'{name}-security.html'
        sources[name] = {'url': url, 'retained_path': f'vendor_sources/{name}-security.html', 'sha256':sha(path)}
    for group, name, version, cve, affected, vendor in SELECTION:
        filename=f'{name}-{version}.jar';path=inputs/'artifacts'/filename
        checksum=Path(str(path)+'.sha1')
        if hashlib.sha1(path.read_bytes()).hexdigest()!=checksum.read_text().strip().split()[0]:
            raise ValueError('Upstream checksum mismatch')
        release=inspect_jar(path,group,name,version)
        purl=f'pkg:maven/{group}/{name}@{version}'
        cases.append({'case_id':f'{name}-{version}:{cve}', 'purl':purl,'advisory_id':cve,
            'advisory_version_affected':affected,'unit':'component_version_for_named_advisory',
            'runtime_exploitability':'not_assessed','other_advisories':'unadjudicated',
            'source':sources[vendor], 'source_rule':
                'Log4j core affected interval includes 2.14.1; 2.17.1 is outside it; log4j-api alone is not affected.' if vendor=='log4j' else
                'Commons Text 1.9 is within the pre-1.10.0 affected version scope; 1.10.0 changes unsafe defaults. Exploitability requires unsafe untrusted interpolation.',
            'artifact_sha256':sha(path),'release_identity':release,
            'release_url':f'https://repo.maven.apache.org/maven2/{group.replace(".","/")}/{name}/{version}/{filename}',
            'upstream_sha1':checksum.read_text().strip().split()[0],
            'identity_limit':'HTTPS release bytes and published checksum agreement; no detached signature verification.',
            'scanner_used_as_oracle':False})
        paths=['lib/'+filename]
        if name=='log4j-core' and version=='2.14.1':paths.append('mirror/'+filename)
        for relative in paths:
            dest=fixtures/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
            occurrences.append({'occurrence_id':relative, 'purl':purl,'sha256':sha(dest),
                'bytes':dest.stat().st_size,'image_path':'opt/sca-inputs/'+relative})
    manifest={'recorded_before_new_scans_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'purpose':'development_reference_selection','selection':'Two well-documented Java advisories with affected/fixed/component-negative controls; one duplicate byte-identical location.',
        'prior_outcome_access':'Log4j 2.14.1 Dependency-Check interface result and other installation reports were previously inspected. This is development, not blind final testing.',
        'cases':cases,'occurrences':occurrences,'vendor_sources':sources,
        'limits':['Five component/advisory predicates, six file occurrences, two planned artifact views; these are not independent applications.',
                  'Negative labels are specific to the named advisory, not all vulnerabilities.',
                  'No dependency closure or running application is claimed. No exploit is executed.']}
    (output/'reference_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();m=prepare(a.inputs,a.output);print(json.dumps({'cases':len(m['cases']),'occurrences':len(m['occurrences'])}))
