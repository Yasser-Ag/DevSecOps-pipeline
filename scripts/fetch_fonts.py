#!/usr/bin/env python3
"""Fetch the fixed URW font release; verify the archive and every font byte."""
import argparse,hashlib,json,tarfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,help='Use a previously downloaded archive without networking');a=p.parse_args()
 c=json.loads((ROOT/'config/font_sources.json').read_text());cache=ROOT/'.source_cache/fonts';cache.mkdir(parents=True,exist_ok=True)
 archive=a.archive or cache/'urw_base35_source.tar.gz'
 if a.archive is None and not archive.exists():
  with urllib.request.urlopen(c['source_archive_url'],timeout=60) as r:archive.write_bytes(r.read())
 if sha(archive.read_bytes())!=c['source_archive_sha256']:raise SystemExit('Font source archive SHA-256 mismatch; no font was installed.')
 staged=[]
 with tarfile.open(archive) as t:
  for f in c['files']:
   data=t.extractfile(f['member']).read()
   if sha(data)!=f['sha256']:raise SystemExit('Font SHA-256 mismatch: '+f['file'])
   staged.append((f['file'],data))
 for name,data in staged:(ROOT/'src/figures/fonts'/name).write_bytes(data)
 print('Verified URW base35 release '+c['release']+'; both Nimbus Sans fonts are ready.')
if __name__=='__main__':main()
