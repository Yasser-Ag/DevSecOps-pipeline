"""Reproduce the validated release using only packaged inputs.

Copied builder sources remain unchanged except documented path-token redactions.
This adapter resolves <PROJECT_ROOT> in memory, without rewriting any source.
"""
from pathlib import Path
from copy import deepcopy
import argparse
import hashlib
import json
import os
import runpy
import sys
import types
from lxml import etree

sys.dont_write_bytecode = True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--figure', choices=['all']+[f'fig{i:02}' for i in range(1,7)], default='all')
    parser.add_argument('--output', type=Path, default=Path('rendered'))
    parser.add_argument('--work', type=Path, default=Path('render_work'))
    args=parser.parse_args()
    assert Path('finalize_labels.py').is_file(), 'Run from the extracted workspace root.'
    assert not args.output.is_absolute() and not args.work.is_absolute(), 'Use relative output paths.'
    assert '..' not in args.output.parts and '..' not in args.work.parts
    assert args.output.parts[0] not in {'reference','baseline','fonts','fig01','fig02','fig03','fig04','fig05','fig06'}
    os.environ['FONTCONFIG_FILE']='fonts/fonts.conf'
    os.environ['XDG_CACHE_HOME']=str(args.work/'cache')
    module=types.ModuleType('figure_style')
    module.__file__='figure_style.py'
    sys.modules['figure_style']=module
    source=Path('figure_style.py').read_text().replace('<PROJECT_ROOT>', '.')
    exec(compile(source,'figure_style.py','exec'),module.__dict__)
    exports=runpy.run_path('finalize_labels.py',run_name='packaged_export')
    manifest=json.loads(Path('baseline_manifest.json').read_text())
    before={p:exports['digest'](p) for p in Path('.').rglob('*.csv')}
    args.output.mkdir(parents=True,exist_ok=True)
    args.work.mkdir(parents=True,exist_ok=True)
    checks={}
    for number,name in enumerate(exports['NAMES'],1):
        fig=f'fig{number:02}'
        if args.figure not in {'all',fig}:continue
        entry=manifest[fig]
        svg=Path('baseline')/fig/entry['source']
        assert exports['digest'](svg)==entry['source_sha256']
        for path,sha in entry['inputs'].items():assert exports['digest'](Path(fig)/path)==sha
        values=entry['values_file']
        if values:
            a=Path(fig)/values['name']; b=Path('baseline')/fig/values['name']
            assert exports['digest'](a)==values['sha256'] and a.read_bytes()==b.read_bytes()
        old=etree.parse(str(svg)).getroot(); new=deepcopy(old)
        allowed,_=exports['correct_labels'](new,number)
        exports['assert_preserved'](old,new,allowed,number)
        svg_bytes=etree.tostring(new,encoding='UTF-8')
        # Replaying the authorized corrections must reproduce the final editable SVG exactly.
        assert svg_bytes==(Path(fig)/entry['source']).read_bytes()
        generated=args.work/(name+'_editable.svg'); generated.write_bytes(svg_bytes)
        checks[fig]=exports['export_publication'](generated,args.output/name,args.work/fig)
        print(fig,'PASS',flush=True)
    for path,sha in before.items():assert exports['digest'](path)==sha
    (args.work/'export_checks.json').write_text(json.dumps(checks,indent=2)+'\n')

if __name__=='__main__':main()
