#!/usr/bin/env python3
"""Re-export recorded values and render the validated editable figure sources.

The builders supply the original CSV export logic. The approved SVGs include
subsequent editorial layout corrections, applied by finalize_labels.py. No
experiment, reference matching, or model inference is executed here.
"""
import argparse,ast,hashlib,json,os,shutil,subprocess,sys,tempfile,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
WORKSPACE=ROOT/'src/figures'
STEMS=['figure01_study_design','figure02_supported_coverage','figure03_grouping','figure04_stage_omission','figure05_execution_cost','figure06_triage_decisions']
EXPORTS=['fig01_study_design','fig02_coverage','fig03_grouping','fig04_omission','fig05_cost','fig06_triage']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rebuild_values(work,output):
    module=types.ModuleType('figure_style');module.__file__=str(work/'figure_style.py')
    sys.modules['figure_style']=module
    exec(compile((work/'figure_style.py').read_text().replace('<PROJECT_ROOT>',str(work)),str(work/'figure_style.py'),'exec'),module.__dict__)
    d=ROOT/'data/derived'
    arguments={2:[d/'reference_populations.csv'],3:[d/'grouping.csv',work/'fig03/study/identity_matching.py',work/'fig03/study/workflow_iac_matching.py'],4:[d/'omissions.csv',d/'reference_populations.csv'],5:[d/'static_profiles.csv',d/'dynamic_profiles.csv'],6:[d/'triage_by_class.csv']}
    checks=[]
    for number,inputs in arguments.items():
        name=f'fig{number:02}';source=work/name/('build_'+name+'.py');text=source.read_text();tree=ast.parse(text)
        # Stop immediately after the original builder writes its value CSV.
        stop=next(node.end_lineno for node in tree.body if isinstance(node,ast.With) and any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='writerows' for n in ast.walk(node)))
        sys.path.insert(0,str(source.parent))
        style_file=source.parent/('fig02_style.py' if number==2 else 'figure_style.py')
        module=types.ModuleType('figure_style');module.__file__=str(style_file)
        exec(compile(style_file.read_text().replace('<PROJECT_ROOT>',str(work)),str(style_file),'exec'),module.__dict__)
        sys.modules['figure_style']=module
        sys.modules['fig02_style']=module
        sys.argv=[str(source),*map(str,inputs)]
        exec(compile('\n'.join(text.splitlines()[:stop])+'\n',str(source),'exec'),{'__name__':'value_export','__file__':str(source)})
        result=source.parent/(name+'_values.csv');validated=WORKSPACE/name/result.name
        if result.read_bytes()!=validated.read_bytes():raise ValueError('Values differ from validated figure: '+name)
        dest=output/(STEMS[number-1]+'_values.csv');shutil.copyfile(result,dest)
        checks.append({'figure':number,'source_files':[str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else 'src/figures/'+str(p.relative_to(work)) for p in inputs], 'sha256':sha(dest),'byte_identical':True})
    return checks

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--values-only',action='store_true');a=p.parse_args()
    if a.output.exists() and any(a.output.iterdir()):p.error('Use an empty output directory')
    font_config=json.loads((ROOT/'config/font_sources.json').read_text())
    for font in font_config['files']:
        path=WORKSPACE/'fonts'/font['file']
        if not path.is_file() or sha(path)!=font['sha256']:
            raise SystemExit('Required Nimbus Sans fonts are missing or differ. Run: python scripts/fetch_fonts.py (or --archive for offline use). No fallback font is allowed.')
    a.output.mkdir(parents=True,exist_ok=True);out=a.output.resolve()
    with tempfile.TemporaryDirectory(prefix='figure_replay_',dir=out) as temporary:
        work=Path(temporary);shutil.copytree(WORKSPACE,work,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__'))
        values=rebuild_values(work,out)
        if not a.values_only:
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            subprocess.run([sys.executable,'render_workspace.py','--figure','all','--output','rendered','--work','render_work'],cwd=work,env=env,check=True)
            for i,(source,dest) in enumerate(zip(EXPORTS,STEMS),1):
                for ext in ['.pdf','.png']:shutil.copyfile(work/'rendered'/(source+ext),out/(dest+ext))
                shutil.copyfile(work/f'fig{i:02}'/(source+'_editable.svg'),out/(dest+'.svg'))
            shutil.copyfile(work/'render_work/export_checks.json',out/'render_checks.json')
    for stem in STEMS:shutil.copyfile(ROOT/'results/figures'/(stem+'_caption.md'),out/(stem+'_caption.md'))
    receipt={'values':values,'figure_1_values':'not applicable: design labels in src/figures/fig01/working/labels_final.json','new_measurements':0,'figures_rendered':0 if a.values_only else 6}
    (out/'figure_verification.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'values_identical':len(values),'figures_rendered':receipt['figures_rendered']}))
if __name__=='__main__':main()
