#!<PROJECT_ROOT> python3
"""Figure 6: draw the recorded pass-1 class counts and operational matrices.

No decision ledger is opened. The CSV is the only numerical source.
Run: python3 build_fig06.py [path/to/triage_by_class.csv]
"""
from pathlib import Path
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo
from xml.sax.saxutils import escape
import csv
import hashlib
import json
import math
import shutil
import subprocess
import sys

import fitz
from fontTools.ttLib import TTFont
from lxml import etree
from PIL import Image, ImageOps
from figure_style import *

ROOT=Path(__file__).resolve().parent
WORK=ROOT/'working'; WORK.mkdir(exist_ok=True)
INPUT=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'K_tables/triage_by_class.csv'
DIGEST=hashlib.sha256(INPUT.read_bytes()).hexdigest()
ROWS=[]
with INPUT.open(newline='',encoding='utf-8-sig') as stream:
    reader=csv.DictReader(stream)
    for row in reader:
        row['_line']=reader.line_num
        ROWS.append(row)
CONDITIONS=['B0','B1','Q-A','Q-C','G-A','G-C']
ACTIONS=['retain','dismiss','abstain','invalid']
PREFIXES=['true_native','false_native','true_literal']
EXPECTED={
 'B0':[[62,0,0,0],[11,0,0,0],[15,0,0,0]],
 'B1':[[62,0,0,0],[11,0,0,0],[15,0,0,0]],
 'Q-A':[[40,0,22,0],[0,0,11,0],[3,0,12,0]],
 'Q-C':[[57,1,3,1],[9,0,2,0],[0,3,12,0]],
 'G-A':[[54,0,0,8],[11,0,0,0],[15,0,0,0]],
 'G-C':[[54,0,0,8],[11,0,0,0],[15,0,0,0]],
}
assert len(ROWS)==12
assert len({(r['condition'],r['pass_number']) for r in ROWS})==12
PASSES={(r['condition'],r['pass_number']):r for r in ROWS}
P1={c:PASSES[c,'1'] for c in CONDITIONS}
COMPARED=[k for k in ROWS[0] if k not in ['pass_number','_line'] and 'source' not in k]
PAIR_CHECKS=[]
for c in CONDITIONS:
    a,b=PASSES[c,'1'],PASSES[c,'2']
    differences=[k for k in COMPARED if a[k]!=b[k]]
    if differences:
        (ROOT/'QUESTIONS.md').write_text('# Plotting stopped\n\nPass mismatch for '+c+': '+', '.join(differences)+'\n')
        raise SystemExit('Pass values differ; see QUESTIONS.md')
    for prefix,expected,total in zip(PREFIXES,EXPECTED[c],[62,11,15]):
        observed=[int(a[prefix+'_'+k]) for k in ACTIONS]
        assert observed==expected,(c,prefix,observed,expected)
        assert int(a[prefix+'_n'])==total and sum(observed)==total
    assert [a[k] for k in ['Tr','Td','Fr','Fd']]==(['61','1','11','0'] if c=='Q-C' else ['62','0','11','0'])
    assert a['native_n']=='73'
    assert a['class_size_check']=='pass' and a['T5_check']=='match' and a['paired_pass_decisions_identical']=='yes'
    PAIR_CHECKS.append({'condition':c,'pass_1_line':a['_line'],'pass_2_line':b['_line'],
       'identical_value_and_check_fields':COMPARED,
       'differing_provenance_fields':[k for k in a if k not in COMPARED and a[k]!=b[k]]})

def source(conditions):
    return '; '.join(f"K_tables/triage_by_class.csv:{P1[c]['_line']}" for c in conditions)

VALUES=[]
def value(panel,kind,conditions,category,number):
    VALUES.append({'panel':panel,'class_or_matrix':kind,'condition':'; '.join(conditions),
       'category':category,'value':number,'source':source(conditions)})

W,H=WIDTH_PT,426
FONTS={False:TTFont(REGULAR_FONT),True:TTFont(BOLD_FONT)}
BACK,GRID,BARS,LEADERS,TEXTS=[],[],[],[],[]
TEXT_QA=[]; SEGMENTS=[]; MATRIX_CELLS=[]
COLORS={'retain':BLUE,'dismiss':'#E69F00','abstain':'#F0E442','invalid':'#CC79A7'}

def n(x): return f'{float(x):.6f}'.rstrip('0').rstrip('.')
def width(s,size=8,bold=False):
    f=FONTS[bold];cmap=f.getBestCmap()
    return sum(f['hmtx'][cmap[ord(c)]][0] for c in s)*size/f['head'].unitsPerEm
def text(s,x,y,size=8,bold=False,color=INK,anchor='start',id_=None):
    assert size>=MIN_FONT_PT
    w=width(s,size,bold);left=x-w if anchor=='end' else x-w/2 if anchor=='middle' else x
    assert 0<=left and left+w<=W,(s,left,left+w)
    attrs=f' id="{id_}"' if id_ else ''
    TEXTS.append(f'<text{attrs} x="{n(x)}" y="{n(y)}" font-family="{FONT_FAMILY}" font-size="{n(size)}" font-weight="{700 if bold else 400}" fill="{color}" text-anchor="{anchor}">{escape(s)}</text>')
    TEXT_QA.append({'id':id_,'text':s,'x':x,'y':y,'left':left,'right':left+w,'size':size})
def rect(x,y,w,h,fill,stroke='none',sw=.4,layer=BACK,id_=None):
    attrs=f' id="{id_}"' if id_ else ''
    layer.append(f'<rect{attrs} x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}" fill="{fill}" stroke="{stroke}" stroke-width="{n(sw)}"/>')
def line(x1,y1,x2,y2,stroke=GRAY,sw=.5,layer=GRID,id_=None):
    attrs=f' id="{id_}"' if id_ else ''
    layer.append(f'<path{attrs} d="M {n(x1)} {n(y1)} L {n(x2)} {n(y2)}" fill="none" stroke="{stroke}" stroke-width="{n(sw)}"/>')
def action_rect(x,y,w,h,action,id_):
    rect(x,y,w,h,COLORS[action],layer=BARS,id_=id_)
    if action in ['abstain','invalid']:
        rect(x,y,w,h,f'url(#{action}-hatch)',layer=BARS,id_=id_+'-hatch')

text('(a) Decisions by reference class',8,14,size=9,bold=True)
PANELS=[('a1','True native alerts','true_native',40,128,[0,20,40,62],'Alerts'),
        ('a2','False native alerts','false_native',192,126,[0,5,11],'Alerts'),
        ('a3','True declarations','true_literal',343,126,[0,5,10,15],'Declarations')]
YS=[70+28*i for i in range(6)]
for c,y in zip(CONDITIONS,YS): text(c,30,y+2.8,size=8.5,anchor='end',id_='condition-'+c)
for panel,label,prefix,x,w,ticks,axis_label in PANELS:
    total=P1['B0'][prefix+'_n']
    text(f'({panel}) {label}',x+w/2,35,size=8.5,bold=True,anchor='middle',id_=panel+'-title')
    text(f'(n = {total})',x+w/2,47,anchor='middle',id_=panel+'-n')
    value(panel,label,CONDITIONS,'n',total)
    for tick in ticks:
        tx=x+w*tick/int(total)
        line(tx,59,tx,220,stroke='#E0E4E7',sw=.4)
        line(tx,228,tx,231,sw=.6)
        text(str(tick),tx,241,anchor='middle')
    line(x,228,x+w,228,sw=.65)
    text(axis_label,x+w/2,254,size=8.5,anchor='middle')
    for c,y in zip(CONDITIONS,YS):
        r=P1[c]; cumulative=0
        for action in ACTIONS:
            raw=r[prefix+'_'+action]; count=int(raw)
            value(panel,label,[c],action,raw)
            left=x+w*cumulative/int(total); sw=w*count/int(total)
            id_=f'{panel}-{c}-{action}'
            SEGMENTS.append({'panel':panel,'condition':c,'category':action,'value':raw,'x':left,'y':y-7,'w':sw,'h':14,'source':source([c])})
            if count:
                action_rect(left,y-7,sw,14,action,id_)
                if cumulative:
                    line(left,y-7,left,y+7,stroke='#FFFFFF',sw=.45,layer=BARS)
                cx=left+sw/2
                if sw>=width(raw,8.5)+1:
                    if action in ['abstain','invalid']:
                        # A small white box prevents hatching from crossing digits.
                        tw=width(raw,8.5)
                        rect(cx-tw/2-.4,y-4.7,tw+.8,9.5,'#FFFFFF',layer=BARS,id_=id_+'-text-backdrop')
                    text(raw,cx,y+2.9,size=8.5,color='#FFFFFF' if action=='retain' else INK,
                         anchor='middle',id_=id_+'-count')
                else:
                    # The two narrow Q-C cells get separate, short leaders above.
                    assert panel=='a1' and c=='Q-C' and action in ['dismiss','invalid'] and raw=='1'
                    lx=129 if action=='dismiss' else 167
                    anchor='end'
                    leader_x=126 if action=='dismiss' else 164
                    text(raw+' '+action,lx,y-11.5,size=8.5,anchor=anchor,id_=id_+'-count')
                    line(cx,y-7,leader_x,y-8.5,stroke=INK,sw=.4,layer=LEADERS,id_=id_+'-leader')
            cumulative+=count
        assert cumulative==int(total)

# Single panel-a legend, in the same order as every stacked bar.
for action,x in zip(ACTIONS,[104,179,258,338]):
    action_rect(x,266,12,8,action,'legend-'+action)
    rect(x,266,12,8,'none',stroke=GRAY,sw=.35,layer=BARS)
    text(action,x+17,273,size=8.5,id_='legend-'+action+'-label')
line(8,287,W-8,287,stroke='#BBC2C7',sw=.65)

text(f"(b) Operational confusion matrices for native alerts after conservative fallback (n = {P1['B0']['native_n']})",8,305,size=9,bold=True)
value('b','Operational matrices',CONDITIONS,'native_n',P1['B0']['native_n'])
GROUPS=[('B0, B1, Q-A, G-A, G-C',['B0','B1','Q-A','G-A','G-C'],95),('Q-C',['Q-C'],310)]
for title,conditions,x in GROUPS:
    r=P1[conditions[0]]
    for c in conditions:
        assert all(P1[c][key]==r[key] for key in ['Tr','Td','Fr','Fd'])
    text(title,x+75,327,size=8.5,bold=True,anchor='middle')
    text('Kept',x+37.5,344,size=8.5,anchor='middle')
    text('Removed',x+112.5,344,size=8.5,anchor='middle')
    for j,keys in enumerate([['Tr','Td'],['Fr','Fd']]):
        for k,key in enumerate(keys):
            cx=x+k*75;cy=352+j*32
            rect(cx,cy,75,32,'#E8EBED' if k==0 else '#F8F9FA',stroke='#BBC2C7',sw=.4,
                 id_='matrix-'+conditions[0]+'-'+key)
            text(r[key],cx+37.5,cy+21,size=16,anchor='middle',id_='matrix-'+conditions[0]+'-'+key+'-count')
            value('b',title,conditions,key,r[key])
            MATRIX_CELLS.append({'matrix':title,'condition':conditions,'category':key,'value':r[key],
                                 'x':cx,'y':cy,'w':75,'h':32,'source':source(conditions)})
    rect(x+75,352,75,64,'none',stroke=GRAY,sw=.85,id_='matrix-'+conditions[0]+'-removed-outline')
text('True native',8,371,size=8.5)
text('False native',8,403,size=8.5)

with (ROOT/'fig06_values.csv').open('w',newline='',encoding='utf-8') as stream:
    writer=csv.DictWriter(stream,fieldnames=['panel','class_or_matrix','condition','category','value','source'])
    writer.writeheader();writer.writerows(VALUES)
assert len(VALUES)==84

source_svg=ROOT/'fig06_triage_editable.svg'
source_svg.write_text(f'''<svg xmlns="http://www.w3.org/2000/svg" width="170mm" height="{n(H*25.4/72)}mm" viewBox="0 0 {n(W)} {H}">
<title>Local LLM triage: decisions by reference class and operational matrices</title>
<desc>Pass 1 is drawn once after all values and checks match pass 2. Panel a has three separate count axes for 62 true native alerts, 11 false native alerts, and 15 true declarations. Actions are retain, dismiss, abstain, invalid; the latter two are hatched. Panel b copies the recorded operational matrices for 73 native alerts after conservative fallback, excluding declarations.</desc>
<metadata>Only numerical source: K_tables/triage_by_class.csv; SHA-256 {DIGEST}. Every count is copied from a recorded pass-1 field. No operational matrix was recomputed. Source file-line references are in fig06_values.csv.</metadata>
<defs>
<pattern id="abstain-hatch" patternUnits="userSpaceOnUse" width="4" height="4"><path d="M -1 1 L 1 -1 M 0 4 L 4 0 M 3 5 L 5 3" fill="none" stroke="#737A80" stroke-width=".45"/></pattern>
<pattern id="invalid-hatch" patternUnits="userSpaceOnUse" width="5" height="5"><path d="M 0 0 L 5 5 M 5 0 L 0 5" fill="none" stroke="#555D64" stroke-width=".4"/></pattern>
</defs>
<rect width="{n(W)}" height="{H}" fill="#FFFFFF"/>
<g id="backgrounds">{''.join(BACK)}</g>
<g id="axes-and-separators">{''.join(GRID)}</g>
<g id="bars-and-legend">{''.join(BARS)}</g>
<g id="narrow-count-leaders">{''.join(LEADERS)}</g>
<g id="labels">{''.join(TEXTS)}</g>
</svg>''',encoding='utf-8')

for name,options in [
 ('fig06_triage.pdf',['--export-area-page','--export-type=pdf']),
 ('fig06_triage.svg',['--export-text-to-path','--export-plain-svg','--export-type=svg']),
 ('fig06_triage.png',['--export-area-page','--export-dpi=600','--export-type=png'])]:
    temp=WORK/('export-'+name)
    subprocess.run(['inkscape',str(source_svg),*options,'--export-filename='+str(temp)],check=True,capture_output=True)
    if name.endswith('.png'):
        with Image.open(temp) as im: im.load()
    temp.replace(ROOT/name)

doc=fitz.open(ROOT/'fig06_triage.pdf');assert len(doc)==1
page=doc[0]
spans=[s for b in page.get_text('dict')['blocks'] for l in b.get('lines',[]) for s in l['spans']]
assert min(s['size'] for s in spans)>=7.99999
assert all('NimbusSans' in s['font'] for s in spans)
assert not page.get_images()
assert abs(page.rect.width*25.4/72-170)<.001
for s in spans:
    box=fitz.Rect(s['bbox'])
    assert box.x0>=0 and box.y0>=0 and box.x1<=W+.01 and box.y1<=H+.01,s
page.get_pixmap(matrix=fitz.Matrix(3,3),alpha=False).save(WORK/'pdf_review.png')
png=Image.open(ROOT/'fig06_triage.png');png.load()
assert png.width==4016 and all(abs(x-600)<.01 for x in png.info['dpi'])
preview=png.copy();preview.thumbnail((1600,1800));preview.save(ROOT/'fig06_preview.png')
ImageOps.grayscale(preview).save(WORK/'grayscale_review.png')
svg=etree.parse(str(ROOT/'fig06_triage.svg'))
assert not svg.xpath('//*[local-name()="text" or local-name()="image"]')
assert hashlib.sha256(INPUT.read_bytes()).hexdigest()==DIGEST
report={'source_sha256':DIGEST,'pass_comparison':PAIR_CHECKS,'pass_drawn':'1','all_expected_values_match':True,
 'nonzero_bar_segments':sum(int(s['value'])>0 for s in SEGMENTS),'bar_values_including_zeros':len(SEGMENTS),
 'narrow_external_labels':2,'matrix_cells':MATRIX_CELLS,'values_csv_rows':len(VALUES),
 'values_are_copied_not_recomputed':True,'declarations_excluded_from_matrices':True,
 'segments':SEGMENTS,'text_layout':TEXT_QA,'size_mm':[170,H*25.4/72],'png_size':list(png.size),
 'png_dpi':list(png.info['dpi']),'pdf_min_font_pt':min(s['size'] for s in spans),'pdf_raster_images':0,
 'export_time_Paris':datetime.now(ZoneInfo('Europe/Paris')).isoformat(timespec='seconds')}
(WORK/'validation.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ['pass_comparison','segments','text_layout','matrix_cells']},indent=2))
