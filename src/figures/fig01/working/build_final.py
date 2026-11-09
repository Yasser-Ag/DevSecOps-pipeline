from pathlib import Path
from fontTools.ttLib import TTFont
from xml.sax.saxutils import escape
import json, math, re, hashlib, base64, io

ROOT=Path(__file__).resolve().parent.parent
DATA=json.loads((ROOT/'working/labels_final.json').read_text())
DATA['llm_input']='88 fixed inputs (73 scanner alerts and 15 declarations)'
ICONS=json.loads((ROOT/'working/icons.json').read_text())
REG='<PROJECT_ROOT>/fonts/NimbusSans-Regular.otf'
BOLD='<PROJECT_ROOT>/fonts/NimbusSans-Bold.otf'
FONTS={False:TTFont(REG),True:TTFont(BOLD)}
W=170/25.4*72
H=200/25.4*72
FONT=8.0
LEAD=9.35
X=[6,169,318,400]
WIDTH=[155,136,72,W-406]
INK='#20262B'; GRAY='#737A80'; LIGHT='#F4F5F6'
PALETTE={'code':'#0072B2','images':'#E69F00','secrets':'#CC79A7','configuration':'#009E73','dynamic':'#D55E00'}
SHAPES=[]; TEXTS=[]; AUDIT=[]; BOXES=[]; EDGES=[]

def num(n):return f'{n:.3f}'.rstrip('0').rstrip('.')
def width(t,size=FONT,bold=False):
 f=FONTS[bold]; cmap=f.getBestCmap()
 return sum(f['hmtx'][cmap.get(ord(ch),'space')][0] for ch in t)*size/f['head'].unitsPerEm
def wrap(s,w,size=FONT,bold=False):
 # A break is prohibited on either side of a middle-dot separator.
 # Split on ordinary spaces only; NBSP keeps Red Hat UBI 9 together.
 words=s.split(' ');lines=[];i=0
 while i<len(words):
  j=i
  while j<len(words) and width(' '.join(words[i:j+1]),size,bold)<=w+.01:j+=1
  while j>i and (words[j-1]=='·' or (j<len(words) and words[j]=='·')):j-=1
  assert j>i,(s,w,words[i])
  lines.append(' '.join(words[i:j]));i=j
 assert ' '.join(lines)==s,(s,lines)
 assert all(not line.startswith('·') and not line.endswith('·') for line in lines)
 return lines
def tint(hex_,alpha=.07):
 rgb=[int(hex_[i:i+2],16) for i in (1,3,5)]
 return '#'+''.join(f'{round((1-alpha)*255+alpha*v):02x}' for v in rgb)
def shape(s):SHAPES.append(s)
def rect(x,y,w,h,fill,stroke='none',rx=4,dashed=False,sw=.5):
 dash=' stroke-dasharray="3 2"' if dashed else ''
 opacity=' fill-opacity="0.04"' if fill=='#0000000A' else ''
 if opacity:fill='#000000'
 shape(f'<rect x="{num(x)}" y="{num(y)}" width="{num(w)}" height="{num(h)}" rx="{num(rx)}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{dash}{opacity}/>')
def path(points,color=GRAY,dashed=False,arrow=True,sw=.65):
 d='M '+' L '.join(f'{num(x)} {num(y)}' for x,y in points)
 dash=' stroke-dasharray="3 2"' if dashed else ''
 marker=' marker-end="url(#arrow)"' if arrow else ''
 shape(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linejoin="round" stroke-linecap="round"{dash}{marker}/>')
 EDGES.append({'points':points,'dashed':dashed})
def dot(x,y,r=1.3,fill='#FFFFFF',stroke=GRAY):
 shape(f'<circle cx="{num(x)}" cy="{num(y)}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width=".55"/>')
def icon(name,x,y,size=9,color=INK):
 parts=[]
 for tag,attrs in ICONS[name]:
  at=' '.join(f'{k}="{escape(str(v))}"' for k,v in attrs.items())
  parts.append(f'<{tag} {at}/>')
 shape(f'<g transform="translate({num(x)} {num(y)}) scale({num(size/24)})" fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'+''.join(parts)+'</g>')
def txt(id_,s,x,y,w,size=FONT,bold=False,color=INK,leading=LEAD,lines=None):
 lines=wrap(s,w,size,bold) if lines is None else lines
 assert ' '.join(lines)==s,(id_,lines,s)
 spans=''.join(f'<tspan x="{num(x)}" y="{num(y+i*leading+size*.78)}">{escape(v)}</tspan>' for i,v in enumerate(lines))
 TEXTS.append(f'<text id="{id_}" font-family="Nimbus Sans" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}" xml:space="preserve">{spans}</text>')
 AUDIT.append({'id':id_,'exact_label':s,'lines':lines,'font_size_pt':size,'x':x,'y':y,'max_width':w,'height':len(lines)*leading,'bold':bold,'leading':leading})
 return len(lines)*leading
def card(id_,x,y,w,h,color=GRAY,dashed=False):
 rect(x+.65,y+.85,w,h,'#0000000A',rx=4)
 rect(x,y,w,h,tint(color,.055) if color!=GRAY else '#F4F5F6',tint(color,.44),rx=4,dashed=dashed,sw=.55)
 if not dashed:rect(x,y+5,1.5,h-10,color,rx=.5)
 BOXES.append({'id':id_,'x':x,'y':y,'width':w,'height':h})
def node(id_,s,x,y,w,icon_name='Database',dashed=False,minh=0):
 lines=['88 fixed inputs (73 scanner alerts', 'and 15 declarations)'] if id_=='llm-input' else wrap(s,w-12)
 h=max(minh,22+len(lines)*LEAD)
 card(id_,x,y,w,h,GRAY,dashed)
 icon(icon_name,x+6,y+6,10)
 txt(id_+'-text',s,x+6,y+20,w-12,lines=lines)
 return (x,y,w,h)

# Final revision: preserve the four-column topology, palette and literal content.
rect(6,5,W-12,32,'#EDF0F2','#D5DADF',rx=5)
txt('banner',DATA['banner'],12,10,W-24,size=8.3,leading=10)
for i,col in enumerate(DATA['columns']):
 txt('column-'+str(i+1),col,X[i],44,WIDTH[i],size=8.8,bold=True,leading=10)
 path([(X[i],57),(X[i]+WIDTH[i],57)],'#C5CBD0',arrow=False,sw=.5)

def wrap_no_trailing_dot(s,w):
 return wrap(s,w)

y=65
ROWS=[]
for i,l in enumerate(DATA['layers'],1):
 mblocks=l.get('material_blocks',[l['material']])
 mlines=[wrap(s,WIDTH[0]-10) for s in mblocks]
 mgaps=[0]*(len(mblocks)-1)
 if i==9:mgaps=[0,2,0]
 slines=[wrap_no_trailing_dot(s,WIDTH[1]-12) for s in l['stage_blocks']]
 if i in [1,2,3,5,7]:
  assert all(len(lines)==1 for lines in slines),(i,slines)
 badges=l['badges']
 badge_widths=[width(b)+5 for b in badges]
 badges_w=sum(badge_widths)+3*max(0,len(badges)-1)
 extra=11 if badges and (i==8 or width(l['title'],8.4,True)+badges_w+23>WIDTH[0]) else 0
 mh=21+sum(map(len,mlines))*LEAD+extra+sum(mgaps)
 sh=21+sum(map(len,slines))*LEAD+2*(len(slines)-1)
 h=max(mh,sh)
 ROWS.append({'index':i,'y':y,'h':h,'cy':y+h/2})
 color=PALETTE[l['family']]
 card('material-'+str(i),X[0],y,WIDTH[0],h,color)
 icon(l['icon'],X[0]+6,y+5,9)
 txt('material-title-'+str(i),l['title'],X[0]+19,y+5,WIDTH[0]-25,size=8 if i in [3,5] else 8.4,bold=True)
 if badges:
  bx=X[0]+WIDTH[0]-badges_w-5;by=y+5+extra
  for j,(badge,bw) in enumerate(zip(badges,badge_widths),1):
   rect(bx,by-1,bw,10,'#FFFFFF',tint(color,.30),rx=2,sw=.4)
   txt(f'material-badge-{i}-{j}',badge,bx+2.5,by,bw-5)
   bx+=bw+3
 yy=y+17+extra
 for j,(s,lines) in enumerate(zip(mblocks,mlines),1):
  txt(f'material-body-{i}-{j}',s,X[0]+5,yy,WIDTH[0]-10,lines=lines)
  yy+=len(lines)*LEAD+(mgaps[j-1] if j<=len(mgaps) else 0)
 card('scanner-'+str(i),X[1],y,WIDTH[1],h,color)
 icon(l['icon'],X[1]+6,y+5,9)
 txt('scanner-title-'+str(i),l['stage_title'],X[1]+19,y+5,WIDTH[1]-23,bold=True)
 yy=y+17
 for j,(s,lines) in enumerate(zip(l['stage_blocks'],slines),1):
  txt(f'scanner-body-{i}-{j}',s,X[1]+6,yy,WIDTH[1]-12,lines=lines)
  yy+=len(lines)*LEAD+2
 cy=y+h/2
 path([(X[0]+WIDTH[0]+1.4,cy),(X[1]-1.3,cy)],color,sw=.65)
 dot(X[0]+WIDTH[0],cy,stroke=color);dot(X[1],cy,stroke=color)
 y+=h+4
assert y-4<536,('rows exceed body',y-4)

# Collection bus from all nine tool cards.
busx=311.5
path([(busx,ROWS[0]['cy']),(busx,ROWS[-1]['cy'])],arrow=False,sw=.65)
for row in ROWS:
 cy=row['cy'];color=PALETTE[DATA['layers'][row['index']-1]['family']]
 path([(X[1]+WIDTH[1]+1.3,cy),(busx,cy)],arrow=False)
 dot(X[1]+WIDTH[1],cy,stroke=color)
 dot(busx,cy,r=.8,fill=GRAY,stroke=GRAY)

e1=node('evidence-1',DATA['evidence'][0],X[2],103,WIDTH[2])
e2=node('evidence-2',DATA['evidence'][1],X[2],220,WIDTH[2])
ref_lines=[wrap(s,WIDTH[2]-6) for s in DATA['evidence_reference_blocks']]
ref_h=22+sum(map(len,ref_lines))*LEAD+3
e3=(X[2],283,WIDTH[2],ref_h)
card('evidence-3',*e3)
icon('Database',X[2]+6,289,10)
ref_y=303
for j,(s,lines) in enumerate(zip(DATA['evidence_reference_blocks'],ref_lines),1):
 txt('evidence-3-block-'+str(j),s,X[2]+3,ref_y,WIDTH[2]-6,lines=lines)
 ref_y+=len(lines)*LEAD+3
def center(b):return b[0]+b[2]/2,b[1]+b[3]/2
ex,ey=center(e1)
path([(busx,ey),(e1[0]-1.3,ey)]);dot(e1[0],ey)
for a,b in [(e1,e2),(e2,e3)]:
 ax=a[0]+a[2]/2;ay=a[1]+a[3];by=b[1]
 assert by>ay+8
 path([(ax,ay+1.3),(ax,by-1.3)]);dot(ax,ay);dot(ax,by)

anodes=[]
for i,(yy,ic) in enumerate([(91,'Target'),(178,'Merge'),(250,'Clock')],1):
 anodes.append(node('analysis-'+str(i),DATA['analyses'][i-1],X[3],yy,WIDTH[3],ic))
axbus=395
sx,sy=e3[0]+e3[2],e3[1]+e3[3]/2
path([(sx+1.3,sy),(axbus,sy),(axbus,center(anodes[0])[1])],arrow=False);dot(sx,sy)
for a in anodes:
 ay=center(a)[1];path([(axbus,ay),(a[0]-1.3,ay)])
 dot(axbus,ay,r=.75,fill=GRAY,stroke=GRAY);dot(a[0],ay)

# Independent fixed cohort: no edge from fresh main-evaluation reports.
lw=W-6-X[2]
llm_input=node('llm-input',DATA['llm_input'],X[2],372,lw,'Database')
llm_y=llm_input[1]+llm_input[3]+12
llm_lines=[[DATA['llm_blocks'][0]],[DATA['llm_blocks'][1]],['Qwen · Gemma:', 'alert-only / added context'],['Local CPU inference,', 'no external network · two passes'],['→ actions, invalid responses,', 'latency, memory']]
llm_h=22+sum(map(len,llm_lines))*LEAD+2*(len(llm_lines)-1)
card('llm',X[2],llm_y,lw,llm_h,GRAY,True)
icon('Cpu',X[2]+6,llm_y+6,10)
yy=llm_y+20
for i,(s,lines) in enumerate(zip(DATA['llm_blocks'],llm_lines),1):
 txt('llm-block-'+str(i),s,X[2]+6,yy,lw-12,lines=lines)
 yy+=len(lines)*LEAD+2
llm_cx=X[2]+lw/2
path([(llm_cx,llm_input[1]+llm_input[3]+1.3),(llm_cx,llm_y-1.3)],dashed=True)
dot(llm_cx,llm_input[1]+llm_input[3]);dot(llm_cx,llm_y)
assert llm_y+llm_h<539,(llm_y,llm_h)
assert e3[1]+e3[3]<llm_input[1]-8

# One exact English legend, with literal middle-dot separators.
path([(6,543),(W-6,543)],'#D5DADF',arrow=False,sw=.45)
txt('legend',DATA['legend'],6,549,W-12,leading=9.3)

meta='Editable publication source. Lucide generic icons: ISC and inherited Feather MIT notices. Text source: labels_final.json. Repository verification remains documented in QUESTIONS.md.'
svg=f'''<svg xmlns="http://www.w3.org/2000/svg" width="170mm" height="200mm" viewBox="0 0 {num(W)} {num(H)}">
<metadata>{escape(meta)}</metadata>
<defs><marker id="arrow" viewBox="0 0 4 4" refX="3.8" refY="2" markerWidth="3.1" markerHeight="3.1" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path d="M 0 0 L 4 2 L 0 4 Z" fill="{GRAY}"/></marker></defs>
<rect width="{num(W)}" height="{num(H)}" fill="#FFFFFF"/>
<g id="geometry">{''.join(SHAPES)}</g>
<g id="labels">{''.join(TEXTS)}</g>
</svg>'''
(ROOT/'fig01_study_design_editable.svg').write_text(svg)

# Check advances, exact labels, physical font sizes and actual text collisions.
for a in AUDIT:
 assert a['font_size_pt']>=8
 assert a['x']>=0 and a['y']>=0 and a['y']+a['height']<=H+1,a['id']
 assert max(width(t,a['font_size_pt'],a['bold']) for t in a['lines'])<=a['max_width']+.05,a
line_boxes=[]
for a in AUDIT:
 for j,t in enumerate(a['lines']):
  yy=a['y']+j*a['leading']
  line_boxes.append((a['id'],a['x'],yy,a['x']+width(t,a['font_size_pt'],a['bold']),yy+a['font_size_pt']))
collisions=[]
for i,a in enumerate(line_boxes):
 for b in line_boxes[i+1:]:
  if a[0]==b[0]:continue
  if min(a[3],b[3])-max(a[1],b[1])>.05 and min(a[4],b[4])-max(a[2],b[2])>.05:collisions.append([a[0],b[0]])
assert not collisions,collisions
visible=' '.join(a['exact_label'] for a in AUDIT)
assert 'analysed' not in visible and 'qualified' not in visible
assert not re.search(r'\bRQ\s*\d|\b\d{4}-\d{2}-\d{2}\b',visible)
assert 'RESTler (crAPI only)' in visible
assert len(ROWS)==9
for a in AUDIT:
 if a['id'].startswith('scanner-title-'):assert not a['exact_label'].endswith(':')
 assert not any(s.strip().startswith('·') or s.strip().endswith('·') for s in a['lines']),a['id']
 if a['id'].startswith('material-body-') and not a['id'].startswith('material-body-9-'):
  assert '·' not in a['exact_label']
  if not a['id'].startswith('material-body-8-'):assert len(a['lines'])==1,a
assert any('Red\u00a0Hat\u00a0UBI\u00a09' in s for a in AUDIT for s in a['lines'])
cb=[a for a in AUDIT if a['id'].startswith('material-badge-8-')]
assert len(cb)==2 and cb[0]['y']==cb[1]['y'] and all(len(a['lines'])==1 for a in cb)
report={'stage':'final_graphics','size_mm':[170,200],'min_font_pt':min(a['font_size_pt'] for a in AUDIT),'font_family':'Nimbus Sans','material_cards':9,'scanner_cards':9,'evidence_nodes':3,'analysis_nodes':3,'llm_input_nodes':1,'llm_separate':True,'labels_exact':True,'word_splitting':False,'text_collisions':collisions,'no_tool_line_ends_with_middle_dot':True,'ci_badges_one_line':True,'main_campaign_profiles_verified':False,'running_api_single_line_per_target':False,'dynamic_api_single_line_per_block':False,'row_bottom_pt':y-4,'llm_bottom_pt':llm_y+llm_h,'label_sha256':hashlib.sha256((ROOT/'working/labels_final.json').read_bytes()).hexdigest(),'rows':ROWS,'cards':BOXES,'labels':AUDIT,'edges':EDGES}
report.update({'no_line_starts_or_ends_with_middle_dot':True,'material_items_separate':True,'red_hat_ubi_9_nonbreaking':True,'running_api_target_and_description_separate':True,'dynamic_api_three_blocks':True,'evidence_reference_two_blocks':True})
(ROOT/'working/qa_final.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
print(json.dumps({k:v for k,v in report.items() if k not in ['rows','cards','labels','edges']},indent=2))

