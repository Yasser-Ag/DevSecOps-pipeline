from pathlib import Path
import subprocess,json,re
import fitz
from PIL import Image,ImageOps
from lxml import etree

ROOT=Path(__file__).resolve().parent.parent
source=ROOT/'fig01_study_design_editable.svg'
for name,options in [
 ('fig01_study_design.pdf',['--export-area-page','--export-type=pdf']),
 ('fig01_study_design.svg',['--export-text-to-path','--export-plain-svg','--export-type=svg']),
 ('fig01_study_design.png',['--export-area-page','--export-dpi=600','--export-type=png'])
]:
 subprocess.run(['inkscape',str(source),*options,'--export-filename='+str(ROOT/name)],check=True,capture_output=True)

doc=fitz.open(ROOT/'fig01_study_design.pdf');pg=doc[0]
assert len(doc)==1
spans=[s for b in pg.get_text('dict')['blocks'] if 'lines' in b for l in b['lines'] for s in l['spans']]
pdf_lines=[''.join(s['text'] for s in l['spans']).strip() for b in pg.get_text('dict')['blocks'] if 'lines' in b for l in b['lines']]
assert not any(s.startswith('·') or s.endswith('·') for s in pdf_lines)
assert any('Red Hat UBI 9' in s.replace('\u00a0',' ') for s in pdf_lines)
assert min(s['size'] for s in spans)>=7.99999
assert all('NimbusSans' in s['font'] for s in spans)
assert not pg.get_images()
assert abs(pg.rect.width/72*25.4-170)<.001
assert abs(pg.rect.height/72*25.4-200)<.001
assert 'RESTler (crAPI only)' in pg.get_text()
assert not re.search(r'\banalysed\b|\bqualified\b|\bRQ\s*\d|\b\d{4}-\d{2}-\d{2}\b',pg.get_text())
pg.get_pixmap(matrix=fitz.Matrix(2.5,2.5),alpha=False).save(ROOT/'working/pdf_review_final.png')

im=Image.open(ROOT/'fig01_study_design.png');im.load()
assert im.size==(4016,4724)
assert all(abs(x-600)<.01 for x in im.info['dpi'])
prev=im.copy();prev.thumbnail((1020,1200));prev.save(ROOT/'fig01_preview.png')
ImageOps.grayscale(prev).save(ROOT/'fig01_grayscale.png')
editable=etree.parse(str(source))
pub=etree.parse(str(ROOT/'fig01_study_design.svg'))
ns='{http://www.w3.org/2000/svg}'
assert not pub.findall('.//'+ns+'image') and not pub.findall('.//'+ns+'text')
qa=json.loads((ROOT/'working/qa_final.json').read_text())
svgtexts={t.attrib['id']:' '.join(''.join(x.itertext()) for x in t) for t in editable.findall('.//'+ns+'text')}
assert len(svgtexts)==len(qa['labels'])
for a in qa['labels']:assert svgtexts[a['id']]==a['exact_label'],a['id']
export_qa={'pdf_pages':1,'pdf_size_mm':[170,200],'pdf_fonts':pg.get_fonts(),'pdf_min_text_pt_raw':min(s['size'] for s in spans),'pdf_min_text_pt_rounded':round(min(s['size'] for s in spans),5),'pdf_raster_images':0,'png_size_px':list(im.size),'png_dpi':list(im.info['dpi']),'publication_svg_outlined':True,'editable_svg_text_labels':len(svgtexts),'exact_xml_label_match':True}
export_qa.update({'no_pdf_line_starts_or_ends_with_middle_dot':True,'red_hat_ubi_9_single_pdf_line':True})
(ROOT/'working/qa_exports.json').write_text(json.dumps(export_qa,indent=2))
print(json.dumps(export_qa,indent=2))
