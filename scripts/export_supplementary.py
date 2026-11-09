#!/usr/bin/env python3
"""Write and verify the supplementary workbook without changing CSV cell values."""
import argparse,csv,hashlib,json,re,zipfile
from decimal import Decimal,InvalidOperation
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
NS='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
REL='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
PKG='http://schemas.openxmlformats.org/package/2006/relationships'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def column(i):
 s=''
 while i:i,r=divmod(i-1,26);s=chr(65+r)+s
 return s
def numeric(text):
 if not re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?',text.strip()):return False
 try:return Decimal(text).is_finite()
 except InvalidOperation:return False
def xml(element):return ET.tostring(element,encoding='utf-8',xml_declaration=True)
def datasets():
 titles=json.loads((ROOT/'config/supplementary_titles.json').read_text());out=[];index=[]
 for i,title in enumerate(titles,1):
  files=list((ROOT/'results/supplementary').glob(f'S{i}_*.csv'));assert len(files)==1
  p=files[0];rows=list(csv.reader(p.open(newline='')));data=[[title],*rows]
  out.append((f'S{i}',data,2));index.append([f'S{i}',str(p.relative_to(ROOT)),sha(p)])
 out.append(('README',[['Sheet','Source CSV','SHA-256'],*index],len(index)+1))
 return out

def export(output):
 content=ET.Element('Types',xmlns='http://schemas.openxmlformats.org/package/2006/content-types')
 for ext,t in [('rels','application/vnd.openxmlformats-package.relationships+xml'),('xml','application/xml')]:ET.SubElement(content,'Default',Extension=ext,ContentType=t)
 ET.SubElement(content,'Override',PartName='/xl/workbook.xml',ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml')
 workbook=ET.Element('workbook',xmlns=NS);sheets=ET.SubElement(workbook,'sheets');rels=ET.Element('Relationships',xmlns=PKG);rootrel=ET.Element('Relationships',xmlns=PKG)
 ET.SubElement(rootrel,'Relationship',Id='rId1',Type=REL+'/officeDocument',Target='xl/workbook.xml')
 entries={};counts=[]
 for i,(name,data,text_rows) in enumerate(datasets(),1):
  ET.SubElement(sheets,'sheet',name=name,sheetId=str(i),attrib={'{'+REL+'}id':f'rId{i}'})
  ET.SubElement(rels,'Relationship',Id=f'rId{i}',Type=REL+'/worksheet',Target=f'worksheets/sheet{i}.xml')
  ET.SubElement(content,'Override',PartName=f'/xl/worksheets/sheet{i}.xml',ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml')
  sheet=ET.Element('worksheet',xmlns=NS);sd=ET.SubElement(sheet,'sheetData');numbers=0;precision=0;cells=0
  for j,row in enumerate(data,1):
   xrow=ET.SubElement(sd,'row',r=str(j))
   for k,value in enumerate(row,1):
    if len(value)>32767:raise ValueError(f'Excel cell limit exceeded at {name}!{column(k)}{j}')
    isnum=j>text_rows and numeric(value);cell=ET.SubElement(xrow,'c',r=column(k)+str(j),t='n' if isnum else 'inlineStr');cells+=1
    if isnum:
     ET.SubElement(cell,'v').text=value;numbers+=1;precision+=len(Decimal(value).as_tuple().digits)>15
    else:
     t=ET.SubElement(ET.SubElement(cell,'is'),'t',{'{http://www.w3.org/XML/1998/namespace}space':'preserve'});t.text=value
  entries[f'xl/worksheets/sheet{i}.xml']=xml(sheet)
  counts.append({'sheet':name,'rows':len(data),'cells':cells,'numeric_cells':numbers,'numeric_cells_over_15_significant_digits':precision})
 entries.update({'[Content_Types].xml':xml(content),'_rels/.rels':xml(rootrel),'xl/workbook.xml':xml(workbook),'xl/_rels/workbook.xml.rels':xml(rels)})
 output.parent.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for name,data in entries.items():
   info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
 return counts

def verify(path):
 checked=0
 with zipfile.ZipFile(path) as z:
  for i,(name,data,text_rows) in enumerate(datasets(),1):
   root=ET.fromstring(z.read(f'xl/worksheets/sheet{i}.xml'));rows=root.findall('.//{'+NS+'}row');assert len(rows)==len(data)
   for j,(observed,expected) in enumerate(zip(rows,data),1):
    cells=list(observed);assert len(cells)==len(expected)
    for cell,value in zip(cells,expected):
     isnum=j>text_rows and numeric(value);assert cell.find('{'+NS+'}f') is None
     if isnum:
      assert cell.get('t')=='n';recorded=cell.find('{'+NS+'}v').text;assert recorded==value and Decimal(recorded)==Decimal(value)
     else:assert cell.get('t')=='inlineStr' and (cell.find('{'+NS+'}is/{'+NS+'}t').text or '')==value
     checked+=1
 return {'cell_by_cell_exact':True,'cells_checked':checked,'formulas':0,'rounding_in_file':False,'numeric_storage':'original CSV decimal text in numeric OOXML cells; spreadsheet software may display fewer digits'}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
 counts=export(a.output);r={'sheets':counts,**verify(a.output),'sha256':sha(a.output)};a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='sheets'}))
if __name__=='__main__':main()
