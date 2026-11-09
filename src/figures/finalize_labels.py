#!<PROJECT_ROOT> python3
"""Apply final presentation corrections to validated SVG exports.

No CSV is written, parsed into numerical values, or used to recompute a drawing.
The frozen SVG supplies every bar, marker, range, number and coordinate.
Use --baseline for the validated exports and --project for the original inputs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
from copy import deepcopy
from lxml import etree
import fitz
from figure_style import export_publication, text_width

NAMES = ['fig01_study_design', 'fig02_coverage', 'fig03_grouping',
         'fig04_omission', 'fig05_cost', 'fig06_triage']

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def element(root, id_):
    found = root.xpath('//*[@id=$id]', id=id_)
    assert len(found) == 1, id_
    return found[0]

def correct_labels(root, number):
    allowed, replacements = set(), []
    if number == 1:
        label = element(root, 'llm-input-text')
        assert ' '.join(label.itertext()) == '88 fixed inputs (scanner observations selected before the main evaluation)'
        lines = ['88 fixed inputs (73 scanner alerts', 'and 15 declarations)']
        assert float(label.get('font-size')) == 8 and len(label) == 2
        assert all(text_width(line) <= 145.89 for line in lines)
        for span, line in zip(label, lines):
            span.text = line
            allowed.add(root.getroottree().getpath(span))
    elif number == 3:
        for y, old, new in [('270', 'Component', 'Reported'), ('280', 'name', 'identifier')]:
            found = root.xpath('//*[local-name()="text" and @x="46.5494" and @y=$y]', y=y)
            assert len(found) == 1 and found[0].text == old
            found[0].text = new
            allowed.add(root.getroottree().getpath(found[0]))
    elif number == 4:
        for row in range(1, 15):
            label = element(root, f'row-{row}-label-1')
            old = label.text
            assert old.count(' \u2014 ') == 1
            label.text = old.replace(' \u2014 ', ': ')
            replacements.append({'row': row, 'before': old, 'after': label.text})
            allowed.add(root.getroottree().getpath(label))
    elif number == 6:
        for action, x, end_x in [('dismiss', '129', '126'), ('invalid', '167', '164')]:
            label = element(root, f'a1-Q-C-{action}-count')
            assert label.text == '1 '+action
            label.set('x', x)
            label.set('text-anchor', 'end')
            allowed.add(root.getroottree().getpath(label))
            leader = element(root, f'a1-Q-C-{action}-leader')
            start = leader.get('d').split(' L ')[0]
            leader.set('d', start + ' L ' + end_x + ' 145.5')
            allowed.add(root.getroottree().getpath(leader))
    return allowed, replacements

def assert_preserved(before, after, allowed, number):
    old, new = list(before.iter()), list(after.iter())
    assert len(old) == len(new), 'Added or removed SVG elements'
    changed = []
    for a, b in zip(old, new):
        assert a.tag == b.tag
        if (dict(a.attrib), a.text, a.tail) != (dict(b.attrib), b.text, b.tail):
            path = after.getroottree().getpath(b)
            assert path in allowed, (number, path)
            changed.append(path)
        if number != 1 and a.text:
            assert re.findall(r'\d+(?:\.\d+)?', a.text) == re.findall(r'\d+(?:\.\d+)?', b.text or '')
    assert set(changed) == allowed
    assert all('\u2014' not in ''.join(t.itertext()) for t in after.xpath('//*[local-name()="text"]'))
    # Range en dashes and the not-eligible symbol must stay exactly as recorded.
    assert sum((t.text or '').count('\u2013') for t in old) == sum((t.text or '').count('\u2013') for t in new)
    return changed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    checks = {}
    for number, name in enumerate(NAMES, 1):
        fig = f'fig{number:02}'
        baseline = args.baseline / fig / (name+'_editable.svg')
        assert digest(baseline) == manifest[fig]['source_sha256']
        for path, expected in manifest[fig]['inputs'].items():
            assert digest(args.project/fig/path) == expected
        value = manifest[fig]['values_file']
        if value:
            assert digest(args.project/fig/value['name']) == value['sha256']
            assert (args.project/fig/value['name']).read_bytes() == (args.baseline/fig/value['name']).read_bytes()
        before = etree.parse(str(baseline)).getroot()
        after = deepcopy(before)
        allowed, replacements = correct_labels(after, number)
        changed = assert_preserved(before, after, allowed, number)
        source = args.work / (name+'_editable.svg')
        source.write_bytes(etree.tostring(after, encoding='UTF-8'))
        result = export_publication(source, args.output/name, args.work/fig)
        assert after.attrib == before.attrib
        with fitz.open(args.output/(name+'.pdf')) as pdf:
            page = pdf[0]
            expected = [float(x) for x in before.get('viewBox').split()[2:]]
            assert all(abs(a-b)<.001 for a,b in zip(result['page_size_pt'], expected))
            if number == 1:
                for text in ['88 fixed inputs (73 scanner alerts', 'and 15 declarations)']:
                    boxes = page.search_for(text, flags=0)
                    assert len(boxes)==1 and boxes[0].x0>=324-.02 and boxes[0].x1<=469.89
            if number == 6:
                boxes = [page.search_for(t)[0] for t in ['1 dismiss', '1 invalid']]
                assert all(b.x0>=40 and b.x1<=168 and b.y0>133 and b.y1<147 for b in boxes)
                assert boxes[0].x1<boxes[1].x0
                assert max(126,158.709677)<min(164,166.967742)
            page.get_pixmap(matrix=fitz.Matrix(2,2), alpha=False).save(args.work/(fig+'_pdf_review.png'))
        result.update({'changed_svg_elements': changed, 'em_dash_replacements': replacements,
                       'values_file_byte_identical': True if value else None,
                       'inputs_byte_identical': True, 'value_manifest': manifest[fig]})
        checks[fig] = result
        print(fig, 'PASS', flush=True)
    for fig, expected in manifest.items():
        for path, sha in expected['inputs'].items():
            assert digest(args.project/fig/path)==sha
        value=expected['values_file']
        if value:
            assert digest(args.project/fig/value['name'])==value['sha256']
    (args.work/'checks.json').write_text(json.dumps(checks, indent=2)+'\n')

if __name__ == '__main__':
    main()
