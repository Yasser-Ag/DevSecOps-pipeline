"""Shared publication typography and lossless figure export.

Presentation exports retain the validated SVG geometry and numerical strings.
"""
from pathlib import Path
import struct
import subprocess
import fitz
from fontTools.ttLib import TTFont
from PIL import Image

FONT_FAMILY = 'Nimbus Sans'
REGULAR_FONT = '<PROJECT_ROOT>/fonts/NimbusSans-Regular.otf'
MIN_FONT_PT = 8.0
PNG_DPI = 600

def text_width(text, size=8.0):
    font = TTFont(REGULAR_FONT)
    cmap = font.getBestCmap()
    return sum(font['hmtx'][cmap[ord(c)]][0] for c in text) * size / font['head'].unitsPerEm

def export_publication(source, output_base, work):
    """Render vectors, embed fonts, and remove optional document metadata.

    PNG IDAT chunks remain byte-for-byte intact: no resampling or recompression.
    """
    output_base, work = Path(output_base), Path(work)
    work.mkdir(parents=True, exist_ok=True)
    raw_pdf = work / (output_base.name + '_raw.pdf')
    raw_png = work / (output_base.name + '_raw.png')
    subprocess.run(['inkscape', str(source), '--export-area-page', '--export-type=pdf',
                    '--export-filename=' + str(raw_pdf)], check=True, capture_output=True)
    subprocess.run(['inkscape', str(source), '--export-area-page', '--export-type=png',
                    '--export-dpi=600', '--export-filename=' + str(raw_png)], check=True, capture_output=True)
    pdf_path = output_base.with_suffix('.pdf')
    with fitz.open(raw_pdf) as doc:
        doc.set_metadata({k: '' for k in doc.metadata if k not in {'format', 'encryption'}})
        doc.del_xml_metadata()
        doc.xref_set_key(-1, 'Info', 'null')
        doc.save(pdf_path, garbage=4, no_new_id=True)
    png = raw_png.read_bytes()
    assert png[:8] == b'\x89PNG\r\n\x1a\n'
    chunks, offset = [], 8
    while offset < len(png):
        length = struct.unpack('>I', png[offset:offset+4])[0]
        kind = png[offset+4:offset+8]
        chunk = png[offset:offset+12+length]
        if kind not in {b'tEXt', b'zTXt', b'iTXt', b'tIME', b'caBX'}:
            chunks.append(chunk)
        offset += length+12
    assert offset == len(png)
    png_path = output_base.with_suffix('.png')
    png_path.write_bytes(png[:8] + b''.join(chunks))
    with Image.open(raw_png) as a, Image.open(png_path) as b:
        a.load(); b.load()
        assert a.size == b.size and a.tobytes() == b.tobytes()
        assert all(abs(d-PNG_DPI) < .01 for d in b.info['dpi'])
        pixel_size = list(b.size)
    with fitz.open(pdf_path) as doc:
        assert len(doc) == 1 and not doc[0].get_images()
        assert all(not v for k, v in doc.metadata.items() if k not in {'format', 'encryption'})
        assert not doc.get_xml_metadata()
        fonts = doc[0].get_fonts(full=True)
        assert fonts and all(doc.extract_font(f[0])[3] for f in fonts)
        spans = [s for b in doc[0].get_text('dict')['blocks'] for l in b.get('lines', []) for s in l['spans']]
        assert min(s['size'] for s in spans) >= MIN_FONT_PT-.0001
        assert '\u2014' not in doc[0].get_text()
        assert all(fitz.Rect(s['bbox']) in doc[0].rect for s in spans)
        return {'pixel_size': pixel_size, 'page_size_pt': list(doc[0].rect)[2:],
                'minimum_font_pt': min(s['size'] for s in spans),
                'embedded_fonts': [f[3] for f in fonts], 'raster_images_in_pdf': 0,
                'png_pixels_preserved': True, 'optional_metadata_removed': True}
