#!<PROJECT_ROOT> python3
"""Validate the supplied CSV, then render Figure 2 without changing evidence.

Run: python3 build_fig02.py [path/to/A1_populations.csv]
Requires Python 3, fontTools, lxml, PyMuPDF, Pillow, and Inkscape.
"""

from pathlib import Path
from xml.sax.saxutils import escape
import csv
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys

from fontTools.ttLib import TTFont
from lxml import etree
import fitz
from PIL import Image, ImageOps

from fig02_style import *

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "working"
WORK.mkdir(exist_ok=True)
SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "K_tables/A1_populations.csv"
SOURCE_REF = "K_tables/A1_populations.csv"
SOURCE_HASH = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
BLOCKS = {"1", "2", "3", "4", "5"}

# Explicit mappings: no population names or counts are inferred.
ROWS = [
    ("sast-java", "Java SAST cases", "java"),
    ("sca", "SCA occurrences", "sca"),
    ("secret", "Secret occurrences", "secrets"),
    ("docker", "Dockerfiles", "docker"),
    ("compose:no_new_privileges_disabled", "Compose: no-new-privileges disabled", "compose"),
    ("compose:privileged_enabled", "Compose: privileged", "compose"),
    ("compose:host_network_enabled", "Compose: host network", "compose"),
    ("compose:docker_socket_mounted", "Compose: Docker socket mounted", "compose"),
    ("terraform:controls", "Terraform: controls", "terraform"),
    ("terraform:originals", "Terraform: originals", "terraform"),
    ("kubernetes:controls", "Kubernetes: controls", "kubernetes"),
    ("kubernetes:originals", "Kubernetes: originals", "kubernetes"),
    ("kubernetes:matrix", "Kubernetes: scope matrix", "kubernetes"),
    ("kubernetes:split", "Kubernetes: split documents", "kubernetes"),
    ("os-advisory", "OS advisories", "os"),
    ("api-authorization", "API object authorization", "api"),
    ("aigoat-declared-properties", "AIGoat declared properties", "property"),
]
COLUMNS = [
    ("Semgrep", ("semgrep",)),
    ("FindSecBugs", ("findsecbugs",)),
    ("Dependency-Check", ("dependency-check",)),
    ("Trivy", ("trivy", "trivy-secret", "trivy-config")),
    ("Grype", ("grype",)),
    ("Gitleaks", ("gitleaks",)),
    ("Checkov", ("checkov",)),
    ("Hadolint", ("hadolint",)),
    ("KICS", ("kics",)),
    ("Kubescape", ("kubescape",)),
    ("RESTler", ("restler",)),
]

records = {}
with SOURCE.open(encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    assert reader.fieldnames is not None  # Consume the header before counting data lines.
    while True:
        start_line = reader.line_num + 1
        try:
            row = next(reader)
        except StopIteration:
            break
        pid = row["population_id"]
        assert pid not in records, f"Duplicate population: {pid}"
        row["_source_line"] = start_line
        row["_tools"] = json.loads(row["supported_by_tool_by_block"])
        row["_eligible"] = json.loads(row["eligible_tools"])
        row["_union"] = json.loads(row["supported_union_by_block"])
        records[pid] = row

errors = []
series_checked = []
for pid, row in records.items():
    # Check every populated per-tool series in the entire supplied CSV.
    for tool, values in row["_tools"].items():
        if set(values) != BLOCKS or len(set(values.values())) != 1:
            errors.append({"population": pid, "tool": tool, "values": values,
                           "source": f"{SOURCE_REF}:{row['_source_line']}"})
        if any(type(v) is not int or v < 0 for v in values.values()):
            errors.append({"population": pid, "tool": tool, "error": "Not an exact nonnegative integer"})
        series_checked.append({"population": pid, "tool": tool, "blocks": values})

selected = []
for i, (pid, label, layer) in enumerate(ROWS):
    if pid not in records:
        errors.append({"population": pid, "error": "Missing required population"})
        continue
    row = records[pid]
    assert row["role_v1_0"] == ("property" if i == 16 else "scored")
    assert set(row["_tools"]) == set(row["_eligible"]), pid
    union = row["_union"]
    if set(union) != BLOCKS or len(set(union.values())) != 1:
        errors.append({"population": pid, "field": "supported_union_by_block", "values": union})
    elif str(union["1"]) != row["supported_union"]:
        errors.append({"population": pid, "error": "supported_union differs from block 1"})
    trivy_modes = set(row["_eligible"]) & {"trivy", "trivy-secret", "trivy-config"}
    if len(trivy_modes) > 1:
        errors.append({"population": pid, "error": "Multiple eligible Trivy modes", "modes": sorted(trivy_modes)})
    selected.append(row)

if errors:
    (ROOT / "QUESTIONS.md").write_text(
        "# Figure 2 — Validation stopped\n\nNo figure was generated.\n\n```json\n"
        + json.dumps(errors, indent=2, ensure_ascii=False) + "\n```\n")
    raise SystemExit("Source validation failed; see QUESTIONS.md")

cells = []
drawn = []
for (pid, label, layer), row in zip(ROWS, selected):
    source = f"{SOURCE_REF}:{row['_source_line']}"
    values = []
    for col, aliases in COLUMNS:
        eligible = [a for a in aliases if a in row["_eligible"]]
        assert len(eligible) <= 1
        value = row["_tools"][eligible[0]]["1"] if eligible else None
        values.append(value)
        cells.append({"row": label, "column": col,
                      "value": str(value) if value is not None else "–", "source": source})
    union_label = row["supported_union"] + "/" + row["catalogue_positive"]
    cells.append({"row": label, "column": "Union / catalog", "value": union_label, "source": source})
    drawn.append({"population_id": pid, "row": label, "layer": layer, "values": values,
                  "union": union_label, "source": source})
assert len(cells) == 204
with (ROOT / "fig02_values.csv").open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["row", "column", "value", "source"])
    writer.writeheader()
    writer.writerows(cells)

positive = [v for row in drawn for v in row["values"] if v is not None and v > 0]
MIN_VALUE, MAX_VALUE = min(positive), max(positive)
assert (MIN_VALUE, MAX_VALUE) == (1, 21)
FONTS = {False: TTFont(REGULAR_FONT), True: TTFont(BOLD_FONT)}

def text_width(s, size=8.5, bold=False):
    font = FONTS[bold]
    cmap = font.getBestCmap()
    return sum(font["hmtx"][cmap[ord(c)]][0] for c in s) * size / font["head"].unitsPerEm

def n(v):
    return f"{v:.4f}".rstrip("0").rstrip(".")

SHAPES, TEXT, TEXT_QA, CELL_QA = [], [], [], []

def rect(x, y, w, h, fill, stroke="none", sw=.4, rx=0, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    SHAPES.append(f'<rect{id_attr} x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}" fill="{fill}" stroke="{stroke}" stroke-width="{n(sw)}" rx="{n(rx)}"/>')

def line(x1, y1, x2, y2, color="#CAD0D4", sw=.5):
    SHAPES.append(f'<path d="M {n(x1)} {n(y1)} L {n(x2)} {n(y2)}" fill="none" stroke="{color}" stroke-width="{n(sw)}"/>')

def txt(s, x, y, size=8.5, bold=False, color=INK, anchor="start", angle=0, id_=None):
    assert size >= MIN_FONT_PT
    assert not s.startswith("·") and not s.endswith("·")
    transform = f' transform="rotate({angle} {n(x)} {n(y)})"' if angle else ""
    id_attr = f' id="{id_}"' if id_ else ""
    TEXT.append(f'<text{id_attr} x="{n(x)}" y="{n(y)}" font-family="{FONT_FAMILY}" font-size="{n(size)}" font-weight="{700 if bold else 400}" fill="{color}" text-anchor="{anchor}"{transform}>{escape(s)}</text>')
    TEXT_QA.append({"text": s, "x": x, "y": y, "size_pt": size, "bold": bold, "angle": angle,
                    "width_pt": text_width(s, size, bold), "id": id_})

def positive_color(v):
    # A single global linear count scale, never a per-row fraction or accuracy.
    strength = .15 + .85 * (v - MIN_VALUE) / (MAX_VALUE - MIN_VALUE)
    return tint(BLUE, strength)

def text_color(bg):
    rgb = [int(bg[i:i+2], 16) / 255 for i in (1, 3, 5)]
    linear = [v/12.92 if v <= .04045 else ((v+.055)/1.055)**2.4 for v in rgb]
    luminance = .2126*linear[0] + .7152*linear[1] + .0722*linear[2]
    return "#FFFFFF" if luminance < .25 else INK

W = WIDTH_PT
M = 6
GX = 158
CW = 22
TOOL_RIGHT = GX + CW * len(COLUMNS)
UNION_X = TOOL_RIGHT + 9
UNION_W = W - M - UNION_X
RH = 19.8
Y0 = 88
GAP = 4.2
PROPERTY_GAP = 25
ys = []
y = Y0
for i, row in enumerate(drawn):
    if i and row["layer"] != drawn[i-1]["layer"]:
        y += PROPERTY_GAP if i == 16 else GAP
    ys.append(y)
    y += RH
BODY_BOTTOM = y
H = BODY_BOTTOM + 76
H_MM = H / 72 * 25.4
assert H_MM <= 200

# Minimal tabular heading; tool names rotate as intact words.
txt("Population", M, Y0 - 11, size=9, bold=True)
for i, (label, aliases) in enumerate(COLUMNS):
    txt(label, GX + i*CW + CW/2 + 2.3, Y0 - 10, size=8.5, bold=True, angle=-60,
        id_=f"column-{i+1}")
txt("Union /", UNION_X + UNION_W/2, Y0 - 23, size=8.5, bold=True, anchor="middle")
txt("catalog", UNION_X + UNION_W/2, Y0 - 12, size=8.5, bold=True, anchor="middle")
line(M, Y0 - 4, W-M, Y0 - 4, GRAY, .65)

for ri, row in enumerate(drawn):
    y = ys[ri]
    if ri and row["layer"] != drawn[ri-1]["layer"]:
        if ri == 16:
            sep_y = y - PROPERTY_GAP + 5
            line(M, sep_y, W-M, sep_y, GRAY, 1)
            txt("Property population (not scored)", M, y - 6, size=8.5, bold=True)
        else:
            line(M, y - GAP/2, W-M, y - GAP/2, "#B8C0C5", .45)
    assert text_width(row["row"]) <= GX-M-7, row["row"]
    txt(row["row"], M, y+RH/2+2.8, id_=f"row-{ri+1}")
    for ci, value in enumerate(row["values"]):
        x = GX + ci*CW
        fill = "#ECEFF1" if value is None else "#FFFFFF" if value == 0 else positive_color(value)
        label = "–" if value is None else str(value)
        rect(x+.5, y+.7, CW-1, RH-1.4, fill, "#D8DDE0", sw=.3, rx=1,
             id_=f"cell-{ri+1}-{ci+1}")
        color = "#717A81" if value is None else text_color(fill)
        txt(label, x+CW/2, y+RH/2+3.1, size=9.5, bold=value is not None and value > 0,
            color=color, anchor="middle", id_=f"value-{ri+1}-{ci+1}")
        CELL_QA.append({"row": ri+1, "column": ci+1, "value": label, "fill": fill,
                        "x": x+.5, "y": y+.7, "width": CW-1, "height": RH-1.4})
    rect(UNION_X, y+.7, UNION_W, RH-1.4, LIGHT, rx=1)
    txt(row["union"], UNION_X+UNION_W/2, y+RH/2+3.1, size=9.5, bold=True, anchor="middle",
        id_=f"value-{ri+1}-12")

# Count legend and categorical keys are separate, so gray never implies zero.
legend_y = BODY_BOTTOM + 17
line(M, BODY_BOTTOM+8, W-M, BODY_BOTTOM+8, "#CAD0D4", .45)
txt("Supported count", M, legend_y+7, size=8, bold=True)
bar_x, bar_y, bar_w, bar_h = 88, legend_y, 106, 9
rect(bar_x, bar_y, bar_w, bar_h, "url(#count-gradient)")
for value in [1, 10, 21]:
    x = bar_x + (value-MIN_VALUE)/(MAX_VALUE-MIN_VALUE)*bar_w
    line(x, bar_y+bar_h+1, x, bar_y+bar_h+3, GRAY, .4)
    txt(str(value), x, bar_y+bar_h+12, size=8, anchor="middle")
rect(221, legend_y-1, 16, 13, "#FFFFFF", "#C9CFD3", .5, 1)
txt("0", 229, legend_y+8, size=8.5, anchor="middle")
txt("Measured absence", 242, legend_y+8, size=8)
rect(335, legend_y-1, 16, 13, "#ECEFF1", "#C9CFD3", .5, 1)
txt("–", 343, legend_y+8, size=8.5, color="#717A81", anchor="middle")
txt("Not eligible", 356, legend_y+8, size=8)
txt("Shading encodes counts, not accuracy.", M, BODY_BOTTOM+54, size=8)
txt("Union / catalog = supported union / catalogue positives.", M, BODY_BOTTOM+66, size=8)

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="170mm" height="{n(H_MM)}mm" viewBox="0 0 {n(W)} {n(H)}">
<title>Coverage by population and tool</title>
<desc>Exact block-1 counts, verified identical across five blocks. White cells with 0 indicate measured absence; gray cells with an en dash indicate ineligibility. Property population shown separately and not scored.</desc>
<metadata>Source: {SOURCE_REF}; SHA-256: {SOURCE_HASH}. Editable text. Font: Nimbus Sans. Color: Okabe–Ito blue. No source evidence modified.</metadata>
<defs><linearGradient id="count-gradient" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="{positive_color(MIN_VALUE)}"/><stop offset="100%" stop-color="{positive_color(MAX_VALUE)}"/></linearGradient></defs>
<rect width="{n(W)}" height="{n(H)}" fill="#FFFFFF"/>
<g id="geometry">{''.join(SHAPES)}</g>
<g id="labels">{''.join(TEXT)}</g>
</svg>'''
editable = ROOT / "fig02_coverage_editable.svg"
editable.write_text(svg, encoding="utf-8")

for filename, options in [
    ("fig02_coverage.pdf", ["--export-area-page", "--export-type=pdf"]),
    ("fig02_coverage.svg", ["--export-text-to-path", "--export-plain-svg", "--export-type=svg"]),
    ("fig02_coverage.png", ["--export-area-page", "--export-dpi=600", "--export-type=png"]),
]:
    subprocess.run(["inkscape", str(editable), *options, "--export-filename="+str(ROOT/filename)],
                   check=True, capture_output=True)

# Vector/text/size checks and a fresh PDF rendering for visual inspection.
doc = fitz.open(ROOT / "fig02_coverage.pdf")
assert len(doc) == 1
page = doc[0]
spans = [s for b in page.get_text("dict")["blocks"] if "lines" in b
         for ln in b["lines"] for s in ln["spans"]]
assert min(s["size"] for s in spans) >= MIN_FONT_PT - .00001
assert all("NimbusSans" in s["font"] for s in spans)
assert not page.get_images()
assert abs(page.rect.width / 72 * 25.4 - 170) < .001
assert abs(page.rect.height / 72 * 25.4 - H_MM) < .001
for span in spans:
    x0, y0, x1, y1 = span["bbox"]
    assert x0 >= 0 and y0 >= 0 and x1 <= W+.01 and y1 <= H+.01, span
text = page.get_text()
assert "Property population (not scored)" in text
assert not re.search(r"\banalysed\b|\bqualified\b|\bRQ\s*\d|\b\d{4}-\d{2}-\d{2}\b", text)
page.get_pixmap(matrix=fitz.Matrix(2.5, 2.5), alpha=False).save(WORK / "pdf_review.png")
png = Image.open(ROOT / "fig02_coverage.png")
png.load()
assert all(abs(v-600) < .01 for v in png.info["dpi"])
assert abs(png.width - 170/25.4*600) <= 1
assert abs(png.height - H_MM/25.4*600) <= 1
preview = png.copy()
preview.thumbnail((1300, 1600))
preview.save(ROOT / "fig02_preview.png")
ImageOps.grayscale(preview).save(WORK / "grayscale_review.png")
ns = "{http://www.w3.org/2000/svg}"
publication = etree.parse(str(ROOT / "fig02_coverage.svg"))
assert not publication.findall(".//"+ns+"text")
assert not publication.findall(".//"+ns+"image")
source_svg = etree.parse(str(editable))
svg_values = {t.get("id"): t.text for t in source_svg.findall(".//"+ns+"text") if t.get("id", "").startswith("value-")}
assert len(svg_values) == 204
for i, c in enumerate(cells):
    ri, ci = divmod(i, 12)
    assert svg_values[f"value-{ri+1}-{ci+1}"] == c["value"]
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_HASH

source_copy = ROOT / "K_tables/A1_populations.csv"
source_copy.parent.mkdir(exist_ok=True)
if SOURCE.resolve() != source_copy.resolve():
    shutil.copyfile(SOURCE, source_copy)
assert hashlib.sha256(source_copy.read_bytes()).hexdigest() == SOURCE_HASH

caption = ("Coverage by population and eligible tool. Cells report supported reference instances from block 1 "
           "after verifying identical counts across five blocks. Shading encodes counts, not accuracy; 0 denotes "
           "measured absence and – denotes ineligibility. The rightmost column reports supported union/catalogue "
           "positives. The final, separately marked property population is not scored.")
assert len(caption.split()) <= 60
(ROOT / "fig02_caption_proposal.txt").write_text(caption+"\n")

report = {
    "source": SOURCE_REF, "source_sha256": SOURCE_HASH, "source_unchanged": True,
    "source_rows": len(records), "all_populated_tool_series_identical": True,
    "all_populated_tool_series_checked": len(series_checked),
    "selected_rows": len(ROWS), "selected_tool_series_checked": sum(len(r["_tools"]) for r in selected),
    "all_selected_unions_identical_and_match_supported_union": True,
    "trivy_aliases": {r["population_id"]: [t for t in r["_eligible"] if t.startswith("trivy")] for r in selected},
    "rows": drawn, "excluded_populations": [pid for pid in records if pid not in {r[0] for r in ROWS}],
    "drawn_data_cells": len(cells), "positive_cells": len(positive),
    "zero_cells": sum(v == 0 for r in drawn for v in r["values"] if v is not None),
    "ineligible_cells": sum(v is None for r in drawn for v in r["values"]),
    "union_denominator": "catalogue_positive", "shading": "global linear positive count scale, 1 to 21",
    "caption_word_count": len(caption.split()), "size_mm": [170, H_MM],
    "png_pixels": list(png.size), "png_dpi": list(png.info["dpi"]),
    "minimum_pdf_font_size_pt": min(s["size"] for s in spans),
    "pdf_raster_image_count": 0, "publication_svg_text_outlined": True,
    "editable_svg_data_cells_match_values_csv": True, "text_layout": TEXT_QA, "cell_layout": CELL_QA,
    "full_five_block_series_checked": series_checked,
}
(WORK / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
(ROOT / "QUESTIONS.md").write_text(
    "# Figure 2 — Questions and validation status\n\n"
    "No blocking ambiguity remains for the requested figure.\n\n"
    "- The previously missing CSV was supplied as `A1_populations.csv`; source references retain the requested repository name `K_tables/A1_populations.csv`. The archive includes an identical, unmodified copy.\n"
    f"- All {len(series_checked)} populated tool series in the file contain five identical block values. The 17 selected populations contain {sum(len(r['_tools']) for r in selected)} eligible tool series; all pass. Their 17 union series also pass and match `supported_union`.\n"
    "- The excluded descriptive population `aigoat-rag-context-authorization` has empty block maps (line 27). It contributes no cell; no missing value has been interpreted as zero.\n"
    "- One eligible Trivy mode per selected population was confirmed. The merged display column performs no summation.\n"
    "- The denominator is always `catalogue_positive`. `catalogue_size` is not used in the plot.\n"
    "- All descriptive populations and `aigoat-http-properties` are excluded. The declared-property population is separate and not scored.\n"
    "- `fig02_values.csv` includes all 204 drawn data cells, including ineligibility dashes and union/catalog entries.\n")

print(json.dumps({k: v for k, v in report.items() if k not in {"text_layout", "cell_layout", "full_five_block_series_checked", "rows", "trivy_aliases", "excluded_populations"}}, indent=2))
