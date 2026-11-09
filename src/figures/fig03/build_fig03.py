#!<PROJECT_ROOT> python3
"""Validate existing A4 counts and draw Figure 3; never run grouping analysis.

python3 build_fig03.py [A4_grouping.csv] [identity_matching.py] [workflow_iac_matching.py]
"""
from pathlib import Path
from collections import defaultdict
from xml.sax.saxutils import escape
import ast
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys

import fitz
from fontTools.ttLib import TTFont
from lxml import etree
from PIL import Image, ImageOps

from figure_style import *

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "working"
WORK.mkdir(exist_ok=True)
SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "K_tables/A4_grouping.csv"
CODE = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "study/identity_matching.py"
WORKFLOW_CODE = Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "study/workflow_iac_matching.py"
REF = "K_tables/A4_grouping.csv"
HASHES = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [SOURCE, CODE, WORKFLOW_CODE]}

# Inspect only the literal key definition; do not import or execute study code.
tree = ast.parse(CODE.read_text())
identity = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "identity_key")
fields = next(ast.literal_eval(n.value) for n in identity.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "fields" for t in n.targets))
assert fields["secret_key"] == ("public_der_sha256",)
assert fields["secret_bytes"] == ("file_sha256",)
assert fields["secret_path"] == ("artifact", "path")
workflow_tree = ast.parse(WORKFLOW_CODE.read_text())
pair_function = next(n for n in workflow_tree.body if isinstance(n, ast.FunctionDef) and n.name == "pair_diagnostics")
assert [a.arg for a in pair_function.args.args] == ["rows", "key_fields"]

records = []
with SOURCE.open(newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    assert reader.fieldnames
    while True:
        line = reader.line_num + 1
        try:
            row = next(reader)
        except StopIteration:
            break
        row["_line"] = line
        records.append(row)

index = defaultdict(list)
for row in records:
    index[(row["population"], row["unit"], row["grouping_key"], row["retention_policy"])].append(row)

checks, errors = [], []

def take(population, unit, key, policy, expected):
    rows = sorted(index[(population, unit, key, policy)], key=lambda r: int(r["block"]))
    if [r["block"] for r in rows] != ["1", "2", "3", "4", "5"]:
        errors.append({"population": population, "unit": unit, "key": key, "policy": policy,
                       "error": "Missing, repeated, or unexpected block", "lines": [r["_line"] for r in rows]})
        return None
    for field, target in expected.items():
        vals = [r[field] for r in rows]
        if len(set(vals)) != 1 or vals[0] != str(target):
            errors.append({"population": population, "unit": unit, "key": key, "policy": policy,
                           "field": field, "blocks_1_to_5": vals, "requested": str(target),
                           "source": [f"{REF}:{r['_line']}" for r in rows]})
    checks.append({"population": population, "unit": unit, "key": key, "policy": policy,
                   "fields": {f: [r[f] for r in rows] for f in expected},
                   "source_lines": [r["_line"] for r in rows]})
    return rows[0]

SCA_SPEC = [
    ("component_literal", ["Reported", "identifier"], 4, 6, 2, 4),
    ("component_alias", ["Component", "alias"], 2, 6, 2, 2),
    ("artifact_occurrence", ["Artifact", "occurrence"], 6, 6, 6, 6),
]
SECRET_SPEC = [
    ("secret_key", ["Key", "fingerprint"], 2, 4, 2, 2),
    ("secret_bytes", ["File", "bytes"], 3, 4, 3, 3),
    ("secret_path", ["File", "path"], 4, 4, 4, 4),
]
PANELS = []
object_rows = []
secret_object_rows = []
for panel, population, specs, total in [("a", "sca", SCA_SPEC, 6), ("b", "secret", SECRET_SPEC, 4)]:
    items = []
    for key, label, groups, all_count, minimum, maximum in specs:
        all_row = take(population, "occurrence", key, "all_members", {
            "group_count": groups, "supported_before": total,
            "supported_retained_min": all_count, "supported_retained_max": all_count})
        rep_row = take(population, "occurrence", key, "one_representative", {
            "group_count": groups, "supported_before": total,
            "supported_retained_min": minimum, "supported_retained_max": maximum})
        items.append({"key": key, "label_lines": label, "all_row": all_row, "rep_row": rep_row})
        if population == "sca":
            for policy in ["all_members", "one_representative"]:
                object_rows.append(take("sca", "object", key, policy, {
                    "supported_before": 2, "supported_retained_min": 2, "supported_retained_max": 2}))
        if population == "secret":
            for policy in ["all_members", "one_representative"]:
                secret_object_rows.append(take("secret", "object", key, policy, {
                    "supported_before": 2, "supported_retained_min": 2, "supported_retained_max": 2}))
    PANELS.append({"panel": panel, "population": population, "items": items, "supported_total": total})

terraform = []
for key, label, groups, pairs in [("file_property", ["File +", "property"], 1, 54),
                                 ("resource_property", ["Resource +", "property"], 4, 0)]:
    row = take("terraform:controls", "resource_property", key, "all_members", {
        "group_count": groups, "supported_before": 4, "supported_retained_min": 4,
        "supported_retained_max": 4, "input_alerts": 12, "incorrect_pairs_false_merge": pairs,
        "pair_count_scope": "grouping before any representative selection"})
    # Verify the missing representative result remains absent, never impute it.
    take("terraform:controls", "resource_property", key, "one_representative", {
        "supported_retained_min": "", "supported_retained_max": "",
        "recorded_comparison_status": "representative_retention_not_recorded"})
    terraform.append({"key": key, "label_lines": label, "row": row})

if errors:
    (ROOT / "QUESTIONS.md").write_text("# Figure 3 — Plotting stopped\n\n```json\n" +
        json.dumps(errors, ensure_ascii=False, indent=2) + "\n```\n")
    raise SystemExit("A4 validation failed; see QUESTIONS.md")

# Only now read validated block-1 values into drawing records.
VALUES = []

def provenance(rows):
    return ";".join(dict.fromkeys(f"{REF}:{r['_line']}" for r in rows))

def add_value(panel, key, policy, value, rows):
    VALUES.append({"panel": panel, "key": key, "policy": policy, "value": str(value), "source": provenance(rows)})

for panel in PANELS:
    for item in panel["items"]:
        a, r = item["all_row"], item["rep_row"]
        item.update(groups=int(a["group_count"]), all_count=int(a["supported_retained_min"]),
                    rep_min=int(r["supported_retained_min"]), rep_max=int(r["supported_retained_max"]))
        add_value(panel["panel"], item["key"], "all_members", a["supported_retained_min"], [a])
        lo, hi = r["supported_retained_min"], r["supported_retained_max"]
        add_value(panel["panel"], item["key"], "one_representative", lo if lo == hi else lo+"–"+hi, [r])
        if lo != hi:
            add_value(panel["panel"], item["key"], "one_representative_min", lo, [r])
            add_value(panel["panel"], item["key"], "one_representative_max", hi, [r])
        add_value(panel["panel"], item["key"], "group_count", a["group_count"], [a, r])
    add_value(panel["panel"], "all_keys", "supported_before", panel["items"][0]["all_row"]["supported_before"],
              [item["all_row"] for item in panel["items"]])
for row in object_rows:
    add_value("a", row["grouping_key"], row["retention_policy"]+":object_retention",
              row["supported_retained_min"]+"/"+row["supported_before"], [row])
for item in terraform:
    r = item["row"]
    item.update(groups=int(r["group_count"]), pairs=int(r["incorrect_pairs_false_merge"]))
    add_value("c", item["key"], "incorrect_pairs_false_merge", r["incorrect_pairs_false_merge"], [r])
    add_value("c", item["key"], "group_count", r["group_count"], [r])
    add_value("c", item["key"], "all_members:resource_retention", r["supported_retained_min"]+"/"+r["supported_before"], [r])
    add_value("c", item["key"], "input_alerts", r["input_alerts"], [r])
for row in secret_object_rows:
    add_value("b", row["grouping_key"], row["retention_policy"]+":object_retention",
              row["supported_retained_min"]+"/"+row["supported_before"], [row])
with (ROOT / "fig03_values.csv").open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["panel", "key", "policy", "value", "source"])
    writer.writeheader(); writer.writerows(VALUES)

W, H = WIDTH_PT, 348.0
M, GAP = 6.0, 8.0
PW = (W - 2*M - 2*GAP)/3
TOP, BOTTOM = 100.0, 256.0
ALL_FILL = BLUE
PAIR_FILL = GRAY
FONTS = {False: TTFont(REGULAR_FONT), True: TTFont(BOLD_FONT)}
SHAPES, TEXTS, DEFS, TEXT_QA, BAR_QA = [], [], [], [], []

def n(x): return f"{x:.4f}".rstrip("0").rstrip(".")

def width(s, size=8, bold=False):
    f = FONTS[bold]; cmap = f.getBestCmap()
    return sum(f["hmtx"][cmap[ord(ch)]][0] for ch in s)*size/f["head"].unitsPerEm

def rect(x, y, w, h, fill, stroke="none", sw=.5, rx=0, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    SHAPES.append(f'<rect{id_attr} x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}" fill="{fill}" stroke="{stroke}" stroke-width="{n(sw)}" rx="{n(rx)}"/>')

def line(x1, y1, x2, y2, color=INK, sw=.6, dashed=False):
    dash = ' stroke-dasharray="3 2"' if dashed else ""
    SHAPES.append(f'<path d="M {n(x1)} {n(y1)} L {n(x2)} {n(y2)}" stroke="{color}" stroke-width="{n(sw)}" fill="none"{dash}/>')

def text(s, x, y, size=8, bold=False, color=INK, anchor="start", rotate=0, id_=None):
    assert size >= MIN_FONT_PT
    id_attr = f' id="{id_}"' if id_ else ""
    rot = f' transform="rotate({rotate} {n(x)} {n(y)})"' if rotate else ""
    TEXTS.append(f'<text{id_attr} x="{n(x)}" y="{n(y)}" font-family="{FONT_FAMILY}" font-size="{n(size)}" font-weight="{700 if bold else 400}" fill="{color}" text-anchor="{anchor}"{rot}>{escape(s)}</text>')
    TEXT_QA.append({"text": s, "x": x, "y": y, "font_size_pt": size, "bold": bold, "rotate": rotate,
                    "width_pt": width(s, size, bold), "id": id_})

def hatch(x, y, w, h, id_):
    rect(x, y, w, h, "#FFFFFF", BLUE, .6, id_=id_)
    clip = "clip-"+id_
    DEFS.append(f'<clipPath id="{clip}"><rect x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}"/></clipPath>')
    paths = []
    offset = -h
    while offset <= w:
        paths.append(f'M {n(x+offset)} {n(y+h)} L {n(x+offset+h)} {n(y)}')
        offset += 4
    SHAPES.append(f'<path d="{" ".join(paths)}" clip-path="url(#{clip})" stroke="{BLUE}" stroke-width=".55" fill="none"/>')

def yvalue(value, maximum): return BOTTOM - value/maximum*(BOTTOM-TOP)

def axes(panel_index, maximum, ylabel):
    px = M+panel_index*(PW+GAP); left = px+(26 if panel_index == 2 else 22); right = px+PW
    ticks = range(maximum+1) if maximum <= 6 else range(0, maximum+1, 10)
    for v in ticks:
        yy = yvalue(v, maximum)
        if v and not (panel_index < 2 and v == maximum):
            line(left, yy, right, yy, "#DCE1E4", .4)
        line(left-2.5, yy, left, yy, GRAY, .6)
        text(str(v), left-5, yy+2.6, anchor="end")
    line(left, TOP, left, BOTTOM, GRAY, .65)
    line(left, BOTTOM, right, BOTTOM, GRAY, .65)
    text(ylabel, px+5, (TOP+BOTTOM)/2, size=8, anchor="middle", rotate=-90)
    if panel_index < 2:
        line(left, TOP, right, TOP, GRAY, .8, dashed=True)
    return left, right

titles = ["(a) SCA: occurrences retained", "(b) Secrets: occurrences retained", "(c) Terraform: incorrect pairs"]
for i, title in enumerate(titles):
    assert width(title, 9, True) <= PW
    text(title, M+i*(PW+GAP), 16, size=9, bold=True)
for i in [1, 2]:
    x = M+i*(PW+GAP)-GAP/2
    line(x, 7, x, 298, "#E1E5E8", .45)

# Requested annotations, checked against A4 before they are written.
rect(M, 28, PW, 42, LIGHT, rx=3)
for j, s in enumerate(["Component/advisory identities", "retained: 2/2 under every key", "and policy"]):
    text(s, M+6, 39+j*10)
bpx = M+(PW+GAP)
rect(bpx, 28, PW, 42, LIGHT, rx=3)
for j, s in enumerate(["Secret identities retained:", "2/2 under every key and", "policy"]):
    text(s, bpx+6, 39+j*10)
cpx = M+2*(PW+GAP)
rect(cpx, 28, PW, 42, LIGHT, rx=3)
text("12 alerts · 4 supported resources", cpx+6, 39)
text("4/4 resources retained under", cpx+6, 53)
text("both keys (all members)", cpx+6, 63)

for pi, panel in enumerate(PANELS):
    maximum = panel["supported_total"]
    left, right = axes(pi, maximum, "Supported occurrences retained")
    step = (right-left)/3
    for ki, item in enumerate(panel["items"]):
        cx = left+(ki+.5)*step
        centers = [cx-7, cx+7]
        bw = 11
        for policy, center, value in [("all_members", centers[0], item["all_count"]),
                                      ("one_representative", centers[1], item["rep_min"])]:
            yy = yvalue(value, maximum); height = BOTTOM-yy
            id_ = f"bar-{panel['panel']}-{item['key']}-{policy}"
            if policy == "all_members":
                rect(center-bw/2, yy, bw, height, ALL_FILL, BLUE, .6, id_=id_)
                label = str(value); label_y = yy-5
            else:
                hatch(center-bw/2, yy, bw, height, id_)
                hi = item["rep_max"]
                label = str(value) if value == hi else f"{value}–{hi}"
                label_y = yvalue(hi, maximum)-5
                if hi != value:
                    top = yvalue(hi, maximum)
                    line(center, top, center, yy, INK, .85)
                    line(center-3, top, center+3, top, INK, .85)
                    line(center-3, yy, center+3, yy, INK, .85)
            text(label, center, label_y, size=9.5, bold=True, anchor="middle", id_=id_+"-label")
            BAR_QA.append({"panel": panel["panel"], "key": item["key"], "policy": policy,
                           "height_value": value, "label": label, "x": center-bw/2, "y": yy,
                           "width": bw, "height": height, "maximum": maximum,
                           "interval_max": item["rep_max"] if policy == "one_representative" else value})
        # Increase separation of the first two SCA label blocks only.
        # Bar positions, axes and the third category remain unchanged.
        tick_cx = cx + (-3 if ki == 0 else 3 if ki == 1 else 0) if pi == 0 else cx
        for j, s in enumerate(item["label_lines"]):
            assert width(s) < step
            text(s, tick_cx, 270+j*10, anchor="middle")
        text(f"({item['groups']} groups)", tick_cx, 292, anchor="middle")

left, right = axes(2, 60, "Incorrect pairs")
step = (right-left)/2
for ki, item in enumerate(terraform):
    cx = left+(ki+.5)*step; bw = 27
    value = item["pairs"]; yy = yvalue(value, 60)
    if value:
        rect(cx-bw/2, yy, bw, BOTTOM-yy, PAIR_FILL, PAIR_FILL, .6, id_="bar-c-"+item["key"])
    else:
        # A zero-height bar, with its exact value printed above the baseline.
        line(cx-bw/2, BOTTOM, cx+bw/2, BOTTOM, PAIR_FILL, .9)
    text(str(value), cx, yy-5, size=9.5, bold=True, anchor="middle", id_="bar-c-"+item["key"]+"-label")
    BAR_QA.append({"panel": "c", "key": item["key"], "policy": "incorrect_pairs_false_merge",
                   "height_value": value, "label": str(value), "x": cx-bw/2, "y": yy,
                   "width": bw, "height": BOTTOM-yy, "maximum": 60, "interval_max": value})
    for j, s in enumerate(item["label_lines"]): text(s, cx, 270+j*10, anchor="middle")
    suffix = "group" if item["groups"] == 1 else "groups"
    text(f"({item['groups']} {suffix})", cx, 292, anchor="middle")

# One shared legend for the two retention panels; Terraform uses its own neutral color.
rect(55, 309, 12, 9, ALL_FILL, BLUE, .6)
text("All members", 73, 316.5, size=8.5)
hatch(146, 309, 12, 9, "legend-one-representative")
text("One representative", 164, 316.5, size=8.5)
line(55, 333, 70, 333, GRAY, .8, dashed=True)
text("Supported total", 76, 336, size=8)
line(167, 329, 167, 337, INK, .85)
line(164, 329, 170, 329, INK, .85); line(164, 337, 170, 337, INK, .85)
text("Min–max", 177, 336, size=8)

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="170mm" height="{n(H*25.4/72)}mm" viewBox="0 0 {n(W)} {n(H)}">
<title>Grouping: retained occurrences and incorrect pairs</title>
<desc>Panels a and b compare all members with one representative. The SCA component-name representative bar is 2 with a 2–4 min–max interval. Panel c shows recorded Terraform false-merge pairs. The panels measure different units.</desc>
<metadata>All drawn values are copied from validated block-1 rows of K_tables/A4_grouping.csv, SHA-256 {HASHES[str(SOURCE)]}. All relevant values are identical across five blocks. Study code is read only, never executed.</metadata>
<defs>{''.join(DEFS)}</defs>
<rect width="{n(W)}" height="{n(H)}" fill="#FFFFFF"/>
<g id="geometry">{''.join(SHAPES)}</g>
<g id="labels">{''.join(TEXTS)}</g>
</svg>'''
editable = ROOT / "fig03_grouping_editable.svg"
editable.write_text(svg)

for name, options in [
    ("fig03_grouping.pdf", ["--export-area-page", "--export-type=pdf"]),
    ("fig03_grouping.svg", ["--export-text-to-path", "--export-plain-svg", "--export-type=svg"]),
    ("fig03_grouping.png", ["--export-area-page", "--export-dpi=600", "--export-type=png"]),
]:
    subprocess.run(["inkscape", str(editable), *options, "--export-filename="+str(ROOT/name)],
                   check=True, capture_output=True)

doc = fitz.open(ROOT / "fig03_grouping.pdf"); assert len(doc) == 1
page = doc[0]
spans = [s for b in page.get_text("dict")["blocks"] if "lines" in b for l in b["lines"] for s in l["spans"]]
assert min(s["size"] for s in spans) >= 7.99999
assert all("NimbusSans" in s["font"] for s in spans)
assert not page.get_images()
assert abs(page.rect.width/72*25.4-170) < .001
for s in spans:
    x0, y0, x1, y1 = s["bbox"]
    assert x0 >= 0 and y0 >= 0 and x1 <= W+.01 and y1 <= H+.01, s
page.get_pixmap(matrix=fitz.Matrix(3, 3), alpha=False).save(WORK / "pdf_review.png")
png = Image.open(ROOT / "fig03_grouping.png"); png.load()
assert all(abs(v-600) < .01 for v in png.info["dpi"])
assert png.width == 4016
preview = png.copy(); preview.thumbnail((1500, 1200)); preview.save(ROOT / "fig03_preview.png")
ImageOps.grayscale(preview).save(WORK / "grayscale_review.png")
publication = etree.parse(str(ROOT / "fig03_grouping.svg")); ns = "{http://www.w3.org/2000/svg}"
assert not publication.findall(".//"+ns+"text") and not publication.findall(".//"+ns+"image")
for path, digest in HASHES.items(): assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest

report = {"source": REF, "source_sha256": HASHES[str(SOURCE)], "identity_code_sha256": HASHES[str(CODE)],
          "workflow_code_sha256": HASHES[str(WORKFLOW_CODE)],
          "all_requested_values_identical_across_five_blocks": True,
          "checked_series": checks, "no_analysis_recomputed": True,
          "fig03_values_records": len(VALUES), "bar_count_including_zero": len(BAR_QA),
          "bars": BAR_QA, "text_layout": TEXT_QA, "size_mm": [170, H*25.4/72],
          "png_size": list(png.size), "png_dpi": list(png.info["dpi"]),
          "pdf_minimum_font_size_raw": min(s["size"] for s in spans), "pdf_raster_image_count": 0,
          "secrets_display_labels": {"secret_key": "Key fingerprint", "secret_bytes": "File bytes", "secret_path": "File path"},
          "workflow_iac_matching_available": True,
          "terraform_pair_rule_source": "study/workflow_iac_matching.py:102-117"}
(WORK / "validation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n")
for original, relative in [(SOURCE, "K_tables/A4_grouping.csv"), (CODE, "study/identity_matching.py"),
                           (WORKFLOW_CODE, "study/workflow_iac_matching.py")]:
    copy = ROOT / relative; copy.parent.mkdir(exist_ok=True)
    if original.resolve() != copy.resolve(): shutil.copyfile(original, copy)
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == HASHES[str(original)]
print(json.dumps({k: v for k, v in report.items() if k not in {"checked_series", "bars", "text_layout"}}, indent=2))
