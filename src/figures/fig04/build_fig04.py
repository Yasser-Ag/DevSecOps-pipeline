#!<PROJECT_ROOT> python3
"""Validate A5 across five blocks, then render the supplied omission results.

No evidence is modified and no scanner/analysis value is recomputed.
The only aggregation is the explicitly requested four Compose populations.
Usage: python3 build_fig04.py [A5_omission.csv] [A1_populations.csv]
"""
from pathlib import Path
from collections import defaultdict
from fractions import Fraction
from xml.sax.saxutils import escape
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import unicodedata

import fitz
from fontTools.ttLib import TTFont
from lxml import etree
from PIL import Image, ImageOps

from figure_style import *

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "working"
WORK.mkdir(exist_ok=True)
A5 = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "K_tables/A5_omission.csv"
A1 = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "K_tables/A1_populations.csv"
REF = "K_tables/A5_omission.csv"
HASHES = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (A5, A1)}

def read_csv(path):
    result = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames
        while True:
            line_number = reader.line_num + 1
            try:
                record = next(reader)
            except StopIteration:
                break
            record["_line"] = line_number
            result.append(record)
    return result

records = read_csv(A5)
# A1 is consulted for names and roles only, never for a numerical value.
populations = {r["population_id"]: {k: r[k] for k in ("population_id", "layer", "role_v1_0", "_line")}
               for r in read_csv(A1)}
index = defaultdict(list)
for r in records:
    index[(r["population"], r["omission_level"], r["omitted"])].append(r)

errors, checks = [], []
NUMERIC_FIELDS = ("supported_before", "supported_after", "lost_count", "identity_before", "identity_after",
                  "identity_lost", "occurrence_before", "occurrence_after")
for key, rows in index.items():
    rows.sort(key=lambda r: int(r["block"]))
    if [r["block"] for r in rows] != ["1", "2", "3", "4", "5"]:
        errors.append({"key": key, "error": "Missing, duplicate, or unexpected block"})
    for field in NUMERIC_FIELDS + ("unit", "role_v1_0", "omitted_profiles", "full_comparison_available"):
        values = [r[field] for r in rows]
        if len(set(values)) != 1:
            errors.append({"key": key, "field": field, "values": values,
                           "source": [f"{REF}:{r['_line']}" for r in rows]})
    checks.append({"population": key[0], "omission_level": key[1], "omitted": key[2],
                   "source_lines": [r["_line"] for r in rows],
                   "numeric_values_by_block": {f: [r[f] for r in rows] for f in NUMERIC_FIELDS}})

COMPOSE = ["compose:docker_socket_mounted", "compose:host_network_enabled",
           "compose:no_new_privileges_disabled", "compose:privileged_enabled"]
# Expected values below are validation targets from the supplied specification.
# Plotted numbers are always obtained from the matching A5 block-1 records.
SPECS = [
    (1, ["sast-java"], "profile", "java-findsecbugs", (10, 6), "cases",
     ["Java SAST: without FindSecBugs"], 64),
    (2, ["sca"], "recorded_stage", "image_scan", (6, 3), "occurrences",
     ["SCA: without image-scan stage"], 96),
    (3, ["sca"], "recorded_stage", "source_sca", (6, 3), "occurrences",
     ["SCA: without source-SCA stage"], 120),
    (4, ["docker"], "profile", "configuration-trivy-config", (3, 2), "final-process properties",
     ["Dockerfiles: without Trivy", "(configuration)"], 152),
    (5, COMPOSE, "profile", "configuration-kics-compose", (4, 0), "service properties",
     ["Compose: without KICS", "(4 populations, 1 property each)"], 184),
    (6, ["kubernetes:controls"], "profile", "infrastructure-controls-checkov-kubernetes", (3, 2), "container properties",
     ["Kubernetes controls: without Checkov"], 216),
    (7, ["kubernetes:originals"], "profile", "infrastructure-originals-trivy-kubernetes", (8, 6), "container properties",
     ["Kubernetes originals: without Trivy"], 240),
    (8, ["kubernetes:matrix"], "profile", "k8s-scope-matrix-checkov", (9, 8), "container properties",
     ["Kubernetes scope matrix: without Checkov"], 264),
    (9, ["kubernetes:matrix"], "profile", "k8s-scope-matrix-trivy", (9, 5), "container properties",
     ["Kubernetes scope matrix: without Trivy"], 288),
    (10, ["kubernetes:split"], "profile", "k8s-scope-split-trivy", (6, 0), "container properties",
     ["Kubernetes split documents: without Trivy"], 312),
    (11, ["api-authorization"], "profile", "crapi-restler-a-raw-namespace", (2, 1), "authorization instances",
     ["API authorization: without RESTler", "(actor a, raw namespace)"], 344),
    (12, ["api-authorization"], "profile", "crapi-restler-b-raw-namespace", (2, 1), "authorization instances",
     ["API authorization: without RESTler", "(actor b, raw namespace)"], 372),
    (13, ["aigoat-declared-properties"], "profile", "aigoat-compose-kics-compose-deployment-qualified", (31, 20), "properties",
     ["AIGoat declared properties: without KICS", "(deployment profile)"], 436),
    (14, ["aigoat-declared-properties"], "profile", "aigoat-kics-compose", (31, 21), "properties",
     ["AIGoat declared properties: without KICS", "(Compose profile)"], 466),
]

DRAW, VALUES, selected = [], [], set()
for row_number, names, level, omitted, expected, display_unit, labels, y in SPECS:
    parts = []
    for pop in names:
        key = (pop, level, omitted)
        selected.add(key)
        if key not in index:
            errors.append({"row": row_number, "missing": key})
            continue
        part = index[key][0]
        parts.append(part)
        if int(part["lost_count"]) <= 0:
            errors.append({"row": row_number, "error": "Selected omission has no loss", "key": key})
        if part["full_comparison_available"] != "true":
            errors.append({"row": row_number, "error": "Comparison unavailable", "key": key})
        expected_role = "property" if row_number >= 13 else "scored"
        if populations[pop]["role_v1_0"] != expected_role or part["role_v1_0"] != expected_role:
            errors.append({"row": row_number, "error": "Role differs from requested section", "population": pop})
    if not parts:
        continue
    if len({p["unit"] for p in parts}) != 1:
        errors.append({"row": row_number, "error": "Cannot sum different units"})
    before = sum(int(p["supported_before"]) for p in parts)
    after = sum(int(p["supported_after"]) for p in parts)
    if (before, after) != expected:
        errors.append({"row": row_number, "expected": expected, "observed": (before, after)})
    if row_number == 5 and any((p["supported_before"], p["supported_after"]) != ("1", "0") for p in parts):
        errors.append({"row": 5, "error": "Each Compose source must be 1 → 0"})
    sources = "; ".join(f"{REF}:{p['_line']}" for p in parts)
    value = {"row": row_number, "population": "; ".join(names), "omitted": omitted,
             "unit": display_unit, "before": before, "after": after, "source": sources}
    VALUES.append(value)
    item = dict(value, label_lines=labels, y=y, property=row_number >= 13,
                omission_level=level, source_unit=parts[0]["unit"], identity=None)
    if row_number in (2, 3):
        part = parts[0]
        identity = (int(part["identity_before"]), int(part["identity_after"]))
        if identity != (2, 2) or (int(part["occurrence_before"]), int(part["occurrence_after"])) != expected:
            errors.append({"row": row_number, "error": "SCA identity/occurrence values differ", "record": part})
        item["identity"] = identity
        VALUES.append(dict(value, unit="identities", before=identity[0], after=identity[1]))
    DRAW.append(item)

all_positive = {key for key, rr in index.items() if int(rr[0]["lost_count"]) > 0
                and key[0] != "aigoat-http-properties"}
if all_positive != selected:
    errors.append({"error": "Requested selection does not equal all available losses",
                   "missing_from_selection": sorted(all_positive-selected),
                   "extra_selection": sorted(selected-all_positive)})
if errors:
    (ROOT / "QUESTIONS.md").write_text("# Figure 4 — Plotting stopped\n\n```json\n" +
                                       json.dumps(errors, ensure_ascii=False, indent=2) + "\n```\n")
    raise SystemExit("Validation failed; see QUESTIONS.md. No figure generated.")

with (ROOT / "fig04_values.csv").open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["row", "population", "omitted", "unit", "before", "after", "source"])
    writer.writeheader()
    writer.writerows(VALUES)

W, H = WIDTH_PT, 534
X0, X1, COUNT_X = 190, 332, 344
M = 8
FONTS = {False: TTFont(REGULAR_FONT), True: TTFont(BOLD_FONT)}
SHAPES, TEXTS, TEXT_QA, MARKER_QA = [], [], [], []

def n(x): return f"{float(x):.6f}".rstrip("0").rstrip(".")

def width(s, size=8, bold=False):
    f = FONTS[bold]
    cmap = f.getBestCmap()
    return sum(f["hmtx"][cmap[ord(c)]][0] for c in s)*size/f["head"].unitsPerEm

def text(s, x, y, size=8, bold=False, color=INK, anchor="start", id_=None):
    assert size >= MIN_FONT_PT
    w = width(s, size, bold)
    left = x-w if anchor == "end" else x-w/2 if anchor == "middle" else x
    assert left >= 0 and left+w <= W, (s, left, left+w)
    id_attr = f' id="{id_}"' if id_ else ""
    TEXTS.append(f'<text{id_attr} x="{n(x)}" y="{n(y)}" font-family="{FONT_FAMILY}" font-size="{n(size)}" font-weight="{700 if bold else 400}" fill="{color}" text-anchor="{anchor}">{escape(s)}</text>')
    TEXT_QA.append({"text": s, "x": float(x), "y": float(y), "size": size, "left": float(left), "right": float(left+w), "id": id_})

def line(x1, y1, x2, y2, color=GRAY, sw=.5, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    SHAPES.append(f'<path{id_attr} d="M {n(x1)} {n(y1)} L {n(x2)} {n(y2)}" fill="none" stroke="{color}" stroke-width="{n(sw)}"/>')

def circle(x, y, r, color, filled=False, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    SHAPES.append(f'<circle{id_attr} cx="{n(x)}" cy="{n(y)}" r="{n(r)}" fill="{color if filled else "#FFFFFF"}" stroke="{color}" stroke-width="1.1"/>')

def diamond(x, y, r, color, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    SHAPES.append(f'<path{id_attr} d="M {n(x)} {n(y-r)} L {n(x+r)} {n(y)} L {n(x)} {n(y+r)} L {n(x-r)} {n(y)} Z" fill="{color}"/>')

def position(after, before):
    # Retain the exact rational until vector-coordinate serialization.
    return Fraction(X0) + Fraction(after, before)*(X1-X0)

# Shape legend also explains the occurrence/identity comparison in the SCA rows.
circle(13, 14, 3.8, BLUE)
text("Before omission", 24, 16.8, size=8.5)
circle(139, 14, 3, BLUE, True)
text("After omission / occurrences", 150, 16.8, size=8.5)
diamond(327, 14, 3.2, BLUE)
text("Identities (SCA)", 338, 16.8, size=8.5)
line(M, 28, W-M, 28, "#DCE1E4", .6)
text("Omitted profile or stage", M, 43, size=8.5, bold=True)
text("Retained", (X0+X1)/2, 43, size=8.5, bold=True, anchor="middle")
text("Before → after · unit", COUNT_X, 43, size=8.5, bold=True)

# Grid lines are interrupted by the distinct property-population section.
for tick in (0, 25, 50, 75, 100):
    x = X0 + Fraction(tick, 100)*(X1-X0)
    line(x, 54, x, 386, "#E1E5E8", .45)
    line(x, 420, x, 482, "#E1E5E8", .45)
    line(x, 486, x, 490, GRAY, .6)
    text(str(tick), x, 501, anchor="middle")
for y in (80, 136, 168, 200, 328):
    line(M, y, W-M, y, "#DCE1E4", .55)
line(M, 393, W-M, 393, GRAY, 1.15)
text("Property population (not scored)", M, 408, size=8.5, bold=True)

for row in DRAW:
    row_id = row["row"]
    y = row["y"]
    color = GRAY if row["property"] else BLUE
    count = f"{row['before']} → {row['after']} {row['unit']}"
    if row["identity"]:
        ib, ia = row["identity"]
        count = f"occurrences {row['before']} → {row['after']} · identities {ib} → {ia}"
    assert width(count) <= W-M-COUNT_X
    count_id = f"row-{row_id}-counts"
    text(count, COUNT_X, y+2.8, id_=count_id)
    first_baseline = y+2.8-(len(row["label_lines"])-1)*5
    for i, label in enumerate(row["label_lines"]):
        assert width(label) <= X0-M-12, label
        text(label, M, first_baseline+i*10, id_=f"row-{row_id}-label-{i+1}")
    after_x = position(row["after"], row["before"])
    line(after_x, y, X1, y, color, 1.5, f"row-{row_id}-connector")
    circle(X1, y, 4, color, id_=f"row-{row_id}-before")
    circle(after_x, y, 3, color, True, id_=f"row-{row_id}-after")
    if row["identity"]:
        # A smaller diamond sits inside the open baseline circle at 100%;
        # both markers remain visible, with no position offset or value change.
        diamond(position(ia, ib), y, 2.65, color, id_=f"row-{row_id}-identity")
    MARKER_QA.append({"row": row_id, "before": row["before"], "after": row["after"],
                      "position_fraction": str(Fraction(row["after"], row["before"])),
                      "x_after_exact": str(after_x), "x_before": X1, "y": y,
                      "color": color, "printed_count": count,
                      "identity": row["identity"]})

line(X0, 486, X1, 486, GRAY, .7)
text("Supported instances retained", (X0+X1)/2, 516, size=8.5, anchor="middle")
text("(% of before omission)", (X0+X1)/2, 527, size=8.5, anchor="middle")
editable = ROOT / "fig04_omission_editable.svg"
editable.write_text(f'''<svg xmlns="http://www.w3.org/2000/svg" width="170mm" height="{n(H*25.4/72)}mm" viewBox="0 0 {n(W)} {n(H)}">
<title>Evidence lost when one profile or stage is omitted</title>
<desc>Fourteen omission rows. The open circle is before omission; the filled circle is after omission. SCA also has an identity diamond at 100 percent: occurrences are halved while identities remain complete. Property-population rows use the same shapes in gray. Raw counts and units are printed at the right.</desc>
<metadata>Values: {REF}, SHA-256 {HASHES[str(A5)]}. All 88 omission series have identical recorded numerical values across blocks 1–5. Block 1 is drawn. A1 supplies population names and roles only. The sole aggregation is four Compose service-property populations, each 1 to 0. Fractional positions are exact until vector serialization.</metadata>
<rect width="{n(W)}" height="{n(H)}" fill="#FFFFFF"/>
<g id="geometry">{''.join(SHAPES)}</g>
<g id="labels">{''.join(TEXTS)}</g>
</svg>''', encoding="utf-8")

for filename, options in [
    ("fig04_omission.pdf", ["--export-area-page", "--export-type=pdf"]),
    ("fig04_omission.svg", ["--export-text-to-path", "--export-plain-svg", "--export-type=svg"]),
    ("fig04_omission.png", ["--export-area-page", "--export-dpi=600", "--export-type=png"]),
]:
    subprocess.run(["inkscape", str(editable), *options, "--export-filename="+str(ROOT/filename)],
                   check=True, capture_output=True)

doc = fitz.open(ROOT / "fig04_omission.pdf")
assert len(doc) == 1
page = doc[0]
spans = [s for b in page.get_text("dict")["blocks"] if "lines" in b for l in b["lines"] for s in l["spans"]]
assert min(s["size"] for s in spans) >= 7.99999
assert all("NimbusSans" in s["font"] for s in spans)
assert not page.get_images()
assert abs(page.rect.width/72*25.4-170) < .001
for s in spans:
    x0, y0, x1, y1 = s["bbox"]
    assert x0 >= 0 and y0 >= 0 and x1 <= W+.01 and y1 <= H+.01, s
pdf_text = unicodedata.normalize("NFKC", page.get_text())
for marker in MARKER_QA:
    assert marker["printed_count"] in pdf_text, marker
assert "Property population (not scored)" in pdf_text
page.get_pixmap(matrix=fitz.Matrix(3, 3), alpha=False).save(WORK / "pdf_review.png")
png = Image.open(ROOT / "fig04_omission.png")
png.load()
assert png.width == 4016 and all(abs(v-600) < .01 for v in png.info["dpi"])
preview = png.copy()
preview.thumbnail((1600, 1800))
preview.save(ROOT / "fig04_preview.png")
ImageOps.grayscale(preview).save(WORK / "grayscale_review.png")
publication = etree.parse(str(ROOT / "fig04_omission.svg"))
ns = "{http://www.w3.org/2000/svg}"
assert not publication.findall(".//"+ns+"text") and not publication.findall(".//"+ns+"image")

for path, digest in HASHES.items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
for original, relative in [(A5, "K_tables/A5_omission.csv"), (A1, "K_tables/A1_populations.csv")]:
    copy = ROOT / relative
    copy.parent.mkdir(exist_ok=True)
    if original.resolve() != copy.resolve():
        shutil.copyfile(original, copy)
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == HASHES[str(original)]

report = {"source": REF, "source_sha256": HASHES[str(A5)], "A1_sha256": HASHES[str(A1)],
          "all_88_omission_series_identical_across_five_blocks": True, "checks": checks,
          "drawn_rows": len(DRAW), "values_csv_records": len(VALUES), "selected_series": len(selected),
          "only_requested_aggregation": "Compose: four service-property populations, each 1 → 0, sum 4 → 0",
          "A1_usage": "population identifiers, layers and roles only; no numerical values",
          "values_file_unit_convention": "displayed unit; SCA identities use A5 identity_before/identity_after",
          "markers": MARKER_QA, "text_layout": TEXT_QA, "size_mm": [170, H*25.4/72],
          "png_size": list(png.size), "png_dpi": list(png.info["dpi"]),
          "pdf_minimum_font_size_raw": min(s["size"] for s in spans), "pdf_raster_images": 0,
          "source_evidence_unchanged": True,
          "population_roles": {p: populations[p] for p in {p for _,names,*_ in SPECS for p in names}}}
(WORK / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
print(json.dumps({k:v for k,v in report.items() if k not in {"checks", "markers", "text_layout", "population_roles"}}, indent=2))
