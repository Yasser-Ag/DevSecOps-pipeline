#!<PROJECT_ROOT> python3
"""Render recorded A6/A7 profile summaries; never recompute their statistics.

Usage: python3 build_fig05.py [A6_static_profiles.csv] [A7_dynamic_profiles.csv]
All geometry uses points; all CSV values preserve the input decimal strings.
"""
from pathlib import Path
from collections import Counter
from decimal import Decimal
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

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "working"
WORK.mkdir(exist_ok=True)
A6 = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "K_tables/A6_static_profiles.csv"
A7 = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "K_tables/A7_dynamic_profiles.csv"
HASHES = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (A6, A7)}

def read(path):
    out = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames
        while True:
            line = reader.line_num + 1
            try:
                row = next(reader)
            except StopIteration:
                break
            row["_line"] = line
            out.append(row)
    return out, reader.fieldnames

STATIC, STATIC_FIELDS = read(A6)
DYNAMIC, DYNAMIC_FIELDS = read(A7)
BANDS = [
    ("SAST", "semgrep", "Semgrep", 3),
    ("SAST", "findsecbugs", "FindSecBugs", 1),
    ("SAST", "bandit", "Bandit", 1),
    ("Packages", "dependency-check", "Dependency-Check", 1),
    ("Packages", "trivy", "Trivy (packages)", 11),
    ("Packages", "grype", "Grype", 10),
    ("Packages", "syft", "Syft", 10),
    ("Secrets", "gitleaks", "Gitleaks", 2),
    ("Secrets", "trivy-secret", "Trivy (secrets)", 2),
    ("Configuration", "checkov", "Checkov", 12),
    ("Configuration", "hadolint", "Hadolint", 3),
    ("Configuration", "kics", "KICS", 5),
    ("Configuration", "trivy-config", "Trivy (configuration)", 9),
    ("Configuration", "kubescape", "Kubescape", 2),
    ("Workflows", "zizmor", "zizmor", 3),
]
TOOL_ORDER = ["zap", "nuclei", "schemathesis", "restler"]
TOOL_LABEL = {"zap": "ZAP", "nuclei": "Nuclei", "schemathesis": "Schemathesis", "restler": "RESTler"}
errors = []
if len(STATIC) != 75 or len(DYNAMIC) != 18:
    errors.append({"profile_counts": [len(STATIC), len(DYNAMIC)], "expected": [75, 18]})
if len({r["profile"] for r in STATIC}) != 75 or len({r["profile"] for r in DYNAMIC}) != 18:
    errors.append({"error": "Duplicate profile identifiers"})
band_counts = Counter(r["tool"] for r in STATIC)
if band_counts != Counter({tool: count for _, tool, _, count in BANDS}):
    errors.append({"error": "Band counts differ", "observed": dict(band_counts)})
for r in STATIC:
    if r["n_blocks"] != "5":
        errors.append({"profile": r["profile"], "n_blocks": r["n_blocks"]})
    expected_role = "I" if r["tool"] == "syft" else "D"
    if r["role"] != expected_role:
        errors.append({"profile": r["profile"], "role": r["role"]})
    lo, md, hi = [Decimal(r[k]) for k in ("time_min_s", "time_median_s", "time_max_s")]
    if not Decimal("0.3") <= lo <= md <= hi <= 40:
        errors.append({"profile": r["profile"], "time_range": [str(lo), str(md), str(hi)]})
    rss = r["sampled_scanner_rss_max_median_MiB"]
    if r["tool"] == "kics":
        if r["memory_measured"] != "no" or rss != "" or r["rss_scanner_min_MiB"] != "" or r["rss_scanner_max_MiB"] != "":
            errors.append({"profile": r["profile"], "error": "Unexpected KICS memory measurement"})
    elif r["memory_measured"] != "yes" or not rss or not Decimal(10) <= Decimal(rss) <= 2000:
        errors.append({"profile": r["profile"], "error": "Missing or out-of-range scanner RSS", "rss": rss})
    else:
        rss_min, rss_max = r["rss_scanner_min_MiB"], r["rss_scanner_max_MiB"]
        if not rss_min or not rss_max or not Decimal(10) <= Decimal(rss_min) <= Decimal(rss) <= Decimal(rss_max) <= 2000:
            errors.append({"profile": r["profile"], "error": "Missing or invalid recorded scanner RSS range"})
for r in DYNAMIC:
    if r["target"] not in ("crapi", "aigoat") or r["tool"] not in TOOL_ORDER:
        errors.append({"profile": r["profile"], "error": "Unexpected target or tool"})
    if r["eligibility"] not in ("eligible", "limited") or r["n_jobs"] != "5":
        errors.append({"profile": r["profile"], "error": "Unexpected job count or eligibility"})
    lo, md, hi = [Decimal(r[k]) for k in ("command_phase_min_s", "command_phase_median_s", "command_phase_max_s")]
    if not Decimal("0.3") <= lo <= md <= hi <= 40:
        errors.append({"profile": r["profile"], "time_range": [str(lo), str(md), str(hi)]})
    if not 0 <= int(r["native_count_min"]) <= int(r["native_count_max"]):
        errors.append({"profile": r["profile"], "error": "Invalid recorded native count range"})
if errors:
    (ROOT / "QUESTIONS.md").write_text("# Figure 5 — Plotting stopped\n\n```json\n" +
                                       json.dumps(errors, indent=2) + "\n```\n")
    raise SystemExit("Source validation failed; see QUESTIONS.md.")

# Preserve the source order within each band and target/tool group.
# Corresponding static profiles occupy exactly the same y in panels a and b.
ORDERED_STATIC = [r for _, tool, _, _ in BANDS for r in STATIC if r["tool"] == tool]
ORDERED_DYNAMIC = [r for target in ("crapi", "aigoat") for tool in TOOL_ORDER
                   for r in DYNAMIC if r["target"] == target and r["tool"] == tool]
band_label = {tool: label for _, tool, label, _ in BANDS}

def native(r):
    lo, hi = r["native_count_min"], r["native_count_max"]
    return lo if lo == hi else lo+"–"+hi

def dynamic_label(r):
    prefix = r["target"]+"-"+r["tool"]+"-"
    assert r["profile"].startswith(prefix)
    suffix = r["profile"][len(prefix):]
    tool = TOOL_LABEL[r["tool"]]
    if r["tool"] == "restler":
        actor, condition = suffix.split("-", 1)
        assert actor in ("a", "b")
        return tool+" · "+actor+" · "+condition.replace("-", " ")
    if suffix == "invalid":
        return tool+" · invalid"
    assert suffix.startswith("valid-")
    actor = suffix[len("valid-"):]
    assert actor in ("a", "alice")
    return tool+" · valid ("+actor+")"

VALUES = []
for panel in ("a", "b"):
    for r in ORDERED_STATIC:
        rss = r["sampled_scanner_rss_max_median_MiB"]
        VALUES.append({"panel": panel, "profile": r["profile"], "tool_band": band_label[r["tool"]],
                       "role_or_eligibility": r["role"],
                       "min": r["time_min_s"] if panel == "a" else "",
                       "median": r["time_median_s"] if panel == "a" else rss,
                       "max": r["time_max_s"] if panel == "a" else "",
                       "rss_MiB": rss if panel == "b" else "", "native": "",
                       "source": f"K_tables/A6_static_profiles.csv:{r['_line']}",
                       "rss_min": r["rss_scanner_min_MiB"] if panel == "b" else "",
                       "rss_max": r["rss_scanner_max_MiB"] if panel == "b" else ""})
for r in ORDERED_DYNAMIC:
    VALUES.append({"panel": "c", "profile": r["profile"], "tool_band": TOOL_LABEL[r["tool"]],
                   "role_or_eligibility": r["eligibility"], "min": r["command_phase_min_s"],
                   "median": r["command_phase_median_s"], "max": r["command_phase_max_s"],
                   "rss_MiB": "", "native": native(r),
                   "source": f"K_tables/A7_dynamic_profiles.csv:{r['_line']}", "rss_min": "", "rss_max": ""})
with (ROOT / "fig05_values.csv").open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["panel", "profile", "tool_band", "role_or_eligibility", "min", "median", "max", "rss_MiB", "native", "source", "rss_min", "rss_max"])
    writer.writeheader()
    writer.writerows(VALUES)

W, H = WIDTH_PT, 670
A0, A1, B0, B1 = 112, 279, 305, 471
C0, C1, NATIVE_X = 146, 409, 448
TOP = 26
FONTS = {False: TTFont(REGULAR_FONT), True: TTFont(BOLD_FONT)}
BACK, GRID, DATA, TEXTS, TEXT_QA, MARKER_QA, BAND_QA = [], [], [], [], [], [], []

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
    TEXT_QA.append({"text": s, "x": x, "y": y, "left": left, "right": left+w, "size": size, "id": id_})

def line(x1, y1, x2, y2, color=GRAY, sw=.55, layer=GRID, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    layer.append(f'<path{id_attr} d="M {n(x1)} {n(y1)} L {n(x2)} {n(y2)}" fill="none" stroke="{color}" stroke-width="{n(sw)}"/>')

def rect(x, y, w, h, color, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    BACK.append(f'<rect{id_attr} x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}" fill="{color}"/>')

def circle(x, y, filled, r=1.1, sw=.55, id_=None):
    id_attr = f' id="{id_}"' if id_ else ""
    DATA.append(f'<circle{id_attr} cx="{n(x)}" cy="{n(y)}" r="{n(r)}" fill="{BLUE if filled else "#FFFFFF"}" stroke="{BLUE}" stroke-width="{n(sw)}"/>')

def log_x(value, low, high, left, right):
    return left+(math.log10(float(value))-math.log10(low))/(math.log10(high)-math.log10(low))*(right-left)

def axis(left, right, low, high, ticks, y_top, y_bottom, y_axis, tick_y, segments=None):
    segments = segments or [(y_top, y_bottom)]
    for value, label in ticks:
        x = log_x(value, low, high, left, right)
        for top, bottom in segments:
            line(x, top, x, bottom, "#DFE3E6", .4)
        line(x, y_axis, x, y_axis+3, GRAY, .6)
        text(label, x, tick_y, anchor="middle")
    line(left, y_axis, right, y_axis, GRAY, .65)

def interval_dot(r, panel, y, left, right, fields, filled, radius):
    lo, md, hi = [r[f] for f in fields]
    xs = [log_x(v, .3, 40, left, right) for v in (lo, md, hi)]
    id_base = f"{panel}-{r['profile']}"
    line(xs[0], y, xs[2], y, BLUE, .7, DATA, id_base+"-range")
    circle(xs[1], y, filled, radius, .6, id_base+"-median")
    MARKER_QA.append({"panel": panel, "profile": r["profile"], "values": [lo, md, hi],
                      "x_min": xs[0], "x_median": xs[1], "x_max": xs[2], "y": y,
                      "filled": filled, "radius": radius})

text("Tool (profiles)", 8, 14, size=8.5, bold=True)
text("(a) Invocation time (s)", A0, 14, size=9, bold=True)
text("(b) Sampled peak RSS (MiB)", B0, 14, size=9, bold=True)
cursor = TOP
for index, (stage, tool, label, expected) in enumerate(BANDS):
    profiles = [r for r in STATIC if r["tool"] == tool]
    count = len(profiles)
    # A 3 pt fixed pitch keeps each profile on a separate reproducible row.
    # Bands have at least a 3 pt margin beyond the outer profile centers.
    height = max(12, 3*(count-1)+6)
    center = cursor+height/2
    rect(5, cursor, W-10, height, LIGHT if index % 2 == 0 else "#FFFFFF", "band-"+tool)
    if index and stage != BANDS[index-1][0]:
        line(5, cursor, W-5, cursor, "#BBC2C7", .65)
    label_text = f"{label} ({count})"
    assert width(label_text) < A0-16
    text(label_text, 8, center+2.6, id_="band-label-"+tool)
    for i, r in enumerate(profiles):
        y = center+(i-(count-1)/2)*3
        assert cursor+3 <= y <= cursor+height-3
        interval_dot(r, "a", y, A0, A1, ("time_min_s", "time_median_s", "time_max_s"), r["role"] == "D", 1.1)
        rss = r["sampled_scanner_rss_max_median_MiB"]
        if r["memory_measured"] == "yes":
            x = log_x(rss, 10, 2000, B0, B1)
            rss_min, rss_max = r["rss_scanner_min_MiB"], r["rss_scanner_max_MiB"]
            x_min = log_x(rss_min, 10, 2000, B0, B1)
            x_max = log_x(rss_max, 10, 2000, B0, B1)
            line(x_min, y, x_max, y, BLUE, .7, DATA, f"b-{r['profile']}-range")
            circle(x, y, r["role"] == "D", 1.1, .6, f"b-{r['profile']}-median")
            MARKER_QA.append({"panel": "b", "profile": r["profile"], "values": [rss_min, rss, rss_max],
                              "x_min": x_min, "x_median": x, "x_max": x_max,
                              "y": y, "filled": r["role"] == "D", "radius": 1.1})
    if tool == "kics":
        text("not measured", (B0+B1)/2, center+2.6, color=GRAY, anchor="middle", id_="kics-not-measured")
    BAND_QA.append({"stage": stage, "tool": tool, "label": label_text, "count": count,
                    "top": cursor, "height": height, "source_lines": [r["_line"] for r in profiles],
                    "profiles_in_vertical_order": [r["profile"] for r in profiles]})
    cursor += height
STATIC_BOTTOM = cursor
assert STATIC_BOTTOM == 323
TIME_TICKS = [(.3, "0.3"), (1, "1"), (3, "3"), (10, "10"), (40, "40")]
RSS_TICKS = [(10, "10"), (30, "30"), (100, "100"), (300, "300"), (2000, "2,000")]
axis(A0, A1, .3, 40, TIME_TICKS, TOP, STATIC_BOTTOM, 327, 339)
axis(B0, B1, 10, 2000, RSS_TICKS, TOP, STATIC_BOTTOM, 327, 339)
line(292, 5, 292, 342, "#DCE1E4", .5)

# Shared static legend for the recorded time and RSS ranges.
circle(114, 354, True, 2, .7)
text("detector profile", 123, 357)
circle(202, 354, False, 2, .7)
text("inventory profile", 211, 357)
line(301, 354, 314, 354, BLUE, .7, DATA)
text("min–max over five blocks", 321, 357)
line(5, 368, W-5, 368, "#BBC2C7", .65)

# Dynamic profiles use the same time-domain bounds as panel a.
text("(c) Dynamic profiles (command phase)", 8, 384, size=9, bold=True)
text("Native alerts", NATIVE_X, 384, size=8.5, bold=True, anchor="middle")
DYNAMIC_ROWS = []
for target, heading, heading_y, first_y in [("crapi", "crAPI", 398, 410), ("aigoat", "AIGoat", 539, 551)]:
    rows = [r for r in ORDERED_DYNAMIC if r["target"] == target]
    text(heading, 8, heading_y, size=8.5, bold=True)
    for i, r in enumerate(rows):
        y = first_y+i*10
        label = dynamic_label(r)
        assert width(label) <= C0-18, label
        text(label, 8, y+2.6, id_="label-"+r["profile"])
        text(native(r), NATIVE_X, y+2.6, anchor="middle", id_="native-"+r["profile"])
        interval_dot(r, "c", y, C0, C1,
                     ("command_phase_min_s", "command_phase_median_s", "command_phase_max_s"),
                     r["eligibility"] == "eligible", 2)
        DYNAMIC_ROWS.append({"profile": r["profile"], "label": label, "target": target, "tool": r["tool"],
                             "y": y, "native": native(r), "eligibility": r["eligibility"], "source_line": r["_line"]})
line(5, 528, W-5, 528, "#BBC2C7", .65)
axis(C0, C1, .3, 40, TIME_TICKS, 404, 607, 616, 629, segments=[(404, 525), (545, 607)])
text("Command phase time (s)", (C0+C1)/2, 644, size=8.5, anchor="middle")
circle(114, 659, True, 2, .7)
text("eligible job", 123, 662)
circle(202, 659, False, 2, .7)
text("limited job", 211, 662)
line(301, 659, 314, 659, BLUE, .7, DATA)
text("min–max over five blocks", 321, 662)

editable = ROOT / "fig05_cost_editable.svg"
editable.write_text(f'''<svg xmlns="http://www.w3.org/2000/svg" width="170mm" height="{n(H*25.4/72)}mm" viewBox="0 0 {n(W)} {n(H)}">
<title>Cost of each scanning profile</title>
<desc>Panels a and b share 15 tool bands covering 75 static profiles. Time and memory show recorded medians with min–max lines; the five KICS profiles are not measured for memory. Open static markers are inventory profiles. Panel c shows 18 dynamic command-phase profiles, grouped by target and tool, with native alert counts. Open dynamic markers are limited jobs. All axes are logarithmic.</desc>
<metadata>Numerical sources only: K_tables/A6_static_profiles.csv SHA-256 {HASHES[str(A6)]}; K_tables/A7_dynamic_profiles.csv SHA-256 {HASHES[str(A7)]}. Recorded summary strings are preserved in fig05_values.csv. No per-observation ledger was used. No memory range was inferred, and no Docker-client tree RSS substituted for KICS scanner RSS.</metadata>
<rect width="{n(W)}" height="{n(H)}" fill="#FFFFFF"/>
<g id="bands">{''.join(BACK)}</g>
<g id="axes-and-separators">{''.join(GRID)}</g>
<g id="profile-marks">{''.join(DATA)}</g>
<g id="labels">{''.join(TEXTS)}</g>
</svg>''', encoding="utf-8")
for name, options in [
    ("fig05_cost.pdf", ["--export-area-page", "--export-type=pdf"]),
    ("fig05_cost.svg", ["--export-text-to-path", "--export-plain-svg", "--export-type=svg"]),
    ("fig05_cost.png", ["--export-area-page", "--export-dpi=600", "--export-type=png"]),
]:
    temporary = WORK / ("export-"+name)
    subprocess.run(["inkscape", str(editable), *options, "--export-filename="+str(temporary)], check=True, capture_output=True)
    if name.endswith(".png"):
        with Image.open(temporary) as check_png:
            check_png.load()
    temporary.replace(ROOT/name)

doc = fitz.open(ROOT / "fig05_cost.pdf")
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
page.get_pixmap(matrix=fitz.Matrix(3,3), alpha=False).save(WORK / "pdf_review.png")
png = Image.open(ROOT / "fig05_cost.png")
png.load()
assert png.width == 4016 and all(abs(v-600) < .01 for v in png.info["dpi"])
preview = png.copy()
preview.thumbnail((1600, 2200))
preview.save(ROOT / "fig05_preview.png")
ImageOps.grayscale(preview).save(WORK / "grayscale_review.png")
svg = etree.parse(str(ROOT / "fig05_cost.svg"))
ns = "{http://www.w3.org/2000/svg}"
assert not svg.findall(".//"+ns+"text") and not svg.findall(".//"+ns+"image")
assert Counter(m["panel"] for m in MARKER_QA) == {"a":75,"b":70,"c":18}
for m in (m for m in MARKER_QA if m["panel"] == "b"):
    a = next(a for a in MARKER_QA if a["panel"] == "a" and a["profile"] == m["profile"])
    assert a["y"] == m["y"]
for path, digest in HASHES.items():
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
for original, relative in [(A6, "K_tables/A6_static_profiles.csv"), (A7, "K_tables/A7_dynamic_profiles.csv")]:
    copy = ROOT / relative
    copy.parent.mkdir(exist_ok=True)
    if original.resolve() != copy.resolve(): shutil.copyfile(original, copy)
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == HASHES[str(original)]

report = {"A6_sha256": HASHES[str(A6)], "A7_sha256": HASHES[str(A7)],
          "static_profiles": len(STATIC), "dynamic_profiles": len(DYNAMIC), "bands": BAND_QA,
          "band_count_sum": sum(b["count"] for b in BAND_QA),
          "source_role_counts": dict(Counter(r["role"] for r in STATIC)),
          "dynamic_eligibility_counts": dict(Counter(r["eligibility"] for r in DYNAMIC)),
          "no_summary_statistics_recomputed": True, "memory_range_unavailable_in_A6": False,
          "kics_memory_points_drawn": 0, "KICS_tree_RSS_not_used": True,
          "missing_memory_profiles": [r["profile"] for r in STATIC if r["memory_measured"] == "no"],
          "values_records": len(VALUES), "time_range_lines": 93, "rss_range_lines": 70, "markers": MARKER_QA,
          "dynamic_rows": DYNAMIC_ROWS, "text_layout": TEXT_QA,
          "size_mm": [170, H*25.4/72], "png_size": list(png.size), "png_dpi": list(png.info["dpi"]),
          "pdf_minimum_font_size_raw": min(s["size"] for s in spans), "pdf_raster_images": 0,
          "input_evidence_unchanged": True}
(WORK / "validation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n")
print(json.dumps({k:v for k,v in report.items() if k not in {"bands","markers","dynamic_rows","text_layout"}}, indent=2))
