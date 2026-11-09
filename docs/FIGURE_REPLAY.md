# Figure replay

The PDF and PNG files in `results/figures/` are the validated delivery, not replacements made during packaging. `results/figures/figure_manifest.json` records their identities and the editable SVGs.

Run `python scripts/reproduce_figures.py --output .replay/figures`. Inkscape 1.2.2 and fontconfig must be on PATH; Python packages are pinned in `requirements.txt`. Retrieve the pinned font files first with `python scripts/fetch_fonts.py`. The verified files in `src/figures/fonts/` are selected by the packaged fontconfig configuration; no fallback is permitted.

The five numerical CSVs are re-exported from `data/derived/` using the CSV-writing portion of the final builders. No scanner, model or frozen analysis is run. The final exporter uses approved SVG drawings and `finalize_labels.py`; this preserves the manual layout and label adjustments made after the initial builders. Regenerating the initial drawing alone would discard those approved adjustments. Figure 1 is a design diagram with `fig01/working/labels_final.json`, not a sixth numerical CSV.

The validated CSVs retain their original source citation labels for byte identity. These labels are provenance labels, not installed paths: `A1_populations.csv` maps to `data/derived/reference_populations.csv`; `A4_grouping.csv` to `grouping.csv`; `A5_omission.csv` to `omissions.csv`; `A6_static_profiles.csv` to `static_profiles.csv`; `A7_dynamic_profiles.csv` to `dynamic_profiles.csv`; and `triage_by_class.csv` to the same basename in `data/derived/`. CSV line references use logical record positions of the retained exports. The packaged copies beside the builders preserve the delivery inputs; replay reads `data/derived/` directly.

PDF and PNG bytes can vary with exporter libraries even if the drawings are unchanged. The release audit records both hashes and maximum per-channel differences at native PNG resolution and at 600 dpi for PDF pages. The validated files remain the publication reference.
