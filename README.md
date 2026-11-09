# What Alert Counts Hide

Reproducibility material for **What Alert Counts Hide: Grouping, Stage Omission and LLM Triage in DevSecOps Pipelines**, by Yasser Agzayal and Mohammed Bouhorma. Article DOI: **to be added**. Version **1.0.0**. Intended artifact DOI: **10.5281/zenodo.24016866**. Publication of this locally prepared package is controlled by the authors.

The study asks whether grouping alerts, omitting scanner stages, or applying local-model triage preserves the reference instances supported by the original outputs. Component/advisory identities, artifact occurrences, configuration properties and native alerts remain separate units. The results concern a fixed laboratory and scoped references, not a general ranking of scanners or models.

## Quick start

Use Python 3.13, Inkscape 1.2.2, fontconfig and an empty output directory. Offline replay needs no scanner, target, Docker daemon or model.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/fetch_fonts.py
.venv/bin/python scripts/verify_release.py --output .replay/level1
```

This checks release hashes and study counts, exports **24 CSV tables** (10 main, five appendix and nine supplementary tables), and renders **six figures**. Tables and five numerical figure-value CSVs are compared exactly with the supplied results. Figure 1 is a source-linked design diagram. Outputs and the verification receipt are under `.replay/level1/`. The verification receipt records elapsed time on the current machine.

Individual exports:

```sh
.venv/bin/python scripts/reproduce_tables.py --output .replay/tables
.venv/bin/python scripts/reproduce_figures.py --output .replay/figures
```

The published PDF/PNG files are the author-validated exports. Replay calls the final builders to re-export the five recorded value CSVs, then applies the documented label corrections to the approved editable SVGs and renders them with the separately fetched, hash-verified fonts. Figure 1 uses its approved labels JSON and has no numerical CSV. PDF figures are vector graphics; PNG exports are 600 dpi. CSVs retain per-block values, units, denominators and limitations. The five KICS profiles have no measured scanner RSS because the sampled tree contains the Docker client.

## Replay from recorded reports

After publication, obtain the evidence archives from the artifact record, verify `SHA256SUMS`, and extract them together into the repository root. Their shared directory is `evidence/`, intentionally ignored by Git. Java excerpts are retrieved separately under their GPL license.

```sh
.venv/bin/python scripts/verify_release.py --output .replay/level2 --evidence evidence --source-cache .source_cache --fetch-sources
```

Only `--fetch-sources` permits network retrieval, restricted to pinned, hash-checked Java sources. Omit it after populating the cache for offline replay. The command reparses 375 static invocations and 90 dynamic jobs, checks five generation jobs, reconstructs support, grouping and omission, and revalidates 704 recorded model responses. Allow several minutes. No scanner, model or target is executed.

[REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) describes the evidence chain and new-experiment requirements. New measurements require an isolated Docker laboratory and pinned assets. Historical vulnerability database payloads, image layers and model weights are not redistributed. Fresh model inference on masked packets is not guaranteed to match the recordings.

## Material and layout

The retained material includes selected OWASP Benchmark Java cases, crAPI and AIGoat files and deployed APIs, TerraGoat Terraform, Kubernetes Goat manifests, CI/CD Goat workflows, four UBI 9 images, and constructed controls. Static file analysis is distinguished from deployment; Table 2 supplies the exact scope and revisions.

| Directory | Contents |
|---|---|
| `protocol/` | Frozen protocol, triage amendments and declared launcher repairs |
| `config/` | Profiles, schedules, input/tool/model identities and release hashes |
| `src/pipeline/` | Execution contracts, native adapters and reference-linking code |
| `src/analysis/` | Frozen triage validator |
| `src/figures/` | Article figure renderers |
| `data/references/` | References, binding rules and replay contracts |
| `data/controls/` | Executed control sources and probe definitions |
| `data/derived/` | Frozen observations, ledgers, instance support and derived tables |
| `results/` | Numbered tables, figures and supplementary datasets |
| `preliminary/` | Permitted preliminary pipeline observations and run metadata |
| `scripts/` | Offline replay and verification entry points |
| `docs/` | Evidence map, masking, licenses, replay and security audit |

[MANUSCRIPT_MAP.md](docs/MANUSCRIPT_MAP.md) maps each article element to files and commands. The 35 populations retain v1.0 roles: 16 scored, two property and 17 descriptive. The CI audit is separate. Limited jobs and unavailable comparisons are not converted into negative findings.

## Masking and limits

Credentials and host-specific identifiers are replaced consistently on copies. The [masking policy](docs/MASKING.md) distinguishes original/public hashes and explains external Java reconstruction. Originals remain private. The public aggregate 32-proposition reference review is distinct from separate author-held checks of model explanations. Raw model explanations remain inspectable.

The preliminary phase supports Appendix C only. Its 31 workflow runs are not pooled with the final campaign. Preliminary reference-evaluation outputs are outside the article and this package.

## License and citation

Author code: Apache-2.0. Author annotations, derived data and documentation: CC BY 4.0. Upstream materials retain their licenses; see [THIRD_PARTY.md](THIRD_PARTY.md). Images, weights and the Java source cache are excluded. Cite the artifact using [CITATION.cff](CITATION.cff), and add the article citation when its DOI is assigned.

Nimbus Sans comes from the fixed URW base35 release `20200910`, under AGPL-3 with the font embedding exception. `scripts/fetch_fonts.py` verifies the source archive and each font SHA-256 from `config/font_sources.json`. Font files are fetched separately and are not redistributed here. Figure replay stops if a required font is missing or differs; it never substitutes another font. The validated PDFs retain their embedded fonts as allowed by that exception.
