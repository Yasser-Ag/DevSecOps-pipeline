# Reproducibility

Offline replay reads recorded evidence. It does not measure a target again or independently validate the authors' reference judgments. Run commands from the repository root in the pinned Python environment.

## Evidence chain

| Input | Script | Checked output |
|---|---|---|
| Static reports and receipts | `replay_static_linking.py` | 375 counts, statuses, scoped interpretations and frozen links |
| Dynamic reports, proxy traces and controls | `replay_dynamic_linking.py` | 90 jobs; 60 eligible and 30 limited |
| Recorded generation requests and probes | `replay_reference_checks.py` | Five jobs, 20 request observations, 40 reference checks |
| Verified native-report links | `replay_supported_results.py` | 490 coverage rows and 180 population/stage omission ledgers |
| Reparsed observations and reference identities | `replay_grouping.py` | 30 domain/block checks, including preserved unavailability |
| Packet descriptors, responses and validator | `replay_triage.py` | 352 packets and 704 complete validator outputs |
| Frozen derived tables | `reproduce_tables.py`, `reproduce_figures.py` | Numbered CSVs, figures and exact source values |

The assertion catalog records the frozen interpretation. Reapplying it tests whether reports reproduce those links; it does not discover new truth labels. Descriptive populations remain descriptive. The combined AIGoat grouping comparison remains unavailable. The CI amendment does not reclassify the v1.0 population table.

## Level 1

```sh
python scripts/fetch_fonts.py
python scripts/verify_release.py --output .replay/level1
```

This verifies the file manifest and study counts, reconstructs 24 tables and six figures, and compares table bytes and numerical figure-value CSVs. Graphics are regenerated; numerical values, rather than PDF/SVG encoding, define scientific equality. Supplementary Table S4 preserves all five omission blocks. S7 distinguishes class counts from individual invalid-response records.

Tables 1, 2, 3 and 10 include structured bibliographic, material, tool and interpretive descriptions. Their supplied CSVs are reproducible editorial data, not scanner-derived outcomes. References and protocol judgments still require scientific reading.

## External Java sources

OWASP Benchmark Java sources are GPL-2.0 and are not bundled under Apache-2.0 or CC BY. `config/benchmark_sources.json` identifies 23 files at revision `20cbf3d11123347e47ed89541e6942836def53f7`. Retrieval checks each file's SHA-256 and applies the recorded comment transformation while preserving original line numbers.

The fallback is `swh:1:rev:20cbf3d11123347e47ed89541e6942836def53f7`. The archived revision and one file were checked. The fetcher tries the pinned upstream source and then Software Heritage; future service availability is not assumed.

```sh
python scripts/replay_triage.py --evidence evidence --source-cache .source_cache --output .replay/triage --fetch-sources
```

The cache and restored excerpts retain GPL-2.0 and are excluded from release archives. Original packet reconstruction was checked privately; only its outcome and original packet hash are published. Public reconstruction checks the distinct masked canonical hash.

## Level 2

Extract the static, dynamic, triage and metadata archives together so their common root is `evidence/`. Verify archive hashes before extraction.

```sh
python scripts/replay_linking.py --evidence evidence --source-cache .source_cache --output .replay/native --fetch-sources
```

Omit `--fetch-sources` after the cache has been populated for offline use. The wrapper executes the evidence-chain commands in dependency order. A missing input or failed comparison is an error, not a skipped check. Its `verification.json` records elapsed time and completion.

The combined display and native check is:

```sh
python scripts/verify_release.py --evidence evidence --source-cache .source_cache --output .replay/complete
```

Runtime controls are recorded evidence, not fresh probes. Static sampled process-tree RSS, dynamic command-phase intervals and model-request latency have different scopes. They are not pooled. KICS scanner RSS is unavailable because its process tree was not measured inside the container.

## Integrity after masking

`data/derived/masking_manifest.csv` relates published paths to original/public file hashes. Original native-report identities also appear in replay contracts. Full original-to-public names and private packet checks are not distributed. A citation of the form `original_sha256:...#L...` identifies a retained source witness, not a public file path.

HTTP projections check hashes of public masked bodies; original hashes remain provenance witnesses. Same-value masking preserves equality between corresponding traces. Credential-value hashes are removed. Synthetic private keys are absent; permitted file hashes and public-key fingerprints remain available for grouping.

All complete validator outputs, including errors and conservative fallbacks, are compared with the recordings. Exact replay of the validator does not establish semantic accuracy of an explanation.

## Level 3

New measurements are outside the verified offline replay. Use `config/plan.json`, `config/dynamic_plan.json`, schedules, asset locks, model identities and protocol to prepare an isolated Docker laboratory. Execution contracts in `src/pipeline/` document commands, resets, timeouts and measurement. They preserve the historical laboratory contract; they are not an installer for an arbitrary host. The archived preliminary workflow is disabled.

Upstream source trees, container layers, weights and database payloads must be obtained separately under their licenses and checked against pinned identities. A current database is not the recorded snapshot. Generate new test credentials, requalify reference probes and keep new results in a separate campaign.

Masked model inputs differ in machine prefixes, test-account identifiers, vehicle identifiers and secret-value fingerprints. Fresh inference is not guaranteed to reproduce recorded output bit for bit. Hardware-dependent time and memory can also differ.

## Validated figures and supplementary workbook

`docs/FIGURE_REPLAY.md` describes the approved drawing sources and their exact value exports. Nimbus Sans is fetched separately at the fixed URW base35 release with archive and font hashes checked; no other font is silently substituted. The six validated PDFs retain their embedded fonts. The Excel workbook can be recreated with `python scripts/export_supplementary.py --output .replay/Supplementary_Tables_S1-S9.xlsx --report .replay/excel_check.json`. The nine CSVs are authoritative. Numeric OOXML cells retain the original decimal text without rounding; spreadsheet applications may display fewer significant digits. No formulas are included.
