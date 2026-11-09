# Third-party material

Apache-2.0 covers the authors' code. CC BY 4.0 covers the authors' structured
reference annotations, derived measurements and documentation. These statements
do not relicense upstream software, source excerpts or advisory descriptions.
Upstream attribution and license notices remain applicable to those materials.

| Project | Pinned revision or identity | Included material | License and source |
|---|---|---|---|
| OWASP Benchmark Java | `20cbf3d11123347e47ed89541e6942836def53f7` | File/line references, hashes and labels; Java source text is retrieved separately | [GPL-2.0 at the pinned revision](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/20cbf3d11123347e47ed89541e6942836def53f7/LICENSE) |
| crAPI | `b5fc307f3e5f875809b095b771108ef342a33724` | Selected workflow/configuration observations, masked configuration and source metadata | Apache-2.0; `docs/licenses/crapi.txt` |
| TerraGoat | `729f8da62c6a85ce4af5ad3d123de97776d954c4` | Selected Terraform and workflow files and observations | Apache-2.0; `docs/licenses/terragoat.txt` |
| Kubernetes Goat | `723a0db478f050d173d23b4ce5044b65bce0bdd0` | Selected manifests and derived resource-scope views | MIT; `docs/licenses/kubernetes_goat.txt` |
| CI/CD Goat | `0ed10925f3983857cf219b2ac1c327b861fcccca` | One selected workflow and its observations | Apache-2.0; `docs/licenses/cicd_goat.txt` |
| AIGoat | `e1c538badb93c6c1c2307096ab5d709a9ee0fe55` | Platform/configuration observations and masked laboratory traces; no training corpus | Apache-2.0 for platform code; see the separate training-content boundary below |
| Red Hat UBI 9 | Four image digests in Supplementary Table S5 | Package/image metadata, vendor-state references and scanner observations; no image layers or package binaries | [UBI distribution terms and image-specific package licenses](https://catalog.redhat.com/en/software/base-images) |
| Qwen and Gemma deployments | Repository, revision, file and SHA-256 in `config/model_identities.json` | Identities and recorded model responses; no weights | The pinned model cards declare Apache-2.0; retrieve weights from the recorded repositories and consult their notices |
| Scanners and parser dependencies | Versions and license-source hashes in `config/tool_licenses.csv` and `requirements.txt` | Author adapters and recorded outputs; no scanner binaries, scanner source trees or vulnerability databases | Each upstream license applies; tool licenses do not automatically license every item quoted in a report |

Selected source files remain under their upstream licenses, including where a
copy was masked or split into resource documents. Those transformations are
recorded in the control-source and masking manifests. They are not endorsements
by the upstream projects.

AIGoat's `NOTICE` distinguishes Apache-2.0 platform code from CC BY-NC-SA 4.0
training material in `app/challenges/`, `prompts/`, `docs/`, `media/` and selected
configuration subdirectories. Its `config/config.yml` is platform configuration;
`config/labs.yml` is training content. See `docs/licenses/aigoat_notice.txt` and
`docs/licenses/aigoat_configuration_notice.txt`. References to a training file's
name or a masked finding are not a redistribution of that training file. This
release does not include a complete training file or an educational scenario.

## External Java retrieval

`scripts/fetch_external_sources.py` retrieves the pinned Java files and verifies
their SHA-256 values. The packet descriptors retain the upstream path, line
range and excerpt hash. The recorded transformation of comments and line
numbers is applied before comparing reconstructed packet hashes. The fallback
revision is `swh:1:rev:20cbf3d11123347e47ed89541e6942836def53f7`.

```sh
python3 scripts/replay_triage.py --evidence evidence --source-cache .source_cache --output reproduced/triage --fetch-sources
```

The source cache and reconstructed Java text retain GPL-2.0. They are deliberately
excluded from the code and data archives. Restoring the sources does not grant
permission to redistribute them under the authors' Apache-2.0 or CC BY license.

## Advisory descriptions and databases

Reports retain upstream advisory identifiers and attribution. Descriptions from
the [GitHub Advisory Database](https://github.com/github/advisory-database/blob/main/LICENSE.md)
are supplied under CC BY 4.0. Other upstream notices remain applicable to their
respective descriptions. The structured vendor-state annotations in the study
are author-created references with source URLs and hashes. Complete proprietary
or otherwise nonredistributable database snapshots are not included. Fetching a
current database is not equivalent to the recorded snapshot.

## Target-side generation model

The AIGoat generation workload is distinct from the two triage models. Its
recorded image/runtime identities are preserved in the dynamic evidence. No
Ollama model weights or model image layers are redistributed. This release makes
no additional license claim for those weights; a new experimental deployment
must check the upstream terms for the pinned target model.

## Figure fonts

Nimbus Sans is retrieved from the fixed URW base35 upstream release `20200910`, mirrored as its unchanged source archive by Debian. The source URL, archive hash, member names and each font SHA-256 are in `config/font_sources.json`. No font binary is redistributed in this package. `python scripts/fetch_fonts.py` retrieves and verifies them; `--archive` uses the identical cached archive offline.

The fonts retain AGPL-3 with the font embedding exception. The notice is in `src/figures/fonts/LICENSE.txt`; it explicitly permits embedding the font in a PostScript or PDF document regardless of that document's license. The validated PDFs keep their embedded fonts. The author's code and data licenses do not relicense the separately fetched fonts. Missing or altered font files stop figure replay with an explicit error.
