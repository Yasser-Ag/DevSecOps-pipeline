# Amendment v1.1: support scoring for constructed CI workflow jobs

Date: 2026-11-03 (UTC). Population: `workflow-job:controls`.

## Reason and timing

The final v1.0 campaign scanned the constructed workflow files but retained this
population as descriptive, with linkage `pending`. This amendment adds a bounded
support score for its four positive job declarations. It does not change the
files, reference labels, scanner commands, tool versions, or stored reports.
Only the ten stored profile reports (two tools, five blocks) from
`static-scanners-final-20261023-01` are eligible. There is no new scanner execution.

This is a post-outcome amendment, not prospective preregistration. Development
observations and the old descriptive totals were available before this document.
This document must be committed alone before the new final-campaign support
calculation. A subsequent commit will contain the scoring implementation and
results. The existing `v1.0-submission` tag and all its tracked files are preserved.
The branch is `amendment-v1.1`; no remote publication is authorized.

The reason for `pending` was substantive, not simply an omitted join. The
2026-09-22 development checkpoint, sections 1 and 4, distinguishes global
permission warnings from job declarations; the 2026-09-23 matching plan prohibits
projecting the former into job write capability. The frozen composition code
therefore marks these populations ineligible and keeps permission links as
candidates. This amendment retains that scope distinction.

## Reference catalogue and source identity

The unit is one `(workflow file, job identifier, declared_contents_write)`.
The property is the **declared** `contents: write` permission after applying the
job override to the workflow declaration, before event, repository and
organization restrictions. It is not a demonstrated exploit, a live token
capability, or proof that a permission is excessive for a real workload.

All paths below are relative to `reference/scanner-inputs/` in the archived
infrastructure collection. The shared prefix is
`controls/workflow/.github/workflows/`.

| Control | File | Job | Source of declaration | Positive property | Source line(s) | Frozen case identifier |
|---|---|---|---|---|---|---|
| W02-alpha | w02.yml | alpha | workflow `write-all`, no job override | contents write | global 3; job 5–8 | case-20af32025590c80e4fe9101a8b55e43b |
| W04-alpha | w04.yml | alpha | job `contents: write` overrides global `read-all` | contents write | job 5–10; permission 9–10 | case-670dda6d23381d529db70bb5c6bf3c5d |
| W05-alpha | w05.yml | alpha | job `contents: write` overrides global `read-all` | contents write | job 5–10; permission 9–10 | case-89f39ace141da37f9a5a1778aab890a4 |
| W05-bravo | w05.yml | bravo | job `contents: write` overrides global `read-all` | contents write | job 11–16; permission 15–16 | case-236c70c49051c1fc99d58e19539fbc49 |

These are four instances in three files. The two jobs in w05.yml must never be
collapsed into one reference. Three negative job declarations are also retained:
W01-alpha (inherited `read-all`, contents read), W03-alpha (job contents read
overrides workflow `write-all`), W06-alpha (job `{}` overrides workflow
`write-all`, contents none). These are negative for this property only; their
workflow policy may still trigger a valid alert about a different property.

| File | SHA-256 |
|---|---|
| w01.yml | e99170c4872a20ee6b2ea2bbc163e6ea2faa9d405df22dcfc040125fb85f4ad1 |
| w02.yml | 920e46bc156693e9557f77e0e181540bfff1672c0e624281296c02584f29dc46 |
| w03.yml | 5c21af0693fc2d763947b5df5ee54d38ab1059ec220d15d3dc80153d3414bc05 |
| w04.yml | b8926833bb58cbc6198238846c01a53d5e739903684fd81d5b3de30d30999546 |
| w05.yml | a905c56381fb6dad550b6f54a6c00450fe4f257a394672ecbc17aeed470e01b6 |
| w06.yml | 94109350661f850844a5a8c7a690d30739c7aa568f8382a22e2e498141666294 |

The generator is `study/infrastructure_cases.py`, SHA-256
`ee66d7f3289ae5ba965c891b111f65cebc2954f82954f9c372d4bdeb6d7e6806`.
The archived reference manifest records construction at
`2026-09-22T20:36:00.448934+00:00`; the input receipt records a pre-scan check at
`2026-09-22T20:44:04.252584+00:00`. The same six content hashes occur in the final
campaign `asset_locks.json`. A source mismatch, duplicate YAML key, missing job,
or reference/property disagreement must be reported as a defect or ambiguity;
it must not be repaired, relabelled or counted as unsupported without disclosure.
An unresolved defect prevents a complete score on the fixed denominator four.

## Eligible reports and matching conventions

The two eligible profiles are `infrastructure-controls-checkov-workflow`
(Checkov 3.3.17) and `infrastructure-controls-zizmor` (zizmor 1.30.1), blocks
b1–b5, executed on 2026-10-23. Use the native JSON report identified by each
`prepared.json`, its stored copy, `receipt.json`, and reset/asset identities.
Checkov exit 1 is an accepted findings exit, not a failed scan. Missing,
unparseable, failed or identity-mismatched reports are unavailable, never empty
reports. No totals are imputed.

Following the Docker/Compose, Terraform and Kubernetes configuration populations,
a supporting finding requires all of: a completed eligible profile; an active
native failure/warning rather than PASS or an ignored finding; a rule whose
predicate entails the reference property; a unique source-file match; and an
unambiguous match to the declared object, here a job. Source declarations are
independent references, not scanner-derived labels. A matching filename or CWE
alone is insufficient. Severity is not used as an eligibility threshold.

Canonicalization removes only a verified campaign/workspace prefix, or resolves
the unique file within the six-file scanned root. Keep the native path and native
JSON pointer. Do not merge different paths because their basenames resemble one
another. Line coordinates are reported one-based and checked against the source.

For zizmor, require a primary symbolic route at
`jobs.<job>.permissions` (or its `contents` child), a corroborating native source
span, and the same job in the file. A workflow-level route or a merely related
location cannot be promoted to a job finding. For Checkov, the rule's documented
scope governs interpretation even when its code block covers the whole workflow.

## Versioned rule-to-property decisions

| Tool and rule | Mapping decision | Required predicate and localization | Official justification |
|---|---|---|---|
| zizmor 1.30.1, `excessive-permissions` | Conditional supporting rule | Active job-scoped finding on exact file/job; primary route resolves to job `permissions: write-all`, which entails declared contents write. Verify source span and value. | Versioned implementation, `check_job_permissions`, specifically its `BasePermission::WriteAll` arm; official audit documentation below. |
| zizmor 1.30.1, same rule at workflow scope | Not mapped | Global/default/read-all warnings do not themselves identify a job-specific write declaration. | `audit_workflow` and `check_workflow_permissions` distinguish global and job locations and assign persona separately. |
| zizmor 1.30.1, same rule about default or read-all at job scope | Not mapped | Unknown/default or read permissions do not entail contents write. | `check_job_permissions` has distinct default/read-all branches. Explicit permission maps produce no finding in this pinned implementation. |
| Checkov 3.3.17, `CKV2_GHA_1` | Not mapped to this job population | The policy tests top-level `permissions != write-all`; its resource is `permissions`, not an identified job. Even a one-job file is not automatically projected. | Official policy index and exact versioned distribution rule below. |
| Other native rules from either profile | Not mapped unless already covered above | Preserve and enumerate, without inventing a predicate or job association after seeing results. | No additional rule-to-job-property mapping is justified in this amendment. |

An unexpected `excessive-permissions` job-contents route contrary to the pinned
implementation, or a conflicting native span, is an ambiguity to report, not a
new mapping. No alternative scanner persona or new custom rule is introduced.
In particular, zizmor's explicit job maps are outside this audit rule's inference
of excess. Absence of support must not be described as an undocumented tool bug.

Official sources (consulted 2026-11-03):

- GitHub permission and override semantics:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions>
  and <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idpermissions>.
  This is living documentation, not an archived engine specification.
- zizmor audit documentation:
  <https://docs.zizmor.sh/audits/#excessive-permissions>.
  Version authority:
  <https://github.com/zizmorcore/zizmor/blob/v1.30.1/crates/zizmor/src/audit/excessive_permissions.rs>.
  Downloaded source SHA-256:
  `878ad819ffe2cdb0c56e6ce3b43a4bd7550a655800ec868ad306c57960359bbf`.
- Checkov official policy index:
  <https://www.checkov.io/5.Policy%20Index/github_actions.html>.
  Version authority: <https://pypi.org/project/checkov/3.3.17/> and release metadata
  <https://pypi.org/pypi/checkov/3.3.17/json>.
  Wheel SHA-256: `57b804d1d06ee642af0b8992af970f07a11d129444aac36d6e2ae7ba129bfd13`.
  Member `checkov/github_actions/checks/graph_checks/ReadOnlyTopLevelPermissions.json`,
  SHA-256 `65d9edaf9c048d5231fbcd3d519ade86660d42fe46d1190e2647dda77be54235`,
  is identical to the rule hashed in the final runtime lock. The live policy
  index's YAML link is not treated as the frozen rule. No package was installed
  or executed to inspect this member.

The finite rule map can yield an empty supporting set. That is a result of a
specified support audit, not a general recall estimate for either scanner.
Inspection of an inherited permission can independently establish the reference
property while the native alert remains global; these are different evidence
roles. The report must retain both facts.

## Calculation and required outputs

For each tool t, block b, and positive reference r, record support S(t,b,r)=1
iff at least one native finding meets every condition above, otherwise 0 when
the report and source are available. Count unique references, not alerts.
Report sum over the four references for each tool and their set union in every
block. Preserve all native alerts with rule, file, native object/scope, line,
native pointer, mapped flag and exclusion reason. Record negatives separately;
an alert on a different policy is not automatically a false positive.

Repeatability means exact agreement of the four-element support vectors across
b1–b5, not merely equal totals. Compare normalized native finding identities
separately after removing only block-specific path prefixes. The five blocks
repeat the same references and do not create twenty independent cases.

For omission, compute the union of supported reference IDs with both tools and
after removing each tool, independently in each block. Do not infer general
redundancy from a zero or unchanged union. This supplies the requested omission
analysis; it does not renumber the frozen manuscript research questions.

Create `ci_controls_scoring.csv` with exactly four references × two tools × five
blocks. Put union, omissions, native alerts, negatives and availability in
separate traceable outputs. Do not pool with other populations or rescore them.

Make a new 35-row population table. Only `workflow-job:controls` changes from
`descriptive` to `scored (amendment v1.1)`, with the newly calculated support
count and the original catalogue size four. Expected role totals are 17 scored,
2 property, 16 descriptive; require exact equality of the other 34 rows against
the same v1.0 table representation. This label describes the added endpoint;
it does not retrofit v1.0 normalized finding labels, TP/FP counts, manuscripts,
LLM inputs, or the original result ledgers.

## Local provenance paths

The following paths are relative to `<PROJECT_ROOT>/` in the research
workspace (the publication repository contains the frozen source snapshot):

- `evidence/infrastructure_development_2026-09-22/attempt-01-collection-v2/reference/reference_manifest.json`
- `evidence/infrastructure_development_2026-09-22/attempt-01-collection-v2/input_receipt.json`
- `INFRASTRUCTURE_DEVELOPMENT_CHECKPOINT_2026-09-22.md`
- `engineering/WORKFLOW_IAC_MATCHING_PLAN.md`
- `WORKFLOW_IAC_CHECKPOINT_2026-09-23.md`
- `study/workflow_iac_matching.py`, `study/workflow_iac_analysis.py`
- `study/consolidate_development.py`, especially `terraform_workflow`,
  `compose_kics`, and `kubernetes` matching conventions
- `evidence/workflow_iac_matching_2026-09-23/local-verification-v1/analysis/registry.json`
- `data/references/bindings.json`
- `protocol/experimental_protocol.md`
- `evidence/final_static_campaign_2026-10-23/static-scanners-final-20261023-01/`
- Repository baseline: `reference-results/analysis/population_coverage.csv`,
  tag `v1.0-submission`, peeled commit `e7f28fc1a94cae675aea6ed3285a233432922c37`.

All existing evidence remains read-only. Hashes, native pointers, defects,
unavailable fields and limitations belong in the amendment report. No secrets,
tokens or real credentials are required or to be copied into these outputs.
