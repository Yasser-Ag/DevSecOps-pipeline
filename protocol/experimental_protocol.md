# Final experimental protocol v1.0

Target: Electronics, special issue *Advanced Technologies for
Information Security*. This document becomes the execution protocol only when
its exact SHA-256 is bound by `release_manifest.json` and all eight readiness
gates pass. The v0.8 planning document and all development evidence remain intact.

## Design and contribution

This is a bounded, development-exposed empirical study of security measurement
in a multilayer DevSecOps pipeline. The central question is how much verified
coverage each configured stage adds, at what computational cost, and how alert
association and filtering can change that conclusion. Three contribution
families are retained: a linked and reproducible reference collection; an
evaluation of matching validity; and stage complementarity/cost with a bounded
local-model triage extension. Infrastructure breadth supplies distinct test
contexts, not independent scientific contributions by itself.

The four questions remain:

- **RQ1:** Which applicable reference instances or declared properties does each
  configured stage detect, within each compatible population?
- **RQ2:** Which verified cases are lost when a stage is omitted, and what time,
  memory and alert burden does that stage add?
- **RQ3:** How do coarse, competent location-aware and typed artifact/context-aware
  matching affect measured coverage and apparent stage redundancy? Distinguish
  grouping errors from losses caused by discarding group members.
- **RQ4:** On the fixed review-supported cohort, how do the two pinned local
  model deployments and their context conditions affect false-warning removal,
  true-warning loss, abstention, stability and computational cost?

The paper will present coverage, matching validity, stage/cost consequences and
triage in that order. No question presupposes an improvement or a model winner.

## Frozen reference and observation scope

The exact case identifiers, profile applicability, source artifacts, relations,
endpoint types, exclusions, clusters and contrasts are defined in
`data/references/bindings.json` and the v10 execution
candidate. These files are copied into the final release and hashed. The
release's component bindings supersede historical "draft"/"pending" operational
status text in those preserved records; their scientific definitions are not
changed.

The inventory contains 14 lots, 35 populations, 338 reference records, 1,988
canonical development observations and 200 recorded links. Sixteen populations
support their specified normalized detection endpoint. The other nineteen
retain property, reference, inventory or unresolved roles. These are not 35
independent applications, and reference records are not interchangeable defects.

The retained contexts include OWASP Benchmark Java cases; selected component,
advisory, SBOM and synthetic-secret controls; Docker/Compose, CI workflow,
Terraform and Kubernetes artifacts; crAPI API/authorization tests; and the
bounded AIGoat application. AIGoat is a separate application context, not a
service added to crAPI. Its target-answer workload is separate from alert triage.
The study does not claim exhaustive coverage of every CI/CD technology, all
documented goat challenges, or live production systems.

Published labels are retained at their original unit and assertion scope.
Source inspections and safe behavioral controls support additional typed
properties. The focused R1 review reconciled 32 propositions with their original
judgments preserved; it is not independent blinded annotation of the entire
corpus. Unsupported native claims remain unresolved. A missing output, unknown
label or inapplicable rule is never recoded as a true negative.

## Execution and asset identity

The manifest binds the qualified `runtime-integration-v1` component for static
and dynamic execution, `triage-repeated-code-v1` for inference, and
`final-composition-v2` for analysis. The scanner component contains the corrected
dynamic attempted-request bookkeeping and verified static-reset receipts.
Source, configuration, image, binary, rule/database and model identities remain
those in the existing asset locks. No update or online enrichment is allowed
during the campaign. Commands and identifiers are listed in
`command_schedule.json`; component-specific release files accommodate the three
existing controller interfaces without altering their code.

All workloads are sequential on the shared Ubuntu host. The cooperative project
guard and inherited exclusive lease protect project sequencing. Controllers
monitor resource reserves and unexpected concurrent activity. Only owned
temporary targets and execution paths may be created or cleaned up. Existing assets, metadata and containers of other projects on the shared host are preserved. No global cache
flush, Docker prune, public exposure, GitHub action or external submission forms
part of this campaign.

The schedule comprises:

| Workload | Fixed size | Interpretation |
|---|---:|---|
| Static profiles | 75 × 5 blocks = 375 jobs | 65 detector and 10 inventory profiles; inventory does not award detections |
| Safe static runtime controls | 12 before and 12 after each of 5 blocks = 120 probes | Construction/reference overhead, separate from scanner detections and costs |
| Dynamic profiles | 18 × 5 blocks = 90 jobs | 60 native detector runs and 30 directed checker runs, distinguished in reporting |
| Target-answer generation | 5 jobs × 4 requests = 20 planned requests | Bounded AIGoat target behavior; attempted requests recorded separately |
| RESTler preparation | 30 grammar compilations | Separate from scanner execution |
| Triage | 4 blocks × 4 jobs = 16 jobs | Two deterministic baseline jobs and two model jobs per block |
| Triage scientific decisions | 2,112 | Fixed 88 observations across six conditions and four blocks |
| Triage scientific generations | 1,408 | Two models, two contexts, 88 observations and four blocks |
| Synthetic model warmups | 16 | Excluded from scientific decisions; cost reported separately |

Static suite reset order is the qualified corrected schedule; all original 375
job identities are preserved. Each dynamic job receives fresh target state,
fixture/request identities and before/after reference checks. Actual raw probes,
cleanup records and time ordering bind runtime support to its own static block.
Failed support invalidates the dependent interpretation without deleting native
warnings or unrelated evidence.

## Matching and evaluation

The six frozen comparator domains cover Java source locations, component/secret
identity, contextual HTTP properties, Kubernetes declarations, Terraform
resources and AIGoat artifact/request properties. Their exact eligibility and
relation types remain in the analysis bindings. Fresh output adapters rederive
observation identifiers from actual reports; historical warning indexes are not
reused as final labels. Fresh fixtures supply request/object identities.

Every applicable comparison retains a competent complete-member baseline. A
coarse group with all members preserved can retain all supported evidence.
Representative-only selection is an explicitly artificial sensitivity control,
not a claim about the default behavior of real products. False merges/splits
require independently supported relations; distinct identifiers or a shared CWE
alone are insufficient. Java fingerprint agreement remains descriptive where
warning-pair identity is unresolved. Native security correctness, literal
properties, inventory, request behavior and contextual authorization are scored
separately.

Coverage denominators contain the frozen applicable reference cases of the same
endpoint type; catalog size, exclusions and unresolved cases are also reported.
Stage contribution is the difference between the supported case union with all
stages and the union omitting one stage. No overall recall percentage pools
incompatible vulnerability, component and configuration units. Loss of a case's
last supported witness is reported separately from reduced alert counts and
from any unmeasured operational security outcome.

## Local-model triage

The fixed cohort contains 73 observations with resolved native security labels
(62 true and 11 false) and 15 supported literal declarations. The eleven false
warnings arise from seven SAST source cases; the 15 declarations have no false
denominator and do not expand security-precision claims. The complete cohort has
26 recorded source clusters. It was selected after development outcome access.
Fresh scanner outputs do not select or substitute triage cases.

Conditions are B0 (retain all), B1 (unchanged literal low/informational severity
gate), Q-A/Q-C (the pinned Qwen deployment without/with qualified context), and
G-A/G-C (the pinned Gemma deployment without/with the same context content).
B1 is a priority policy, not an independent false-positive classifier. Exact
deployment/quantization, prompt, generation, token and input hashes are bound by
the qualified triage package; these are deployment comparisons, not isolated
architecture or parameter-count effects.

Four blocks use the accepted Qwen/Gemma, Gemma/Qwen, Gemma/Qwen, Qwen/Gemma order,
seed 17 and temperature 0. Alert/context order is counterbalanced and the slot
is erased before each request. Each model job has a fresh process and two fixed
synthetic warmups. Evaluation labels, human review material and the full project
root are excluded from inference mounts. No paid API or model update is used.

Primary contrasts remain Q-C versus B1, G-C versus B1, Q-A versus G-A, Q-C versus
G-C, Q-C minus Q-A and G-C minus G-A. B0 denominators and retained sets are shown
for every condition, with B1 versus B0 as the deterministic reference. Context
effects distinguish 61 cases with additional evidence from 27 without qualified
added evidence. Invalid, absent, timed-out or abstaining responses retain the
finding and retain their distinct failure category. They are not silently
repaired, retried as successful observations or credited as correct dismissals.

## Costs, uncertainty and failures

Retain every block/request outcome. Report reset, fixture construction, grammar
compile, target/model startup, tool execution, inference, reference checks and
cleanup separately. Record wall/CPU time, supported process or cgroup memory
measurements, tokens and output sizes at their named boundaries. Sampled RSS,
cgroup peaks and host memory are different quantities. Missing measurements
remain null with a reason. No energy, human effort or financial saving is claimed
without a corresponding measurement.

Repeated executions measure execution/output variability; they do not increase
the number of independent defects or applications. Primary results are paired
descriptive effects with raw counts and source-cluster counts. Retain the frozen
bounded source-family sensitivity analysis. Do not use naive warning/pair-level
confidence intervals, significance fishing or test-based model selection.

An essential failed reset, identity, isolation, support or parsing check blocks
the dependent measurement and triggers diagnosis. Preserve the original attempt,
including attempted request counts and partial outputs. Do not overwrite or
silently rerun it, omit an unfavorable result, enlarge the cohort or change a
threshold after seeing final outcomes. An engineering repair must be versioned
and its effect assessed before any continuation; a scientific change requires a
dated amendment that discloses outcome access.

## Interpretation and publication

This is a prospective execution extension following extensive development access,
not a preregistration before all outcome access, an unseen holdout or a broad
generalization study. Favorable, tied and adverse outcomes are equally retained.
Scope claims to the configured versions, selected targets, supported endpoint
types and measured host. Local inference supports a bounded data-locality
description, not certification of sovereignty. Regulatory crosswalks illustrate
selected evidence relationships and do not establish NIS2/DORA compliance.

The evidence audit and analysis precede result claims, figures and manuscript
conclusions. The controlled public reproduction repository and submission
package are subsequent work; the present release performs no publication or
external communication.
