# Additional complete triage pass — 24 October 2026

The researcher authorized one additional complete pass after discussion of the
completed first pass. Any third or fourth pass requires a stated scientific
reason, cost estimate and discussion with the researcher before execution.
This is a prospective execution specification written after access to the first
pass outcomes; it is not a pre-outcome preregistration or restoration of the
original four-block experiment.

## Purpose and fixed selection

Assess observed repeatability of each pinned deployment's decisions and output
validity on the same 88 observations, and describe timing/resource variation.
Retain the completed first pass as the primary comparison and report this pass
as supplementary replication. Preserve all responses, including invalid outputs
and unfavorable results. No model, prompt, threshold, input or label is tuned.

Use exactly original schedule block 2, selected by ordinal position before this
additional execution. Its four phases are B1, B0, Gemma, Qwen. Original block 1
used B0, B1, Qwen, Gemma. Block 2 reverses the original case order and the first
information condition for each case, consistently across models. Thus both
orders are represented. This design does not isolate the causal effect of model
order, case order or changing host conditions; no such attribution is planned.

The 88 observations, both context conditions, serialized request bytes, model
files, quantizations, runtime, sampling (temperature 0, seed 17), 384-token output
limit, 4096-token context, cache erasure, synthetic warmups, conservative decision
validator and measurement boundaries remain unchanged. Evaluation labels and
review material remain outside inference mounts. Baselines have identical
semantics. The second pass has 528 decisions, 352 model responses and four
excluded synthetic warmups. The two passes together contain 1,056 decisions and
704 model responses on 88 observations, not 176 independent observations.

## Prior outcome access and prerequisites

First run: `triage-single-final-20261024-01`, completed at 15:04:45 UTC on
Its 352 model responses and full raw evidence are retained.
Recorded validator counts (one invalid Qwen output and sixteen invalid Gemma
outputs) and measured controller duration (11,595.30 seconds) were discussed
before this amendment. The raw-response audit necessarily inspects their
contents. Selection of block 2 is unrelated to which findings were invalid or
to any favorable performance contrast. The earlier interrupted four-block
attempt and resource-driven single-pass amendment remain disclosed.

Before launch, require a successful first-pass raw decision and measurement
audit, exact package derivation checks, local and Ubuntu engineering checks,
an isolated no-inference preflight and a fresh asset/host-readiness check.
Do not edit the completed first pass or completed static/dynamic campaigns.

## Analysis and stopping boundary

Report first and second pass results separately, with paired effective-action
agreement, status transitions and all disagreements per model/context. Report
raw response equality separately from decision agreement. Invalid or abstaining
responses retain their findings under the existing conservative policy; they
remain in denominators and are not selectively regenerated. Join the unchanged
scoped reference labels only in analysis. Keep the 73 native-security labels
separate from the 15 literal declarations; source clusters remain unchanged.

Describe changes in false-warning removal, true-warning loss and retained-case
effects between passes without selecting a preferred pass or treating repeated
warnings as independent cases. Timing comparisons remain paired and descriptive;
startup, warmup, per-request work and whole-phase time are separate boundaries.
Two observations per condition do not establish a reliable distribution of
execution variability. This extension does not increase benchmark diversity,
create an unseen holdout, or justify a general model-superiority claim.

Expected additional computation is approximately 3 h 15 min, extrapolated from
the first pass. No automatic three-hour cutoff is added. Existing per-request
and per-phase safety limits remain in force. A failed essential check stops the
dependent work; retain the attempt and diagnose before a separately documented
continuation. No automatic retry, extra pass or selective case substitution.

Further repetitions may be proposed for an unresolved repeatability question or
unexplained execution variation, with the question and fixed design stated
before running. Neither statistical significance nor a favorable score is a
stopping or extension rule. Changes in implementation would require separate
versioned qualification and would not be silently combined as identical repeats.

## Isolation and provenance

Create new package, release and run paths under the DevSecOps project. Preserve
the first release, raw files and the original four-block package. The shared-host
lease, idle-host boundary, networkless model containers and existing memory/disk
reserves apply unchanged. Existing assets, metadata and containers of other projects on the shared host are preserved. No scanner,
target service, external API, publication, push or submission is involved.
