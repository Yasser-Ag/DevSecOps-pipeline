# ZAP startup repair and retained failed attempt

Date: 23 October 2026. Base scientific protocol: v1.0. This is an engineering
repair after access to the first four dynamic results and the first ZAP failure.
It does not change the scientific schedule, populations, labels, scan budgets,
matching methods, triage conditions, eligibility rules, or measured endpoints.

## Observed failure and causal diagnosis

`dynamic-final-20261023-01-b01-crapi-zap-valid-a` completed its lifecycle and
preservation checks, but ZAP exited 3 before sending a scanner request. All three
declared operations were unreached and no native report existed. Keep this
attempt as a startup failure, with its measured cost; never interpret it as a
negative detection result. Its terminal summary SHA-256 is
`7c2d6e1b32bd8e3d103b2defe86153a67cb6cc4ae85fbb0b90e00b00ec02814e`.

Two offline startup controls used the same pinned ZAP image and container
restrictions, without a target or external network. The initial command exited
1 and reported that `<USER_HOME>/.ZAP/` was not writable. Specifying the job-private
directory with `-dir /zap/wrk<USER_HOME>` allowed ZAP 2.17.0 to respond to its local
version API in 11.174 seconds. These are startup controls, not scientific scans.
The argument is documented in the [ZAP command-line reference](https://www.zaproxy.org/docs/desktop/cmdline/).
The exact installed image scripts and all diagnostic outputs are retained.

## Narrow correction and validation

The new runtime appends that single `-dir` argument to each of the four ZAP
profiles. The other 14 profiles, resource limits, modes, request/time budgets,
authentication policy and target resets are unchanged. The image filesystem
stays read-only; no additional permission, host mount, port or network is added.
The fresh directory resides within the existing job-private writable mount.

The explicit command-delta audit covers all 18 profiles. Forty-six tests pass
locally and on Ubuntu. An existing command-fidelity test correctly rejected the
first repair candidate until its expected argument was explicitly updated;
the unreleased first candidate is preserved. All host-preservation checks pass.

Original runtime manifest:
`06e60151cacc46b6bb57d39db4dda1292ce76f586ede82ebbe7e8c5df8e5e662`.
Repaired runtime manifest:
`be6c21c75ae33a083e1b393578dcc0d4c2d7b35e125945bc5def9b2a29c4b6b9`.
Only `study/dynamic_scan_contract.py`, its command-regression expectation,
and a repair provenance record differ. The new package is installed separately
at `<LAB_ROOT>/environment/zap-runtime-repair-v2`.

## Recovery and scientific interpretation

Use the corrected runtime for all 20 planned ZAP jobs (four profiles, five
blocks). Give those jobs distinct `-zapfix1` run identities and preserve the
original failed attempt. Only the first such job is a repeated attempt; the
other 19 have not run. Previously completed jobs are retained without replay.
All non-ZAP jobs retain their original package and release. Scientific job IDs
and block order remain unchanged. Each job retains its actual release hash.

A successful replacement still requires the unchanged native-report, target,
resource and preservation checks. Keep failed startup cost separate from usable
scan cost and report the extra attempt. Do not select between successful results,
replace an adverse result, treat attempts as independent vulnerabilities, or
promote any limited result to complete coverage. New failures require diagnosis.

Evidence directory:
`evidence/final_dynamic_campaign_2026-10-23/zap-runtime-repair-v2/`.
