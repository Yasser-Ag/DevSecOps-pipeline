# Complete ZAP private-home and bundled-policy recovery

This dated engineering repair supersedes the incomplete startup-only repair in
`ENGINEERING_REPAIR_ZAP_2026-10-23.md`. The scientific protocol remains v1.0.

The original ZAP attempt exited before any scanner request because its default
home was read-only. The `-zapfix1` attempt then started ZAP and contacted all
three declared endpoints, but could not start the active scan: the private home
lacked the image-bundled `API-Minimal` policy. Both attempts, their raw records
and measured costs are retained. Neither produced a usable native report.
No adverse successful result is being replaced or selected away.

The complete repair keeps `-dir /zap/wrk<USER_HOME>` and copies the exact policy
from `<USER_HOME>/.ZAP/policies/API-Minimal.policy` in the pinned image. Its 1,743
bytes must hash to
`029a8670ff8f78a5a2af027c3667bf25500c6e2bed7996644a35f9e147144520`.
A changed source, escaping destination or overwrite is rejected before startup.
No scan rule is edited or downloaded; modes, budgets, authentication, target
states, runtime limits, scientific labels and eligibility rules are unchanged.
Only ZAP jobs use the repaired runtime. Non-ZAP jobs keep the original release.

The package passes 50 tests locally and on Ubuntu, including policy provenance,
overwrite protection and absence of ZAP preparation for other tools. Its
manifest is
`264fcef5993020616d4b4f2c264b32716b2587ea8b422a501254cd815ba1a65b`.

Two complete synthetic canaries run the real wrapper, active/passive native
commands and report parser in separate containers with no external network.
Both reach three synthetic routes and produce valid native reports. The active
canary sends 44 authenticated requests; the passive one sends three. These
counts are engineering checks, not scientific findings or extra target cases.
All canary preservation checks pass. Evidence is under
`evidence/final_dynamic_campaign_2026-10-23/zap-end-to-end-canary-v1/`.

Use `-zapfix2` identities for the 20 scheduled ZAP jobs. The first is a third
attempt after two explicitly retained engineering failures; the other 19 have
not run. The 95 scientific job IDs, block order, all existing usable results,
native report rules and frozen analysis remain unchanged. Each run binds its
actual runtime and release. A failure or new limitation still stops sequencing.

Outcome access: the first four dynamic results and both ZAP failures were seen
before this repair. The first failure sent zero scanner requests; the second
performed three API-import requests, without an active scan or native report.
This repair neither establishes effectiveness nor changes the reference truth.
