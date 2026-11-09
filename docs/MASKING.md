# Masking and evidence integrity

## Scope

Publication copies use deterministic labels of the form `<MASKED:category:n>`.
One distinct value receives the same label wherever it occurs. Original evidence
is retained privately and is not edited. The value-to-label registry is private;
neither its values nor hashes of masked credential values are distributed.

Credential categories include private keys, passwords, API keys, bearer and
session tokens, cookies, and test-account identifiers. Host-specific paths and
addresses are normalized while preserving the coordinates needed for linking.
An image-internal location remains an artifact coordinate: it is not a path to
the researcher's machine.

## Verified changes to triage packets

The following counts are per pass, with 88 packets in each condition. The same
counts apply to both passes. Counts across categories may overlap.

| Category | Alert only | Added context | Affected fields |
|---|---:|---:|---|
| Machine path prefix | 6 packets | 12 packets | Source paths inside the evidence |
| Secret-value fingerprint | 4 packets | 4 packets | `evidence[].content.reported_secret_sha256` |
| Test-account identifier | 0 packets | 2 packets | `evidence[].content[].response.body.email` |
| Vehicle fixture identifier | 2 packets | 2 packets | Vehicle identifiers within recorded API routes |

Only the host-specific prefix of each source path is replaced with `<LAB_ROOT>`.
The useful suffix, including the Java test filename, remains unchanged. Three
other packets in each condition contain image-internal paths; these paths remain
unchanged. Test-account email values use `<MASKED:test_account_email:n>`.
Vehicle identifiers inherited from the authorization fixtures use
`<MASKED:fixture:n>` consistently in reference routes, native observations,
packets and recorded requests. The route structure remains visible.

The `reported_secret_sha256` field originally contained the hash of a private-key
literal, including synthetic test keys. In a publication copy, this field holds
the deterministic label of the corresponding key, such as
`<MASKED:private_key:n>`. The field name is retained to preserve packet structure;
its masked value must not be interpreted as a SHA-256 digest. This removes 16
secret-fingerprint fields across the two conditions and two passes. File
integrity hashes and public-key fingerprints used for grouping remain distinct
from hashes of credential literals.

The complete field-level change inventory is in
`data/derived/triage_masked_fields.csv`. Packet checks are recorded in
`data/derived/triage_packet_manifest.csv`. The audit compared every scalar field
after restoring the external Java snippets. It found only the four documented
change categories above. Finding identifiers and evidence identifiers are
unchanged.

Authentication-header fingerprints in dynamic traces are masked too. A hash of
a credential is not a substitute for removing that credential from the release.
Secret literals reproduced in infrastructure code excerpts, including test cloud
credentials and encoded Kubernetes secrets, are masked in all copies. Names of
fields used by `secretKeyRef` and public GnuPG signing-key fingerprints are not
private credentials; detector exceptions for these require a stated field,
path and justification.

## Java source retrieval

Java excerpts from OWASP Benchmark are not redistributed under this repository's
licenses. Each excerpt is represented by an upstream path, pinned revision, line
range, transformation description, and SHA-256. Retrieval restores its exact
recorded text, including the recorded comment-blanking transformation.

Each packet has two separate checks:

1. The original packet is reconstructed privately and its canonical SHA-256 is
   compared with the original. Only the result and original packet hash are
   published; the private check details are not distributed.
2. The public packet is reconstructed and compared with the canonical SHA-256 of
   the masked packet. This hash is intentionally different when masking occurred.

All 352 packet records passed both checks. The recorded request body also matches
the original packet for all 704 model responses. Replaying the frozen validator
on the publication copies preserves its complete output for all 704 responses.
The raw model explanation text required no alteration in these responses.

## Interpretation of replay

After external Java text is restored, publication packets differ from the inputs
received by the models only in the documented machine prefixes, test-account
identifiers, vehicle fixture identifiers, and secret-value fingerprints. The license reference descriptors
are a storage mechanism, not replacement text for inference.

Revalidating recorded responses is exact. New inference on masked packets is a
different operation: its input text differs, so identical model output is not
guaranteed, even with the same model and runtime settings. This is a limitation
of level-3 triage reproduction.

An integrity manifest distinguishes the original file SHA-256 from the
publication-copy SHA-256. A changed publication file is never represented as
byte-identical to the original. Masking does not make the reference labels more
independent, widen the evaluated population, or establish new scientific results.

## File manifests and audit scope

`data/derived/masking_manifest.csv` records original and publication SHA-256
values, transformation status, inserted mask-label counts by category, and the
original recorded hash field for native reports. There are 555 native reports:
340 carry an observation-level `raw_report_sha256`; 215 carry another recorded
report hash. Original hash witnesses identify retained evidence by content hash,
not by a private machine path. Generated release files are covered separately by
`config/release_manifest.csv`.

Replacement counts count inserted labels, not every path rewrite or editorial
change. Path normalization, source-license externalization and documentation
preparation are separately described. The complete original-to-public pathname
mapping and value-to-label dictionary remain private.

Additional masked values include synthetic cloud credentials, AIGoat decoy and
billing tokens, fixture identifiers and short credentials in copied Compose
configuration. These changes are applied to report copies and corresponding
reference fields. Public-key fingerprints and whole-file integrity hashes used
by the analysis are retained; hashes of credential literals are excluded.

The exact replay checks described in `REPRODUCIBILITY.md` cover native adapters,
reference linking, grouping, omission and the recorded triage validator.
`SECURITY_SCAN.md` describes the separate detector and targeted checks. Neither
check establishes that the original scientific annotations were independently
correct, or that a fresh inference on altered inputs would be identical.

## Archived-source integrity recovery

One retained working copy of a static Trivy report failed its original recorded
SHA-256 check during packaging. The corresponding member of the preserved
collection archive matched the recorded original SHA-256 exactly. That archived
member supplies the original bytes for the integrity comparison; the working
copy was not overwritten. The masking manifest identifies this one archived
source recovery and the source archive's SHA-256. This is evidence recovery,
not a new scan or a change to the recorded results. The cause of the working-copy
difference was not established.

## Publication-copy update

`data/derived/publication_masking_updates.csv` lists each additional private-path, other-project or fixture masking operation, its previous published hash, new hash, category and reason. The main manifest continues to retain the original report hash. Other-project labels are `<OTHER_PROJECT_1>` and `<OTHER_PROJECT_2>`; private machine prefixes use `<PROJECT_ROOT>` or `<USER_HOME>`. Protocol dates and run identifiers are preserved. These changes do not add or recompute a scientific observation. The two failed ZAP attempt records and the command-delta record are retained in the dynamic engineering evidence; they are not extra measured scanner jobs.
