# Security checks

Gitleaks 8.30.1 uses its default rules and the published `.gitleaks.toml`. The configured scans of repository files, recorded evidence, preliminary material and the decompressed supplementary workbook report zero findings. The 39 retained path-and-pattern allowlists are inherited from the reviewed release; no broad new exception was added. The final release procedure also checks the single-commit Git history and verifies every archive member against its scanned copy.

The independent detector is detect-secrets 1.5.0. Its pattern plugins ran without any online credential verification; the two general entropy plugins were disabled, with Gitleaks supplying the entropy-and-pattern check. The pass inspected 5960 distinct file contents, including 5947 completed text inspections and 13 binary files. Binary drawings are verified by identity and their text sources; the workbook is inspected after decompression. An additional check covers the final documentation and archive exports.

Every detector match has an explicit classification. Inspected non-secret matches are integrity/grouping hashes, public package-file digests, configuration network literals, masked key delimiters and scanner or figure category names. Public upstream attribution in license notices is retained. No unexplained detector match remains in the audited material. New text is checked before the final package is delivered.

Targeted checks cover credentials, private-key bodies, session tokens, private machine and other-project identifiers, previous metadata and excluded review material. The original workflow credential is not tested online. Documentation that states the exclusion of private review material is distinguished from that material itself. The old author metadata is absent from the recreated history; both author and committer use the supplied no-reply address.

Original/private hashes are distinct from published-copy hashes. `.gitleaks.toml` exceptions concern specific non-secret matches; they do not certify an arbitrary future file or commit. Rerun the checks after changes. These checks describe the inspected files and rules, not a guarantee about new material.

## Mounted execution code

The added execution sources and generated RESTler inputs undergo the same repository, history and archive checks. Publication copies mask host identifiers and synthetic credential literals found in test fixtures; `config/mounted_code_identities.csv` and the masking manifest preserve the file-level provenance. Network-binding literals, a documentation-address reachability probe, a public DNS deny-test input and code that generates a fresh random password are classified separately from stored credentials. No Gitleaks exception is added for these files. The targeted-update scan results are retained in the private delivery report.
