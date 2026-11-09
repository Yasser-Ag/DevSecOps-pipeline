# Executed control sources

The source manifest links each published file to its original content hash and
its artifact coordinate. Docker and Compose controls are author-created. The
infrastructure tree contains both author-created controls and selected upstream
files; upstream revisions are in `config/third_party_sources.json` and licenses
are described in `THIRD_PARTY.md`. Masking affects copied credential fields only.
Synthetic private-key files are excluded. Their permitted file hashes and public
key fingerprints are in `data/references/comparator_context.json`.

Runtime probes are preserved with the execution receipts in the evidence archive.
Reading these files does not execute a probe or establish a new measurement.
