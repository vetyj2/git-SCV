# Future Package Manager Inspection

Future package-manager inspection must preserve the same no-exec and no-leak
contract:

- do not run `npm install`, `pip install`, `cargo build`, `brew install`, or
  `curl | sh`
- inspect package metadata, archives, formulas, and scripts statically
- verify archive digests before extraction
- store redacted specs and hashes, not raw tokenized URLs or private paths
- bind package reports to source fingerprints and artifact manifests

Package-manager support is an expansion layer, not a reason to weaken P0/P1
artifact, redaction, source, or gate contracts.
