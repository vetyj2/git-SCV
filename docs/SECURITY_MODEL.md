# Security Model

Git-SCV attempts to guarantee:

- it did not execute target repository commands, scripts, hooks, binaries,
  builds, tests, workflows, package managers, or containers
- raw token-like URL query/fragment/userinfo and secret-like markers are
  redacted from artifacts
- sensitive candidates are excluded from default model input
- inspection results are bound to a source fingerprint
- agent receipts and gate contracts bind to source and artifact identity

Git-SCV does not guarantee:

- absence of malware
- install or execution safety
- full transitive dependency review
- sandbox safety
- correctness of later model semantic analysis
