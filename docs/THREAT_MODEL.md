# Threat Model

Git-SCV assumes an unfamiliar repository may be malicious or malformed before
any install, build, test, or run step.

Primary risks:

- artifact leakage of tokens, URL queries/fragments, private paths, and raw
  command excerpts
- source changes between inspection and execution approval
- agents skipping brief, gate, or source verification steps
- static parsers being confused by large, deeply nested, or unsupported inputs
- target repository instruction files attempting prompt injection

Git-SCV mitigates these risks by avoiding target execution, redacting
untrusted values before writing artifacts, binding reports to source
fingerprints, emitting gate contracts, and requiring agent receipts for the
brief-reading step.

Non-goals:

- proving absence of malware
- proving install or execution safety
- fully reviewing all transitive dependency source code
- validating semantic truth of every later agent claim
