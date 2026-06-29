# Approval Gates

Git-SCV separates three review gates:

- `sensitive_raw_review`: approval before sensitive candidate raw content is
  included in diagnostic or model input
- `execution_model_input_review`: approval before execution-related candidate
  bodies are sent to a model
- `execution_command_review`: approval before any install/build/test/run style
  command is requested

Execution approval requires an exact command envelope. A path approval is not an
execution approval, and a model-input approval is not an execution approval.

`gates.json.decision_binding` declares that decisions must bind to:

- `source_fingerprint_hash`
- `artifact_manifest_sha256`
- path metadata hash for path approvals
- exact command envelope for execution approvals

Changing the source or artifact manifest invalidates prior approvals.
