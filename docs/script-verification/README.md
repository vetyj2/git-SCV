# Script Verification Plan

This plan verifies every public helper script as a set of smaller modules. Each
module is checked against three independent sources:

- REQ documents: `docs/spec/*` plus public contract docs.
- User intent: the requested Hermes workflow and no-exec behavior.
- 2026-06-29 documents: `docs/internal/2026-06-29-*.md` P0 through P5 plan.

The process is intentionally checklist-driven. A script change is not complete
until the final meta-check proves that every checklist item is covered by either
a script module or the final verification stage.

## Verification Stages

| Stage | Purpose | Output |
| --- | --- | --- |
| SV0 scope discovery | Enumerate every file under `scripts/` and reject untracked script assumptions. | `script_inventory.json` |
| SV1 module split | Divide each script into dispatch, case, install, inspect, brief, cleanup, and other functional modules. | `script_inventory.json` |
| SV2 REQ conformance | Map each module to CLI, flow, artifact, gate, case, release, security, and supported-surface requirements. | `traceability.json` |
| SV3 user-intent conformance | Map each module to the user-requested Hermes behavior: no target execution, brief-first, no leak, source/gate binding awareness, and cleanup safety. | `traceability.json` |
| SV4 0629 conformance | Map each module to the 2026-06-29 P0/P1/P1.5/P3/P4/P5 security plan. | `traceability.json` |
| SV5 mechanical checks | Run tests that verify script inventory completeness, checklist coverage, cleanup acknowledgement, Rust case deletion delegation, brief-first output, architecture/synthesis artifact visibility, and target package-manager no-exec constraints. | `tests/script_contract.rs` |
| SV6 final meta-check | Confirm that every checklist item is referenced by a module or final verification entry and that every module has REQ, user-intent, and 0629 coverage. | `tests/script_contract.rs` |

## Module Rules

Every module entry must include:

- `module_id`
- script path
- function names or command names owned by that module
- the verification stage where it is primarily checked
- at least one `REQ-*`, one `UI-*`, and one `P0629-*` checklist reference

The final verification entry may cover `META-*` checklist items. Normal modules
should not rely on `META-*` items to satisfy their own contract coverage.

## Current Script Modules

The current public script set contains one script:

- `scripts/git-scv-hermes.sh`

It is split into these modules:

- `M01-BOOTSTRAP-DISPATCH`
- `M02-CASE-PACKAGE`
- `M03-INSTALL-UPDATE`
- `M04-INSPECT-SNAPSHOT`
- `M05-BRIEF-ARTIFACTS`
- `M06-CLEANUP-SAFETY`

If another file is added under `scripts/`, it must be added to
`script_inventory.json` and given module traceability before the test suite can
pass.

## Final Acceptance

The script verification work is complete only when:

- `docs/script-verification/checklist.json` is valid JSON.
- `docs/script-verification/script_inventory.json` is valid JSON.
- `docs/script-verification/traceability.json` is valid JSON.
- Every script under `scripts/` appears in the inventory.
- Every module in the inventory appears in traceability.
- Every traceability checklist ID exists in the checklist.
- Every checklist item is covered by a module or final verification.
- Every module has REQ, user-intent, and 2026-06-29 coverage.
- The Hermes script exposes the mandatory brief and synthesis artifacts.
- Cleanup requires exact acknowledgement and delegates to Rust case delete/prune.
- The script does not run target repository package managers or container
  commands.
