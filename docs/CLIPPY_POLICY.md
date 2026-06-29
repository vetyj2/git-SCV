# Clippy Policy

Git-SCV is a security-adjacent no-exec inspection tool. The RC target is:

- zero clippy warnings in production security paths where practical;
- explicit, narrow exceptions when a warning is accepted;
- test-only `unwrap`/`expect` allowed when failure messages are clear and the
  unwrap is part of test setup or assertion scaffolding.

For P0/P1 security paths, prefer:

- `Result` propagation over panic;
- no target-repo command execution helpers;
- no broad `allow` attributes;
- small helpers for redaction, path privacy, source verification, and artifact
  writing.

Before release, run:

```sh
cargo clippy --all-targets
```

Any warning left in production code must be documented here with the module,
reason, and planned removal path.

## Current Known Warnings

- `src/detect.rs::read_package_json`, `src/evidence.rs::EvidenceBuilder::add`,
  and `src/review.rs::reason_codes` exceed clippy's default argument-count
  preference. They are stable internal helpers in current parser/review paths;
  refactor after v0.3 RC if their call sites change.
- Test modules and test helpers intentionally use `unwrap`/`expect` for fixture
  setup and assertion scaffolding. Production code should not copy that style.
