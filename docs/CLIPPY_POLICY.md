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

## Narrow Unsafe Boundary

- `src/terminal_ui.rs` uses a small Unix `termios` boundary to put the current
  controlling terminal into raw mode for the interactive quick-start selector.
  This code:
  - reads only stdin key bytes for the current Git-SCV process;
  - restores the original terminal mode with `Drop`;
  - does not inspect target repository content;
  - does not read OAuth/API/token files;
  - does not spawn a shell or target repository command;
  - falls back to the numbered prompt if raw terminal mode is unavailable.
- Keep this boundary isolated in `terminal_ui`; do not copy `unsafe` terminal
  handling into inspection, redaction, snapshot, worker, or artifact paths.

## Current Known Warnings

- Production `src/` warnings are expected to stay at zero for the current RC
  policy surface.
- Test modules, `cfg(test)` helpers, and test-only snapshot archive builders
  intentionally use `unwrap`/`expect` for fixture setup and assertion
  scaffolding. Production code should not copy that style.
