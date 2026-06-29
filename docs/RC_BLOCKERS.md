# Git-SCV v0.3 RC Blockers

Do not publish the release if any of these are true.

- README, Cargo.toml, tag, release notes, or install commands disagree on the
  version.
- A documented CLI command is missing.
- The documented artifact set does not match generated artifacts.
- Raw token, URL query, URL fragment, URL userinfo, secret-like marker, raw
  lifecycle command, raw sensitive content, or raw HTML injection appears in
  artifacts, stdout, stderr, report.md, report.html, or architecture.html.
- `run.json.command.raw_args_stored` is true.
- Command-like evidence has `raw_excerpt_stored:true` or stores a raw command
  body.
- The no-exec sentinel fixture is triggered.
- Source changes are not detected by `case verify-source`.
- `case next-action` allows install/build/test/run with stale source, missing
  receipt, missing exact command envelope, or unresolved execution gate.
- Cleanup can delete outside the configured case root or delete source paths.
- `brief.md` lacks verdict, action_required, blocked reasons, next safe
  commands, visual output path, or no-safe-claim language.
- Unsupported or parse-failed execution surface still allows
  `no-blocker-observed`.
- report.html or architecture.html contains raw injection payload or executes
  target repo HTML/JS.
- `case show` or `case status` leaks the absolute source path by default.
- `cargo fmt`, `cargo test`, `cargo clippy --all-targets`, schema validation,
  script syntax checks, or package verification fail.

Non-blockers before stable:

- Complete parser support for every ecosystem.
- Full package-manager acquisition path expansion.
- Advanced graph layout and minimap.
- Optional shellcheck integration when unavailable locally.
- Hard CI performance budgets.
