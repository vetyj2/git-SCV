# Supported Surfaces

Current support is conservative and signal-oriented.

Parsed or detected surfaces include:

- `package.json` scripts and direct dependency names/source kinds
- npm lockfile names
- Cargo manifest and lockfile names
- `build.rs`
- shell scripts
- Makefile-like automation files
- Dockerfile/Containerfile names
- GitHub Actions workflow names
- `.envrc`, `.vscode/tasks.json`, and `.husky/*`
- sensitive-name candidates such as `.env`, private keys, tokens, and
  credentials

Unsupported or parser-failed execution surfaces restrict
`no-blocker-observed` and should be treated as insufficient coverage in later
expansion.
