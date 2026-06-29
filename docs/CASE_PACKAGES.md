# Case Packages

Case packages store inspection artifacts under a managed cache root. The
default root is:

- `$GIT_SCV_CASE_ROOT` when set
- `$XDG_CACHE_HOME/git-scv/cases`
- `$HOME/.cache/git-scv/cases`
- `%APPDATA%/git-scv/cases`

Commands:

```sh
git-scv case create <repo-path>
git-scv case list
git-scv case show <case-id>
git-scv case brief <case-id>
git-scv case verify-source <case-id>
git-scv case status <case-id>
git-scv case delete <case-id> --ack delete-git-scv-case
git-scv case prune --all --ack delete-all-git-scv-cases
git-scv case doctor
```

Each case contains `.git-scv-case.json`. Delete and prune refuse paths without
the sentinel and refuse source/case path containment relationships.
