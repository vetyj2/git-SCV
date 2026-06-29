#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${GIT_SCV_REPO_URL:-https://github.com/vetyj2/git-SCV}"
CASE_ROOT="${GIT_SCV_CASE_ROOT:-${TMPDIR:-/tmp}/git-scv-cases}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

usage() {
  cat <<'EOF'
git-scv Hermes harness

Commands:
  commands                         List user intents and matching harness commands
  install [commit-sha]             Install Git-SCV from GitHub, optionally pinned
  update-latest                    Reinstall Git-SCV from the latest GitHub default branch
  uninstall                        Remove the installed git-scv binary with cargo
  version                          Print git-scv version
  inspect <repo-path> [label]      Create a case package and run git-scv inspect
  snapshot <url> <sha256> [label]  Create a case package and run git-scv snapshot
  brief <case-dir>                 Print the mandatory agent briefing for a case
  show <case-dir>                  Print important artifact paths for a case
  list                             List local case packages
  cleanup <case-dir> --ack delete-git-scv-case
                                   Remove one harness case package under the case root
  cleanup-all --ack delete-all-git-scv-cases
                                   Remove every harness case package under the case root

Environment:
  GIT_SCV_REPO_URL    Git repository URL for install/update
  GIT_SCV_CASE_ROOT   Directory for per-repository report packages
EOF
}

commands() {
  cat <<'EOF'
User intent -> Hermes command

Install Git-SCV:
  scripts/git-scv-hermes.sh install

Install a reviewed revision:
  scripts/git-scv-hermes.sh install <commit-sha>

Update Git-SCV to latest GitHub version:
  scripts/git-scv-hermes.sh update-latest

Inspect a local repository:
  scripts/git-scv-hermes.sh inspect <repo-path> [label]

Inspect a verified HTTPS archive:
  scripts/git-scv-hermes.sh snapshot <archive-url> <sha256> [label]

Show report paths for an existing case:
  scripts/git-scv-hermes.sh show <case-dir>

Print the mandatory agent briefing before any next action:
  scripts/git-scv-hermes.sh brief <case-dir>

Delete one report package after review:
  scripts/git-scv-hermes.sh cleanup <case-dir> --ack delete-git-scv-case

Delete all local report packages:
  scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases

Uninstall Git-SCV and then optionally delete report packages:
  scripts/git-scv-hermes.sh uninstall
  scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
EOF
}

case_root() {
  mkdir -p "$CASE_ROOT"
  (cd "$CASE_ROOT" && pwd -P)
}

sanitize_label() {
  local label="${1:-case}"
  local safe
  safe="$(printf '%s' "$label" | tr -cs 'A-Za-z0-9._-' '-' | sed 's/^-*//; s/-*$//')"
  if [ -z "$safe" ]; then
    safe="case"
  fi
  printf '%s' "$safe"
}

new_case_dir() {
  local root label safe dir
  root="$(case_root)"
  label="${1:-case}"
  safe="$(sanitize_label "$label")"
  dir="$(mktemp -d "$root/${safe}.XXXXXX")"
  printf 'git-scv-harness-case\n' > "$dir/.git-scv-harness-case"
  printf '%s\n' "$dir"
}

run_dir_for_case() {
  local case_dir="$1"
  if [ -d "$case_dir/run" ]; then
    printf '%s/run' "$case_dir"
  elif [ -d "$case_dir/snapshot/run" ]; then
    printf '%s/snapshot/run' "$case_dir"
  else
    return 1
  fi
}

print_case_info() {
  local case_dir="$1"
  local run_dir="$2"

  cat <<EOF
case_dir=$case_dir
run_dir=$run_dir
report_md=$run_dir/report.md
report_html=$run_dir/report.html
artifact_manifest_json=$run_dir/artifact_manifest.json
brief_json=$run_dir/brief.json
brief_md=$run_dir/brief.md
security_json=$run_dir/security.json
review_json=$run_dir/review.json
gates_json=$run_dir/gates.json
sensitive_json=$run_dir/sensitive.json
slices_json=$run_dir/slices.json
connection_graph_json=$run_dir/connection_graph.json
analysis_plan_json=$run_dir/analysis_plan.json
cross_unit_analysis_json=$run_dir/cross_unit_analysis.json
synthesis_json=$run_dir/synthesis.json
followup_plan_json=$run_dir/followup_plan.json
brief_command=scripts/git-scv-hermes.sh brief "$case_dir"
cleanup_command=scripts/git-scv-hermes.sh cleanup "$case_dir" --ack delete-git-scv-case
EOF
}

install_cmd() {
  need_cmd cargo
  if [ "${1:-}" = "" ]; then
    cargo install --git "$REPO_URL" --locked
  else
    cargo install --git "$REPO_URL" --rev "$1" --locked --force
  fi
}

update_latest_cmd() {
  need_cmd cargo
  cargo install --git "$REPO_URL" --locked --force
}

uninstall_cmd() {
  need_cmd cargo
  cargo uninstall git-scv
}

version_cmd() {
  need_cmd git-scv
  git-scv --version
}

inspect_cmd() {
  need_cmd git-scv
  local repo="${1:-}"
  [ -n "$repo" ] || die "inspect requires <repo-path>"
  local label="${2:-$(basename "$repo")}"
  local case_dir run_dir
  case_dir="$(new_case_dir "$label")"
  run_dir="$case_dir/run"
  git-scv inspect "$repo" --out "$run_dir"
  print_case_info "$case_dir" "$run_dir"
  printf '\n'
  git-scv brief "$run_dir"
}

snapshot_cmd() {
  need_cmd git-scv
  local url="${1:-}"
  local sha256="${2:-}"
  [ -n "$url" ] || die "snapshot requires <archive-url>"
  [ -n "$sha256" ] || die "snapshot requires <sha256>"
  local label="${3:-snapshot}"
  local case_dir snapshot_dir run_dir
  case_dir="$(new_case_dir "$label")"
  snapshot_dir="$case_dir/snapshot"
  git-scv snapshot "$url" --out "$snapshot_dir" --sha256 "$sha256"
  run_dir="$snapshot_dir/run"
  print_case_info "$case_dir" "$run_dir"
  printf '\n'
  git-scv brief "$run_dir"
}

brief_cmd() {
  need_cmd git-scv
  local case_dir="${1:-}"
  [ -n "$case_dir" ] || die "brief requires <case-dir>"
  [ -d "$case_dir" ] || die "case directory not found: $case_dir"
  local run_dir
  run_dir="$(run_dir_for_case "$case_dir")" || die "case has no run artifacts: $case_dir"
  git-scv brief "$run_dir"
}

show_cmd() {
  local case_dir="${1:-}"
  [ -n "$case_dir" ] || die "show requires <case-dir>"
  [ -d "$case_dir" ] || die "case directory not found: $case_dir"
  local run_dir
  run_dir="$(run_dir_for_case "$case_dir")" || die "case has no run artifacts: $case_dir"
  print_case_info "$case_dir" "$run_dir"
}

list_cmd() {
  local root
  root="$(case_root)"
  printf 'case_root=%s\n' "$root"
  local found=0
  for case_dir in "$root"/*; do
    [ -d "$case_dir" ] || continue
    found=1
    if run_dir="$(run_dir_for_case "$case_dir" 2>/dev/null)"; then
      printf '%s -> %s\n' "$case_dir" "$run_dir"
    else
      printf '%s -> no run artifacts\n' "$case_dir"
    fi
  done
  [ "$found" -eq 1 ] || printf 'no cases\n'
}

cleanup_cmd() {
  [ "$#" -eq 3 ] || die "cleanup requires <case-dir> --ack delete-git-scv-case"
  local case_dir="$1"
  local ack_flag="$2"
  local ack="$3"
  [ "$ack_flag" = "--ack" ] && [ "$ack" = "delete-git-scv-case" ] || die "cleanup requires --ack delete-git-scv-case"
  [ -d "$case_dir" ] || die "case directory not found: $case_dir"

  local root target
  root="$(case_root)"
  target="$(cd "$case_dir" && pwd -P)"

  case "$target" in
    "$root"/*) ;;
    *) die "refusing to remove outside case root: $target" ;;
  esac
  [ "$target" != "$root" ] || die "refusing to remove case root directly"
  [ -f "$target/.git-scv-harness-case" ] || die "refusing to remove case without harness sentinel: $target"

  rm -rf -- "$target"
  printf 'removed=%s\n' "$target"
}

cleanup_all_cmd() {
  [ "$#" -eq 2 ] || die "cleanup-all requires --ack delete-all-git-scv-cases"
  local ack_flag="$1"
  local ack="$2"
  [ "$ack_flag" = "--ack" ] && [ "$ack" = "delete-all-git-scv-cases" ] || die "cleanup-all requires --ack delete-all-git-scv-cases"
  local root
  root="$(case_root)"
  [ -n "$root" ] || die "empty case root"
  [ "$root" != "/" ] || die "refusing to remove /"
  local deleted=0
  local case_dir target
  for case_dir in "$root"/*; do
    [ -d "$case_dir" ] || continue
    target="$(cd "$case_dir" && pwd -P)"
    case "$target" in
      "$root"/*) ;;
      *) continue ;;
    esac
    [ -f "$target/.git-scv-harness-case" ] || continue
    rm -rf -- "$target"
    deleted=$((deleted + 1))
  done
  printf 'case_root=%s\n' "$root"
  printf 'deleted_cases=%s\n' "$deleted"
}

main() {
  local cmd="${1:-}"
  if [ -z "$cmd" ]; then
    usage
    exit 2
  fi
  shift || true

  case "$cmd" in
    commands) commands ;;
    install) install_cmd "${1:-}" ;;
    update-latest) update_latest_cmd ;;
    uninstall) uninstall_cmd ;;
    version) version_cmd ;;
    inspect) inspect_cmd "$@" ;;
    snapshot) snapshot_cmd "$@" ;;
    brief) brief_cmd "$@" ;;
    show) show_cmd "$@" ;;
    list) list_cmd ;;
    cleanup) cleanup_cmd "$@" ;;
    cleanup-all) cleanup_all_cmd "$@" ;;
    -h|--help|help) usage ;;
    *) usage >&2; die "unknown command: $cmd" ;;
  esac
}

main "$@"
