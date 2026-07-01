#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${GIT_SCV_REPO_URL:-https://github.com/vetyj2/git-SCV}"
CASE_ROOT="${GIT_SCV_CASE_ROOT:-${TMPDIR:-/tmp}/git-scv-cases}"
INSTALL_TAG="${GIT_SCV_INSTALL_TAG:-v0.3.1}"
UPDATE_TAG="${GIT_SCV_UPDATE_TAG:-v0.3.1}"

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
  update-latest                    Reinstall Git-SCV from a configured release tag
  uninstall                        Remove the installed git-scv binary with cargo
  version                          Print git-scv version
  inspect <repo-path>              Create a case package with git-scv case create
  snapshot <url> <sha256> [label]  Create a case package and run git-scv snapshot
  brief <case-id>                  Print the mandatory agent briefing for a case
  show <case-id>                   Print important artifact paths for a case
  list                             List local case packages
  next-action <case-id> --action <kind> [--argv ...]
                                   Ask git-scv whether a next action is blocked
  cleanup <case-id> --ack delete-git-scv-case
                                   Remove one case package through git-scv case delete
  cleanup-all --ack delete-all-git-scv-cases
                                   Remove every case package through git-scv case prune

Environment:
  GIT_SCV_REPO_URL    Git repository URL for install/update
  GIT_SCV_CASE_ROOT   Directory for per-repository report packages
  GIT_SCV_INSTALL_TAG Release tag used by install without a commit
  GIT_SCV_UPDATE_TAG  Release tag used by update-latest
EOF
}

commands() {
  cat <<'EOF'
User intent -> Hermes command

Install Git-SCV:
  scripts/git-scv-hermes.sh install

Install a reviewed revision:
  scripts/git-scv-hermes.sh install <commit-sha>

Update Git-SCV to a configured release tag:
  scripts/git-scv-hermes.sh update-latest

Inspect a local repository:
  scripts/git-scv-hermes.sh inspect <repo-path>

Inspect a verified HTTPS archive:
  scripts/git-scv-hermes.sh snapshot <archive-url> <sha256> [label]

Show report paths for an existing case:
  scripts/git-scv-hermes.sh show <case-id>

Print the mandatory agent briefing before any next action:
  scripts/git-scv-hermes.sh brief <case-id>

Check whether install/build/test/run/model-input is blocked:
  scripts/git-scv-hermes.sh next-action <case-id> --action install --argv <program> <arg>

Delete one report package after review:
  scripts/git-scv-hermes.sh cleanup <case-id> --ack delete-git-scv-case

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

case_cli() {
  GIT_SCV_CASE_ROOT="$(case_root)" git-scv case "$@"
}

case_id_from_output() {
  while IFS= read -r line; do
    case "$line" in
      case_id=*)
        printf '%s\n' "${line#case_id=}"
        return 0
        ;;
    esac
  done
  return 1
}

case_id_from_arg() {
  local value="$1"
  case "$value" in
    */*) basename "$value" ;;
    *) printf '%s\n' "$value" ;;
  esac
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
  local case_id="$1"
  local run_dir="$2"

  cat <<EOF
case_id=$case_id
run_dir=$run_dir
report_md=$run_dir/report.md
report_html=$run_dir/report.html
architecture_html=$run_dir/architecture.html
artifact_manifest_json=$run_dir/artifact_manifest.json
brief_json=$run_dir/brief.json
brief_md=$run_dir/brief.md
security_json=$run_dir/security.json
review_json=$run_dir/review.json
gates_json=$run_dir/gates.json
gate_decisions_json=$run_dir/gate_decisions.json
sensitive_json=$run_dir/sensitive.json
slices_json=$run_dir/slices.json
supported_surfaces_json=$run_dir/supported_surfaces.json
connection_graph_json=$run_dir/connection_graph.json
reachability_scenarios_json=$run_dir/reachability_scenarios.json
architecture_map_json=$run_dir/architecture_map.json
relation_map_json=$run_dir/relation_map.json
source_landmarks_json=$run_dir/source_landmarks.json
visualization_index_json=$run_dir/visualization_index.json
analysis_plan_json=$run_dir/analysis_plan.json
cross_unit_analysis_json=$run_dir/cross_unit_analysis.json
synthesis_json=$run_dir/synthesis.json
followup_plan_json=$run_dir/followup_plan.json
brief_command=scripts/git-scv-hermes.sh brief "$case_id"
next_action_command=scripts/git-scv-hermes.sh next-action "$case_id" --action install --argv <program> <arg>
cleanup_command=scripts/git-scv-hermes.sh cleanup "$case_id" --ack delete-git-scv-case
EOF
}

install_cmd() {
  need_cmd cargo
  if [ "${1:-}" = "" ]; then
    cargo install --git "$REPO_URL" --tag "$INSTALL_TAG" --locked
  else
    cargo install --git "$REPO_URL" --rev "$1" --locked --force
  fi
}

update_latest_cmd() {
  need_cmd cargo
  cargo install --git "$REPO_URL" --tag "$UPDATE_TAG" --locked --force
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
  local create_output case_id run_dir
  create_output="$(case_cli create "$repo" --path-privacy repo-relative)"
  printf '%s\n' "$create_output"
  case_id="$(printf '%s\n' "$create_output" | case_id_from_output)" || die "case create did not return case_id"
  run_dir="$(case_root)/$case_id"
  print_case_info "$case_id" "$run_dir"
  printf '\n'
  case_cli brief "$case_id"
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
  print_case_info "snapshot-run" "$run_dir"
  printf '\n'
  git-scv brief "$run_dir"
}

brief_cmd() {
  need_cmd git-scv
  local case_id="${1:-}"
  [ -n "$case_id" ] || die "brief requires <case-id>"
  case_id="$(case_id_from_arg "$case_id")"
  case_cli brief "$case_id"
}

show_cmd() {
  need_cmd git-scv
  local case_id="${1:-}"
  [ -n "$case_id" ] || die "show requires <case-id>"
  case_id="$(case_id_from_arg "$case_id")"
  case_cli show "$case_id"
  print_case_info "$case_id" "$(case_root)/$case_id"
}

list_cmd() {
  need_cmd git-scv
  case_cli list
}

next_action_cmd() {
  need_cmd git-scv
  local case_id="${1:-}"
  [ -n "$case_id" ] || die "next-action requires <case-id>"
  shift || true
  case_id="$(case_id_from_arg "$case_id")"
  case_cli next-action "$case_id" "$@"
}

cleanup_cmd() {
  [ "$#" -eq 3 ] || die "cleanup requires <case-id> --ack delete-git-scv-case"
  local case_id="$1"
  local ack_flag="$2"
  local ack="$3"
  [ "$ack_flag" = "--ack" ] && [ "$ack" = "delete-git-scv-case" ] || die "cleanup requires --ack delete-git-scv-case"
  case_id="$(case_id_from_arg "$case_id")"
  case_cli delete "$case_id" --ack "$ack"
}

cleanup_all_cmd() {
  [ "$#" -eq 2 ] || die "cleanup-all requires --ack delete-all-git-scv-cases"
  local ack_flag="$1"
  local ack="$2"
  [ "$ack_flag" = "--ack" ] && [ "$ack" = "delete-all-git-scv-cases" ] || die "cleanup-all requires --ack delete-all-git-scv-cases"
  need_cmd git-scv
  case_cli prune --all --ack "$ack"
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
    next-action) next_action_cmd "$@" ;;
    cleanup) cleanup_cmd "$@" ;;
    cleanup-all) cleanup_all_cmd "$@" ;;
    -h|--help|help) usage ;;
    *) usage >&2; die "unknown command: $cmd" ;;
  esac
}

main "$@"
