//! GitHub remote-first planning.
//!
//! This command reads GitHub tree metadata only. It does not clone, extract, or
//! execute repository content.

use crate::cli::GithubPlanArgs;
use crate::errors::ScvError;
use crate::redaction::redact_command_excerpt;
use crate::redaction::{redact_url_for_error, strip_url_query_fragment, url_has_userinfo};
use crate::safety;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Duration;

const GITHUB_TIMEOUT_SECS: u64 = 30;
const WEB_SELECTED_MAX_BYTES_PER_FILE: u64 = 128 * 1024;
const WEB_SELECTED_MAX_TOTAL_BYTES: u64 = 512 * 1024;
const WEB_SELECTED_EXCERPT_CHARS: usize = 600;

#[derive(Deserialize)]
struct TreeResponse {
    sha: String,
    truncated: bool,
    tree: Vec<TreeEntry>,
}

#[derive(Deserialize)]
struct RepoResponse {
    default_branch: String,
}

#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
}

pub struct PinnedSnapshotPlan {
    pub archive_url: String,
    pub pinned_commit: String,
    pub owner: String,
    pub name: String,
    pub requested_ref: String,
    pub resolved_ref: String,
    pub redacted_url: String,
}

#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
    size: Option<u64>,
    url: Option<String>,
}

pub fn plan(args: GithubPlanArgs) -> Result<(), ScvError> {
    validate_output(&args.out)?;
    let repo = parse_github_repo(&args.repo_url)?;
    fs::create_dir_all(&args.out).map_err(|err| {
        ScvError::Inspect(format!(
            "github plan: 출력 디렉터리를 만들지 못했다: {}: {err}",
            args.out.display()
        ))
    })?;

    let tree = fetch_tree(&repo.owner, &repo.name, &args.r#ref)?;
    let surfaces = classify_surfaces(&tree.tree);
    let fingerprint = remote_fingerprint(&repo, &args.r#ref, &tree);
    let artifact = json!({
        "artifact_kind": "github_remote_plan",
        "schema_version": "1",
        "contract_version": "artifact-contract-v2",
        "producer": {"name": "git-scv", "version": env!("CARGO_PKG_VERSION")},
        "min_reader_version": env!("CARGO_PKG_VERSION"),
        "analysis_stage": "web-metadata-preflight",
        "source_acquisition": "web-metadata-preflight",
        "code_body_analysis": false,
        "worker_started": false,
        "semantic_analysis_complete": false,
        "repo": {
            "host": "github.com",
            "owner": repo.owner,
            "name": repo.name,
            "repo_url_redacted": repo.redacted_url,
        },
        "ref": {
            "requested": args.r#ref,
            "moving_ref_warning": !looks_pinned_ref(&args.r#ref),
        },
        "tree": {
            "sha": tree.sha,
            "truncated": tree.truncated,
            "entries": tree.tree.len(),
        },
        "remote_fingerprint_hash": fingerprint,
        "surfaces": surfaces,
        "privacy": {
            "raw_file_content_fetched": false,
            "target_repo_commands_executed": false,
            "clone_performed": false,
            "archive_downloaded": false,
            "worker_started": false,
            "code_body_analysis": false,
            "semantic_analysis_complete": false,
        },
        "next_safe_commands": [
            "git-scv scan <repo-url> --mode pinned-snapshot --worker codex",
            "git-scv snapshot <archive-url> --sha256 <external-digest>"
        ],
        "limitations": [
            "Tree metadata cannot reveal script body semantics.",
            "Moving branch refs can change after planning unless pinned to a commit SHA.",
            "GitHub API truncation limits may reduce coverage."
        ]
    });
    let path = args.out.join("github_remote_plan.json");
    safety::assert_inside(&args.out, &path)?;
    let mut text = serde_json::to_string_pretty(&artifact)
        .map_err(|err| ScvError::Inspect(format!("github plan: artifact 직렬화 실패: {err}")))?;
    text.push('\n');
    fs::write(&path, text).map_err(|err| {
        ScvError::Inspect(format!(
            "github plan: artifact를 쓰지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    println!("github_remote_plan={}", path.display());
    println!("tree_entries={}", artifact["tree"]["entries"]);
    println!("tree_truncated={}", artifact["tree"]["truncated"]);
    println!(
        "moving_ref_warning={}",
        artifact["ref"]["moving_ref_warning"]
    );
    Ok(())
}

pub fn selected_preflight(args: GithubPlanArgs) -> Result<(), ScvError> {
    validate_output(&args.out)?;
    let repo = parse_github_repo(&args.repo_url)?;
    fs::create_dir_all(&args.out).map_err(|err| {
        ScvError::Inspect(format!(
            "github selected preflight: 출력 디렉터리를 만들지 못했다: {}: {err}",
            args.out.display()
        ))
    })?;

    let tree = fetch_tree(&repo.owner, &repo.name, &args.r#ref)?;
    let surfaces = classify_surfaces(&tree.tree);
    let fingerprint = remote_fingerprint(&repo, &args.r#ref, &tree);
    let selected_entries = selected_body_candidates(&tree.tree);
    let selected_paths = fetch_selected_bodies(&repo, &args.r#ref, &selected_entries);
    let artifact = web_selected_preflight_artifact(
        &repo,
        &args.r#ref,
        &tree,
        surfaces,
        fingerprint,
        selected_paths,
    );
    let path = args.out.join("web_selected_preflight.json");
    safety::assert_inside(&args.out, &path)?;
    let mut text = serde_json::to_string_pretty(&artifact).map_err(|err| {
        ScvError::Inspect(format!(
            "github selected preflight: artifact 직렬화 실패: {err}"
        ))
    })?;
    text.push('\n');
    fs::write(&path, text).map_err(|err| {
        ScvError::Inspect(format!(
            "github selected preflight: artifact를 쓰지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    println!("web_selected_preflight={}", path.display());
    println!("tree_entries={}", artifact["tree"]["entries"]);
    println!(
        "selected_paths={}",
        artifact["selected_paths"].as_array().map_or(0, Vec::len)
    );
    println!("code_body_analysis=limited");
    println!("worker_started=false");
    println!("semantic_analysis_complete=false");
    Ok(())
}

pub fn resolve_pinned_snapshot(
    repo_url: &str,
    requested_ref: &str,
) -> Result<PinnedSnapshotPlan, ScvError> {
    let repo = parse_github_repo(repo_url)?;
    let resolved_ref = if requested_ref == "HEAD" {
        fetch_default_branch(&repo.owner, &repo.name)?
    } else {
        requested_ref.to_string()
    };
    let commit = fetch_commit_sha(&repo.owner, &repo.name, &resolved_ref)?;
    Ok(PinnedSnapshotPlan {
        archive_url: pinned_archive_url(&repo.owner, &repo.name, &commit),
        pinned_commit: commit,
        owner: repo.owner,
        name: repo.name,
        requested_ref: requested_ref.into(),
        resolved_ref,
        redacted_url: repo.redacted_url,
    })
}

fn pinned_archive_url(owner: &str, repo: &str, commit: &str) -> String {
    format!("https://codeload.github.com/{owner}/{repo}/zip/{commit}")
}

struct GithubRepo {
    owner: String,
    name: String,
    redacted_url: String,
}

fn parse_github_repo(value: &str) -> Result<GithubRepo, ScvError> {
    if url_has_userinfo(value) {
        return Err(ScvError::Usage(
            "오류: GitHub URL은 userinfo를 포함할 수 없다.".into(),
        ));
    }
    let stripped = strip_url_query_fragment(value);
    let text = stripped
        .strip_prefix("https://github.com/")
        .or_else(|| stripped.strip_prefix("http://github.com/"))
        .ok_or_else(|| {
            ScvError::Usage(format!(
                "오류: GitHub repo URL을 해석할 수 없다: {}",
                redact_url_for_error(value)
            ))
        })?;
    let mut parts = text.trim_matches('/').split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default().trim_end_matches(".git");
    if owner.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err(ScvError::Usage(format!(
            "오류: GitHub repo URL은 https://github.com/<owner>/<repo> 형태여야 한다: {}",
            redact_url_for_error(value)
        )));
    }
    Ok(GithubRepo {
        owner: owner.into(),
        name: name.into(),
        redacted_url: format!("https://github.com/{owner}/{name}"),
    })
}

fn fetch_tree(owner: &str, repo: &str, git_ref: &str) -> Result<TreeResponse, ScvError> {
    let url =
        format!("https://api.github.com/repos/{owner}/{repo}/git/trees/{git_ref}?recursive=1");
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(GITHUB_TIMEOUT_SECS)))
        .https_only(true)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(&url)
        .header("User-Agent", "git-scv/0.3")
        .call()
        .map_err(|_err| ScvError::Usage("오류: GitHub tree metadata 요청 실패.".into()))?;
    let text = response
        .body_mut()
        .with_config()
        .limit(10 * 1024 * 1024)
        .read_to_string()
        .map_err(|_err| ScvError::Usage("오류: GitHub tree metadata 본문 읽기 실패.".into()))?;
    serde_json::from_str(&text)
        .map_err(|_err| ScvError::Usage("오류: GitHub tree metadata JSON 해석 실패.".into()))
}

fn fetch_default_branch(owner: &str, repo: &str) -> Result<String, ScvError> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}");
    let text = fetch_github_json_text(&url, 2 * 1024 * 1024, "GitHub repo metadata")?;
    let response: RepoResponse = serde_json::from_str(&text)
        .map_err(|_err| ScvError::Usage("오류: GitHub repo metadata JSON 해석 실패.".into()))?;
    Ok(response.default_branch)
}

fn fetch_commit_sha(owner: &str, repo: &str, git_ref: &str) -> Result<String, ScvError> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/commits/{git_ref}");
    let text = fetch_github_json_text(&url, 4 * 1024 * 1024, "GitHub commit metadata")?;
    let response: CommitResponse = serde_json::from_str(&text)
        .map_err(|_err| ScvError::Usage("오류: GitHub commit metadata JSON 해석 실패.".into()))?;
    if looks_pinned_ref(&response.sha) {
        Ok(response.sha)
    } else {
        Err(ScvError::Usage(
            "오류: GitHub commit metadata가 commit SHA를 제공하지 않았다.".into(),
        ))
    }
}

fn fetch_github_json_text(url: &str, limit: u64, label: &str) -> Result<String, ScvError> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(GITHUB_TIMEOUT_SECS)))
        .https_only(true)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(url)
        .header("User-Agent", "git-scv/0.3")
        .call()
        .map_err(|_err| ScvError::Usage(format!("오류: {label} 요청 실패.")))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|_err| ScvError::Usage(format!("오류: {label} 본문 읽기 실패.")))
}

fn fetch_github_text(url: &str, limit: u64, label: &str) -> Result<String, ScvError> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(GITHUB_TIMEOUT_SECS)))
        .https_only(true)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(url)
        .header("User-Agent", "git-scv/0.3")
        .call()
        .map_err(|_err| ScvError::Usage(format!("오류: {label} 요청 실패.")))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|_err| ScvError::Usage(format!("오류: {label} 본문 읽기 실패.")))
}

fn selected_body_candidates(entries: &[TreeEntry]) -> Vec<&TreeEntry> {
    entries
        .iter()
        .filter(|entry| entry.kind == "blob")
        .filter(|entry| selected_body_reason(&entry.path).is_some())
        .collect()
}

fn fetch_selected_bodies(
    repo: &GithubRepo,
    git_ref: &str,
    entries: &[&TreeEntry],
) -> Vec<serde_json::Value> {
    let mut total_read = 0_u64;
    let mut selected = Vec::new();
    for entry in entries {
        let reason = selected_body_reason(&entry.path).unwrap_or("selected");
        if is_sensitive_selected_path(&entry.path) {
            selected.push(selected_body_record(
                &entry.path,
                reason,
                false,
                false,
                false,
                "sensitive-candidate-body-skipped",
                "",
            ));
            continue;
        }
        if entry.size.unwrap_or(0) > WEB_SELECTED_MAX_BYTES_PER_FILE {
            selected.push(selected_body_record(
                &entry.path,
                reason,
                false,
                false,
                true,
                "per-file-limit-exceeded",
                "",
            ));
            continue;
        }
        if total_read >= WEB_SELECTED_MAX_TOTAL_BYTES {
            selected.push(selected_body_record(
                &entry.path,
                reason,
                false,
                false,
                true,
                "total-limit-exceeded",
                "",
            ));
            continue;
        }
        let remaining = WEB_SELECTED_MAX_TOTAL_BYTES.saturating_sub(total_read);
        let limit = remaining
            .min(WEB_SELECTED_MAX_BYTES_PER_FILE)
            .saturating_add(1);
        let url = raw_github_url(&repo.owner, &repo.name, git_ref, &entry.path);
        match fetch_github_text(&url, limit, "GitHub selected file") {
            Ok(body) => {
                let body_len = body.len() as u64;
                total_read = total_read.saturating_add(body_len.min(limit));
                let truncated = body_len > WEB_SELECTED_MAX_BYTES_PER_FILE || body_len > remaining;
                selected.push(selected_body_record(
                    &entry.path,
                    reason,
                    true,
                    false,
                    truncated,
                    "allowlisted-public-body",
                    &body,
                ));
            }
            Err(_) => selected.push(selected_body_record(
                &entry.path,
                reason,
                false,
                false,
                false,
                "fetch-failed",
                "",
            )),
        }
    }
    selected
}

fn web_selected_preflight_artifact(
    repo: &GithubRepo,
    git_ref: &str,
    tree: &TreeResponse,
    surfaces: Vec<serde_json::Value>,
    fingerprint: String,
    selected_paths: Vec<serde_json::Value>,
) -> serde_json::Value {
    json!({
        "artifact_kind": "web_selected_preflight",
        "schema_version": "1",
        "contract_version": "artifact-contract-v2",
        "producer": {"name": "git-scv", "version": env!("CARGO_PKG_VERSION")},
        "min_reader_version": env!("CARGO_PKG_VERSION"),
        "analysis_stage": "web-selected-preflight",
        "source_acquisition": "web-selected-preflight",
        "code_body_analysis": "limited",
        "worker_started": false,
        "semantic_analysis_complete": false,
        "repo": {
            "host": "github.com",
            "owner": repo.owner,
            "name": repo.name,
            "repo_url_redacted": repo.redacted_url,
        },
        "ref": {
            "requested": git_ref,
            "moving_ref_warning": !looks_pinned_ref(git_ref),
        },
        "tree": {
            "sha": tree.sha,
            "truncated": tree.truncated,
            "entries": tree.tree.len(),
        },
        "remote_fingerprint_hash": fingerprint,
        "surfaces": surfaces,
        "selected_paths": selected_paths,
        "limits": {
            "max_bytes_per_file": WEB_SELECTED_MAX_BYTES_PER_FILE,
            "max_total_bytes": WEB_SELECTED_MAX_TOTAL_BYTES,
            "excerpt_chars": WEB_SELECTED_EXCERPT_CHARS,
        },
        "privacy": {
            "raw_file_content_fetched": true,
            "raw_file_content_stored": false,
            "raw_sensitive_content_included": false,
            "target_repo_commands_executed": false,
            "clone_performed": false,
            "archive_downloaded": false,
            "worker_started": false,
            "code_body_analysis": "limited",
            "semantic_analysis_complete": false,
        },
        "next_safe_commands": [
            "git-scv scan <repo-url> --mode pinned-snapshot --worker codex",
            "git-scv scan <local-source-path> --mode local-full --worker codex"
        ],
        "limitations": [
            "Selected public body preflight is limited and not full repository semantic analysis.",
            "Selected body excerpts are redacted and truncated; raw file bodies are not stored.",
            "Moving branch refs can change after planning unless pinned to a commit SHA.",
            "Install/build/test/run decisions still require pinned or local source analysis and gates."
        ]
    })
}

fn selected_body_record(
    path: &str,
    reason: &str,
    body_read: bool,
    raw_body_stored: bool,
    truncated: bool,
    status: &str,
    body: &str,
) -> serde_json::Value {
    let redacted_excerpt = if body_read {
        truncate_chars(
            redact_command_excerpt(body).as_str(),
            WEB_SELECTED_EXCERPT_CHARS,
        )
    } else {
        String::new()
    };
    json!({
        "path": path,
        "reason": reason,
        "body_read": body_read,
        "raw_body_stored": raw_body_stored,
        "redaction_applied": body_read,
        "redacted_excerpt": redacted_excerpt,
        "truncated": truncated,
        "status": status,
        "target_repo_commands_executed": false,
    })
}

fn selected_body_reason(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(lower.as_str());
    if matches!(
        file_name,
        "readme" | "readme.md" | "readme.rst" | "readme.txt"
    ) {
        Some("readme-overview")
    } else if matches!(
        file_name,
        "package.json" | "cargo.toml" | "pyproject.toml" | "go.mod"
    ) {
        Some("manifest-overview")
    } else if matches!(file_name, "dockerfile" | "containerfile") {
        Some("container-overview")
    } else if file_name == "makefile" {
        Some("makefile-overview")
    } else if lower.starts_with(".github/workflows/")
        && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
    {
        Some("workflow-overview")
    } else {
        None
    }
}

fn is_sensitive_selected_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(lower.as_str());
    matches!(
        file_name,
        ".env"
            | ".npmrc"
            | ".pypirc"
            | ".netrc"
            | "credentials.json"
            | "kubeconfig"
            | "id_rsa"
            | "id_ed25519"
    ) || file_name.ends_with(".env")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
}

fn raw_github_url(owner: &str, repo: &str, git_ref: &str, path: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/{}/{}/{}/{}",
        percent_encode_path_segment(owner),
        percent_encode_path_segment(repo),
        percent_encode_path_segment(git_ref),
        path.split('/')
            .map(percent_encode_path_segment)
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>() + "<truncated>"
}

fn classify_surfaces(entries: &[TreeEntry]) -> Vec<serde_json::Value> {
    let mut surfaces = Vec::new();
    for entry in entries {
        let path = entry.path.as_str();
        let surface = if path == "package.json" || path.ends_with("/package.json") {
            Some("npm/package.json")
        } else if path == "Cargo.toml" || path.ends_with("/Cargo.toml") {
            Some("rust/Cargo.toml")
        } else if path == "Dockerfile" || path.ends_with("/Dockerfile") {
            Some("docker/Dockerfile")
        } else if path == "Makefile" || path.ends_with("/Makefile") {
            Some("make/Makefile")
        } else if path.starts_with(".github/workflows/") {
            Some("github-actions/workflow")
        } else if path.starts_with(".husky/") {
            Some("git-hook/husky")
        } else if path.ends_with(".sh") {
            Some("shell/script")
        } else if path == ".env" || path.contains("/.env") || path.ends_with(".env") {
            Some("sensitive/env-candidate")
        } else {
            None
        };
        if let Some(surface) = surface {
            surfaces.push(json!({
                "path": path,
                "surface": surface,
                "support": "name-detected",
                "mode": entry.mode,
                "kind": entry.kind,
                "blob_sha": entry.sha,
                "size": entry.size,
                "raw_content_fetched": false,
                "blob_url_stored": entry.url.is_some(),
            }));
        }
    }
    surfaces
}

fn remote_fingerprint(repo: &GithubRepo, git_ref: &str, tree: &TreeResponse) -> String {
    let mut hasher = Sha256::new();
    hasher.update(repo.owner.as_bytes());
    hasher.update(repo.name.as_bytes());
    hasher.update(git_ref.as_bytes());
    hasher.update(tree.sha.as_bytes());
    hasher.update((tree.tree.len() as u64).to_le_bytes());
    format!("sha256:{}", hex_lower(hasher.finalize()))
}

fn looks_pinned_ref(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_output(path: &Path) -> Result<(), ScvError> {
    if path.exists() && !path.is_dir() {
        return Err(ScvError::Usage(format!(
            "오류: 출력 경로가 디렉터리가 아니다: {}",
            path.display()
        )));
    }
    Ok(())
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        parse_github_repo, pinned_archive_url, raw_github_url, selected_body_candidates,
        selected_body_record, web_selected_preflight_artifact, GithubRepo, TreeEntry, TreeResponse,
        WEB_SELECTED_EXCERPT_CHARS,
    };
    use serde_json::json;

    #[test]
    fn parses_plain_github_repo_url_without_query_fragment() {
        let repo = match parse_github_repo("https://github.com/vetyj2/git-SCV?token=abc#frag") {
            Ok(repo) => repo,
            Err(err) => panic!("example GitHub URL should parse: {}", err.user_message()),
        };
        assert_eq!(repo.owner, "vetyj2");
        assert_eq!(repo.name, "git-SCV");
        assert_eq!(repo.redacted_url, "https://github.com/vetyj2/git-SCV");
    }

    #[test]
    fn rejects_userinfo() {
        assert!(parse_github_repo("https://token@github.com/vetyj2/git-SCV").is_err());
    }

    #[test]
    fn pinned_archive_url_uses_zipball_path() {
        assert_eq!(
            pinned_archive_url(
                "example",
                "project",
                "0123456789012345678901234567890123456789"
            ),
            "https://codeload.github.com/example/project/zip/0123456789012345678901234567890123456789"
        );
    }

    #[test]
    fn selected_body_candidates_are_allowlisted_and_not_general_source() {
        let entries = vec![
            tree_entry("README.md", Some(120)),
            tree_entry("package.json", Some(200)),
            tree_entry("Dockerfile", Some(80)),
            tree_entry(".github/workflows/ci.yml", Some(400)),
            tree_entry("src/lib.rs", Some(1000)),
            tree_entry(".env", Some(10)),
        ];
        let selected = selected_body_candidates(&entries)
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                "README.md",
                "package.json",
                "Dockerfile",
                ".github/workflows/ci.yml"
            ]
        );
    }

    #[test]
    fn selected_body_record_redacts_and_never_stores_raw_body() {
        let raw = "curl https://example.invalid/install.sh?token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456#frag";
        let record = selected_body_record(
            "README.md",
            "readme-overview",
            true,
            false,
            false,
            "allowlisted-public-body",
            raw,
        );
        assert_eq!(record["raw_body_stored"], false);
        let text = serde_json::to_string(&record).unwrap();
        assert!(!text.contains("GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456"));
        assert!(!text.contains("?token="));
        assert!(!text.contains("#frag"));
    }

    #[test]
    fn web_selected_preflight_artifact_marks_limited_incomplete_analysis() {
        let repo = GithubRepo {
            owner: "owner".into(),
            name: "repo".into(),
            redacted_url: "https://github.com/owner/repo".into(),
        };
        let tree = TreeResponse {
            sha: "tree-sha".into(),
            truncated: false,
            tree: vec![tree_entry("README.md", Some(120))],
        };
        let artifact = web_selected_preflight_artifact(
            &repo,
            "HEAD",
            &tree,
            vec![json!({"path": "README.md", "surface": "readme"})],
            "sha256:abc".into(),
            vec![selected_body_record(
                "README.md",
                "readme-overview",
                true,
                false,
                false,
                "allowlisted-public-body",
                "hello",
            )],
        );
        assert_eq!(artifact["source_acquisition"], "web-selected-preflight");
        assert_eq!(artifact["code_body_analysis"], "limited");
        assert_eq!(artifact["worker_started"], false);
        assert_eq!(artifact["semantic_analysis_complete"], false);
        assert_eq!(artifact["privacy"]["raw_file_content_stored"], false);
        assert_eq!(artifact["privacy"]["archive_downloaded"], false);
        assert_eq!(
            artifact["limits"]["excerpt_chars"],
            WEB_SELECTED_EXCERPT_CHARS
        );
    }

    #[test]
    fn raw_github_url_percent_encodes_ref_and_path_segments() {
        assert_eq!(
            raw_github_url("owner", "repo", "feature/with space", "docs/setup guide.md"),
            "https://raw.githubusercontent.com/owner/repo/feature%2Fwith%20space/docs/setup%20guide.md"
        );
    }

    fn tree_entry(path: &str, size: Option<u64>) -> TreeEntry {
        TreeEntry {
            path: path.into(),
            mode: "100644".into(),
            kind: "blob".into(),
            sha: "blob-sha".into(),
            size,
            url: None,
        }
    }
}
