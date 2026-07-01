//! GitHub remote-first planning.
//!
//! This command reads GitHub tree metadata only. It does not clone, extract, or
//! execute repository content.

use crate::cli::GithubPlanArgs;
use crate::errors::ScvError;
use crate::redaction::{redact_url_for_error, strip_url_query_fragment, url_has_userinfo};
use crate::safety;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Duration;

const GITHUB_TIMEOUT_SECS: u64 = 30;

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
        archive_url: format!(
            "https://codeload.github.com/{}/{}/tar.gz/{}",
            repo.owner, repo.name, commit
        ),
        pinned_commit: commit,
        owner: repo.owner,
        name: repo.name,
        requested_ref: requested_ref.into(),
        resolved_ref,
        redacted_url: repo.redacted_url,
    })
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
    use super::parse_github_repo;

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
}
