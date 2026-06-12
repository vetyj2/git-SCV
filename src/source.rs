//! 원본 식별.
//!
//! 깃 정보는 반드시 `gix` 로 in-process 수집한다. 외부 `git` 명령 호출은
//! 금지다(fsmonitor 공격면). discover 방식(상위 디렉터리 탐색)도 금지 —
//! `<root>/.git` 이 있을 때만 깃 저장소다.

use crate::errors::ScvError;
use crate::model::{GitInfo, GitRemote, InputInfo, SourceArtifact, SCHEMA_VERSION};
use std::fs;
use std::path::Path;

/// 반환값의 `git` 필드: 깃 저장소가 아니면 None.
/// dirty 계산 실패 시 `dirty: None` 으로 두고, 호출자(inspect)가 한계
/// 문장을 추가할 수 있도록 두 번째 반환값에 true 를 담는다.
pub fn identify(
    raw_input: &str,
    root: &Path,
    run_id: &str,
) -> Result<(SourceArtifact, /* dirty_unknown */ bool), ScvError> {
    let resolved = fs::canonicalize(root).map_err(|err| {
        ScvError::Inspect(format!(
            "source: 검사 대상 경로를 정규화하지 못했다: {}: {err}",
            root.display()
        ))
    })?;
    let git_dir = resolved.join(".git");
    let (git, dirty_unknown) = if git_dir.exists() {
        identify_git(&resolved)
    } else {
        (None, false)
    };

    Ok((
        SourceArtifact {
            schema_version: SCHEMA_VERSION.into(),
            run_id: run_id.into(),
            input: InputInfo {
                raw: raw_input.into(),
                kind: "local-path".into(),
            },
            resolved_path: resolved.display().to_string(),
            git,
            snapshot: None,
        },
        dirty_unknown,
    ))
}

fn identify_git(root: &Path) -> (Option<GitInfo>, bool) {
    let Ok(repo) = gix::open(root) else {
        return (None, false);
    };

    let branch = repo
        .head_name()
        .ok()
        .flatten()
        .map(|name| name.shorten().to_string());
    let commit = repo.head_id().ok().map(|id| id.to_string());
    let detached = branch.is_none() && commit.is_some();
    let (dirty, dirty_unknown) = match repo.is_dirty() {
        Ok(value) => (Some(value), false),
        Err(_) => (None, true),
    };
    let mut remotes = repo
        .remote_names()
        .iter()
        .filter_map(|name| {
            let remote = repo.find_remote(name.as_ref()).ok()?;
            let url = remote.url(gix::remote::Direction::Fetch)?;
            Some(GitRemote {
                name: name.to_string(),
                url: redact_remote_url(&url.to_bstring().to_string()),
            })
        })
        .collect::<Vec<_>>();
    remotes.sort_by(|left, right| left.name.cmp(&right.name));

    (
        Some(GitInfo {
            is_repo: true,
            branch,
            commit,
            detached,
            dirty,
            remotes,
        }),
        dirty_unknown,
    )
}

fn redact_remote_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return redact_scp_like_remote_url(url).unwrap_or_else(|| url.into());
    };
    let authority_start = scheme_end + 3;
    let path_start = url[authority_start..]
        .find('/')
        .map(|pos| authority_start + pos)
        .unwrap_or(url.len());
    let Some(at_offset) = url[authority_start..path_start].find('@') else {
        return url.into();
    };
    let at = authority_start + at_offset;
    format!("{}***@{}", &url[..authority_start], &url[at + 1..])
}

fn redact_scp_like_remote_url(url: &str) -> Option<String> {
    let (user, rest) = url.split_once('@')?;
    let (host, path) = rest.split_once(':')?;
    if user.is_empty() || host.is_empty() || path.is_empty() {
        return None;
    }
    if user.contains('/') || host.contains('/') {
        return None;
    }
    Some(format!("***@{host}:{path}"))
}

#[cfg(test)]
mod tests {
    use super::redact_remote_url;

    #[test]
    fn remote_url_userinfo_is_redacted() {
        for (input, expected) in [
            (
                "https://token@example.com/org/repo.git",
                "https://***@example.com/org/repo.git",
            ),
            (
                "https://user:token@example.com/org/repo.git",
                "https://***@example.com/org/repo.git",
            ),
            (
                "ssh://git@example.com/org/repo.git",
                "ssh://***@example.com/org/repo.git",
            ),
            (
                "git@example.com:org/repo.git",
                "***@example.com:org/repo.git",
            ),
            (
                "https://example.com/org/repo.git",
                "https://example.com/org/repo.git",
            ),
        ] {
            assert_eq!(redact_remote_url(input), expected);
        }
    }
}
