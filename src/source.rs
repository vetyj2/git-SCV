//! 원본 식별.
//!
//! 깃 정보는 반드시 `gix` 로 in-process 수집한다. 외부 `git` 명령 호출은
//! 금지다(fsmonitor 공격면). discover 방식(상위 디렉터리 탐색)도 금지 —
//! `<root>/.git` 이 있을 때만 깃 저장소다.

use crate::errors::ScvError;
use crate::model::{
    EntryKind, GitInfo, GitRemote, InputInfo, InventoryArtifact, PathPrivacy, PathPrivacyMode,
    SensitiveArtifact, SourceArtifact, SourceFingerprint, LOCAL_MAX_READ_BYTES_PER_MANIFEST,
    LOCAL_MAX_TOTAL_READ_BYTES, SCHEMA_VERSION,
};
use crate::redaction::redact_remote_url;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
            path_privacy: PathPrivacy::new(PathPrivacyMode::RepoRelative),
            source_fingerprint: None,
        },
        dirty_unknown,
    ))
}

pub fn apply_path_privacy(
    source: &mut SourceArtifact,
    inventory: &mut InventoryArtifact,
    mode: PathPrivacyMode,
) {
    source.path_privacy = PathPrivacy::new(mode);
    match mode {
        PathPrivacyMode::RepoRelative => {
            source.input.raw = "<repo-root>".into();
            source.resolved_path = "<repo-root>".into();
            inventory.root = "<repo-root>".into();
            if let Some(snapshot) = source.snapshot.as_mut() {
                snapshot.extracted_path = "<repo-root>".into();
            }
        }
        PathPrivacyMode::RedactedAbsolute => {
            source.input.raw = redact_home(&source.input.raw);
            source.resolved_path = redact_home(&source.resolved_path);
            inventory.root = redact_home(&inventory.root);
            if let Some(snapshot) = source.snapshot.as_mut() {
                snapshot.extracted_path = redact_home(&snapshot.extracted_path);
            }
        }
        PathPrivacyMode::Absolute => {}
    }
}

fn redact_home(value: &str) -> String {
    let Ok(home) = std::env::var("HOME") else {
        return value.into();
    };
    if home.is_empty() {
        return value.into();
    }
    value.replace(&home, "<home>")
}

pub fn fingerprint(
    source: &SourceArtifact,
    inventory: &InventoryArtifact,
    sensitive: &SensitiveArtifact,
    root: &Path,
    created_at: &str,
) -> SourceFingerprint {
    let sensitive_paths = sensitive
        .candidates
        .iter()
        .map(|candidate| candidate.path.as_str())
        .collect::<BTreeSet<_>>();
    let inventory_hash = hash_inventory(inventory);
    let non_sensitive_content_hash = hash_non_sensitive_content(inventory, root, &sensitive_paths);
    let sensitive_metadata_hash = hash_sensitive_metadata(sensitive);
    let kind = if source.snapshot.is_some() {
        "snapshot"
    } else if source.git.is_some() {
        "git-worktree"
    } else {
        "plain-directory"
    };
    let git_commit = source.git.as_ref().and_then(|git| git.commit.clone());
    let git_branch = source.git.as_ref().and_then(|git| git.branch.clone());
    let git_dirty = source.git.as_ref().and_then(|git| git.dirty);
    let git_untracked_policy = "included-metadata";
    let raw_sensitive_content_hashed = false;
    let symlinks_followed = false;
    let fingerprint_material = format!(
        "kind={kind}\ngit_commit={:?}\ngit_branch={:?}\ngit_dirty={:?}\ngit_untracked_policy={git_untracked_policy}\ninventory_hash={inventory_hash}\nnon_sensitive_content_hash={non_sensitive_content_hash}\nsensitive_metadata_hash={sensitive_metadata_hash}\nraw_sensitive_content_hashed={raw_sensitive_content_hashed}\nsymlinks_followed={symlinks_followed}\n",
        git_commit, git_branch, git_dirty
    );
    let fingerprint_hash = sha256_prefixed(fingerprint_material.as_bytes());

    SourceFingerprint {
        kind: kind.into(),
        git_commit,
        git_branch,
        git_dirty,
        git_untracked_policy: git_untracked_policy.into(),
        inventory_hash,
        non_sensitive_content_hash,
        sensitive_metadata_hash,
        raw_sensitive_content_hashed,
        symlinks_followed,
        created_at: created_at.into(),
        fingerprint_hash,
    }
}

fn hash_inventory(inventory: &InventoryArtifact) -> String {
    let mut material = String::new();
    for entry in &inventory.entries {
        material.push_str(&format!(
            "{}\t{:?}\t{:?}\t{:?}\t{:?}\n",
            entry.path, entry.kind, entry.size, entry.ext, entry.symlink_target
        ));
    }
    for skipped in &inventory.skipped {
        material.push_str(&format!(
            "skipped\t{}\t{:?}\n",
            skipped.path, skipped.reason
        ));
    }
    sha256_prefixed(material.as_bytes())
}

fn hash_non_sensitive_content(
    inventory: &InventoryArtifact,
    root: &Path,
    sensitive_paths: &BTreeSet<&str>,
) -> String {
    let mut hasher = Sha256::new();
    let mut total_read = 0_u64;
    for entry in &inventory.entries {
        if entry.kind != EntryKind::File || sensitive_paths.contains(entry.path.as_str()) {
            continue;
        }
        hasher.update(entry.path.as_bytes());
        hasher.update(b"\0");
        let size = entry.size.unwrap_or(0);
        if size > LOCAL_MAX_READ_BYTES_PER_MANIFEST {
            hasher.update(b"content-skipped:manifest-read-limit-exceeded");
        } else if total_read.saturating_add(size) > LOCAL_MAX_TOTAL_READ_BYTES {
            hasher.update(b"content-skipped:total-read-limit-exceeded");
        } else {
            match fs::read(root.join(&entry.path)) {
                Ok(bytes) => hasher.update(sha256_bytes(&bytes).as_bytes()),
                Err(err) => hasher.update(format!("unreadable:{err}").as_bytes()),
            }
            total_read = total_read.saturating_add(size);
        }
        hasher.update(b"\n");
    }
    format!("sha256:{}", hex_lower(hasher.finalize()))
}

fn hash_sensitive_metadata(sensitive: &SensitiveArtifact) -> String {
    let mut material = String::new();
    for candidate in &sensitive.candidates {
        material.push_str(&format!(
            "{}\t{:?}\t{}\t{:?}\n",
            candidate.path, candidate.size, candidate.summary, candidate.signals
        ));
    }
    sha256_prefixed(material.as_bytes())
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_bytes(bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(hasher.finalize())
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

#[cfg(test)]
mod tests {
    use crate::redaction::redact_remote_url;

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
