//! 파일 탐색.
//!
//! walkdir, follow_links(false) 고정. 무시 규칙 미적용(0407),
//! .git 내부 제외(0408), 심볼릭 링크 기록만(9007).
//! entries/skipped 는 경로 바이트 사전순으로 정렬해 돌려준다(T10 결정성).

use crate::errors::ScvError;
use crate::model::{
    Entry, EntryKind, InventoryArtifact, Limits, Policy, Skip, SkipReason, Totals, SCHEMA_VERSION,
};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn walk(root: &Path, run_id: &str) -> Result<InventoryArtifact, ScvError> {
    let resolved_root = fs::canonicalize(root).map_err(|err| {
        ScvError::Inspect(format!(
            "walk: 검사 대상 경로를 정규화하지 못했다: {}: {err}",
            root.display()
        ))
    })?;
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let mut limits = Limits::default();
    let mut symlink_count = 0_u64;
    let mut iterator = WalkDir::new(&resolved_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    while let Some(next) = iterator.next() {
        let dir_entry = match next {
            Ok(entry) => entry,
            Err(err) => {
                if let Some(path) = err.path() {
                    skipped.push(Skip {
                        path: relative_path(&resolved_root, path),
                        reason: SkipReason::Unreadable,
                    });
                }
                continue;
            }
        };

        if dir_entry.depth() == 0 {
            continue;
        }

        let relative = relative_path(&resolved_root, dir_entry.path());
        if dir_entry.depth() as u64 > limits.max_depth {
            push_limit_reason(&mut limits, "path-depth-limit-exceeded");
            if dir_entry.file_type().is_dir() {
                iterator.skip_current_dir();
            }
            continue;
        }
        if relative.len() as u64 > limits.max_path_bytes {
            push_limit_reason(&mut limits, "path-byte-limit-exceeded");
            if dir_entry.file_type().is_dir() {
                iterator.skip_current_dir();
            }
            continue;
        }
        if (entries.len() + skipped.len()) as u64 >= limits.max_entries {
            push_limit_reason(&mut limits, "local-entry-limit-exceeded");
            if dir_entry.file_type().is_dir() {
                iterator.skip_current_dir();
            }
            continue;
        }
        if relative == ".git" && dir_entry.file_type().is_dir() {
            skipped.push(Skip {
                path: relative,
                reason: SkipReason::ExcludedGitDir,
            });
            iterator.skip_current_dir();
            continue;
        }

        let metadata = match fs::symlink_metadata(dir_entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => {
                skipped.push(Skip {
                    path: relative,
                    reason: SkipReason::Unreadable,
                });
                if dir_entry.file_type().is_dir() {
                    iterator.skip_current_dir();
                }
                continue;
            }
        };

        let kind = entry_kind(&metadata.file_type());
        let symlink_target = if kind == EntryKind::Symlink {
            fs::read_link(dir_entry.path()).ok().map(path_to_slash)
        } else {
            None
        };

        if kind == EntryKind::Symlink {
            symlink_count += 1;
            if symlink_count > limits.max_symlinks {
                push_limit_reason(&mut limits, "symlink-limit-exceeded");
                continue;
            }
            skipped.push(Skip {
                path: relative.clone(),
                reason: SkipReason::Symlink,
            });
        }

        entries.push(Entry {
            ext: extension_lower(dir_entry.path()),
            path: relative,
            size: if kind == EntryKind::File {
                Some(metadata.len())
            } else {
                None
            },
            kind,
            symlink_target,
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    skipped.sort_by(|left, right| left.path.cmp(&right.path));

    let listed = entries
        .iter()
        .filter(|entry| entry.kind != EntryKind::Symlink)
        .count() as u64;
    let skipped_count = skipped.len() as u64;

    Ok(InventoryArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        root: resolved_root.display().to_string(),
        policy: Policy::default(),
        limits,
        entries,
        skipped,
        totals: Totals {
            discovered: listed + skipped_count,
            listed,
            skipped: skipped_count,
        },
    })
}

fn push_limit_reason(limits: &mut Limits, reason: &str) {
    if !limits
        .exceeded_reason_codes
        .iter()
        .any(|item| item == reason)
    {
        limits.exceeded_reason_codes.push(reason.into());
        limits.exceeded_reason_codes.sort();
    }
    limits.truncation_recorded = true;
}

fn entry_kind(file_type: &fs::FileType) -> EntryKind {
    if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Dir
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::Other
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(path_to_slash)
        .unwrap_or_else(|_| {
            path.file_name()
                .map(PathBuf::from)
                .map(path_to_slash)
                .unwrap_or_else(|| path.display().to_string())
        })
}

fn path_to_slash(path: impl AsRef<Path>) -> String {
    path.as_ref()
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase())
}
