//! 민감 후보 별도 진단 기록.
//!
//! 기본 모드는 후보 파일 원문을 읽지 않는다. `approved-raw` 모드에서도
//! 두 승인 플래그와 경로 목록이 모두 주어진 후보만 읽고, 원문은 저장하지
//! 않고 정적 신호 라벨만 남긴다.

use crate::cli::InspectArgs;
use crate::errors::ScvError;
use crate::model::{
    Detection, Entry, InventoryArtifact, RuleId, SensitiveArtifact, SensitiveCandidate,
    SensitiveReadStatus, SensitiveReviewMode, SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub fn build(
    inventory: &InventoryArtifact,
    detections: &[Detection],
    root: &Path,
    args: &InspectArgs,
    run_id: &str,
) -> Result<SensitiveArtifact, ScvError> {
    let approved_paths = approved_paths(args);
    let candidate_paths = candidate_paths(detections);
    let entry_by_path: BTreeMap<&str, &Entry> = inventory
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let mut candidates = Vec::new();
    let mut unapproved_paths = Vec::new();
    for path in &candidate_paths {
        let approved = approved_paths.contains(path);
        if !approved {
            unapproved_paths.push(path.clone());
        }

        let size = entry_by_path
            .get(path.as_str())
            .and_then(|entry| entry.size);
        let mut candidate = base_candidate(path, size, approved, args.sensitive_mode);
        if args.sensitive_mode == SensitiveReviewMode::ApprovedRaw && approved {
            read_approved_candidate(root, path, &mut candidate)?;
        }
        candidates.push(candidate);
    }

    Ok(SensitiveArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        mode: args.sensitive_mode,
        first_approval: args.approve_sensitive_review,
        second_approval: args.approve_sensitive_raw,
        approved_paths: approved_paths.into_iter().collect(),
        unapproved_paths,
        candidates,
        raw_content_stored: false,
        note: note(args.sensitive_mode),
    })
}

fn candidate_paths(detections: &[Detection]) -> Vec<String> {
    let mut paths: Vec<String> = detections
        .iter()
        .filter(|detection| detection.rule == RuleId::D13)
        .map(|detection| detection.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    paths.sort();
    paths
}

fn approved_paths(args: &InspectArgs) -> BTreeSet<String> {
    args.sensitive_paths
        .iter()
        .filter_map(|path| repo_relative_string(path))
        .collect()
}

fn base_candidate(
    path: &str,
    size: Option<u64>,
    approved: bool,
    mode: SensitiveReviewMode,
) -> SensitiveCandidate {
    let (read_status, summary, signals) = match mode {
        SensitiveReviewMode::Exclude => (
            SensitiveReadStatus::NotRead,
            "별도 진단 제외: 기본 검사에서 내용은 열지 않았다.".into(),
            vec!["name-only-secret-candidate".into()],
        ),
        SensitiveReviewMode::RedactedSummary => (
            SensitiveReadStatus::MetadataOnly,
            "가린 로컬 요약: 경로, 크기, 이름 기반 분류만 기록했다.".into(),
            vec!["metadata-only-secret-candidate".into()],
        ),
        SensitiveReviewMode::ApprovedRaw if approved => (
            SensitiveReadStatus::NotRead,
            "승인 경로 원문 분석 대기: 원문 저장 없이 정적 신호만 남긴다.".into(),
            vec!["approved-path-pending-read".into()],
        ),
        SensitiveReviewMode::ApprovedRaw => (
            SensitiveReadStatus::NotRead,
            "승인 경로에 없어서 내용은 열지 않았다.".into(),
            vec!["not-approved-for-raw-review".into()],
        ),
    };

    SensitiveCandidate {
        path: path.into(),
        size,
        approved_for_raw: approved,
        raw_read: false,
        read_status,
        summary,
        signals,
    }
}

fn read_approved_candidate(
    root: &Path,
    relative_path: &str,
    candidate: &mut SensitiveCandidate,
) -> Result<(), ScvError> {
    let target = root.join(relative_path);
    let bytes = std::fs::read(&target).map_err(|err| {
        ScvError::Inspect(format!(
            "sensitive: 승인된 민감 후보를 읽지 못했다: {relative_path}: {err}"
        ))
    })?;

    candidate.raw_read = true;
    let (status, signals) = classify_approved_bytes(&bytes);
    candidate.read_status = status;
    candidate.signals = signals;
    candidate.summary = match status {
        SensitiveReadStatus::Binary => {
            "승인된 파일을 읽었고 바이너리 또는 널 바이트 신호만 기록했다.".into()
        }
        SensitiveReadStatus::Read => {
            "승인된 원문을 읽었지만 원문은 저장하지 않았고 정적 신호만 기록했다.".into()
        }
        SensitiveReadStatus::Unreadable => "승인됐지만 내용을 읽지 못했다.".into(),
        SensitiveReadStatus::NotRead | SensitiveReadStatus::MetadataOnly => {
            "내용을 열지 않았다.".into()
        }
    };
    Ok(())
}

fn classify_approved_bytes(bytes: &[u8]) -> (SensitiveReadStatus, Vec<String>) {
    if bytes.iter().take(8192).any(|byte| *byte == 0) {
        return (
            SensitiveReadStatus::Binary,
            vec!["binary-or-nul-byte".into()],
        );
    }

    let text = String::from_utf8_lossy(bytes);
    let lower = text.to_lowercase();
    let mut signals = Vec::new();

    if text.starts_with("#!") {
        signals.push("shebang-present".into());
    }
    if text.lines().take(40).any(is_env_assignment_like) {
        signals.push("environment-assignment-like".into());
    }
    if contains_any(&lower, &["curl ", "wget "]) {
        signals.push("network-download-command-token".into());
    }
    if contains_any(&lower, &["chmod ", "chown "]) {
        signals.push("permission-change-command-token".into());
    }
    if contains_any(
        &lower,
        &["eval", "bash -c", "sh -c", "node -e", "python -c"],
    ) {
        signals.push("dynamic-execution-token".into());
    }
    if lower.contains("base64") {
        signals.push("base64-token".into());
    }
    if lower.contains("rm -rf") {
        signals.push("destructive-remove-token".into());
    }

    if signals.is_empty() {
        signals.push("no-static-script-signal-detected".into());
    }

    (SensitiveReadStatus::Read, signals)
}

fn is_env_assignment_like(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("export ") {
        return trimmed
            .strip_prefix("export ")
            .is_some_and(has_assignment_name);
    }
    has_assignment_name(trimmed)
}

fn has_assignment_name(value: &str) -> bool {
    let Some((name, _)) = value.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn repo_relative_string(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn note(mode: SensitiveReviewMode) -> String {
    match mode {
        SensitiveReviewMode::Exclude => {
            "민감 후보는 기본 검사에서 보류 항목으로 남으며 원문을 열지 않았다.".into()
        }
        SensitiveReviewMode::RedactedSummary => {
            "1차 승인에 따라 가린 로컬 요약만 만들었고 원문은 열지 않았다.".into()
        }
        SensitiveReviewMode::ApprovedRaw => {
            "2중 승인과 경로 목록이 모두 주어진 후보만 읽었고 원문은 산출물에 저장하지 않았다."
                .into()
        }
    }
}
