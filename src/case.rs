//! Case package manager.
//!
//! A case is an inspect output directory with a `.git-scv-case.json` sentinel.
//! The manager never deletes the source repository and never runs target code.

use crate::cli::{
    CaseCreateArgs, CaseDeleteArgs, CaseIdArgs, CaseNextActionArgs, CasePruneArgs, InspectArgs,
};
use crate::errors::ScvError;
use crate::model::{PathPrivacyMode, SensitiveReviewMode};
use crate::safety;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const CASE_SENTINEL: &str = ".git-scv-case.json";
const CASE_LOCK: &str = ".git-scv-case.lock";
const DELETE_CASE_ACK: &str = "delete-git-scv-case";
const DELETE_ALL_ACK: &str = "delete-all-git-scv-cases";

#[derive(Serialize, Deserialize)]
struct CaseMetadata {
    schema_version: String,
    case_id: String,
    case_path: String,
    source_path: String,
    created_at_unix_nanos: i128,
    artifact_manifest_sha256: String,
    source_fingerprint_hash: String,
    git_scv_version: String,
    incomplete: bool,
}

#[derive(Deserialize)]
struct BriefSummary {
    run_id: String,
    artifact_manifest_sha256: String,
    source_fingerprint_hash: String,
    verdict: String,
    action_required: bool,
}

#[derive(Deserialize)]
struct SourcePrivacySummary {
    path_privacy: SourcePrivacyModeSummary,
}

#[derive(Deserialize)]
struct SourcePrivacyModeSummary {
    mode: String,
}

#[derive(Deserialize)]
struct ApprovalGateSummary {
    approval_required: bool,
}

#[derive(Deserialize)]
struct ExecutionGateSummary {
    approval_required: bool,
    requires_exact_command: bool,
}

#[derive(Deserialize)]
struct GatesSummary {
    sensitive_raw_review: ApprovalGateSummary,
    execution_model_input_review: ApprovalGateSummary,
    execution_command_review: ExecutionGateSummary,
}

#[derive(Deserialize)]
struct ReceiptSummary {
    artifact_manifest_sha256: String,
    source_fingerprint_hash: String,
    summarized_to_user: bool,
    blocked_actions_acknowledged: bool,
}

struct SourceStatusCheck {
    expected: String,
    current: Option<String>,
    valid: bool,
}

#[derive(Serialize)]
struct NextActionResponse {
    action: String,
    argv: Vec<String>,
    allowed: bool,
    blocked_by: Vec<String>,
    next_required_steps: Vec<String>,
    source_status: String,
    artifact_manifest_sha256: String,
    artifact_manifest_valid: bool,
    receipt_valid: bool,
    safe_claim_made: bool,
}

struct CaseLock {
    path: PathBuf,
}

impl Drop for CaseLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn create(args: CaseCreateArgs) -> Result<(), ScvError> {
    let root = ensure_case_root()?;
    let _lock = acquire_lock(&root)?;
    let source_path = fs::canonicalize(&args.repo_path).map_err(|err| {
        ScvError::Usage(format!(
            "오류: case create 검사 대상 경로를 정규화하지 못했다: {}: {err}",
            args.repo_path.display()
        ))
    })?;
    let case_id = new_case_id(&source_path);
    let case_path = root.join(&case_id);
    if case_path.exists() {
        return Err(ScvError::Usage(format!(
            "오류: case 경로가 이미 존재한다: {}",
            case_path.display()
        )));
    }
    let tmp_path = root.join(format!(".tmp-{case_id}"));
    if tmp_path.exists() {
        fs::remove_dir_all(&tmp_path).map_err(|err| {
            ScvError::Inspect(format!(
                "case: 임시 case 디렉터리를 정리하지 못했다: {}: {err}",
                tmp_path.display()
            ))
        })?;
    }
    fs::create_dir_all(&tmp_path).map_err(|err| {
        ScvError::Inspect(format!(
            "case: 임시 case 디렉터리를 만들지 못했다: {}: {err}",
            tmp_path.display()
        ))
    })?;

    let inspect_args = InspectArgs {
        repo_path: source_path.clone(),
        out: tmp_path.clone(),
        sensitive_mode: SensitiveReviewMode::Exclude,
        approve_sensitive_review: false,
        sensitive_review_ack: None,
        approve_sensitive_raw: false,
        sensitive_raw_ack: None,
        sensitive_paths: Vec::new(),
        path_privacy: args.path_privacy,
    };
    if let Err(err) = crate::inspect::run(inspect_args) {
        let _ = fs::write(tmp_path.join("INCOMPLETE"), err.user_message());
        return Err(err);
    }

    let brief: BriefSummary = read_json(&tmp_path, "brief.json")?;
    let metadata = CaseMetadata {
        schema_version: "2".into(),
        case_id: case_id.clone(),
        case_path: case_path.display().to_string(),
        source_path: source_path.display().to_string(),
        created_at_unix_nanos: OffsetDateTime::now_utc().unix_timestamp_nanos(),
        artifact_manifest_sha256: brief.artifact_manifest_sha256.clone(),
        source_fingerprint_hash: brief.source_fingerprint_hash.clone(),
        git_scv_version: env!("CARGO_PKG_VERSION").into(),
        incomplete: false,
    };
    write_json(&tmp_path, CASE_SENTINEL, &metadata)?;
    fs::rename(&tmp_path, &case_path).map_err(|err| {
        ScvError::Inspect(format!(
            "case: case package를 최종 경로로 이동하지 못했다: {} -> {}: {err}",
            tmp_path.display(),
            case_path.display()
        ))
    })?;

    println!("case_id={case_id}");
    println!("case_path={}", case_path.display());
    println!(
        "artifact_manifest_sha256={}",
        metadata.artifact_manifest_sha256
    );
    println!(
        "source_fingerprint_hash={}",
        metadata.source_fingerprint_hash
    );
    Ok(())
}

pub fn list() -> Result<(), ScvError> {
    let root = ensure_case_root()?;
    println!("case_root={}", root.display());
    for entry in case_entries(&root)? {
        let metadata = read_case_metadata_path(&entry)?;
        let brief = read_json::<BriefSummary>(&entry, "brief.json").ok();
        println!(
            "case_id={} verdict={} action_required={} path={}",
            metadata.case_id,
            brief
                .as_ref()
                .map(|item| item.verdict.as_str())
                .unwrap_or("unknown"),
            brief
                .as_ref()
                .map(|item| item.action_required.to_string())
                .unwrap_or_else(|| "unknown".into()),
            entry.display()
        );
    }
    Ok(())
}

pub fn show(args: CaseIdArgs) -> Result<(), ScvError> {
    let path = checked_case_path(&args.case_id)?;
    let metadata = read_case_metadata_path(&path)?;
    let brief: BriefSummary = read_json(&path, "brief.json")?;
    println!("case_id={}", metadata.case_id);
    println!("case_path={}", path.display());
    println!("source_path={}", source_path_for_display(&path, &metadata));
    println!("run_id={}", brief.run_id);
    println!("verdict={}", brief.verdict);
    println!("action_required={}", brief.action_required);
    println!(
        "artifact_manifest_sha256={}",
        metadata.artifact_manifest_sha256
    );
    println!(
        "source_fingerprint_hash={}",
        metadata.source_fingerprint_hash
    );
    Ok(())
}

pub fn brief(args: CaseIdArgs) -> Result<(), ScvError> {
    let path = checked_case_path(&args.case_id)?;
    crate::brief::run(crate::cli::BriefArgs { run_dir: path })
}

pub fn verify_source(args: CaseIdArgs) -> Result<(), ScvError> {
    let path = checked_case_path(&args.case_id)?;
    let status = source_status(&path)?;
    if status.valid {
        println!("source_status=valid");
        Ok(())
    } else {
        Err(ScvError::Validation(vec![
            "stale-source: source fingerprint mismatch".into(),
        ]))
    }
}

pub fn status(args: CaseIdArgs) -> Result<(), ScvError> {
    let path = checked_case_path(&args.case_id)?;
    let metadata = read_case_metadata_path(&path)?;
    let status = source_status(&path)?;
    println!("case_id={}", metadata.case_id);
    println!(
        "source_status={}",
        if status.valid {
            "valid"
        } else {
            "stale-source"
        }
    );
    println!("case_path={}", path.display());
    println!("source_path={}", source_path_for_display(&path, &metadata));
    Ok(())
}

pub fn next_action(args: CaseNextActionArgs) -> Result<(), ScvError> {
    let path = checked_case_path(&args.case_id)?;
    let metadata = read_case_metadata_path(&path)?;
    let brief: BriefSummary = read_json(&path, "brief.json")?;
    let gates = read_json::<GatesSummary>(&path, "gates.json").ok();

    let mut blocked_by = Vec::new();
    let mut next_required_steps = Vec::new();
    let mut artifact_manifest_valid = false;
    let mut source_status_label = "unknown".to_string();

    let manifest_path = path.join("artifact_manifest.json");
    if manifest_path.is_file() {
        match crate::artifacts::file_sha256(&path, "artifact_manifest.json") {
            Ok(actual_hash) => {
                artifact_manifest_valid = actual_hash == brief.artifact_manifest_sha256
                    && actual_hash == metadata.artifact_manifest_sha256;
                if !artifact_manifest_valid {
                    push_unique(&mut blocked_by, "artifact-manifest-mismatch");
                    push_unique(
                        &mut next_required_steps,
                        "re-run git-scv case create after artifact/package change",
                    );
                }
            }
            Err(_) => {
                push_unique(&mut blocked_by, "artifact-manifest-hash-failed");
                push_unique(
                    &mut next_required_steps,
                    "re-run git-scv case create after artifact/package change",
                );
            }
        }
    } else {
        push_unique(&mut blocked_by, "artifact-manifest-missing");
        push_unique(
            &mut next_required_steps,
            "re-run git-scv case create after artifact/package change",
        );
    }

    match source_status_check(&path) {
        Ok(source_status) => {
            source_status_label = if source_status.valid {
                "valid".into()
            } else {
                push_unique(&mut blocked_by, "stale-source");
                push_unique(
                    &mut next_required_steps,
                    "git-scv case verify-source <case-id>",
                );
                "stale-source".into()
            };
        }
        Err(_) => {
            push_unique(&mut blocked_by, "source-verify-failed");
            push_unique(
                &mut next_required_steps,
                "git-scv case verify-source <case-id>",
            );
        }
    }

    let receipt_valid = receipt_valid_for_case(&path, &brief);
    if action_requires_receipt(&args.action) && !receipt_valid {
        push_unique(&mut blocked_by, "agent-read-receipt-required");
        push_unique(
            &mut next_required_steps,
            "git-scv receipt create <case-path> --agent Hermes --summary-file <summary.md> --summarized-to-user --blocked-actions-acknowledged",
        );
    }

    if let Some(gates) = gates.as_ref() {
        if is_execution_action(&args.action, &args.argv) {
            if gates.execution_command_review.requires_exact_command && args.argv.is_empty() {
                push_unique(&mut blocked_by, "exact-command-envelope-required");
                push_unique(
                    &mut next_required_steps,
                    "git-scv case next-action <case-id> --action install --argv npm install",
                );
            }
            if gates.execution_command_review.approval_required {
                push_unique(&mut blocked_by, "execution-command-review-required");
                push_unique(
                    &mut next_required_steps,
                    "request source-bound exact execution approval before running target commands",
                );
            }
        }
        if is_model_input_action(&args.action)
            && gates.execution_model_input_review.approval_required
        {
            push_unique(&mut blocked_by, "execution-model-input-review-required");
            push_unique(
                &mut next_required_steps,
                "list execution/model-input candidates and request user review",
            );
        }
        if is_sensitive_raw_action(&args.action) && gates.sensitive_raw_review.approval_required {
            push_unique(&mut blocked_by, "sensitive-raw-review-required");
            push_unique(
                &mut next_required_steps,
                "request sensitive raw review with exact approved repo-relative paths",
            );
        }
    } else {
        push_unique(&mut blocked_by, "gates-artifact-missing");
        push_unique(
            &mut next_required_steps,
            "re-run git-scv case create after artifact/package change",
        );
    }

    let response = NextActionResponse {
        action: args.action,
        argv: args.argv,
        allowed: blocked_by.is_empty(),
        blocked_by,
        next_required_steps,
        source_status: source_status_label,
        artifact_manifest_sha256: brief.artifact_manifest_sha256,
        artifact_manifest_valid,
        receipt_valid,
        safe_claim_made: false,
    };
    let mut text = serde_json::to_string_pretty(&response)
        .map_err(|err| ScvError::Inspect(format!("case: next-action JSON 직렬화 실패: {err}")))?;
    text.push('\n');
    print!("{text}");
    Ok(())
}

pub fn delete(args: CaseDeleteArgs) -> Result<(), ScvError> {
    if args.ack != DELETE_CASE_ACK {
        return Err(ScvError::Usage(format!(
            "오류: case 삭제에는 --ack {DELETE_CASE_ACK} 확인이 필요하다."
        )));
    }
    let path = checked_case_path(&args.case_id)?;
    ensure_delete_safe(&path)?;
    fs::remove_dir_all(&path).map_err(|err| {
        ScvError::Inspect(format!(
            "case: case package를 삭제하지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    println!("deleted_case_id={}", args.case_id);
    Ok(())
}

pub fn prune(args: CasePruneArgs) -> Result<(), ScvError> {
    if !args.all || args.ack != DELETE_ALL_ACK {
        return Err(ScvError::Usage(format!(
            "오류: 전체 case 삭제에는 --all --ack {DELETE_ALL_ACK} 확인이 필요하다."
        )));
    }
    let root = ensure_case_root()?;
    let _lock = acquire_lock(&root)?;
    let mut deleted = 0_u64;
    for entry in case_entries(&root)? {
        ensure_delete_safe(&entry)?;
        fs::remove_dir_all(&entry).map_err(|err| {
            ScvError::Inspect(format!(
                "case: case package를 삭제하지 못했다: {}: {err}",
                entry.display()
            ))
        })?;
        deleted += 1;
    }
    println!("deleted_cases={deleted}");
    Ok(())
}

pub fn doctor() -> Result<(), ScvError> {
    let root = ensure_case_root()?;
    println!("case_root={}", root.display());
    println!("exists={}", root.is_dir());
    println!("world_readable={}", case_root_world_readable(&root)?);
    println!("sentinel_name={CASE_SENTINEL}");
    println!("lock_file={CASE_LOCK}");
    Ok(())
}

fn source_status(case_path: &Path) -> Result<SourceStatusCheck, ScvError> {
    let status = source_status_check(case_path)?;
    println!("expected_source_fingerprint_hash={}", status.expected);
    if let Some(current) = status.current.as_deref() {
        println!("current_source_fingerprint_hash={current}");
    } else {
        println!("current_source_fingerprint_hash=unknown");
    }
    Ok(status)
}

fn source_status_check(case_path: &Path) -> Result<SourceStatusCheck, ScvError> {
    let metadata = read_case_metadata_path(case_path)?;
    let source_path = PathBuf::from(&metadata.source_path);
    let current = current_source_fingerprint_hash(&source_path, case_path)?;
    let valid = current == metadata.source_fingerprint_hash;
    Ok(SourceStatusCheck {
        expected: metadata.source_fingerprint_hash,
        current: Some(current),
        valid,
    })
}

fn current_source_fingerprint_hash(
    source_path: &Path,
    case_path: &Path,
) -> Result<String, ScvError> {
    let run_id = "case-verify-source";
    let raw_input = source_path.display().to_string();
    let (mut source, _) = crate::source::identify(&raw_input, source_path, run_id)?;
    let root = Path::new(&source.resolved_path);
    let inventory = crate::walk::walk(root, run_id)?;
    let detect_outcome = crate::detect::detect(&inventory, root)?;
    let inspect_args = InspectArgs {
        repo_path: source_path.to_path_buf(),
        out: case_path.to_path_buf(),
        sensitive_mode: SensitiveReviewMode::Exclude,
        approve_sensitive_review: false,
        sensitive_review_ack: None,
        approve_sensitive_raw: false,
        sensitive_raw_ack: None,
        sensitive_paths: Vec::new(),
        path_privacy: PathPrivacyMode::RepoRelative,
    };
    let sensitive = crate::sensitive::build(
        &inventory,
        &detect_outcome.detections,
        root,
        &inspect_args,
        run_id,
    )?;
    source.source_fingerprint = Some(crate::source::fingerprint(
        &source,
        &inventory,
        &sensitive,
        root,
        "case-verify-source",
    ));
    Ok(source
        .source_fingerprint
        .as_ref()
        .map(|fingerprint| fingerprint.fingerprint_hash.clone())
        .unwrap_or_else(|| "sha256:unknown".into()))
}

fn ensure_case_root() -> Result<PathBuf, ScvError> {
    let root = default_case_root()?;
    fs::create_dir_all(&root).map_err(|err| {
        ScvError::Inspect(format!(
            "case: case root를 만들지 못했다: {}: {err}",
            root.display()
        ))
    })?;
    set_owner_only_permissions(&root)?;
    Ok(root)
}

fn default_case_root() -> Result<PathBuf, ScvError> {
    if let Some(value) = nonempty_env("GIT_SCV_CASE_ROOT") {
        return Ok(PathBuf::from(value));
    }
    if let Some(value) = nonempty_env("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(value).join("git-scv").join("cases"));
    }
    if let Some(value) = nonempty_env("HOME") {
        return Ok(PathBuf::from(value)
            .join(".cache")
            .join("git-scv")
            .join("cases"));
    }
    if let Some(value) = nonempty_env("APPDATA") {
        return Ok(PathBuf::from(value).join("git-scv").join("cases"));
    }
    Err(ScvError::Usage(
        "오류: case root를 정할 HOME/XDG_CACHE_HOME/APPDATA가 없다.".into(),
    ))
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn set_owner_only_permissions(path: &Path) -> Result<(), ScvError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            ScvError::Inspect(format!(
                "case: case root 권한을 0700으로 설정하지 못했다: {}: {err}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn acquire_lock(root: &Path) -> Result<CaseLock, ScvError> {
    let path = root.join(CASE_LOCK);
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(CaseLock { path }),
        Err(err) => Err(ScvError::Inspect(format!(
            "case: case root lock을 얻지 못했다: {}: {err}",
            path.display()
        ))),
    }
}

fn checked_case_path(case_id: &str) -> Result<PathBuf, ScvError> {
    validate_case_id(case_id)?;
    let root = ensure_case_root()?;
    let path = root.join(case_id);
    ensure_case_dir_shape(&root, &path, case_id)?;
    Ok(path)
}

fn validate_case_id(case_id: &str) -> Result<(), ScvError> {
    if case_id.is_empty()
        || case_id.contains('/')
        || case_id.contains('\\')
        || case_id.contains("..")
    {
        return Err(ScvError::Usage(format!("오류: 잘못된 case id: {case_id}")));
    }
    Ok(())
}

fn ensure_case_dir_shape(root: &Path, path: &Path, case_id: &str) -> Result<(), ScvError> {
    let root_canon = fs::canonicalize(root).map_err(|err| {
        ScvError::Inspect(format!(
            "case: case root를 정규화하지 못했다: {}: {err}",
            root.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        ScvError::Usage(format!(
            "오류: case package를 찾지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ScvError::Usage(format!(
            "오류: case package 경로가 디렉터리가 아니거나 symlink다: {}",
            path.display()
        )));
    }
    let path_canon = fs::canonicalize(path).map_err(|err| {
        ScvError::Inspect(format!(
            "case: case package를 정규화하지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    if !path_canon.starts_with(&root_canon) {
        return Err(ScvError::Usage(format!(
            "오류: case package가 case root 밖에 있다: {}",
            path.display()
        )));
    }
    let case_metadata = read_case_metadata_path(path)?;
    if case_metadata.case_id != case_id {
        return Err(ScvError::Usage(format!(
            "오류: sentinel case_id 불일치: expected {case_id}, actual {}",
            case_metadata.case_id
        )));
    }
    Ok(())
}

fn ensure_delete_safe(path: &Path) -> Result<(), ScvError> {
    let metadata = read_case_metadata_path(path)?;
    let source = PathBuf::from(&metadata.source_path);
    if let (Ok(source), Ok(case_path)) = (fs::canonicalize(&source), fs::canonicalize(path)) {
        if source.starts_with(&case_path) || case_path.starts_with(&source) {
            return Err(ScvError::Usage(
                "오류: source path와 case path가 같거나 포함 관계라 삭제를 거부한다.".into(),
            ));
        }
    }
    Ok(())
}

fn read_case_metadata_path(path: &Path) -> Result<CaseMetadata, ScvError> {
    read_json(path, CASE_SENTINEL)
}

fn source_path_for_display(case_path: &Path, metadata: &CaseMetadata) -> String {
    let mode = read_json::<SourcePrivacySummary>(case_path, "source.json")
        .ok()
        .map(|source| source.path_privacy.mode)
        .unwrap_or_else(|| "repo-relative".into());
    if mode == "absolute" {
        metadata.source_path.clone()
    } else {
        "<repo-root>".into()
    }
}

fn receipt_valid_for_case(case_path: &Path, brief: &BriefSummary) -> bool {
    read_json::<ReceiptSummary>(case_path, "agent_receipt.json")
        .map(|receipt| {
            receipt.artifact_manifest_sha256 == brief.artifact_manifest_sha256
                && receipt.source_fingerprint_hash == brief.source_fingerprint_hash
                && receipt.summarized_to_user
                && receipt.blocked_actions_acknowledged
        })
        .unwrap_or(false)
}

fn action_requires_receipt(action: &str) -> bool {
    !matches!(
        action.to_ascii_lowercase().as_str(),
        "none" | "show" | "status" | "brief"
    )
}

fn is_execution_action(action: &str, argv: &[String]) -> bool {
    if !argv.is_empty() {
        return true;
    }
    matches!(
        action.to_ascii_lowercase().as_str(),
        "install"
            | "build"
            | "test"
            | "run"
            | "execute"
            | "npm"
            | "cargo"
            | "pip"
            | "docker"
            | "make"
            | "git-commit"
            | "open-vscode"
    )
}

fn is_model_input_action(action: &str) -> bool {
    matches!(
        action.to_ascii_lowercase().as_str(),
        "model-input" | "inspect-slice" | "read-execution-candidate"
    )
}

fn is_sensitive_raw_action(action: &str) -> bool {
    matches!(
        action.to_ascii_lowercase().as_str(),
        "sensitive-raw" | "read-sensitive-raw"
    )
}

fn push_unique(items: &mut Vec<String>, value: &str) {
    if !items.iter().any(|item| item == value) {
        items.push(value.to_string());
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(dir: &Path, name: &str) -> Result<T, ScvError> {
    let path = dir.join(name);
    let bytes = fs::read(&path).map_err(|err| {
        ScvError::Inspect(format!(
            "case: JSON 파일을 읽지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        ScvError::Inspect(format!(
            "case: JSON 파일을 해석하지 못했다: {}: {err}",
            path.display()
        ))
    })
}

fn write_json<T: Serialize>(dir: &Path, name: &str, value: &T) -> Result<(), ScvError> {
    let target = dir.join(name);
    safety::assert_inside(dir, &target)?;
    let mut text = serde_json::to_string_pretty(value)
        .map_err(|err| ScvError::Inspect(format!("case: JSON 직렬화 실패: {name}: {err}")))?;
    text.push('\n');
    fs::write(&target, text).map_err(|err| {
        ScvError::Inspect(format!(
            "case: JSON 파일을 쓰지 못했다: {}: {err}",
            target.display()
        ))
    })
}

fn case_entries(root: &Path) -> Result<Vec<PathBuf>, ScvError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).map_err(|err| {
        ScvError::Inspect(format!(
            "case: case root를 읽지 못했다: {}: {err}",
            root.display()
        ))
    })? {
        let entry = entry.map_err(|err| {
            ScvError::Inspect(format!("case: case root 항목을 읽지 못했다: {err}"))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join(CASE_SENTINEL).is_file() {
            entries.push(path);
        }
    }
    entries.sort();
    Ok(entries)
}

fn new_case_id(source_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_path.display().to_string().as_bytes());
    hasher.update(
        OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
            .as_bytes(),
    );
    let digest = hex_lower(hasher.finalize());
    format!("case-{}", &digest[..16])
}

fn case_root_world_readable(root: &Path) -> Result<bool, ScvError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root)
            .map_err(|err| {
                ScvError::Inspect(format!(
                    "case: case root metadata를 읽지 못했다: {}: {err}",
                    root.display()
                ))
            })?
            .permissions()
            .mode();
        Ok(mode & 0o077 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Ok(false)
    }
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
