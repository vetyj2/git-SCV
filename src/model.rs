//! 산출물과 단계 간 데이터의 단일 타입 정의.
//! 모든 단계 함수는 이 모듈의 타입만 주고받는다.

use serde::Serialize;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1";

/// 0804 — report.md 와 V05 가 그대로 비교하는 무실행 고정 문장.
pub const NO_EXEC_SENTENCE: &str =
    "이 검사는 대상 저장소의 어떤 명령, 스크립트, 훅도 실행하지 않았다.";

/// 0805 / V06 — 낮은 확신 고정 문장.
pub const LOW_CONFIDENCE_SENTENCE: &str = "이 검사는 증거가 충분하지 않아 낮은 확신의 결과다.";

// ---------------------------------------------------------------- run.json

#[derive(Serialize, Clone, Debug)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum StageStatus {
    Ok,
    Failed,
    Skipped,
}

#[derive(Serialize, Clone, Debug)]
pub struct StageRecord {
    pub name: String,
    pub status: StageStatus,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Success,
    Failed,
    Invalid,
}

#[derive(Serialize, Debug)]
pub struct RunArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub tool: ToolInfo,
    pub command: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub status: RunStatus,
    pub stages: Vec<StageRecord>,
    pub exit_code: i32,
}

// ------------------------------------------------------------- source.json

#[derive(Serialize, Clone, Debug)]
pub struct InputInfo {
    pub raw: String,
    pub kind: String, // 최소 기능판에서는 항상 "local-path" (0021)
}

#[derive(Serialize, Clone, Debug)]
pub struct GitRemote {
    pub name: String,
    pub url: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct GitInfo {
    pub is_repo: bool,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub detached: bool,
    /// 상태 계산 실패 시 None — 한계 문장으로 이어진다.
    pub dirty: Option<bool>,
    pub remotes: Vec<GitRemote>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub input: InputInfo,
    pub resolved_path: String,
    pub git: Option<GitInfo>,
    pub snapshot: Option<String>, // 최소 기능판에서 항상 None (0305)
}

// ---------------------------------------------------------- inventory.json

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Serialize, Clone, Debug)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub ext: Option<String>,
    pub symlink_target: Option<String>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SkipReason {
    #[serde(rename = "symlink")]
    Symlink,
    #[serde(rename = "unreadable")]
    Unreadable,
    #[serde(rename = "excluded-git-dir")]
    ExcludedGitDir,
}

#[derive(Serialize, Clone, Debug)]
pub struct Skip {
    pub path: String,
    pub reason: SkipReason,
}

#[derive(Serialize, Clone, Debug)]
pub struct Policy {
    pub hidden_entries: String,
    pub git_dir: String,
    pub ignore_rules: String,
    pub symlinks: String,
}

impl Default for Policy {
    fn default() -> Self {
        // 고정 문자열 — inventory.json policy.
        Policy {
            hidden_entries: "included".into(),
            git_dir: "excluded-from-entries".into(),
            ignore_rules: "not-applied".into(),
            symlinks: "recorded-not-followed".into(),
        }
    }
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct Limits {
    pub max_files: Option<u64>,               // 9003 확정: 항상 None
    pub max_read_bytes_per_file: Option<u64>, // 9003 확정: 항상 None
}

#[derive(Serialize, Clone, Debug)]
pub struct Totals {
    pub discovered: u64,
    pub listed: u64,
    pub skipped: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct InventoryArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub root: String,
    pub policy: Policy,
    pub limits: Limits,
    pub entries: Vec<Entry>,
    pub skipped: Vec<Skip>,
    pub totals: Totals,
}

// ----------------------------------------------------------- coverage.json

#[derive(Serialize, Clone, Debug)]
pub struct ReadFile {
    pub path: String,
    pub bytes: u64,
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct SkipReasons {
    pub symlink: u64,
    pub binary: u64,
    pub unreadable: u64,
    #[serde(rename = "excluded-git-dir")]
    pub excluded_git_dir: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct CoverageArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub files_discovered: u64,
    pub files_read: u64,
    pub files_skipped: u64,
    pub bytes_read_total: u64,
    pub read_files: Vec<ReadFile>,
    pub skip_reasons: SkipReasons,
    pub confidence_note: String,
}

// ----------------------------------------------------------- evidence.json

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceKind {
    #[serde(rename = "file-presence")]
    FilePresence,
    #[serde(rename = "content-line")]
    ContentLine,
    #[serde(rename = "symlink-record")]
    SymlinkRecord,
    #[serde(rename = "secret-name")]
    SecretName,
}

#[derive(Serialize, Clone, Copy, Debug)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Serialize, Clone, Debug)]
pub struct Evidence {
    pub id: String,
    pub path: String,
    pub kind: EvidenceKind,
    pub lines: Option<LineRange>,
    pub summary: String,
    pub excerpt: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct EvidenceArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub evidence: Vec<Evidence>,
}

// ----------------------------------------------------------- findings.json

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    #[serde(rename = "auto-exec-hook")]
    AutoExecHook,
    #[serde(rename = "build-automation")]
    BuildAutomation,
    #[serde(rename = "container")]
    Container,
    #[serde(rename = "ci-automation")]
    CiAutomation,
    #[serde(rename = "shell-script")]
    ShellScript,
    #[serde(rename = "secret-candidate")]
    SecretCandidate,
    #[serde(rename = "manifest")]
    Manifest,
}

/// 9001 확정 — 네 단어 라벨, 숫자 없음.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Priority {
    #[serde(rename = "정보")]
    Info,
    #[serde(rename = "낮음")]
    Low,
    #[serde(rename = "중간")]
    Medium,
    #[serde(rename = "높음")]
    High,
}

/// 증거 없는 발견사항은 타입 수준에서 만들 수 없다 (0605, 0606, 1304).
/// 필드가 비공개이므로 생성 경로는 `Finding::new` 뿐이다.
#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    id: String,
    category: Category,
    priority: Priority,
    summary: String,
    detail: String,
    limitation: String,
    evidence: Vec<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        category: Category,
        priority: Priority,
        summary: impl Into<String>,
        detail: impl Into<String>,
        limitation: impl Into<String>,
        evidence: Vec<String>,
    ) -> Result<Self, String> {
        if evidence.is_empty() {
            return Err("증거 없는 발견사항은 만들 수 없다 (0606)".into());
        }
        Ok(Finding {
            id: id.into(),
            category,
            priority,
            summary: summary.into(),
            detail: detail.into(),
            limitation: limitation.into(),
            evidence,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn evidence_ids(&self) -> &[String] {
        &self.evidence
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    pub fn category(&self) -> Category {
        self.category
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct FindingsArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}

// -------------------------------------------------------- dependencies.json

#[derive(Serialize, Clone, Debug)]
pub struct DependencyItem {
    pub name: String,
    pub scope: String,
    pub source_kind: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DependencyManifest {
    pub path: String,
    pub ecosystem: String,
    pub dependencies: Vec<DependencyItem>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DependencyArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub manifests: Vec<DependencyManifest>,
    pub limitations: Vec<String>,
    pub note: String,
}

// ------------------------------------------------------------ sectors.json

#[derive(Serialize, Clone, Debug)]
pub struct Sector {
    pub name: String,
    pub files: u64,
    pub bytes: u64,
    pub estimated_tokens: u64,
    pub extensions: BTreeMap<String, u64>,
    pub detections: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct SectorsArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub sectors: Vec<Sector>,
    pub suggested_read_order: Vec<String>,
    pub note: String,
}

// --------------------------------------------------------- sensitive.json

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum SensitiveReviewMode {
    Exclude,
    RedactedSummary,
    ApprovedRaw,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum SensitiveReadStatus {
    NotRead,
    MetadataOnly,
    Read,
    Binary,
    Unreadable,
}

#[derive(Serialize, Clone, Debug)]
pub struct SensitiveCandidate {
    pub path: String,
    pub size: Option<u64>,
    pub approved_for_raw: bool,
    pub raw_read: bool,
    pub read_status: SensitiveReadStatus,
    pub summary: String,
    pub signals: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SensitiveArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub mode: SensitiveReviewMode,
    pub first_approval: bool,
    pub second_approval: bool,
    pub review_ack_confirmed: bool,
    pub raw_ack_confirmed: bool,
    pub approved_paths: Vec<String>,
    pub unapproved_paths: Vec<String>,
    pub candidates: Vec<SensitiveCandidate>,
    pub raw_content_stored: bool,
    pub note: String,
}

// ------------------------------------------------------------- gates.json

#[derive(Serialize, Clone, Debug)]
pub struct GatePrompt {
    pub approval_required: bool,
    pub message: String,
    pub paths: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct GateItem {
    pub path: String,
    pub rule: String,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct GateArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub sensitive_raw_review: GatePrompt,
    pub execution_review: GatePrompt,
    pub sensitive_candidates: Vec<GateItem>,
    pub automatic_execution_candidates: Vec<GateItem>,
    pub execution_related_candidates: Vec<GateItem>,
    pub note: String,
}

// ------------------------------------------------------------ slices.json

#[derive(Serialize, Clone, Debug)]
pub struct SlicePolicy {
    pub source_order: String,
    pub max_estimated_tokens_per_slice: u64,
    pub default_model_input: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct SliceFile {
    pub path: String,
    pub bytes: u64,
    pub estimated_tokens: u64,
    pub sector: String,
    pub default_model_input: bool,
    pub sensitive_candidate: bool,
    pub automatic_execution_candidate: bool,
    pub execution_related_candidate: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Slice {
    pub id: String,
    pub files: Vec<SliceFile>,
    pub estimated_tokens: u64,
    pub over_token_limit: bool,
    pub requires_sensitive_raw_approval: bool,
    pub requires_execution_approval: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct SliceArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub policy: SlicePolicy,
    pub slices: Vec<Slice>,
    pub note: String,
}

// ------------------------------------------------------------- review.json

#[derive(Serialize, Clone, Debug)]
pub struct ReviewCounts {
    pub findings_total: u64,
    pub high_priority_findings: u64,
    pub medium_priority_findings: u64,
    pub sensitive_candidates: u64,
    pub automatic_execution_candidates: u64,
    pub execution_related_candidates: u64,
    pub slices_total: u64,
    pub slices_over_token_limit: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct ReviewAction {
    pub id: String,
    pub required: bool,
    pub reason: String,
    pub paths: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ReviewArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub verdict: String,
    pub counts: ReviewCounts,
    pub required_actions: Vec<ReviewAction>,
    pub default_model_excluded_paths: Vec<String>,
    pub note: String,
}

// ------------------------------------------------- 감지 단계의 중간 데이터

/// Detection rule id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum RuleId {
    D01,
    D02,
    D03,
    D04,
    D05,
    D06,
    D07,
    D08,
    D09,
    D10,
    D11,
    D12,
    D13,
}

#[derive(Clone, Debug)]
pub struct Detection {
    pub rule: RuleId,
    pub path: String,
    /// D02 전용: 키가 있는 줄 번호 (1부터).
    pub line: Option<u32>,
    /// D02 전용: scripts 키 이름.
    pub key: Option<String>,
    /// D02 전용: 해당 줄 원문 (200자 절단).
    pub excerpt: Option<String>,
}

/// detect 단계의 출력 묶음 — coverage 집계 재료를 함께 나른다.
pub struct DetectOutcome {
    pub detections: Vec<Detection>,
    pub read_files: Vec<ReadFile>,
    pub binary_skips: u64,
    pub dependency_manifests: Vec<DependencyManifest>,
    /// 예: package.json 파싱 실패 문장 (사양 0500 2절).
    pub limitations: Vec<String>,
}

// ------------------------------------------------------------ 실행 집합체

/// 한 번의 검사가 만든 모든 데이터. artifacts 단계가 이것을 그대로 쓴다.
pub struct RunData {
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub command: Vec<String>,
    pub source: SourceArtifact,
    pub inventory: InventoryArtifact,
    pub coverage: CoverageArtifact,
    pub evidence: EvidenceArtifact,
    pub findings: FindingsArtifact,
    pub dependencies: DependencyArtifact,
    pub sectors: SectorsArtifact,
    pub sensitive: SensitiveArtifact,
    pub gates: GateArtifact,
    pub slices: SliceArtifact,
    pub review: ReviewArtifact,
    pub report_md: String,
}
