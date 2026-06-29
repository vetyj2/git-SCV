//! 산출물과 단계 간 데이터의 단일 타입 정의.
//! 모든 단계 함수는 이 모듈의 타입만 주고받는다.

use serde::Serialize;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1";

/// 0804 — report.md 와 V05 가 그대로 비교하는 무실행 고정 문장.
pub const NO_EXEC_SENTENCE: &str = "이 검사는 대상 저장소의 명령, 스크립트, 훅, 바이너리, 빌드, 테스트, 워크플로, 패키지 매니저, 컨테이너를 실행하지 않았다.";

/// 0805 / V06 — 낮은 확신 고정 문장.
pub const LOW_CONFIDENCE_SENTENCE: &str = "이 검사는 증거가 충분하지 않아 낮은 확신의 결과다.";

pub const LOCAL_MAX_ENTRIES: u64 = 200_000;
pub const LOCAL_MAX_DEPTH: u64 = 64;
pub const LOCAL_MAX_PATH_BYTES: u64 = 4096;
pub const LOCAL_MAX_READ_BYTES_PER_MANIFEST: u64 = 1_048_576;
pub const LOCAL_MAX_TOTAL_READ_BYTES: u64 = 52_428_800;
pub const LOCAL_MAX_REPORTED_FINDINGS_PER_RULE: u64 = 1000;
pub const LOCAL_MAX_SYMLINKS: u64 = 1000;

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

#[derive(Serialize, Clone, Debug)]
pub struct RunCommand {
    pub program: String,
    pub subcommand: String,
    pub args_redacted: Vec<String>,
    pub raw_args_stored: bool,
}

#[derive(Serialize, Debug)]
pub struct RunArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub tool: ToolInfo,
    pub command: RunCommand,
    pub started_at: String,
    pub finished_at: String,
    pub status: RunStatus,
    pub stages: Vec<StageRecord>,
    pub exit_code: i32,
}

#[derive(Serialize, Clone, Debug)]
pub struct ManifestArtifactEntry {
    pub name: String,
    pub sha256: String,
    pub required: bool,
    pub validated: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct ManifestValidation {
    pub schema_validation_passed: bool,
    pub artifact_leak_scan_passed: bool,
    pub post_write_verify_passed: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct ArtifactManifest {
    pub artifact_kind: String,
    pub schema_version: String,
    pub contract_version: String,
    pub producer: ToolInfo,
    pub min_reader_version: String,
    pub run_id: String,
    pub source_fingerprint_hash: String,
    pub redaction_policy_version: String,
    pub path_privacy_policy: String,
    pub artifacts: Vec<ManifestArtifactEntry>,
    pub validation: ManifestValidation,
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
pub struct SnapshotInfo {
    pub url: String,
    pub sha256: String,
    pub archive_format: String,
    pub extracted_path: String,
    pub archive_limits: ArchiveLimits,
}

#[derive(Serialize, Clone, Debug)]
pub struct ArchiveLimits {
    pub download_limit_bytes: u64,
    pub max_entries: u64,
    pub max_decompressed_bytes: u64,
    pub max_path_bytes: u64,
    pub max_depth: u64,
    pub symlinks_allowed: bool,
    pub hardlinks_allowed: bool,
    pub devices_allowed: bool,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum PathPrivacyMode {
    RepoRelative,
    RedactedAbsolute,
    Absolute,
}

#[derive(Serialize, Clone, Debug)]
pub struct PathPrivacy {
    pub mode: PathPrivacyMode,
    pub absolute_paths_stored: bool,
    pub home_dir_redacted: bool,
    pub repo_root_alias: String,
}

impl PathPrivacy {
    pub fn new(mode: PathPrivacyMode) -> Self {
        Self {
            mode,
            absolute_paths_stored: mode == PathPrivacyMode::Absolute,
            home_dir_redacted: mode != PathPrivacyMode::Absolute,
            repo_root_alias: "<repo-root>".into(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceFingerprint {
    pub kind: String,
    pub git_commit: Option<String>,
    pub git_branch: Option<String>,
    pub git_dirty: Option<bool>,
    pub git_untracked_policy: String,
    pub inventory_hash: String,
    pub non_sensitive_content_hash: String,
    pub sensitive_metadata_hash: String,
    pub raw_sensitive_content_hashed: bool,
    pub symlinks_followed: bool,
    pub created_at: String,
    pub fingerprint_hash: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub input: InputInfo,
    pub resolved_path: String,
    pub git: Option<GitInfo>,
    pub snapshot: Option<SnapshotInfo>,
    pub path_privacy: PathPrivacy,
    pub source_fingerprint: Option<SourceFingerprint>,
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

#[derive(Serialize, Clone, Debug)]
pub struct Limits {
    pub max_entries: u64,
    pub max_depth: u64,
    pub max_path_bytes: u64,
    pub max_read_bytes_per_manifest: u64,
    pub max_total_read_bytes: u64,
    pub max_reported_findings_per_rule: u64,
    pub max_symlinks: u64,
    pub truncation_recorded: bool,
    pub exceeded_reason_codes: Vec<String>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: LOCAL_MAX_ENTRIES,
            max_depth: LOCAL_MAX_DEPTH,
            max_path_bytes: LOCAL_MAX_PATH_BYTES,
            max_read_bytes_per_manifest: LOCAL_MAX_READ_BYTES_PER_MANIFEST,
            max_total_read_bytes: LOCAL_MAX_TOTAL_READ_BYTES,
            max_reported_findings_per_rule: LOCAL_MAX_REPORTED_FINDINGS_PER_RULE,
            max_symlinks: LOCAL_MAX_SYMLINKS,
            truncation_recorded: false,
            exceeded_reason_codes: Vec::new(),
        }
    }
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
    pub local_limits: Limits,
    pub limit_reason_codes: Vec<String>,
    pub capabilities: Vec<SurfaceCapability>,
    pub prompt_injection_surfaces: Vec<PromptInjectionSurface>,
    pub files_discovered: u64,
    pub files_read: u64,
    pub files_skipped: u64,
    pub bytes_read_total: u64,
    pub read_files: Vec<ReadFile>,
    pub skip_reasons: SkipReasons,
    pub confidence_note: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct SurfaceCapability {
    pub surface: String,
    pub support: String,
    pub signals: Vec<String>,
    pub raw_values_stored: bool,
    pub verdict_effect: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PromptInjectionSurface {
    pub path: String,
    pub default_model_input: String,
    pub agent_must_not_obey: bool,
    pub reason: String,
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
    pub json_pointer: Option<String>,
    pub lines: Option<LineRange>,
    pub summary: String,
    pub value_stored: bool,
    pub redacted_excerpt: Option<String>,
    pub signal_labels: Vec<String>,
    pub raw_excerpt_stored: bool,
    pub redaction_applied: bool,
    pub redaction_labels: Vec<String>,
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
    pub raw_spec_stored: bool,
    pub redacted_spec: String,
    pub spec_hash: String,
    pub risk_signals: Vec<String>,
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
    pub acknowledgements: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ExecutionCommandGate {
    pub approval_required: bool,
    pub message: String,
    pub requires_exact_command: bool,
    pub approved_commands: Vec<String>,
    pub acknowledgements: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct GateItem {
    pub path: String,
    pub rule: String,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct GateDecisionBinding {
    pub requires_source_fingerprint_hash: bool,
    pub requires_artifact_manifest_sha256: bool,
    pub expires_on_source_change: bool,
    pub expires_on_artifact_manifest_change: bool,
    pub requires_path_metadata_hash_for_path_approval: bool,
    pub requires_exact_command_envelope_for_execution: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct GateArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub decision_binding: GateDecisionBinding,
    pub sensitive_raw_review: GatePrompt,
    pub execution_model_input_review: GatePrompt,
    pub execution_command_review: ExecutionCommandGate,
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
    pub language_hint: Option<String>,
    pub deep_analysis_candidate: bool,
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

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ReviewCounts {
    pub findings_total: u64,
    pub high_priority_findings: u64,
    pub medium_priority_findings: u64,
    pub sensitive_candidates: u64,
    pub automatic_execution_candidates: u64,
    pub execution_related_candidates: u64,
    pub deep_analysis_candidates: u64,
    pub slices_total: u64,
    pub slices_over_token_limit: u64,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ReviewAction {
    pub id: String,
    pub required: bool,
    pub reason: String,
    pub paths: Vec<String>,
    pub acknowledgements: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ReviewArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub verdict: String,
    pub safe_claim_made: bool,
    pub may_user_run_install: bool,
    pub may_agent_request_run_approval: bool,
    pub may_agent_run_without_user: bool,
    pub reason_codes: Vec<String>,
    pub counts: ReviewCounts,
    pub required_actions: Vec<ReviewAction>,
    pub default_model_excluded_paths: Vec<String>,
    pub note: String,
}

// ----------------------------------------------------------- security.json

#[derive(Serialize, Clone, Debug)]
pub struct SecurityArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub verdict: String,
    pub safe_claim_made: bool,
    pub may_user_run_install: bool,
    pub may_agent_request_run_approval: bool,
    pub may_agent_run_without_user: bool,
    pub reason_codes: Vec<String>,
    pub action_required: bool,
    pub no_exec: String,
    pub counts: ReviewCounts,
    pub required_actions: Vec<ReviewAction>,
    pub default_model_excluded_paths: Vec<String>,
    pub limitations: Vec<String>,
    pub references: Vec<String>,
    pub note: String,
}

// --------------------------------------------------------------- brief.json

#[derive(Serialize, Clone, Debug)]
pub struct BriefArtifact {
    pub artifact_kind: String,
    pub schema_version: String,
    pub run_id: String,
    pub artifact_manifest_sha256: String,
    pub source_fingerprint_hash: String,
    pub verdict: String,
    pub safe_claim_made: bool,
    pub may_user_run_install: bool,
    pub may_agent_request_run_approval: bool,
    pub may_agent_run_without_user: bool,
    pub action_required: bool,
    pub counts: ReviewCounts,
    pub required_actions: Vec<String>,
    pub reason_codes: Vec<String>,
    pub next_step_blocked_until: Vec<String>,
    pub actionability: BriefActionability,
    pub visual_outputs: Vec<String>,
    pub do_not_do_yet: Vec<String>,
    pub no_exec_statement: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct BriefActionability {
    pub top_blockers: Vec<ActionabilityBlocker>,
    pub next_safe_commands: Vec<String>,
    pub do_not_do_yet: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ActionabilityBlocker {
    pub id: String,
    pub kind: String,
    pub summary: String,
    pub why_it_matters: String,
    pub next_step: String,
    pub artifact_refs: Vec<String>,
}

// ------------------------------------------------------- agent_receipt.json

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum ReceiptNextAction {
    None,
    AskUserApproval,
    InspectSlice,
}

#[derive(Serialize, Clone, Debug)]
pub struct AgentReceipt {
    pub artifact_kind: String,
    pub schema_version: String,
    pub receipt_id: String,
    pub agent: String,
    pub run_id: String,
    pub artifact_manifest_sha256: String,
    pub source_fingerprint_hash: String,
    pub read_artifacts: Vec<String>,
    pub summarized_to_user: bool,
    pub blocked_actions_acknowledged: bool,
    pub next_action_requested: ReceiptNextAction,
    pub summary_file_sha256: String,
    pub summary_text_stored: bool,
    pub receipt_text: String,
}

// ----------------------------------------------------- connection_graph.json

#[derive(Serialize, Clone, Debug)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub path: Option<String>,
    pub default_model_input: Option<bool>,
    pub requires_execution_review: bool,
    pub requires_user_approval: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub execution_condition: Option<String>,
    pub approval_gate: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ReachabilityScenario {
    pub scenario_id: String,
    pub user_action: String,
    pub reachable_nodes: Vec<String>,
    pub blocked_by: Vec<String>,
    pub safe_to_execute_without_user: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct ConnectionGraphArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub scenarios: Vec<ReachabilityScenario>,
}

// ----------------------------------------------------- supported_surfaces.json

#[derive(Serialize, Clone, Debug)]
pub struct SupportedSurfacesArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub capabilities: Vec<SurfaceCapability>,
    pub note: String,
}

// --------------------------------------------------------- gate_decisions.json

#[derive(Serialize, Clone, Debug)]
pub struct GateDecisionArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub source_fingerprint_hash: String,
    pub artifact_manifest_sha256_required: bool,
    pub expires_on_source_change: bool,
    pub decisions: Vec<GateDecision>,
    pub note: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct GateDecision {
    pub gate_decision_id: String,
    pub decision_kind: String,
    pub approved_repo_relative_path: Option<String>,
    pub path_metadata_hash_at_approval: Option<String>,
    pub execution_request: Option<ExecutionRequest>,
    pub ack: String,
    pub created_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct ExecutionRequest {
    pub argv: Vec<String>,
    pub shell: bool,
    pub cwd: String,
    pub env_policy: String,
    pub network: String,
    pub writes_to_repo: String,
    pub source_fingerprint_hash: String,
    pub artifact_manifest_sha256: String,
    pub requires_user_approval: bool,
}

// ------------------------------------------------ reachability_scenarios.json

#[derive(Serialize, Clone, Debug)]
pub struct ReachabilityScenariosArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub scenarios: Vec<ReachabilityScenario>,
    pub note: String,
}

// --------------------------------------------------------- architecture maps

#[derive(Serialize, Clone, Debug)]
pub struct ArchitectureMapArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub repo_shape: RepoShape,
    pub sectors: Vec<ArchitectureSector>,
    pub entrypoints: Vec<ArchitectureEntrypoint>,
    pub architecture_summary: ArchitectureSummary,
    pub visualization_recommendations: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct RepoShape {
    pub detected_shapes: Vec<String>,
    pub confidence: String,
    pub limitations: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ArchitectureSector {
    pub sector_id: String,
    pub name: String,
    pub paths: Vec<String>,
    pub primary_role: String,
    pub model_input_status: String,
    pub gate_status: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct ArchitectureEntrypoint {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub path: String,
    pub reachable_under: Vec<String>,
    pub blocked_by: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ArchitectureSummary {
    pub human_summary: String,
    pub safe_claim_made: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct RelationMapArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub relations: Vec<Relation>,
    pub unresolved_relations: Vec<UnresolvedRelation>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Relation {
    pub relation_id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub confidence: String,
    pub evidence_refs: Vec<String>,
    pub blocked_by: Vec<String>,
    pub unresolved: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct UnresolvedRelation {
    pub relation_id: String,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceLandmarksArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub recommended_reading_order: Vec<SourceLandmark>,
    pub do_not_read_by_default: Vec<SourceLandmarkGuard>,
    pub gate_before_reading: Vec<SourceLandmarkGuard>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceLandmark {
    pub rank: u64,
    pub path: String,
    pub why: String,
    pub model_input_status: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceLandmarkGuard {
    pub path: String,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct VisualizationIndexArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub default_visualization: String,
    pub views: Vec<VisualizationView>,
    pub privacy: VisualizationPrivacy,
    pub graph_limits: VisualizationGraphLimits,
}

#[derive(Serialize, Clone, Debug)]
pub struct VisualizationView {
    pub view_id: String,
    pub title: String,
    pub source_artifacts: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct VisualizationPrivacy {
    pub raw_sensitive_content_included: bool,
    pub target_repo_js_executed: bool,
    pub external_network_required: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct VisualizationGraphLimits {
    pub max_nodes: u64,
    pub max_edges: u64,
    pub truncated: bool,
}

// ---------------------------------------------------------- analysis_plan.json

#[derive(Serialize, Clone, Debug)]
pub struct AnalysisUnit {
    pub unit_id: String,
    pub kind: String,
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub questions: Vec<String>,
    pub depends_on_units: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct CrossUnitTask {
    pub task_id: String,
    pub kind: String,
    pub input_units: Vec<String>,
    pub questions: Vec<String>,
    pub required_outputs: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct AnalysisPlanArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub units: Vec<AnalysisUnit>,
    pub cross_unit_tasks: Vec<CrossUnitTask>,
}

// ------------------------------------------------------ synthesis artifacts

#[derive(Serialize, Clone, Debug)]
pub struct AggregatePath {
    pub scenario: String,
    pub reachable_nodes: Vec<String>,
    pub blocked_by_gates: Vec<String>,
    pub risk_summary: String,
    pub safe_to_execute_without_user: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct SynergyFinding {
    pub id: String,
    pub kind: String,
    pub summary: String,
    pub requires_followup: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct CrossUnitAnalysisArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub input_units: Vec<String>,
    pub aggregate_paths: Vec<AggregatePath>,
    pub synergy_findings: Vec<SynergyFinding>,
    pub conflicts: Vec<String>,
    pub unresolved_edges: Vec<String>,
    pub followup_required: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct AggregateSafetyDiagnosis {
    pub no_blocker_observed_within_scope: bool,
    pub blocked_execution_surfaces: Vec<String>,
    pub insufficient_coverage_reasons: Vec<String>,
    pub what_cannot_be_concluded: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SynthesisArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub verdict: String,
    pub safe_claim_made: bool,
    pub unit_analyses_complete: bool,
    pub cross_unit_analysis_complete: String,
    pub architecture_visualization_complete: bool,
    pub source_fingerprint_verified: bool,
    pub unresolved_edges_count: u64,
    pub conflicts_count: u64,
    pub required_user_actions: Vec<String>,
    pub architecture_synthesis: ArchitectureSynthesis,
    pub aggregate_safety_diagnosis: AggregateSafetyDiagnosis,
}

#[derive(Serialize, Clone, Debug)]
pub struct ArchitectureSynthesis {
    pub detected_shapes: Vec<String>,
    pub primary_sectors: Vec<String>,
    pub recommended_visualization: String,
    pub source_landmarks_available: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct FollowupItem {
    pub followup_id: String,
    pub kind: String,
    pub needed_artifacts: Vec<String>,
    pub needed_user_approval: Option<String>,
    pub question: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct FollowupPlanArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub round: u64,
    pub reason: String,
    pub required_followups: Vec<FollowupItem>,
    pub blocked_until: Vec<String>,
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
    D14,
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
    pub limit_reason_codes: Vec<String>,
    /// 예: package.json 파싱 실패 문장 (사양 0500 2절).
    pub limitations: Vec<String>,
}

// ------------------------------------------------------------ 실행 집합체

/// 한 번의 검사가 만든 모든 데이터. artifacts 단계가 이것을 그대로 쓴다.
pub struct RunData {
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub command: RunCommand,
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
    pub security: SecurityArtifact,
    pub supported_surfaces: SupportedSurfacesArtifact,
    pub gate_decisions: GateDecisionArtifact,
    pub connection_graph: ConnectionGraphArtifact,
    pub reachability_scenarios: ReachabilityScenariosArtifact,
    pub architecture_map: ArchitectureMapArtifact,
    pub relation_map: RelationMapArtifact,
    pub source_landmarks: SourceLandmarksArtifact,
    pub visualization_index: VisualizationIndexArtifact,
    pub analysis_plan: AnalysisPlanArtifact,
    pub cross_unit_analysis: CrossUnitAnalysisArtifact,
    pub synthesis: SynthesisArtifact,
    pub followup_plan: FollowupPlanArtifact,
    pub report_md: String,
    pub architecture_html: String,
}
