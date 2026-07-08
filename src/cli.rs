//! 명령 입구.
//! 인자 구조와 도움말, 실행 전 입력 검증을 맡는다.

use crate::errors::ScvError;
use crate::model::{PathPrivacyMode, ReceiptNextAction, SensitiveReviewMode};
use crate::redaction::{redact_url_for_error, strip_url_query_fragment, url_has_userinfo};
use clap::{CommandFactory, Parser};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// 도움말 고정 문구.
pub const NO_EXEC_HELP: &str = "git-scv는 대상 저장소의 어떤 명령, 스크립트, 훅도 실행하지 않는다.";
/// 민감 후보 별도 진단 1차 승인 확인 문구.
pub const SENSITIVE_REVIEW_ACK: &str = "review-sensitive-candidates";
/// 민감 후보 원문 분석 2차 승인 확인 문구.
pub const SENSITIVE_RAW_ACK: &str = "include-approved-sensitive-raw-in-diagnostic-input";

#[derive(Parser)]
#[command(
    name = "git-scv",
    version,
    about = "무실행 저장소 검사 하네스",
    after_help = NO_EXEC_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Subcommand>,
    /// Quick entry target. Example: git-scv https://github.com/owner/repo
    pub quick_target: Option<PathBuf>,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// 첫 실행 전 worker/OAuth/model-cost 설정을 안내하고 점검한다
    #[command(after_help = NO_EXEC_HELP)]
    Init(InitArgs),
    /// Git-SCV 사용 전반의 준비 상태와 대응 방법을 점검한다
    #[command(after_help = NO_EXEC_HELP)]
    Doctor(DoctorArgs),
    /// 낯선 repo를 no-exec preflight부터 slice worker 분석과 final report까지 한 번에 진행한다
    #[command(after_help = NO_EXEC_HELP)]
    Scan(ScanArgs),
    /// 낯선 repo를 설치/빌드/실행 전에 no-exec Codex slice review 세션으로 시작한다
    #[command(after_help = NO_EXEC_HELP)]
    Review(ReviewArgs),
    /// 중단된 review 세션을 다음 안전 단계로 이어간다
    #[command(after_help = NO_EXEC_HELP)]
    Continue(RunDirArgs),
    /// 저장소를 무실행으로 검사하고 산출물 디렉터리를 만든다
    #[command(after_help = NO_EXEC_HELP)]
    Inspect(InspectArgs),
    /// 원격 압축 스냅샷을 내려받아 체크섬 검증 뒤 로컬 검사 대상으로 준비한다
    #[command(after_help = NO_EXEC_HELP)]
    Snapshot(SnapshotArgs),
    /// 기존 검사 산출물 디렉터리에서 에이전트용 필수 브리핑을 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Brief(BriefArgs),
    /// 에이전트가 brief/gates를 읽고 사용자에게 요약했음을 source/manifest에 묶어 기록한다
    #[command(after_help = NO_EXEC_HELP)]
    Receipt(ReceiptArgs),
    /// 검사 case package를 만들고 조회한다
    #[command(after_help = NO_EXEC_HELP)]
    Case(CaseArgs),
    /// unit-analysis JSON 하나를 검증한다
    #[command(after_help = NO_EXEC_HELP)]
    ValidateUnit(ValidateUnitArgs),
    /// unit-analysis 디렉터리를 검증한다
    #[command(after_help = NO_EXEC_HELP)]
    ValidateUnits(RunDirArgs),
    /// synthesis artifact 상태를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Synthesize(RunDirArgs),
    /// followup_plan artifact 상태를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    FollowupPlan(RunDirArgs),
    /// followup_plan artifact를 검증한다
    #[command(after_help = NO_EXEC_HELP)]
    ValidateFollowup(RunDirArgs),
    /// LLM 분석 런타임을 준비하거나 수동 export backend를 실행한다
    #[command(after_help = NO_EXEC_HELP)]
    Analyze(AnalyzeArgs),
    /// 분석 결과를 가져오거나 분석 패키지 상태를 다룬다
    #[command(after_help = NO_EXEC_HELP)]
    Analysis(AnalysisArgs),
    /// analysis_state/events 기반 진행 상태를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Watch(RunDirArgs),
    /// 중단된 분석을 재개할 수 있는지 점검한다
    #[command(after_help = NO_EXEC_HELP)]
    Resume(RunDirArgs),
    /// 사용자 보고서를 생성하거나 상태를 점검한다
    #[command(after_help = NO_EXEC_HELP)]
    Report(ReportArgs),
    /// GitHub remote-first metadata planning
    #[command(after_help = NO_EXEC_HELP)]
    Github(GithubArgs),
    /// Codex/Claude worker CLI 사용 가능 여부를 auth 파일 접근 없이 점검한다
    #[command(after_help = NO_EXEC_HELP)]
    Worker(WorkerArgs),
    /// run/case 내부 임시 분석 export를 안전하게 정리한다
    #[command(after_help = NO_EXEC_HELP)]
    Clean(CleanArgs),
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// 처음 설정할 권장 worker backend
    #[arg(long, value_enum, default_value = "codex")]
    pub worker: WorkerBackend,
    /// worker 준비가 안 되어 있으면 실패 코드로 종료한다
    #[arg(long)]
    pub strict: bool,
}

#[derive(clap::Args)]
pub struct DoctorArgs {
    /// 특정 backend만 점검한다. 없으면 Codex와 Claude를 모두 확인한다.
    #[arg(long, value_enum)]
    pub backend: Option<WorkerBackend>,
    /// 준비가 안 된 backend가 있으면 실패 코드로 종료한다
    #[arg(long)]
    pub strict: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuickFlow {
    LocalPreflight,
    WebMetadataPreflight,
    WebSelectedPreflight,
    StrictSnapshotReminder,
    PinnedSnapshotAnalysis,
    LocalFullWorker,
}

pub struct QuickArgs {
    pub target: PathBuf,
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// 검사하고 분석할 로컬 저장소 경로 또는 GitHub URL.
    pub target: PathBuf,
    /// 사용자가 판단하려는 목표
    #[arg(long, value_enum, default_value = "install")]
    pub goal: ReviewGoal,
    /// source acquisition/analysis mode
    #[arg(long, value_enum, default_value = "local-full")]
    pub mode: ScanMode,
    /// slice를 처리할 worker backend
    #[arg(long, value_enum, default_value = "manual")]
    pub worker: WorkerBackend,
    /// case package 대신 직접 쓸 출력 디렉터리
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// artifact/report에 저장할 경로 privacy 정책
    #[arg(long, value_enum, default_value = "repo-relative")]
    pub path_privacy: PathPrivacyMode,
    /// terminal progress 출력 모드
    #[arg(long, value_enum, default_value = "auto")]
    pub progress: ProgressMode,
    /// 실험/테스트용: 이번 scan에서 자동 처리할 최대 job 수
    #[arg(long)]
    pub max_jobs: Option<usize>,
    /// worker formatting/schema 오류 재시도 횟수
    #[arg(long, default_value_t = 1)]
    pub retry_format_errors: u8,
    /// worker 호출 사이 최소 지연(ms)
    #[arg(long, default_value_t = 0)]
    pub worker_delay_ms: u64,
    /// 분당 worker 호출 상한. 0이면 비활성화한다.
    #[arg(long, default_value_t = 0)]
    pub max_worker_calls_per_minute: u32,
    /// worker 오류가 나면 즉시 멈춘다. 기본값은 계속 안전 실패 상태로 남기는 것이다.
    #[arg(long)]
    pub stop_on_worker_error: bool,
    /// real worker 호출 예산 게이트
    #[arg(long, value_enum, default_value = "auto")]
    pub budget_gate: BudgetGate,
    /// 예산 승인 전 real worker sample job 수
    #[arg(long, default_value_t = 3)]
    pub sample_jobs: usize,
    /// 예산 승인 후 이어서 처리할 job 수
    #[arg(long)]
    pub continue_jobs: Option<usize>,
    /// 예산 승인 후 전체 job 대비 처리할 비율
    #[arg(long)]
    pub continue_percent: Option<u8>,
    /// real worker 예산 승인 문구. continue-worker-budget 필요.
    #[arg(long)]
    pub approve_worker_budget: Option<String>,
    /// 기존 run dir가 있으면 이어서 진행한다.
    #[arg(long)]
    pub resume: bool,
    /// strict verified snapshot에서 사용할 외부 SHA-256 digest
    #[arg(long)]
    pub sha256: Option<String>,
    /// GitHub pinned snapshot에서 해석할 ref
    #[arg(long, default_value = "HEAD")]
    pub r#ref: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum BudgetGate {
    Auto,
    Always,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ScanMode {
    LocalFull,
    #[value(alias = "web-only")]
    WebMetadataPreflight,
    WebSelectedPreflight,
    #[value(alias = "verified-snapshot")]
    StrictVerifiedSnapshot,
    PinnedSnapshot,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanMode::LocalFull => "local-full",
            ScanMode::WebMetadataPreflight => "web-metadata-preflight",
            ScanMode::WebSelectedPreflight => "web-selected-preflight",
            ScanMode::StrictVerifiedSnapshot => "strict-verified-snapshot",
            ScanMode::PinnedSnapshot => "pinned-snapshot",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum WorkerBackend {
    Manual,
    Fake,
    Codex,
    Claude,
}

impl WorkerBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerBackend::Manual => "manual",
            WorkerBackend::Fake => "fake",
            WorkerBackend::Codex => "codex",
            WorkerBackend::Claude => "claude",
        }
    }

    pub fn agent_name(self) -> &'static str {
        match self {
            WorkerBackend::Manual => "Manual",
            WorkerBackend::Fake => "GitSCVFakeWorker",
            WorkerBackend::Codex => "Codex",
            WorkerBackend::Claude => "Claude",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ProgressMode {
    Auto,
    Plain,
    Jsonl,
    Quiet,
}

#[derive(clap::Args)]
pub struct ReviewArgs {
    /// 검사할 로컬 저장소 경로. URL 입력은 metadata plan 이후 source acquisition 단계에서 처리한다.
    pub target: PathBuf,
    /// 사용자가 판단하려는 목표
    #[arg(long, value_enum, default_value = "install")]
    pub goal: ReviewGoal,
    /// case package 대신 직접 쓸 출력 디렉터리
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// artifact/report에 저장할 경로 privacy 정책
    #[arg(long, value_enum, default_value = "repo-relative")]
    pub path_privacy: PathPrivacyMode,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ReviewGoal {
    Install,
    Build,
    Test,
    Run,
    OpenVscode,
    Docker,
    GeneralReview,
}

impl ReviewGoal {
    pub fn as_str(self) -> &'static str {
        match self {
            ReviewGoal::Install => "install",
            ReviewGoal::Build => "build",
            ReviewGoal::Test => "test",
            ReviewGoal::Run => "run",
            ReviewGoal::OpenVscode => "open-vscode",
            ReviewGoal::Docker => "docker",
            ReviewGoal::GeneralReview => "general-review",
        }
    }
}

#[derive(clap::Args)]
pub struct InspectArgs {
    /// 검사할 로컬 저장소 경로
    pub repo_path: PathBuf,
    /// 산출물을 쓸 디렉터리 (새 경로 또는 빈 디렉터리)
    #[arg(long)]
    pub out: PathBuf,
    /// 민감 후보 별도 진단 모드
    #[arg(long, value_enum, default_value = "exclude")]
    pub sensitive_mode: SensitiveReviewMode,
    /// 민감 후보 별도 진단 1차 승인
    #[arg(long)]
    pub approve_sensitive_review: bool,
    /// 민감 후보 별도 진단 1차 승인 확인 문구
    #[arg(long = "sensitive-review-ack")]
    pub sensitive_review_ack: Option<String>,
    /// 승인 경로 원문 분석 2차 승인
    #[arg(long)]
    pub approve_sensitive_raw: bool,
    /// 승인 경로 원문 분석 2차 승인 확인 문구
    #[arg(long = "sensitive-raw-ack")]
    pub sensitive_raw_ack: Option<String>,
    /// 원문 분석을 승인할 저장소 상대 경로
    #[arg(long = "sensitive-path")]
    pub sensitive_paths: Vec<PathBuf>,
    /// artifact/report에 저장할 경로 privacy 정책
    #[arg(long, value_enum, default_value = "repo-relative")]
    pub path_privacy: PathPrivacyMode,
}

#[derive(clap::Args)]
pub struct SnapshotArgs {
    /// 내려받을 원격 압축 스냅샷 URL
    pub url: String,
    /// 스냅샷을 준비할 출력 디렉터리
    #[arg(long)]
    pub out: PathBuf,
    /// 사용자가 별도 경로로 확인한 SHA-256 체크섬
    #[arg(long)]
    pub sha256: Option<String>,
}

#[derive(clap::Args)]
pub struct BriefArgs {
    /// inspect 또는 snapshot run 산출물 디렉터리
    pub run_dir: PathBuf,
}

#[derive(clap::Args)]
pub struct ReceiptArgs {
    #[command(subcommand)]
    pub command: ReceiptSubcommand,
}

#[derive(clap::Subcommand)]
pub enum ReceiptSubcommand {
    /// agent_receipt.json을 생성한다
    #[command(after_help = NO_EXEC_HELP)]
    Create(ReceiptCreateArgs),
}

#[derive(clap::Args)]
pub struct ReceiptCreateArgs {
    /// inspect 또는 snapshot run 산출물 디렉터리
    pub run_dir: PathBuf,
    /// receipt를 남기는 에이전트 이름
    #[arg(long)]
    pub agent: String,
    /// 사용자가 받은 에이전트 요약 파일. 원문은 저장하지 않고 sha256만 저장한다
    #[arg(long)]
    pub summary_file: PathBuf,
    /// 에이전트가 brief 요약을 사용자에게 제시했음을 확인
    #[arg(long)]
    pub summarized_to_user: bool,
    /// 에이전트가 차단된 액션과 승인 요구를 확인했음을 확인
    #[arg(long)]
    pub blocked_actions_acknowledged: bool,
    /// receipt 뒤에 요청하려는 다음 행동
    #[arg(long, value_enum, default_value = "none")]
    pub next_action: ReceiptNextAction,
}

#[derive(clap::Args)]
pub struct CaseArgs {
    #[command(subcommand)]
    pub command: CaseSubcommand,
}

#[derive(clap::Subcommand)]
pub enum CaseSubcommand {
    /// 새 case package를 만든다
    #[command(after_help = NO_EXEC_HELP)]
    Create(CaseCreateArgs),
    /// case 목록을 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    List,
    /// case 세부 정보를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Show(CaseIdArgs),
    /// case brief를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Brief(CaseIdArgs),
    /// 현재 source fingerprint가 case와 같은지 검증한다
    #[command(after_help = NO_EXEC_HELP)]
    VerifySource(CaseIdArgs),
    /// case source 상태를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Status(CaseIdArgs),
    /// 다음 행동이 source/receipt/gate 계약상 가능한지 판정한다
    #[command(after_help = NO_EXEC_HELP)]
    NextAction(CaseNextActionArgs),
    /// case package를 삭제한다
    #[command(after_help = NO_EXEC_HELP)]
    Delete(CaseDeleteArgs),
    /// case root의 모든 case package를 삭제한다
    #[command(after_help = NO_EXEC_HELP)]
    Prune(CasePruneArgs),
    /// case root 상태를 점검한다
    #[command(after_help = NO_EXEC_HELP)]
    Doctor,
}

#[derive(clap::Args)]
pub struct CaseCreateArgs {
    /// 검사할 로컬 저장소 경로
    pub repo_path: PathBuf,
    /// artifact/report에 저장할 경로 privacy 정책
    #[arg(long, value_enum, default_value = "repo-relative")]
    pub path_privacy: PathPrivacyMode,
}

#[derive(clap::Args)]
pub struct CaseIdArgs {
    /// case id
    pub case_id: String,
}

#[derive(clap::Args)]
pub struct CaseNextActionArgs {
    /// case id
    pub case_id: String,
    /// 요청하려는 행동 종류. 예: install, build, test, run, model-input, sensitive-raw
    #[arg(long)]
    pub action: String,
    /// 실행 승인 요청에 묶을 exact argv. 예: --argv npm install
    #[arg(long = "argv", num_args = 1..)]
    pub argv: Vec<String>,
}

#[derive(clap::Args)]
pub struct CaseDeleteArgs {
    /// case id
    pub case_id: String,
    /// 삭제 확인 문구
    #[arg(long)]
    pub ack: String,
}

#[derive(clap::Args)]
pub struct CasePruneArgs {
    /// 모든 case package 삭제
    #[arg(long)]
    pub all: bool,
    /// 삭제 확인 문구
    #[arg(long)]
    pub ack: String,
}

#[derive(clap::Args)]
pub struct RunDirArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
}

#[derive(clap::Args)]
pub struct AnalyzeArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// 분석 backend. 현재 안전 기본값은 manual-export
    #[arg(long, default_value = "manual-export")]
    pub backend: String,
}

#[derive(clap::Args)]
pub struct AnalysisArgs {
    #[command(subcommand)]
    pub command: AnalysisSubcommand,
}

#[derive(clap::Subcommand)]
pub enum AnalysisSubcommand {
    /// unit-analysis JSON 또는 JSONL을 가져와 검증 후 누적한다
    #[command(after_help = NO_EXEC_HELP)]
    Import(AnalysisImportArgs),
    /// analysis job queue를 조회하거나 갱신한다
    #[command(after_help = NO_EXEC_HELP)]
    Job(AnalysisJobArgs),
    /// claim된 job의 허용 content range를 redacted export로 만든다
    #[command(after_help = NO_EXEC_HELP)]
    ExportContent(AnalysisExportContentArgs),
}

#[derive(clap::Args)]
pub struct AnalysisImportArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// unit-analysis JSON 또는 JSONL 파일
    pub input: PathBuf,
}

#[derive(clap::Args)]
pub struct AnalysisJobArgs {
    #[command(subcommand)]
    pub command: AnalysisJobSubcommand,
}

#[derive(clap::Subcommand)]
pub enum AnalysisJobSubcommand {
    /// job queue 목록과 집계를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    List(RunDirArgs),
    /// 다음 queued job 하나를 출력한다
    #[command(after_help = NO_EXEC_HELP)]
    Next(RunDirArgs),
    /// 다음 queued job 하나를 agent가 claim한다
    #[command(after_help = NO_EXEC_HELP)]
    Claim(AnalysisJobClaimArgs),
    /// job 결과를 검증하고 complete 처리한다
    #[command(after_help = NO_EXEC_HELP)]
    Complete(AnalysisJobCompleteArgs),
    /// job을 실패 처리한다
    #[command(after_help = NO_EXEC_HELP)]
    Fail(AnalysisJobFailArgs),
}

#[derive(clap::Args)]
pub struct AnalysisJobClaimArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// job을 claim하는 agent 이름
    #[arg(long, default_value = "Codex")]
    pub agent: String,
}

#[derive(clap::Args)]
pub struct AnalysisJobCompleteArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// 완료할 job id
    #[arg(long)]
    pub job: String,
    /// unit-analysis JSON 파일
    #[arg(long)]
    pub result: PathBuf,
}

#[derive(clap::Args)]
pub struct AnalysisJobFailArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// 실패 처리할 job id
    #[arg(long)]
    pub job: String,
    /// 실패 reason code
    #[arg(long)]
    pub reason: String,
}

#[derive(clap::Args)]
pub struct AnalysisExportContentArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// export할 claimed job id
    #[arg(long)]
    pub job: String,
}

#[derive(clap::Args)]
pub struct ReportArgs {
    #[command(subcommand)]
    pub command: ReportSubcommand,
}

#[derive(clap::Subcommand)]
pub enum ReportSubcommand {
    /// analysis_map 기반 최종 사용자 보고서를 생성한다
    #[command(after_help = NO_EXEC_HELP)]
    Final(RunDirArgs),
}

#[derive(clap::Args)]
pub struct GithubArgs {
    #[command(subcommand)]
    pub command: GithubSubcommand,
}

#[derive(clap::Subcommand)]
pub enum GithubSubcommand {
    /// GitHub tree metadata로 pre-download analysis plan을 만든다
    #[command(after_help = NO_EXEC_HELP)]
    Plan(GithubPlanArgs),
}

#[derive(clap::Args)]
pub struct GithubPlanArgs {
    /// GitHub repository URL. 예: https://github.com/owner/repo
    pub repo_url: String,
    /// Git ref, tag, branch, or commit. Branch refs are recorded as moving refs.
    #[arg(long, default_value = "HEAD")]
    pub r#ref: String,
    /// 출력 디렉터리
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(clap::Args)]
pub struct WorkerArgs {
    #[command(subcommand)]
    pub command: WorkerSubcommand,
}

#[derive(clap::Subcommand)]
pub enum WorkerSubcommand {
    /// worker CLI가 PATH/override에서 실행 가능한지만 확인한다. auth 파일은 읽지 않는다.
    #[command(after_help = NO_EXEC_HELP)]
    Doctor(WorkerDoctorArgs),
}

#[derive(clap::Args)]
pub struct WorkerDoctorArgs {
    /// 점검할 backend
    #[arg(long, value_enum, default_value = "codex")]
    pub backend: WorkerBackend,
}

#[derive(clap::Args)]
pub struct CleanArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// 삭제 대상 범위. 기본은 analysis 임시 export/result만 포함한다.
    #[arg(long, value_enum, default_value = "analysis-temp")]
    pub scope: CleanScope,
    /// 실제 삭제 실행. 없으면 dry-run plan만 출력한다.
    #[arg(long)]
    pub apply: bool,
    /// 삭제 확인 문구. 실제 삭제 시 clean-git-scv-run 필요.
    #[arg(long)]
    pub ack: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum CleanScope {
    AnalysisTemp,
    SnapshotSource,
    All,
}

#[derive(clap::Args)]
pub struct ValidateUnitArgs {
    /// inspect run directory 또는 case package directory
    pub run_dir: PathBuf,
    /// unit-analysis JSON 파일
    pub unit_file: PathBuf,
}

pub enum Invocation {
    Quick(QuickArgs),
    Init(InitArgs),
    Doctor(DoctorArgs),
    Scan(ScanArgs),
    Review(ReviewArgs),
    Continue(RunDirArgs),
    Inspect(InspectArgs),
    Snapshot(SnapshotArgs),
    Brief(BriefArgs),
    ReceiptCreate(ReceiptCreateArgs),
    CaseCreate(CaseCreateArgs),
    CaseList,
    CaseShow(CaseIdArgs),
    CaseBrief(CaseIdArgs),
    CaseVerifySource(CaseIdArgs),
    CaseStatus(CaseIdArgs),
    CaseNextAction(CaseNextActionArgs),
    CaseDelete(CaseDeleteArgs),
    CasePrune(CasePruneArgs),
    CaseDoctor,
    ValidateUnit(ValidateUnitArgs),
    ValidateUnits(RunDirArgs),
    Synthesize(RunDirArgs),
    FollowupPlan(RunDirArgs),
    ValidateFollowup(RunDirArgs),
    Analyze(AnalyzeArgs),
    AnalysisImport(AnalysisImportArgs),
    AnalysisJobList(RunDirArgs),
    AnalysisJobNext(RunDirArgs),
    AnalysisJobClaim(AnalysisJobClaimArgs),
    AnalysisJobComplete(AnalysisJobCompleteArgs),
    AnalysisJobFail(AnalysisJobFailArgs),
    AnalysisExportContent(AnalysisExportContentArgs),
    Watch(RunDirArgs),
    Resume(RunDirArgs),
    ReportFinal(RunDirArgs),
    GithubPlan(GithubPlanArgs),
    WorkerDoctor(WorkerDoctorArgs),
    Clean(CleanArgs),
}

pub fn parse() -> Invocation {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        if let Some(target) = cli.quick_target {
            return Invocation::Quick(QuickArgs { target });
        }
        Cli::command().print_help().ok();
        println!();
        std::process::exit(0);
    };
    match command {
        Subcommand::Init(args) => Invocation::Init(args),
        Subcommand::Doctor(args) => Invocation::Doctor(args),
        Subcommand::Scan(args) => Invocation::Scan(args),
        Subcommand::Review(args) => Invocation::Review(args),
        Subcommand::Continue(args) => Invocation::Continue(args),
        Subcommand::Inspect(args) => Invocation::Inspect(args),
        Subcommand::Snapshot(args) => Invocation::Snapshot(args),
        Subcommand::Brief(args) => Invocation::Brief(args),
        Subcommand::Receipt(args) => match args.command {
            ReceiptSubcommand::Create(args) => Invocation::ReceiptCreate(args),
        },
        Subcommand::Case(args) => match args.command {
            CaseSubcommand::Create(args) => Invocation::CaseCreate(args),
            CaseSubcommand::List => Invocation::CaseList,
            CaseSubcommand::Show(args) => Invocation::CaseShow(args),
            CaseSubcommand::Brief(args) => Invocation::CaseBrief(args),
            CaseSubcommand::VerifySource(args) => Invocation::CaseVerifySource(args),
            CaseSubcommand::Status(args) => Invocation::CaseStatus(args),
            CaseSubcommand::NextAction(args) => Invocation::CaseNextAction(args),
            CaseSubcommand::Delete(args) => Invocation::CaseDelete(args),
            CaseSubcommand::Prune(args) => Invocation::CasePrune(args),
            CaseSubcommand::Doctor => Invocation::CaseDoctor,
        },
        Subcommand::ValidateUnit(args) => Invocation::ValidateUnit(args),
        Subcommand::ValidateUnits(args) => Invocation::ValidateUnits(args),
        Subcommand::Synthesize(args) => Invocation::Synthesize(args),
        Subcommand::FollowupPlan(args) => Invocation::FollowupPlan(args),
        Subcommand::ValidateFollowup(args) => Invocation::ValidateFollowup(args),
        Subcommand::Analyze(args) => Invocation::Analyze(args),
        Subcommand::Analysis(args) => match args.command {
            AnalysisSubcommand::Import(args) => Invocation::AnalysisImport(args),
            AnalysisSubcommand::Job(args) => match args.command {
                AnalysisJobSubcommand::List(args) => Invocation::AnalysisJobList(args),
                AnalysisJobSubcommand::Next(args) => Invocation::AnalysisJobNext(args),
                AnalysisJobSubcommand::Claim(args) => Invocation::AnalysisJobClaim(args),
                AnalysisJobSubcommand::Complete(args) => Invocation::AnalysisJobComplete(args),
                AnalysisJobSubcommand::Fail(args) => Invocation::AnalysisJobFail(args),
            },
            AnalysisSubcommand::ExportContent(args) => Invocation::AnalysisExportContent(args),
        },
        Subcommand::Watch(args) => Invocation::Watch(args),
        Subcommand::Resume(args) => Invocation::Resume(args),
        Subcommand::Report(args) => match args.command {
            ReportSubcommand::Final(args) => Invocation::ReportFinal(args),
        },
        Subcommand::Github(args) => match args.command {
            GithubSubcommand::Plan(args) => Invocation::GithubPlan(args),
        },
        Subcommand::Worker(args) => match args.command {
            WorkerSubcommand::Doctor(args) => Invocation::WorkerDoctor(args),
        },
        Subcommand::Clean(args) => Invocation::Clean(args),
    }
}

/// 이 함수가 Ok를 돌려주기 전에는 어떤 파일도 만들지 않는다.
pub fn validate(args: &InspectArgs) -> Result<(), ScvError> {
    if is_repo_url_input(&args.repo_path) {
        let repo_input = args.repo_path.to_string_lossy();
        return usage(format!(
            "오류: 저장소 URL 입력은 아직 지원하지 않는다. 먼저 로컬로 받은 저장소 경로를 지정한다: {}",
            redact_url_for_error(&repo_input)
        ));
    }

    if !args.repo_path.exists() {
        return usage(format!(
            "오류: 검사 대상 경로가 존재하지 않는다: {}",
            args.repo_path.display()
        ));
    }

    if !args.repo_path.is_dir() {
        return usage(format!(
            "오류: 검사 대상 경로가 디렉터리가 아니다: {}",
            args.repo_path.display()
        ));
    }

    if args.out.exists() && !args.out.is_dir() {
        return usage(format!(
            "오류: 출력 경로가 디렉터리가 아니다: {}",
            args.out.display()
        ));
    }

    if args.out.is_dir() && has_entries(&args.out)? {
        return usage(format!(
            "오류: 출력 디렉터리가 비어 있지 않다: {}",
            args.out.display()
        ));
    }

    if output_is_inside_repo(&args.repo_path, &args.out)? {
        return usage(format!(
            "오류: 출력 디렉터리가 검사 대상 내부에 있다: {}",
            args.out.display()
        ));
    }

    validate_sensitive_args(args)?;

    Ok(())
}

pub fn validate_snapshot(args: &SnapshotArgs) -> Result<(), ScvError> {
    let Some(sha256) = args.sha256.as_deref() else {
        return usage("오류: snapshot 명령은 --sha256 체크섬이 필요하다.".into());
    };
    if sha256.is_empty() {
        return usage("오류: snapshot 명령은 --sha256 체크섬이 필요하다.".into());
    }
    if !is_sha256_hex(sha256) {
        return usage("오류: snapshot 명령의 --sha256 값은 64자리 hex여야 한다.".into());
    }
    if args.out.exists() && !args.out.is_dir() {
        return usage(format!(
            "오류: snapshot 출력 경로가 디렉터리가 아니다: {}",
            args.out.display()
        ));
    }
    if args.out.is_dir() && has_entries(&args.out)? {
        return usage(format!(
            "오류: snapshot 출력 디렉터리가 비어 있지 않다: {}",
            args.out.display()
        ));
    }
    if url_has_userinfo(&args.url) {
        return usage("오류: snapshot URL은 사용자 정보를 포함할 수 없다.".into());
    }
    if !is_https_snapshot_url(&args.url) {
        return usage(format!(
            "오류: snapshot URL은 https:// 원격 압축 주소여야 한다: {}",
            redact_url_for_error(&args.url)
        ));
    }
    if !is_supported_archive_url(&args.url) {
        return usage(format!(
            "오류: snapshot URL은 .zip, .tar.gz, .tgz 압축 주소여야 한다: {}",
            redact_url_for_error(&args.url)
        ));
    }

    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_https_snapshot_url(value: &str) -> bool {
    value.to_ascii_lowercase().starts_with("https://")
}

fn is_supported_archive_url(value: &str) -> bool {
    let path = strip_url_query_fragment(value).to_ascii_lowercase();
    path.ends_with(".zip") || path.ends_with(".tar.gz") || path.ends_with(".tgz")
}

fn usage<T>(message: String) -> Result<T, ScvError> {
    Err(ScvError::Usage(message))
}

fn has_entries(path: &Path) -> Result<bool, ScvError> {
    let mut entries = fs::read_dir(path).map_err(|err| {
        ScvError::Usage(format!(
            "오류: 출력 경로를 읽을 수 없다: {}: {err}",
            path.display()
        ))
    })?;
    Ok(entries.next().is_some())
}

fn output_is_inside_repo(repo_path: &Path, out_path: &Path) -> Result<bool, ScvError> {
    let repo = fs::canonicalize(repo_path).map_err(|err| {
        ScvError::Usage(format!(
            "오류: 검사 대상 경로를 정규화할 수 없다: {}: {err}",
            repo_path.display()
        ))
    })?;
    let out_anchor = canonical_existing_anchor(out_path)?;
    Ok(out_anchor.starts_with(repo))
}

fn canonical_existing_anchor(path: &Path) -> Result<PathBuf, ScvError> {
    if path.exists() {
        return fs::canonicalize(path).map_err(|err| {
            ScvError::Usage(format!(
                "오류: 출력 경로를 정규화할 수 없다: {}: {err}",
                path.display()
            ))
        });
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| ScvError::Usage(format!("오류: 현재 디렉터리를 읽을 수 없다: {err}")))?
            .join(path)
    };

    let mut cursor = absolute.as_path();
    while !cursor.exists() {
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }

    fs::canonicalize(cursor).map_err(|err| {
        ScvError::Usage(format!(
            "오류: 출력 경로를 정규화할 수 없다: {}: {err}",
            path.display()
        ))
    })
}

fn validate_sensitive_args(args: &InspectArgs) -> Result<(), ScvError> {
    for path in &args.sensitive_paths {
        if !is_clean_repo_relative_path(path) {
            return usage(format!(
                "오류: 민감 후보 승인 경로는 저장소 상대 경로여야 한다: {}",
                path.display()
            ));
        }
    }

    match args.sensitive_mode {
        SensitiveReviewMode::Exclude => {
            if args.approve_sensitive_review
                || args.approve_sensitive_raw
                || args.sensitive_review_ack.is_some()
                || args.sensitive_raw_ack.is_some()
                || !args.sensitive_paths.is_empty()
            {
                return usage(
                    "오류: exclude 모드에서는 민감 후보 승인 옵션을 함께 쓸 수 없다.".into(),
                );
            }
        }
        SensitiveReviewMode::RedactedSummary => {
            if !args.approve_sensitive_review {
                return usage(
                    "오류: redacted-summary 모드는 --approve-sensitive-review 1차 승인이 필요하다."
                        .into(),
                );
            }
            if args.sensitive_review_ack.as_deref() != Some(SENSITIVE_REVIEW_ACK) {
                return usage(format!(
                    "오류: redacted-summary 모드는 --sensitive-review-ack {SENSITIVE_REVIEW_ACK} 확인 문구가 필요하다."
                ));
            }
            if args.approve_sensitive_raw
                || args.sensitive_raw_ack.is_some()
                || !args.sensitive_paths.is_empty()
            {
                return usage("오류: 원문 승인 옵션은 approved-raw 모드에서만 쓸 수 있다.".into());
            }
        }
        SensitiveReviewMode::ApprovedRaw => {
            if !args.approve_sensitive_review || !args.approve_sensitive_raw {
                return usage(
                    "오류: approved-raw 모드는 --approve-sensitive-review 와 --approve-sensitive-raw 2중 승인이 필요하다."
                        .into(),
                );
            }
            if args.sensitive_paths.is_empty() {
                return usage(
                    "오류: approved-raw 모드는 --sensitive-path 승인 경로가 하나 이상 필요하다."
                        .into(),
                );
            }
            if args.sensitive_review_ack.as_deref() != Some(SENSITIVE_REVIEW_ACK)
                || args.sensitive_raw_ack.as_deref() != Some(SENSITIVE_RAW_ACK)
            {
                return usage(format!(
                    "오류: approved-raw 모드는 --sensitive-review-ack {SENSITIVE_REVIEW_ACK} 와 --sensitive-raw-ack {SENSITIVE_RAW_ACK} 확인 문구가 필요하다."
                ));
            }
        }
    }

    Ok(())
}

fn is_clean_repo_relative_path(path: &Path) -> bool {
    if is_repo_url_input(path) {
        return false;
    }

    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => saw_normal = true,
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    saw_normal
}

fn is_repo_url_input(path: &Path) -> bool {
    let value = path.to_string_lossy();
    let lower = value.to_ascii_lowercase();
    if has_url_scheme(&lower) {
        return true;
    }

    let Some((user_host, repo_part)) = value.split_once(':') else {
        return false;
    };
    user_host.contains('@')
        && !user_host.contains(std::path::MAIN_SEPARATOR)
        && !repo_part.is_empty()
        && !repo_part.starts_with(std::path::MAIN_SEPARATOR)
        && (repo_part.contains('/') || repo_part.ends_with(".git"))
}

fn has_url_scheme(value: &str) -> bool {
    let Some((scheme, _rest)) = value.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}
