//! 명령 입구.
//! 인자 구조와 도움말은 고정되어 있고, 입력 검증은 구현 대기 상태다.

use crate::errors::ScvError;
use crate::model::SensitiveReviewMode;
use clap::Parser;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// 도움말 고정 문구.
pub const NO_EXEC_HELP: &str = "git-scv는 대상 저장소의 어떤 명령, 스크립트, 훅도 실행하지 않는다.";

#[derive(Parser)]
#[command(
    name = "git-scv",
    version,
    about = "무실행 저장소 검사 하네스",
    after_help = NO_EXEC_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// 저장소를 무실행으로 검사하고 산출물 디렉터리를 만든다
    #[command(after_help = NO_EXEC_HELP)]
    Inspect(InspectArgs),
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
    /// 승인 경로 원문 분석 2차 승인
    #[arg(long)]
    pub approve_sensitive_raw: bool,
    /// 원문 분석을 승인할 저장소 상대 경로
    #[arg(long = "sensitive-path")]
    pub sensitive_paths: Vec<PathBuf>,
}

pub fn parse() -> InspectArgs {
    match Cli::parse().command {
        Subcommand::Inspect(args) => args,
    }
}

/// 이 함수가 Ok를 돌려주기 전에는 어떤 파일도 만들지 않는다.
pub fn validate(args: &InspectArgs) -> Result<(), ScvError> {
    if is_repo_url_input(&args.repo_path) {
        return usage(format!(
            "오류: 저장소 URL 입력은 아직 지원하지 않는다. 먼저 로컬로 받은 저장소 경로를 지정한다: {}",
            args.repo_path.display()
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
            if args.approve_sensitive_raw || !args.sensitive_paths.is_empty() {
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
        }
    }

    Ok(())
}

fn is_clean_repo_relative_path(path: &Path) -> bool {
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
