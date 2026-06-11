//! 명령 입구.
//! 인자 구조와 도움말은 고정되어 있고, 입력 검증은 구현 대기 상태다.

use crate::errors::ScvError;
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

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
}

pub fn parse() -> InspectArgs {
    match Cli::parse().command {
        Subcommand::Inspect(args) => args,
    }
}

/// 이 함수가 Ok를 돌려주기 전에는 어떤 파일도 만들지 않는다.
pub fn validate(args: &InspectArgs) -> Result<(), ScvError> {
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
