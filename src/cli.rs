//! 명령 입구.
//! 인자 구조와 도움말은 고정되어 있고, 입력 검증은 구현 대기 상태다.

use crate::errors::ScvError;
use clap::Parser;
use std::path::PathBuf;

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
    let _ = args;
    todo!("input validation is not implemented yet")
}
