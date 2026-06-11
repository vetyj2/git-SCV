//! 검사 흐름 조립.
//!
//! 단계 순서: source → walk → detect → evidence → findings →
//! validate → artifacts → report. run.json 은 마지막에 쓴다.

use crate::cli::InspectArgs;
use crate::errors::ScvError;

pub fn run(args: InspectArgs) -> Result<(), ScvError> {
    crate::cli::validate(&args)?;
    let _ = args;
    todo!("inspect flow is not implemented yet")
}
