//! 산출물 기록.
//!
//! 쓰기 순서 고정: source → inventory → coverage → evidence → findings →
//! sectors → report.md. run.json 은 별도 함수로, 항상 마지막에(0202).
//! 모든 쓰기 직전에 safety::assert_inside 를 호출한다(1105).
//! JSON 은 to_string_pretty + 끝 줄바꿈 하나.

use crate::errors::ScvError;
use crate::model::{RunArtifact, RunData};
use std::path::Path;

pub fn write_all(out: &Path, data: &RunData) -> Result<(), ScvError> {
    let _ = (out, data);
    todo!("artifact writing is not implemented yet")
}

/// run.json 만 따로 — 단계 실패 시에도 호출되어야 한다(0202, 0203).
pub fn write_run_json(out: &Path, run: &RunArtifact) -> Result<(), ScvError> {
    let _ = (out, run);
    todo!("run artifact writing is not implemented yet")
}
