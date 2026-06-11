//! 검증 관문.
//!
//! validate: 쓰기 전 메모리 검증 (V02, V03, V04, V06)
//! verify_outputs: 쓰기 후 디스크 검증 (V01, V05) — 이 함수만 IO 예외다
//! (architecture.md 1절). 실패 문자열은 사양의 표 그대로 만든다.

use crate::model::RunData;
use std::path::Path;

pub fn validate(data: &RunData) -> Result<(), Vec<String>> {
    let _ = data;
    todo!("in-memory validation is not implemented yet")
}

pub fn verify_outputs(out_dir: &Path) -> Result<(), Vec<String>> {
    let _ = out_dir;
    todo!("output verification is not implemented yet")
}
