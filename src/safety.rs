//! 안전 경계.
//!
//! 출력은 요청한 출력 디렉터리 아래에만(1105). target 의 존재하는 가장
//! 가까운 부모를 canonicalize 해서 out_root 포함 여부를 확인한다(1106).
//! 프로세스 생성 금지는 이 모듈이 아니라 시험 T09가 강제한다.

use crate::errors::ScvError;
use std::path::Path;

pub fn assert_inside(out_root: &Path, target: &Path) -> Result<(), ScvError> {
    let _ = (out_root, target);
    todo!("path safety check is not implemented yet")
}
