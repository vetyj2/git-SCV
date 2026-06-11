//! 형태 감지.
//!
//! 규칙은 D01–D13 표가 전부다. 내용을 여는 파일은 D01(package.json)뿐이고,
//! D13(비밀값 후보)에 걸린 파일은 어떤 경우에도 열지 않는다(D13이 항상
//! 이긴다). 바이너리 판정: 첫 8KiB 에 NUL 바이트.

use crate::errors::ScvError;
use crate::model::{DetectOutcome, InventoryArtifact};
use std::path::Path;

/// inventory 의 entries 를 규칙표와 대조하고, D01 파일만 내용을 읽는다.
/// 읽기 집계(read_files, binary_skips)는 coverage.json 의 재료가 된다.
pub fn detect(inventory: &InventoryArtifact, root: &Path) -> Result<DetectOutcome, ScvError> {
    let _ = (inventory, root);
    todo!("detection rules are not implemented yet")
}
