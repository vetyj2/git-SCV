//! 파일 탐색.
//!
//! walkdir, follow_links(false) 고정. 무시 규칙 미적용(0407),
//! .git 내부 제외(0408), 심볼릭 링크 기록만(9007).
//! entries/skipped 는 경로 바이트 사전순으로 정렬해 돌려준다(T10 결정성).

use crate::errors::ScvError;
use crate::model::InventoryArtifact;
use std::path::Path;

pub fn walk(root: &Path, run_id: &str) -> Result<InventoryArtifact, ScvError> {
    let _ = (root, run_id);
    todo!("repository walk is not implemented yet")
}
