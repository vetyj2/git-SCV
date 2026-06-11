//! 섹터 지도.
//!
//! 에이전트의 읽기 계획 보조 자료다. 섹터 = 최상위 디렉터리, 루트 직속
//! 파일은 "(root)". 추정 토큰 = ceil(bytes / 4). 권장 읽기 순서는
//! 매니페스트 → 자동 실행 지점 → 진입점 후보 → 크기 오름차순, 최대 200개.

use crate::model::{Detection, InventoryArtifact, SectorsArtifact};

pub fn build(
    inventory: &InventoryArtifact,
    detections: &[Detection],
    run_id: &str,
) -> SectorsArtifact {
    let _ = (inventory, detections, run_id);
    todo!("sector map generation is not implemented yet")
}
