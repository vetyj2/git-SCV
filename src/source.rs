//! 원본 식별.
//!
//! 깃 정보는 반드시 `gix` 로 in-process 수집한다. 외부 `git` 명령 호출은
//! 금지다(fsmonitor 공격면). discover 방식(상위 디렉터리 탐색)도 금지 —
//! `<root>/.git` 이 있을 때만 깃 저장소다.

use crate::errors::ScvError;
use crate::model::SourceArtifact;
use std::path::Path;

/// 반환값의 `git` 필드: 깃 저장소가 아니면 None.
/// dirty 계산 실패 시 `dirty: None` 으로 두고, 호출자(inspect)가 한계
/// 문장을 추가할 수 있도록 두 번째 반환값에 true 를 담는다.
pub fn identify(
    raw_input: &str,
    root: &Path,
    run_id: &str,
) -> Result<(SourceArtifact, /* dirty_unknown */ bool), ScvError> {
    let _ = (raw_input, root, run_id);
    todo!("source identification is not implemented yet")
}
