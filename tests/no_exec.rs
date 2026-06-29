//! T09 — 무실행 회귀 (1305, 1307).
//! 크레이트 소스(src/)에 프로세스 생성 API 가 들어오면 실패한다.
//! 무실행 원칙은 코드 리뷰가 아니라 이 시험이 강제한다.

use std::fs;
use std::path::Path;

#[test]
fn t09_no_process_spawn_api_in_src() {
    let forbidden = ["Command::", ".spawn(", ".output(", ".status("];
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;

    for entry in walkdir::WalkDir::new(&src) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().map(|e| e == "rs") != Some(true) {
            continue;
        }
        let content = fs::read_to_string(entry.path()).unwrap();
        for f in forbidden {
            assert!(
                !content.contains(f),
                "{} 에 금지 문자열 `{}` — 무실행 원칙 위반 (1305, 1307)",
                entry.path().display(),
                f
            );
        }
        checked += 1;
    }
    assert!(checked >= 10, "src/ 스캔이 비정상적으로 적다: {checked}개");
}
