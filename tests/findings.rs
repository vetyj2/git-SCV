//! T04, T05 — 증거 강제와 비밀값 미유출.
//! 사양: docs/spec/0500-detect.md 3·4절, 0606, 1103, 1104.

mod common;

use git_scv::model::{Category, Finding, Priority};
use std::fs;
use std::process::Command;

#[test]
fn t04_finding_without_evidence_rejected() {
    // 0606, 1304 — 타입 수준 거부
    let r = Finding::new(
        "F0001",
        Category::Manifest,
        Priority::Info,
        "요약",
        "설명",
        "한계",
        vec![],
    );
    assert!(r.is_err());
}

#[test]
fn t04_finding_with_evidence_accepted() {
    let r = Finding::new(
        "F0001",
        Category::Manifest,
        Priority::Info,
        "요약",
        "설명",
        "한계",
        vec!["E0001".into()],
    );
    assert!(r.is_ok());
}

#[test]
fn t05_secret_content_never_appears_in_artifacts() {
    let repo = common::materialize("t05-repo");
    let out_parent = common::temp_dir("t05-out");
    let out = out_parent.join("run");

    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "검사 실패: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for entry in fs::read_dir(&out).unwrap() {
        let path = entry.unwrap().path();
        let content = String::from_utf8_lossy(&fs::read(&path).unwrap()).to_string();
        assert!(
            !content.contains("abc123secretvalue"),
            "{} 에 비밀 값이 복사됐다 (1104)",
            path.display()
        );
        assert!(
            !content.contains("FAKE_TOKEN_DO_NOT_READ"),
            "{} 에 비밀 파일 내용이 복사됐다 (1103)",
            path.display()
        );
    }
}
