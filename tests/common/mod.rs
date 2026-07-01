//! 시험 공용 헬퍼. 픽스처를 임시 디렉터리에 실체화한다
//! (docs/spec/work-packages.md 3절). 원본 픽스처는 절대 수정하지 않는다.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_git-scv")
}

pub fn fixture_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample-repo")
}

pub fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("git-scv-test-{}-{}", std::process::id(), tag));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// 픽스처 복사 + 깃에 담기 어려운 항목 생성:
/// .env(D13), .husky/(D12), NUL 바이너리, 바이너리 package.json(바이너리 판정),
/// 저장소 밖을 가리키는 심볼릭 링크(9007).
pub fn materialize(tag: &str) -> PathBuf {
    let repo = temp_dir(tag);
    copy_dir(&fixture_src(), &repo);

    fs::write(
        repo.join(".env"),
        "GIT_SCV_TEST_SECRET=redacted-test-marker\n",
    )
    .unwrap();

    fs::create_dir_all(repo.join(".husky")).unwrap();
    fs::write(repo.join(".husky").join("pre-commit"), "#!/bin/sh\n").unwrap();

    fs::write(repo.join("blob.bin"), [0u8, 159, 146, 150]).unwrap();

    fs::create_dir_all(repo.join("vendor")).unwrap();
    fs::write(
        repo.join("vendor").join("package.json"),
        [123u8, 0, 1, 2, 125],
    )
    .unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink("/tmp", repo.join("link-out")).unwrap();

    repo
}
