//! 안전 경계.
//!
//! 출력은 요청한 출력 디렉터리 아래에만(1105). target 의 존재하는 가장
//! 가까운 부모를 canonicalize 해서 out_root 포함 여부를 확인한다(1106).
//! 프로세스 생성 금지는 이 모듈이 아니라 시험 T09가 강제한다.

use crate::errors::ScvError;
use std::fs;
use std::path::{Path, PathBuf};

pub fn assert_inside(out_root: &Path, target: &Path) -> Result<(), ScvError> {
    let root = fs::canonicalize(out_root).map_err(|err| {
        ScvError::Inspect(format!(
            "artifacts: 출력 디렉터리를 정규화하지 못했다: {}: {err}",
            out_root.display()
        ))
    })?;
    let anchor = canonical_existing_anchor(target)?;

    if anchor.starts_with(&root) {
        Ok(())
    } else {
        Err(ScvError::Inspect(format!(
            "artifacts: 출력 경로가 출력 디렉터리 밖에 있다: {}",
            target.display()
        )))
    }
}

fn canonical_existing_anchor(path: &Path) -> Result<PathBuf, ScvError> {
    if path.exists() {
        return fs::canonicalize(path).map_err(|err| {
            ScvError::Inspect(format!(
                "artifacts: 출력 경로를 정규화하지 못했다: {}: {err}",
                path.display()
            ))
        });
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| {
                ScvError::Inspect(format!("artifacts: 현재 디렉터리를 읽지 못했다: {err}"))
            })?
            .join(path)
    };

    let mut cursor = absolute.as_path();
    while !cursor.exists() {
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }

    fs::canonicalize(cursor).map_err(|err| {
        ScvError::Inspect(format!(
            "artifacts: 출력 경로를 정규화하지 못했다: {}: {err}",
            path.display()
        ))
    })
}
