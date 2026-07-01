//! Allowlisted worker CLI process boundary.
//!
//! GIT_SCV_WORKER_PROCESS_ALLOWLIST:
//! - This module may start Codex/Claude/fake worker CLI processes.
//! - It must not start target repository commands, package managers, hooks,
//!   scripts, binaries, containers, or shells.
//! - It must not inspect OAuth/token files. Auth readiness is inferred only
//!   from allowlisted CLI command exit status and redacted stdout/stderr.

use crate::errors::ScvError;
use crate::redaction::redact_command_excerpt;
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const GIT_SCV_WORKER_PROCESS_ALLOWLIST: &str = "worker-cli-only-target-repo-never-executed";

#[derive(Debug)]
pub struct WorkerProcessOutput {
    pub success: bool,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_worker_process(
    program: &Path,
    args: &[String],
    stdin_text: &str,
    cwd: Option<&Path>,
    source_root: Option<&Path>,
    max_output_bytes: usize,
) -> Result<WorkerProcessOutput, ScvError> {
    let resolved = resolve_program(program)?;
    reject_target_repo_path(&resolved, source_root, "worker-executable-inside-source")?;
    if let Some(cwd) = cwd {
        reject_target_repo_path(cwd, source_root, "worker-cwd-inside-source")?;
    }

    let mut command = Command::new(&resolved);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|err| {
        ScvError::Inspect(format!(
            "worker process: worker CLI를 시작하지 못했다: {}: {err}",
            display_program(&resolved)
        ))
    })?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(stdin_text.as_bytes()).map_err(|err| {
            ScvError::Inspect(format!("worker process: worker stdin 쓰기 실패: {err}"))
        })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| ScvError::Inspect(format!("worker process: worker 대기 실패: {err}")))?;

    Ok(WorkerProcessOutput {
        success: output.status.success(),
        status_code: output.status.code(),
        stdout: sanitize_output(&output.stdout, max_output_bytes),
        stderr: sanitize_output(&output.stderr, max_output_bytes),
    })
}

pub fn resolve_program(program: &Path) -> Result<PathBuf, ScvError> {
    if program.components().count() > 1 {
        return canonical_executable(program);
    }
    let Some(program_name) = program.to_str() else {
        return Err(ScvError::Usage(
            "오류: worker executable path is not valid UTF-8".into(),
        ));
    };
    let Some(path_var) = env::var_os("PATH") else {
        return Err(ScvError::Validation(vec![format!(
            "worker-command-not-found:{program_name}"
        )]));
    };
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(program_name);
        if candidate.is_file() {
            return canonical_executable(&candidate);
        }
    }
    Err(ScvError::Validation(vec![format!(
        "worker-command-not-found:{program_name}"
    )]))
}

fn canonical_executable(path: &Path) -> Result<PathBuf, ScvError> {
    if !path.is_file() {
        return Err(ScvError::Validation(vec![format!(
            "worker-command-not-found:{}",
            path.display()
        )]));
    }
    path.canonicalize().map_err(|err| {
        ScvError::Inspect(format!(
            "worker process: worker executable canonicalize 실패: {}: {err}",
            path.display()
        ))
    })
}

fn reject_target_repo_path(
    path: &Path,
    source_root: Option<&Path>,
    reason: &str,
) -> Result<(), ScvError> {
    let Some(source_root) = source_root else {
        return Ok(());
    };
    let Ok(root) = source_root.canonicalize() else {
        return Ok(());
    };
    let candidate = if path.exists() {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    if candidate.starts_with(&root) {
        return Err(ScvError::Validation(vec![format!(
            "{reason}:{}",
            candidate.display()
        )]));
    }
    Ok(())
}

fn sanitize_output(bytes: &[u8], max_bytes: usize) -> String {
    let mut text = String::from_utf8_lossy(bytes).to_string();
    if text.len() > max_bytes {
        text.truncate(max_bytes);
        text.push_str("\n<truncated-worker-output>");
    }
    redact_command_excerpt(&text).as_str().to_string()
}

fn display_program(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<worker-cli>")
        .to_string()
}
