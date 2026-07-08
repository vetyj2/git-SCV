//! T01, T02 — 명령 입구. 사양: docs/spec/0100-cli.md 3·4절.

mod common;

use std::fs;
use std::process::Command;

#[test]
fn help_contains_no_exec_sentence() {
    // 0106 — 도움말 무실행 문구
    for args in [
        vec!["--help"],
        vec!["inspect", "--help"],
        vec!["snapshot", "--help"],
        vec!["brief", "--help"],
        vec!["receipt", "--help"],
        vec!["receipt", "create", "--help"],
        vec!["case", "--help"],
        vec!["case", "create", "--help"],
        vec!["case", "next-action", "--help"],
        vec!["validate-unit", "--help"],
        vec!["validate-units", "--help"],
        vec!["synthesize", "--help"],
        vec!["followup-plan", "--help"],
        vec!["validate-followup", "--help"],
    ] {
        let output = Command::new(common::bin()).args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "help 종료 코드");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(git_scv::cli::NO_EXEC_HELP),
            "도움말에 무실행 문구가 없다: {args:?}"
        );
    }
}

#[test]
fn t01_snapshot_requires_checksum_before_any_output() {
    let out = common::temp_dir("t01-snapshot-no-checksum").join("run");
    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "https://github.com/example/project/archive/main.zip",
        ])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot 명령은 --sha256 체크섬이 필요하다"),
        "{stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_snapshot_rejects_invalid_checksum_before_any_output() {
    let out = common::temp_dir("t01-snapshot-bad-checksum").join("run");
    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "https://github.com/example/project/archive/main.zip",
        ])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", "abc123"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot 명령의 --sha256 값은 64자리 hex여야 한다"),
        "{stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_snapshot_rejects_non_https_urls_before_any_output() {
    for input in [
        "file:///tmp/project.zip",
        "ssh://github.com/example/project.git",
        "git@github.com:example/project.git",
    ] {
        let out = common::temp_dir("t01-snapshot-url").join("run");
        let output = Command::new(common::bin())
            .args(["snapshot", input])
            .arg("--out")
            .arg(&out)
            .args(["--sha256", &"a".repeat(64)])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{input}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("오류: snapshot URL은 https:// 원격 압축 주소여야 한다"),
            "{stderr}"
        );
        assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
    }
}

#[test]
fn t01_snapshot_rejects_non_archive_urls_before_any_output() {
    for input in [
        "https://github.com/example/project.git",
        "https://example.com/project/readme.txt",
    ] {
        let out = common::temp_dir("t01-snapshot-non-archive").join("run");
        let output = Command::new(common::bin())
            .args(["snapshot", input])
            .arg("--out")
            .arg(&out)
            .args(["--sha256", &"a".repeat(64)])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{input}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("오류: snapshot URL은 .zip, .tar.gz, .tgz 압축 주소여야 한다"),
            "{stderr}"
        );
        assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
    }
}

#[test]
fn t01_snapshot_rejects_url_userinfo_without_echoing_secret() {
    let out = common::temp_dir("t01-snapshot-userinfo").join("run");
    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "https://user-info@example.com/project/archive/main.zip",
        ])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", &"a".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot URL은 사용자 정보를 포함할 수 없다"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("user-info"),
        "URL 사용자 정보가 오류 출력에 복사되면 안 된다: {stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_snapshot_rejects_any_scheme_userinfo_without_echoing_secret() {
    let out = common::temp_dir("t01-snapshot-any-userinfo").join("run");
    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "http://user-info@example.com/project/archive/main.zip",
        ])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", &"a".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot URL은 사용자 정보를 포함할 수 없다"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("user-info"),
        "URL 사용자 정보가 오류 출력에 복사되면 안 된다: {stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_snapshot_rejects_non_archive_without_echoing_query() {
    let out = common::temp_dir("t01-snapshot-query-redaction").join("run");
    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "https://example.com/project/readme.txt?query-marker=value",
        ])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", &"a".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot URL은 .zip, .tar.gz, .tgz 압축 주소여야 한다"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("query-marker"),
        "URL query가 오류 출력에 복사되면 안 된다: {stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_snapshot_failure_redacts_fake_token_marker() {
    let out = common::temp_dir("t01-snapshot-fake-token-redaction").join("run");
    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "https://example.invalid/project/readme.txt?token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456#frag",
        ])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", &"a".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot URL은 .zip, .tar.gz, .tgz 압축 주소여야 한다"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456"),
        "fake token marker가 실패 출력에 복사되면 안 된다: {stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_snapshot_download_failure_is_reserved_without_output() {
    let out = common::temp_dir("t01-snapshot-download-failure").join("run");
    let output = Command::new(common::bin())
        .args(["snapshot", "https://127.0.0.1:9/project/archive/main.zip"])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", &"a".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("snapshot 다운로드 실패"), "{stderr}");
    assert!(
        !out.exists(),
        "다운로드 실패 단계에서는 산출물을 만들지 않아야 한다"
    );
}

#[test]
fn t01_repo_path_missing() {
    // U01 (0024, 1301)
    let out = common::temp_dir("t01a-out");
    let output = Command::new(common::bin())
        .args(["inspect", "/git-scv-no-such-path"])
        .arg("--out")
        .arg(out.join("run"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: 검사 대상 경로가 존재하지 않는다"),
        "{stderr}"
    );
}

#[test]
fn t01_repo_url_rejected_before_path_lookup() {
    // 0023, 1401 — 스냅샷 URL 입력은 이후 기능. 현재는 로컬 경로만 받는다.
    for input in [
        "https://github.com/example/project.git",
        "file:///tmp/example/project.git",
        "git@github.com:example/project.git",
    ] {
        let out = common::temp_dir("t01-remote-url").join("run");
        let output = Command::new(common::bin())
            .args(["inspect", input])
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{input}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("오류: 저장소 URL 입력은 아직 지원하지 않는다"),
            "{stderr}"
        );
        assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
    }
}

#[test]
fn t01_repo_url_userinfo_rejected_without_echoing_secret() {
    let out = common::temp_dir("t01-remote-userinfo").join("run");
    let output = Command::new(common::bin())
        .args([
            "inspect",
            "https://user-info@example.com/example/project.git",
        ])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: 저장소 URL 입력은 아직 지원하지 않는다"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("user-info"),
        "URL 사용자 정보가 오류 출력에 복사되면 안 된다: {stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t01_repo_path_is_file() {
    // U02 (0024)
    let dir = common::temp_dir("t01b");
    let file = dir.join("not-a-dir.txt");
    fs::write(&file, "x").unwrap();
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&file)
        .arg("--out")
        .arg(dir.join("run"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: 검사 대상 경로가 디렉터리가 아니다"),
        "{stderr}"
    );
}

#[test]
fn t02_nonempty_out_rejected_and_untouched() {
    // U04 (9006 확정) — 거부하고, 아무것도 쓰지 않는다
    let repo = common::materialize("t02-repo");
    let out = common::temp_dir("t02-out");
    fs::write(out.join("junk.txt"), "이미 있던 파일").unwrap();

    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: 출력 디렉터리가 비어 있지 않다"),
        "{stderr}"
    );

    let names: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("junk.txt")],
        "출력 디렉터리가 변형됐다"
    );
}

#[test]
fn t02_snapshot_nonempty_out_rejected_and_untouched() {
    let out = common::temp_dir("t02-snapshot-out");
    fs::write(out.join("junk.txt"), "이미 있던 파일").unwrap();

    let output = Command::new(common::bin())
        .args([
            "snapshot",
            "https://github.com/example/project/archive/main.zip",
        ])
        .arg("--out")
        .arg(&out)
        .args(["--sha256", &"a".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: snapshot 출력 디렉터리가 비어 있지 않다"),
        "{stderr}"
    );

    let names: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("junk.txt")],
        "출력 디렉터리가 변형됐다"
    );
}

#[test]
fn t02_out_inside_repo_rejected() {
    // U05 (1105)
    let repo = common::materialize("t02c-repo");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(repo.join("scv-out"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("오류: 출력 디렉터리가 검사 대상 내부에 있다"),
        "{stderr}"
    );
}

#[test]
fn t03_redacted_summary_requires_first_approval() {
    let repo = common::materialize("t03-sensitive-approval");
    let out = common::temp_dir("t03-sensitive-approval-out").join("run");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .args(["--sensitive-mode", "redacted-summary"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--approve-sensitive-review 1차 승인이 필요하다"),
        "{stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t03_redacted_summary_requires_review_ack() {
    let repo = common::materialize("t03-sensitive-review-ack");
    let out = common::temp_dir("t03-sensitive-review-ack-out").join("run");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .args([
            "--sensitive-mode",
            "redacted-summary",
            "--approve-sensitive-review",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--sensitive-review-ack"), "{stderr}");
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t03_approved_raw_requires_two_approvals_and_path() {
    let repo = common::materialize("t03-sensitive-raw");
    let out = common::temp_dir("t03-sensitive-raw-out").join("run");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .args([
            "--sensitive-mode",
            "approved-raw",
            "--approve-sensitive-review",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .contains("--approve-sensitive-review 와 --approve-sensitive-raw 2중 승인이 필요하다"),
        "{stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t03_approved_raw_requires_ack_phrases() {
    let repo = common::materialize("t03-sensitive-raw-ack");
    let out = common::temp_dir("t03-sensitive-raw-ack-out").join("run");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .args([
            "--sensitive-mode",
            "approved-raw",
            "--approve-sensitive-review",
            "--approve-sensitive-raw",
            "--sensitive-path",
            ".env",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--sensitive-review-ack"), "{stderr}");
    assert!(stderr.contains("--sensitive-raw-ack"), "{stderr}");
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t03_sensitive_path_must_stay_repo_relative() {
    let repo = common::materialize("t03-sensitive-path");
    let out = common::temp_dir("t03-sensitive-path-out").join("run");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .args([
            "--sensitive-mode",
            "approved-raw",
            "--approve-sensitive-review",
            "--approve-sensitive-raw",
            "--sensitive-path",
            "../outside.sh",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("민감 후보 승인 경로는 저장소 상대 경로여야 한다"),
        "{stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t03_sensitive_path_must_not_be_url_like() {
    let repo = common::materialize("t03-sensitive-path-url");
    let out = common::temp_dir("t03-sensitive-path-url-out").join("run");
    let output = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .args([
            "--sensitive-mode",
            "approved-raw",
            "--approve-sensitive-review",
            "--approve-sensitive-raw",
            "--sensitive-path",
            "file://.env",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("민감 후보 승인 경로는 저장소 상대 경로여야 한다"),
        "{stderr}"
    );
    assert!(!out.exists(), "검증 실패 시 산출물을 만들지 않아야 한다");
}

#[test]
fn t04_brief_outputs_mandatory_agent_guard() {
    let repo = common::materialize("t04-brief-repo");
    let out = common::temp_dir("t04-brief-out").join("run");
    let inspect = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(inspect.status.code(), Some(0));

    let brief = Command::new(common::bin())
        .args(["brief"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(brief.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&brief.stdout);
    assert!(stdout.contains("git-scv 필수 에이전트 브리핑"), "{stdout}");
    assert!(
        stdout.contains("artifact_manifest_sha256=sha256:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("source_fingerprint_hash=sha256:"),
        "{stdout}"
    );
    assert!(stdout.contains("verdict=insufficient-coverage"), "{stdout}");
    assert!(stdout.contains("safe_claim_made=false"), "{stdout}");
    assert!(stdout.contains("may_user_run_install=false"), "{stdout}");
    assert!(
        stdout.contains("may_agent_request_run_approval=true"),
        "{stdout}"
    );
    assert!(
        stdout.contains("may_agent_run_without_user=false"),
        "{stdout}"
    );
    assert!(stdout.contains("reason_codes="), "{stdout}");
    assert!(stdout.contains("required_actions:"), "{stdout}");
    assert!(
        stdout.contains("id=sensitive-raw-review required=true"),
        "{stdout}"
    );
    assert!(
        stdout.contains("default_model_excluded_paths_count="),
        "{stdout}"
    );
    assert!(stdout.contains("mandatory_agent_rules:"), "{stdout}");
    assert!(
        stdout.contains("agent_read_receipt=git-scv-brief:v2:sha256:"),
        "{stdout}"
    );
}

#[test]
fn t04_receipt_create_binds_agent_read_to_manifest_and_source() {
    let repo = common::materialize("t04-receipt-repo");
    let out = common::temp_dir("t04-receipt-out").join("run");
    let inspect = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(inspect.status.code(), Some(0));

    let summary_file = common::temp_dir("t04-receipt-summary").join("summary.md");
    fs::write(
        &summary_file,
        "verdict=approval-required\naction_required=true\n",
    )
    .unwrap();

    let blocked = Command::new(common::bin())
        .args(["receipt", "create"])
        .arg(&out)
        .args(["--agent", "Hermes"])
        .arg("--summary-file")
        .arg(&summary_file)
        .output()
        .unwrap();
    assert_eq!(blocked.status.code(), Some(2));
    assert!(
        !out.join("agent_receipt.json").exists(),
        "ack 없는 receipt는 생성되면 안 된다"
    );

    let created = Command::new(common::bin())
        .args(["receipt", "create"])
        .arg(&out)
        .args(["--agent", "Hermes"])
        .arg("--summary-file")
        .arg(&summary_file)
        .args([
            "--summarized-to-user",
            "--blocked-actions-acknowledged",
            "--next-action",
            "ask-user-approval",
        ])
        .output()
        .unwrap();
    assert_eq!(
        created.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let stdout = String::from_utf8_lossy(&created.stdout);
    assert!(stdout.contains("receipt_id=AR"), "{stdout}");
    assert!(
        stdout.contains("artifact_manifest_sha256=sha256:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("source_fingerprint_hash=sha256:"),
        "{stdout}"
    );

    let brief: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("brief.json")).unwrap()).unwrap();
    let receipt: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("agent_receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["artifact_kind"], "agent_receipt", "{receipt}");
    assert_eq!(receipt["schema_version"], "2", "{receipt}");
    assert_eq!(
        receipt["contract_version"], "artifact-contract-v2",
        "{receipt}"
    );
    assert_eq!(receipt["producer"]["name"], "git-scv", "{receipt}");
    assert_eq!(
        receipt["min_reader_version"],
        env!("CARGO_PKG_VERSION"),
        "{receipt}"
    );
    assert_eq!(receipt["agent"], "Hermes", "{receipt}");
    assert_eq!(
        receipt["artifact_manifest_sha256"], brief["artifact_manifest_sha256"],
        "{receipt}"
    );
    assert_eq!(
        receipt["source_fingerprint_hash"], brief["source_fingerprint_hash"],
        "{receipt}"
    );
    assert_eq!(receipt["summary_text_stored"], false, "{receipt}");
    assert_eq!(
        receipt["next_action_requested"], "ask-user-approval",
        "{receipt}"
    );
    assert!(
        receipt["summary_file_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "{receipt}"
    );
    assert!(
        receipt["read_artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "brief.json"),
        "{receipt}"
    );
}

#[test]
fn t04_case_cli_manages_case_package_and_verifies_source() {
    let repo = common::materialize("t04-case-repo");
    let case_root = common::temp_dir("t04-case-root");

    let doctor = Command::new(common::bin())
        .args(["case", "doctor"])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(doctor.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&doctor.stdout).contains("world_readable=false"),
        "{}",
        String::from_utf8_lossy(&doctor.stdout)
    );

    let created = Command::new(common::bin())
        .args(["case", "create"])
        .arg(&repo)
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(
        created.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created_stdout = String::from_utf8_lossy(&created.stdout);
    let case_id = value_line(&created_stdout, "case_id=");
    let case_path = case_root.join(&case_id);
    assert!(case_path.join(".git-scv-case.json").is_file());
    assert!(case_path.join("artifact_manifest.json").is_file());
    assert!(case_path.join("brief.json").is_file());

    let listed = Command::new(common::bin())
        .args(["case", "list"])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains(&case_id),
        "{}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let shown = Command::new(common::bin())
        .args(["case", "show", &case_id])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("artifact_manifest_sha256=sha256:"),
        "{}",
        String::from_utf8_lossy(&shown.stdout)
    );
    let shown_stdout = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown_stdout.contains("source_path=<repo-root>"),
        "{shown_stdout}"
    );
    assert!(
        !shown_stdout.contains(repo.to_string_lossy().as_ref()),
        "case show must not leak the absolute source path by default: {shown_stdout}"
    );

    let brief = Command::new(common::bin())
        .args(["case", "brief", &case_id])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(brief.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&brief.stdout).contains("git-scv 필수 에이전트 브리핑"),
        "{}",
        String::from_utf8_lossy(&brief.stdout)
    );

    let verified = Command::new(common::bin())
        .args(["case", "verify-source", &case_id])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(
        verified.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        String::from_utf8_lossy(&verified.stdout).contains("source_status=valid"),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );

    let blocked_next = Command::new(common::bin())
        .args([
            "case",
            "next-action",
            &case_id,
            "--action",
            "install",
            "--argv",
            "npm",
            "install",
        ])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(
        blocked_next.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&blocked_next.stderr)
    );
    let next_json: serde_json::Value =
        serde_json::from_slice(&blocked_next.stdout).expect("next-action should emit JSON");
    assert_eq!(next_json["allowed"], false, "{next_json}");
    assert_eq!(next_json["artifact_manifest_valid"], true, "{next_json}");
    assert_eq!(next_json["source_status"], "valid", "{next_json}");
    let blocked_by: Vec<&str> = next_json["blocked_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect();
    assert!(
        blocked_by.contains(&"agent-read-receipt-required")
            && blocked_by.contains(&"execution-command-review-required"),
        "{next_json}"
    );

    fs::write(repo.join("new-file-after-case.txt"), "changed\n").unwrap();
    let stale = Command::new(common::bin())
        .args(["case", "verify-source", &case_id])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&stale.stderr).contains("stale-source"),
        "{}",
        String::from_utf8_lossy(&stale.stderr)
    );
    let status = Command::new(common::bin())
        .args(["case", "status", &case_id])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("source_status=stale-source"),
        "{}",
        String::from_utf8_lossy(&status.stdout)
    );
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("source_path=<repo-root>"),
        "{status_stdout}"
    );
    assert!(
        !status_stdout.contains(repo.to_string_lossy().as_ref()),
        "case status must not leak the absolute source path by default: {status_stdout}"
    );

    let stale_next = Command::new(common::bin())
        .args([
            "case",
            "next-action",
            &case_id,
            "--action",
            "install",
            "--argv",
            "npm",
            "install",
        ])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(stale_next.status.code(), Some(0));
    let stale_next_json: serde_json::Value =
        serde_json::from_slice(&stale_next.stdout).expect("next-action should emit JSON");
    assert_eq!(stale_next_json["allowed"], false, "{stale_next_json}");
    assert_eq!(
        stale_next_json["source_status"], "stale-source",
        "{stale_next_json}"
    );
    let stale_blocked_by: Vec<&str> = stale_next_json["blocked_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect();
    assert!(
        stale_blocked_by.contains(&"stale-source"),
        "{stale_next_json}"
    );

    let blocked_delete = Command::new(common::bin())
        .args(["case", "delete", &case_id, "--ack", "wrong"])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(blocked_delete.status.code(), Some(2));
    assert!(case_path.exists());

    let deleted = Command::new(common::bin())
        .args(["case", "delete", &case_id, "--ack", "delete-git-scv-case"])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(
        deleted.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(!case_path.exists());

    let created_again = Command::new(common::bin())
        .args(["case", "create"])
        .arg(&repo)
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(created_again.status.code(), Some(0));
    let pruned = Command::new(common::bin())
        .args([
            "case",
            "prune",
            "--all",
            "--ack",
            "delete-all-git-scv-cases",
        ])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(
        pruned.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&pruned.stderr)
    );
    assert!(
        String::from_utf8_lossy(&pruned.stdout).contains("deleted_cases=1"),
        "{}",
        String::from_utf8_lossy(&pruned.stdout)
    );
}

#[test]
fn t04_unit_analysis_and_synthesis_loop_commands_work() {
    let repo = common::materialize("t04-unit-loop-repo");
    let out = common::temp_dir("t04-unit-loop-out").join("run");
    let inspect = Command::new(common::bin())
        .args(["inspect"])
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );

    let evidence: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("evidence.json")).unwrap()).unwrap();
    let evidence_id = evidence["evidence"].as_array().unwrap().first().unwrap()["id"]
        .as_str()
        .unwrap();

    let unit_dir = out.join("unit-analysis");
    fs::create_dir_all(&unit_dir).unwrap();
    let unit_file = unit_dir.join("U0001.json");
    let unit = serde_json::json!({
        "unit_id": "U0001",
        "allowed_paths": ["package.json"],
        "forbidden_paths": [".env"],
        "claims": [
            {
                "claim_id": "C0001",
                "type": "execution-surface",
                "summary": "package manifest has an execution-related signal.",
                "confidence": "medium",
                "evidence_refs": [evidence_id],
                "source_paths": ["package.json"],
                "requires_followup": true,
                "verification_status": "evidence-linked",
                "validated_by_git_scv": ["schema", "path-boundary", "evidence-link"],
                "not_validated_by_git_scv": ["semantic-truth", "malware-absence"]
            }
        ],
        "connections_observed": [
            {
                "from": "file:package.json",
                "to": "gate:execution-command-review",
                "edge_kind": "gates",
                "confidence": "medium",
                "evidence_refs": [evidence_id]
            }
        ],
        "unresolved_questions": [
            {
                "id": "Q0001",
                "reason": "execution body remains gate-bound",
                "needed_approval": "execution-model-input-review"
            }
        ],
        "qualitative_digest": {
            "summary": "package.json contains an execution-related manifest signal that remains gate-bound.",
            "important_points": ["package.json is the reviewed manifest surface"],
            "scoped_uncertainty": ["Execution body semantics were not validated by Git-SCV."]
        },
        "map_delta": {
            "repo_purpose_candidates": ["Package manifest centered project"],
            "major_modules": ["package.json"],
            "execution_flows": ["Manifest execution signal is blocked by review gates."],
            "owner_questions": ["Which install/build/test command is officially supported?"],
            "pre_use_checklist": ["Verify source and resolve execution gates before running package-manager commands."]
        },
        "relation_candidates": [
            {
                "from": "file:package.json",
                "to": "gate:execution-command-review",
                "kind": "gates",
                "confidence": "medium"
            }
        ],
        "followup_candidates": [
            {
                "summary": "Review the gated execution surface after user approval.",
                "path": "package.json"
            }
        ],
        "abstentions": [
            {
                "reason": "Git-SCV validates structure and evidence boundaries, not semantic truth.",
                "scope": "semantic-truth"
            }
        ]
    });
    fs::write(&unit_file, serde_json::to_string_pretty(&unit).unwrap()).unwrap();

    let one = Command::new(common::bin())
        .args(["validate-unit"])
        .arg(&out)
        .arg(&unit_file)
        .output()
        .unwrap();
    assert_eq!(
        one.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&one.stderr)
    );
    assert!(
        String::from_utf8_lossy(&one.stdout).contains("unit_validation=ok"),
        "{}",
        String::from_utf8_lossy(&one.stdout)
    );

    let all = Command::new(common::bin())
        .args(["validate-units"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        all.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&all.stderr)
    );
    assert!(
        String::from_utf8_lossy(&all.stdout).contains("unit_validations=1"),
        "{}",
        String::from_utf8_lossy(&all.stdout)
    );

    let synthesis = Command::new(common::bin())
        .args(["synthesize"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        synthesis.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&synthesis.stderr)
    );
    assert!(
        String::from_utf8_lossy(&synthesis.stdout).contains("safe_claim_made=false"),
        "{}",
        String::from_utf8_lossy(&synthesis.stdout)
    );

    let followup = Command::new(common::bin())
        .args(["followup-plan"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        followup.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&followup.stderr)
    );
    assert!(
        String::from_utf8_lossy(&followup.stdout).contains("followup_plan=ok"),
        "{}",
        String::from_utf8_lossy(&followup.stdout)
    );

    let validate_followup = Command::new(common::bin())
        .args(["validate-followup"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        validate_followup.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&validate_followup.stderr)
    );
    assert!(
        String::from_utf8_lossy(&validate_followup.stdout).contains("followup_validation=ok"),
        "{}",
        String::from_utf8_lossy(&validate_followup.stdout)
    );
}

fn value_line(text: &str, prefix: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("missing line prefix {prefix}: {text}"))
}
