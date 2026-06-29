//! 원격 스냅샷 준비에 필요한 순수 검증 유틸리티.

use crate::cli::SnapshotArgs;
use crate::errors::ScvError;
use crate::model::{ArchiveLimits, SensitiveReviewMode, SnapshotInfo};
use crate::redaction::{redact_url_for_artifact, strip_url_query_fragment};
use crate::safety;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Cursor};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tar::EntryType;
use zip::ZipArchive;

/// 초기 원격 스냅샷 다운로드 한도. 이후 CLI 옵션으로 확장할 수 있다.
pub const SNAPSHOT_DOWNLOAD_LIMIT_BYTES: u64 = 50 * 1024 * 1024;
pub const SNAPSHOT_MAX_ENTRIES: u64 = 20_000;
pub const SNAPSHOT_MAX_DECOMPRESSED_BYTES: u64 = 500 * 1024 * 1024;
pub const SNAPSHOT_MAX_PATH_BYTES: u64 = 4096;
pub const SNAPSHOT_MAX_DEPTH: u64 = 64;
const SNAPSHOT_DOWNLOAD_TIMEOUT_SECS: u64 = 30;

pub fn run(args: SnapshotArgs) -> Result<(), ScvError> {
    crate::cli::validate_snapshot(&args)?;
    let expected = args.sha256.as_deref().unwrap_or_default();
    let bytes = download_snapshot_bytes(&args.url)?;
    let command = crate::inspect::snapshot_command(&args);
    finish_downloaded_snapshot(&bytes, expected, &args.url, &args.out, command)
}

/// 내려받은 바이트의 SHA-256 digest를 소문자 hex로 돌려준다.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(hasher.finalize())
}

/// 내려받은 바이트가 사용자가 제공한 SHA-256 digest와 일치하는지 확인한다.
pub fn sha256_matches(bytes: &[u8], expected: &str) -> bool {
    expected.len() == 64 && sha256_hex(bytes).eq_ignore_ascii_case(expected)
}

pub fn finish_downloaded_snapshot(
    bytes: &[u8],
    expected: &str,
    archive_url: &str,
    out: &Path,
    command: crate::model::RunCommand,
) -> Result<(), ScvError> {
    if !sha256_matches(bytes, expected) {
        return usage("오류: snapshot 체크섬이 일치하지 않는다.".into());
    }

    let archive_kind = archive_kind(archive_url)
        .ok_or_else(|| usage_error("오류: snapshot 압축 형식을 확인할 수 없다.".into()))?;
    let source_dir = out.join("source");
    let run_dir = out.join("run");
    extract_archive_bytes(bytes, archive_kind, &source_dir)?;
    let snapshot = build_snapshot_info(expected, archive_url, archive_kind, &source_dir)?;
    crate::inspect::run_with_snapshot(
        crate::cli::InspectArgs {
            repo_path: source_dir.clone(),
            out: run_dir,
            sensitive_mode: SensitiveReviewMode::Exclude,
            approve_sensitive_review: false,
            sensitive_review_ack: None,
            approve_sensitive_raw: false,
            sensitive_raw_ack: None,
            sensitive_paths: Vec::new(),
            path_privacy: crate::model::PathPrivacyMode::RepoRelative,
        },
        snapshot,
        command,
    )
}

fn download_snapshot_bytes(url: &str) -> Result<Vec<u8>, ScvError> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(SNAPSHOT_DOWNLOAD_TIMEOUT_SECS)))
        .https_only(true)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(url)
        .header("User-Agent", "git-scv/0.2")
        .call()
        .map_err(|_err| usage_error("오류: snapshot 다운로드 실패.".into()))?;
    response
        .body_mut()
        .with_config()
        .limit(SNAPSHOT_DOWNLOAD_LIMIT_BYTES)
        .read_to_vec()
        .map_err(|_err| usage_error("오류: snapshot 다운로드 본문을 읽을 수 없다.".into()))
}

fn usage<T>(message: String) -> Result<T, ScvError> {
    Err(usage_error(message))
}

fn usage_error(message: String) -> ScvError {
    ScvError::Usage(message)
}

fn extract_archive_bytes(
    bytes: &[u8],
    archive_kind: ArchiveKind,
    out: &Path,
) -> Result<(), ScvError> {
    match archive_kind {
        ArchiveKind::Zip => extract_zip(bytes, out),
        ArchiveKind::TarGz => extract_tar_gz(bytes, out),
    }
}

#[derive(Clone, Copy)]
enum ArchiveKind {
    Zip,
    TarGz,
}

impl ArchiveKind {
    fn label(self) -> &'static str {
        match self {
            ArchiveKind::Zip => "zip",
            ArchiveKind::TarGz => "tar.gz",
        }
    }
}

fn archive_kind(value: &str) -> Option<ArchiveKind> {
    let path = strip_url_query_fragment(value).to_ascii_lowercase();
    if path.ends_with(".zip") {
        Some(ArchiveKind::Zip)
    } else if path.ends_with(".tar.gz") || path.ends_with(".tgz") {
        Some(ArchiveKind::TarGz)
    } else {
        None
    }
}

fn build_snapshot_info(
    expected: &str,
    archive_url: &str,
    archive_kind: ArchiveKind,
    source_dir: &Path,
) -> Result<SnapshotInfo, ScvError> {
    let extracted_path = fs::canonicalize(source_dir).map_err(|err| {
        ScvError::Inspect(format!(
            "snapshot: 압축 해제 경로를 정규화하지 못했다: {}: {err}",
            source_dir.display()
        ))
    })?;
    Ok(SnapshotInfo {
        url: snapshot_metadata_url(archive_url),
        sha256: expected.to_ascii_lowercase(),
        archive_format: archive_kind.label().into(),
        extracted_path: extracted_path.display().to_string(),
        archive_limits: ArchiveLimits {
            download_limit_bytes: SNAPSHOT_DOWNLOAD_LIMIT_BYTES,
            max_entries: SNAPSHOT_MAX_ENTRIES,
            max_decompressed_bytes: SNAPSHOT_MAX_DECOMPRESSED_BYTES,
            max_path_bytes: SNAPSHOT_MAX_PATH_BYTES,
            max_depth: SNAPSHOT_MAX_DEPTH,
            symlinks_allowed: false,
            hardlinks_allowed: false,
            devices_allowed: false,
        },
    })
}

fn snapshot_metadata_url(value: &str) -> String {
    redact_url_for_artifact(value).into_string()
}

fn extract_zip(bytes: &[u8], out: &Path) -> Result<(), ScvError> {
    validate_zip(bytes)?;
    create_output_root(out)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|_err| usage_error("오류: snapshot zip 압축을 읽을 수 없다.".into()))?;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|_err| usage_error("오류: snapshot zip 항목을 읽을 수 없다.".into()))?;
        let relative = zip_entry_path(&file)?;
        let target = out.join(&relative);
        if file.is_dir() {
            create_dir_inside(out, &target)?;
        } else {
            write_file_inside(out, &target, &mut file)?;
        }
    }
    Ok(())
}

fn validate_zip(bytes: &[u8]) -> Result<(), ScvError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|_err| usage_error("오류: snapshot zip 압축을 읽을 수 없다.".into()))?;
    if archive.len() as u64 > SNAPSHOT_MAX_ENTRIES {
        return usage("오류: snapshot 압축 항목 수 한도를 초과했다.".into());
    }
    let mut total_decompressed = 0_u64;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_err| usage_error("오류: snapshot zip 항목을 읽을 수 없다.".into()))?;
        total_decompressed = total_decompressed.saturating_add(file.size());
        if total_decompressed > SNAPSHOT_MAX_DECOMPRESSED_BYTES {
            return usage("오류: snapshot 압축 해제 크기 한도를 초과했다.".into());
        }
        let path = zip_entry_path(&file)?;
        validate_archive_path_limits(&path)?;
    }
    Ok(())
}

fn zip_entry_path<R: io::Read>(file: &zip::read::ZipFile<'_, R>) -> Result<PathBuf, ScvError> {
    if file.is_symlink() {
        return usage("오류: snapshot 압축 항목 형식이 안전하지 않다.".into());
    }
    file.enclosed_name()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| usage_error("오류: snapshot 압축 항목 경로가 안전하지 않다.".into()))
}

fn extract_tar_gz(bytes: &[u8], out: &Path) -> Result<(), ScvError> {
    validate_tar_gz(bytes)?;
    create_output_root(out)?;
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|_err| usage_error("오류: snapshot tar 압축을 읽을 수 없다.".into()))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|_err| usage_error("오류: snapshot tar 항목을 읽을 수 없다.".into()))?;
        let relative = tar_entry_path(&entry)?;
        let target = out.join(&relative);
        if entry.header().entry_type().is_dir() {
            create_dir_inside(out, &target)?;
        } else {
            write_file_inside(out, &target, &mut entry)?;
        }
    }
    Ok(())
}

fn validate_tar_gz(bytes: &[u8]) -> Result<(), ScvError> {
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|_err| usage_error("오류: snapshot tar 압축을 읽을 수 없다.".into()))?;
    let mut count = 0_u64;
    let mut total_decompressed = 0_u64;
    for entry in entries {
        let entry =
            entry.map_err(|_err| usage_error("오류: snapshot tar 항목을 읽을 수 없다.".into()))?;
        count += 1;
        if count > SNAPSHOT_MAX_ENTRIES {
            return usage("오류: snapshot 압축 항목 수 한도를 초과했다.".into());
        }
        total_decompressed = total_decompressed.saturating_add(entry.header().size().unwrap_or(0));
        if total_decompressed > SNAPSHOT_MAX_DECOMPRESSED_BYTES {
            return usage("오류: snapshot 압축 해제 크기 한도를 초과했다.".into());
        }
        let path = tar_entry_path(&entry)?;
        validate_archive_path_limits(&path)?;
    }
    Ok(())
}

fn validate_archive_path_limits(path: &Path) -> Result<(), ScvError> {
    if path.to_string_lossy().len() as u64 > SNAPSHOT_MAX_PATH_BYTES {
        return usage("오류: snapshot 압축 항목 경로 길이 한도를 초과했다.".into());
    }
    if path.components().count() as u64 > SNAPSHOT_MAX_DEPTH {
        return usage("오류: snapshot 압축 항목 깊이 한도를 초과했다.".into());
    }
    Ok(())
}

fn tar_entry_path<R: io::Read>(entry: &tar::Entry<'_, R>) -> Result<PathBuf, ScvError> {
    let kind = entry.header().entry_type();
    if !matches!(kind, EntryType::Regular | EntryType::Directory) {
        return usage("오류: snapshot 압축 항목 형식이 안전하지 않다.".into());
    }
    let path = entry
        .path()
        .map_err(|_err| usage_error("오류: snapshot 압축 항목 경로를 읽을 수 없다.".into()))?;
    clean_relative_path(path.as_ref())
}

fn clean_relative_path(path: &Path) -> Result<PathBuf, ScvError> {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => cleaned.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return usage("오류: snapshot 압축 항목 경로가 안전하지 않다.".into());
            }
        }
    }
    if cleaned.as_os_str().is_empty() {
        return usage("오류: snapshot 압축 항목 경로가 안전하지 않다.".into());
    }
    Ok(cleaned)
}

fn create_output_root(out: &Path) -> Result<(), ScvError> {
    fs::create_dir_all(out).map_err(|err| {
        ScvError::Usage(format!(
            "오류: snapshot 출력 디렉터리를 만들 수 없다: {}: {err}",
            out.display()
        ))
    })
}

fn create_dir_inside(out: &Path, target: &Path) -> Result<(), ScvError> {
    safety::assert_inside(out, target)?;
    fs::create_dir_all(target).map_err(|err| {
        ScvError::Usage(format!(
            "오류: snapshot 디렉터리를 만들 수 없다: {}: {err}",
            target.display()
        ))
    })
}

fn write_file_inside(
    out: &Path,
    target: &Path,
    reader: &mut impl io::Read,
) -> Result<(), ScvError> {
    if let Some(parent) = target.parent() {
        create_dir_inside(out, parent)?;
    }
    safety::assert_inside(out, target)?;
    let mut file = fs::File::create(target).map_err(|err| {
        ScvError::Usage(format!(
            "오류: snapshot 파일을 만들 수 없다: {}: {err}",
            target.display()
        ))
    })?;
    io::copy(reader, &mut file).map_err(|err| {
        ScvError::Usage(format!(
            "오류: snapshot 파일을 쓸 수 없다: {}: {err}",
            target.display()
        ))
    })?;
    Ok(())
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        finish_downloaded_snapshot, sha256_hex, sha256_matches, SNAPSHOT_DOWNLOAD_LIMIT_BYTES,
        SNAPSHOT_MAX_DEPTH,
    };
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::{Cursor, Write};
    use std::path::{Path, PathBuf};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn sha256_hex_is_stable_lower_hex() {
        assert_eq!(sha256_hex(b"abc"), ABC_SHA256);
    }

    #[test]
    fn sha256_match_accepts_uppercase_expected_digest() {
        assert!(sha256_matches(b"abc", &ABC_SHA256.to_ascii_uppercase()));
    }

    #[test]
    fn sha256_match_rejects_wrong_or_malformed_digest() {
        assert!(!sha256_matches(b"abc", &"0".repeat(64)));
        assert!(!sha256_matches(b"abc", "abc"));
    }

    #[test]
    fn checksum_mismatch_rejects_without_creating_output() {
        let out = test_path("checksum-mismatch-output");
        let err = finish_downloaded_snapshot(
            b"abc",
            &"0".repeat(64),
            "https://example.com/a.zip",
            &out,
            test_snapshot_command("https://example.com/a.zip", &out, &"0".repeat(64)),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.user_message()
                .contains("snapshot 체크섬이 일치하지 않는다"),
            "{}",
            err.user_message()
        );
        assert!(
            !out.exists(),
            "checksum mismatch 단계에서는 출력 디렉터리를 만들지 않아야 한다"
        );
    }

    #[test]
    fn checksum_match_extracts_zip_inside_output() {
        let bytes = zip_bytes("project/README.md", b"hello");
        let checksum = sha256_hex(&bytes);
        let out = test_path("zip-output");
        finish_downloaded_snapshot(
            &bytes,
            &checksum,
            "https://example.invalid/a.zip?token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456#frag",
            &out,
            test_snapshot_command(
                "https://example.invalid/a.zip?token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456#frag",
                &out,
                &checksum,
            ),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(out.join("source/project/README.md")).unwrap(),
            "hello"
        );
        assert_snapshot_run_artifacts(&out);
        let source: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("run/source.json")).unwrap())
                .unwrap();
        assert_eq!(source["snapshot"]["url"], "https://example.invalid/a.zip");
        assert_eq!(source["snapshot"]["sha256"], checksum);
        assert_eq!(source["snapshot"]["archive_format"], "zip");
        assert_eq!(
            source["snapshot"]["archive_limits"]["download_limit_bytes"],
            SNAPSHOT_DOWNLOAD_LIMIT_BYTES
        );
        assert_eq!(
            source["snapshot"]["archive_limits"]["symlinks_allowed"],
            false
        );
        assert_eq!(source["snapshot"]["extracted_path"], "<repo-root>");
        assert_eq!(source["path_privacy"]["mode"], "repo-relative");
        assert!(
            !fs::read_to_string(out.join("run/source.json"))
                .unwrap()
                .contains("GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456"),
            "snapshot metadata에 URL query 원문을 저장하면 안 된다"
        );
        let run: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("run/run.json")).unwrap()).unwrap();
        assert_eq!(run["command"]["subcommand"], "snapshot");
        assert_eq!(run["command"]["raw_args_stored"], false);
        assert_eq!(
            run["command"]["args_redacted"][0],
            "<archive-url:redacted-userinfo-query-fragment>"
        );
        assert!(
            !fs::read_to_string(out.join("run/run.json"))
                .unwrap()
                .contains("GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456"),
            "run.json에 snapshot URL query 원문을 저장하면 안 된다"
        );
    }

    #[test]
    fn checksum_match_extracts_tar_gz_inside_output() {
        let bytes = tar_gz_bytes("project/src/lib.rs", b"pub fn ok() {}");
        let checksum = sha256_hex(&bytes);
        let out = test_path("tar-gz-output");
        finish_downloaded_snapshot(
            &bytes,
            &checksum,
            "https://example.com/a.tar.gz",
            &out,
            test_snapshot_command("https://example.com/a.tar.gz", &out, &checksum),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(out.join("source/project/src/lib.rs")).unwrap(),
            "pub fn ok() {}"
        );
        assert_snapshot_run_artifacts(&out);
    }

    #[test]
    fn zip_traversal_entry_rejected_without_creating_output() {
        let bytes = zip_bytes("../escape.txt", b"nope");
        let checksum = sha256_hex(&bytes);
        let out = test_path("zip-traversal-output");
        let err = finish_downloaded_snapshot(
            &bytes,
            &checksum,
            "https://example.com/a.zip",
            &out,
            test_snapshot_command("https://example.com/a.zip", &out, &checksum),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.user_message()
                .contains("snapshot 압축 항목 경로가 안전하지 않다"),
            "{}",
            err.user_message()
        );
        assert!(
            !out.exists(),
            "unsafe archive는 출력 디렉터리를 만들기 전에 거부해야 한다"
        );
    }

    #[test]
    fn tar_traversal_entry_rejected_without_creating_output() {
        let bytes = malicious_tar_gz_bytes("../escape.txt", b"nope");
        let checksum = sha256_hex(&bytes);
        let out = test_path("tar-traversal-output");
        let err = finish_downloaded_snapshot(
            &bytes,
            &checksum,
            "https://example.com/a.tgz",
            &out,
            test_snapshot_command("https://example.com/a.tgz", &out, &checksum),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.user_message()
                .contains("snapshot 압축 항목 경로가 안전하지 않다"),
            "{}",
            err.user_message()
        );
        assert!(
            !out.exists(),
            "unsafe archive는 출력 디렉터리를 만들기 전에 거부해야 한다"
        );
    }

    #[test]
    fn zip_path_depth_limit_rejected_without_creating_output() {
        let deep_path = (0..(SNAPSHOT_MAX_DEPTH + 1))
            .map(|idx| format!("d{idx}"))
            .collect::<Vec<_>>()
            .join("/");
        let bytes = zip_bytes(&format!("{deep_path}/file.txt"), b"nope");
        let checksum = sha256_hex(&bytes);
        let out = test_path("zip-depth-limit-output");
        let err = finish_downloaded_snapshot(
            &bytes,
            &checksum,
            "https://example.com/a.zip",
            &out,
            test_snapshot_command("https://example.com/a.zip", &out, &checksum),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(
            err.user_message().contains("깊이 한도를 초과"),
            "{}",
            err.user_message()
        );
        assert!(
            !out.exists(),
            "limit 초과 archive는 출력 디렉터리를 만들기 전에 거부해야 한다"
        );
    }

    fn test_path(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("git-scv-snapshot-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn test_snapshot_command(url: &str, out: &Path, sha256: &str) -> crate::model::RunCommand {
        crate::inspect::snapshot_command(&crate::cli::SnapshotArgs {
            url: url.into(),
            out: out.to_path_buf(),
            sha256: Some(sha256.into()),
        })
    }

    fn assert_snapshot_run_artifacts(out: &Path) {
        for name in [
            "artifact_manifest.json",
            "brief.json",
            "brief.md",
            "run.json",
            "source.json",
            "inventory.json",
            "coverage.json",
            "evidence.json",
            "findings.json",
            "dependencies.json",
            "sectors.json",
            "sensitive.json",
            "gates.json",
            "slices.json",
            "review.json",
            "security.json",
            "connection_graph.json",
            "analysis_plan.json",
            "cross_unit_analysis.json",
            "synthesis.json",
            "followup_plan.json",
            "report.md",
            "report.html",
        ] {
            assert!(
                out.join("run").join(name).is_file(),
                "snapshot inspect 산출물 누락: {name}"
            );
        }
    }

    fn zip_bytes(path: &str, content: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .start_file(path, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(content).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn tar_gz_bytes(path: &str, content: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, content).unwrap();
            builder.finish().unwrap();
        }
        encoder.finish().unwrap()
    }

    fn malicious_tar_gz_bytes(path: &str, content: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        let name = path.as_bytes();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(header.as_bytes());
        tar_bytes.extend_from_slice(content);
        let padding = (512 - (content.len() % 512)) % 512;
        tar_bytes.extend(std::iter::repeat_n(0, padding));
        tar_bytes.extend([0; 1024]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }
}
