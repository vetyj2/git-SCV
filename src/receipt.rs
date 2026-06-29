//! Agent receipt creation.
//!
//! The receipt binds an agent acknowledgement to the exact artifact manifest and
//! source fingerprint that the agent claims to have read.

use crate::cli::ReceiptCreateArgs;
use crate::errors::ScvError;
use crate::model::AgentReceipt;
use crate::safety;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;

#[derive(Deserialize)]
struct BriefSummary {
    run_id: String,
    artifact_manifest_sha256: String,
    source_fingerprint_hash: String,
}

pub fn create(args: ReceiptCreateArgs) -> Result<(), ScvError> {
    if !args.summarized_to_user {
        return Err(ScvError::Usage(
            "오류: receipt 생성에는 --summarized-to-user 확인이 필요하다.".into(),
        ));
    }
    if !args.blocked_actions_acknowledged {
        return Err(ScvError::Usage(
            "오류: receipt 생성에는 --blocked-actions-acknowledged 확인이 필요하다.".into(),
        ));
    }
    if !args.run_dir.is_dir() {
        return Err(ScvError::Usage(format!(
            "오류: receipt 산출물 디렉터리가 아니다: {}",
            args.run_dir.display()
        )));
    }
    if !args.summary_file.is_file() {
        return Err(ScvError::Usage(format!(
            "오류: receipt summary 파일이 아니다: {}",
            args.summary_file.display()
        )));
    }

    for name in [
        "brief.json",
        "artifact_manifest.json",
        "security.json",
        "review.json",
        "gates.json",
    ] {
        let path = args.run_dir.join(name);
        if !path.is_file() {
            return Err(ScvError::Usage(format!(
                "오류: receipt 생성에 필요한 산출물이 없다: {}",
                path.display()
            )));
        }
    }

    let brief: BriefSummary = read_json(&args.run_dir, "brief.json")?;
    let manifest_hash = crate::artifacts::file_sha256(&args.run_dir, "artifact_manifest.json")?;
    if manifest_hash != brief.artifact_manifest_sha256 {
        return Err(ScvError::Inspect(format!(
            "receipt: brief.json의 artifact_manifest_sha256이 현재 artifact_manifest.json과 일치하지 않는다: expected {}, actual {}",
            brief.artifact_manifest_sha256, manifest_hash
        )));
    }

    let summary_file_sha256 = bytes_sha256(&fs::read(&args.summary_file).map_err(|err| {
        ScvError::Inspect(format!(
            "receipt: summary 파일을 읽지 못했다: {}: {err}",
            args.summary_file.display()
        ))
    })?);
    let receipt = AgentReceipt {
        artifact_kind: "agent_receipt".into(),
        schema_version: "2".into(),
        receipt_id: receipt_id(&args.agent, &brief, &summary_file_sha256),
        agent: args.agent,
        run_id: brief.run_id,
        artifact_manifest_sha256: brief.artifact_manifest_sha256,
        source_fingerprint_hash: brief.source_fingerprint_hash,
        read_artifacts: vec![
            "brief.json".into(),
            "security.json".into(),
            "review.json".into(),
            "gates.json".into(),
        ],
        summarized_to_user: true,
        blocked_actions_acknowledged: true,
        next_action_requested: args.next_action,
        summary_file_sha256,
        summary_text_stored: false,
        receipt_text: "I read the Git-SCV brief and will not run install/build/test/scripts/hooks/binaries/containers without explicit approval.".into(),
    };

    write_json(&args.run_dir, "agent_receipt.json", &receipt)?;
    println!(
        "agent_receipt={}",
        args.run_dir.join("agent_receipt.json").display()
    );
    println!("receipt_id={}", receipt.receipt_id);
    println!(
        "artifact_manifest_sha256={}",
        receipt.artifact_manifest_sha256
    );
    println!(
        "source_fingerprint_hash={}",
        receipt.source_fingerprint_hash
    );
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(run_dir: &Path, name: &str) -> Result<T, ScvError> {
    let path = run_dir.join(name);
    let bytes = fs::read(&path).map_err(|err| {
        ScvError::Inspect(format!(
            "receipt: 산출물 파일을 읽지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        ScvError::Inspect(format!(
            "receipt: 산출물 JSON을 해석하지 못했다: {}: {err}",
            path.display()
        ))
    })
}

fn write_json<T: serde::Serialize>(run_dir: &Path, name: &str, value: &T) -> Result<(), ScvError> {
    let target = run_dir.join(name);
    safety::assert_inside(run_dir, &target)?;
    let value = crate::artifacts::artifact_value_with_contract(name, value)?;
    let mut text = serde_json::to_string_pretty(&value)
        .map_err(|err| ScvError::Inspect(format!("receipt: JSON 직렬화 실패: {name}: {err}")))?;
    text.push('\n');
    fs::write(&target, text).map_err(|err| {
        ScvError::Inspect(format!(
            "receipt: 산출물을 쓰지 못했다: {}: {err}",
            target.display()
        ))
    })
}

fn receipt_id(agent: &str, brief: &BriefSummary, summary_file_sha256: &str) -> String {
    let created = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let mut hasher = Sha256::new();
    hasher.update(agent.as_bytes());
    hasher.update(brief.artifact_manifest_sha256.as_bytes());
    hasher.update(brief.source_fingerprint_hash.as_bytes());
    hasher.update(summary_file_sha256.as_bytes());
    hasher.update(created.to_string().as_bytes());
    let digest = hex_lower(hasher.finalize());
    format!("AR{}", &digest[..16])
}

fn bytes_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex_lower(hasher.finalize()))
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
