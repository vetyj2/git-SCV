mod common;

use std::fs;
use std::process::Command;

fn value_line(text: &str, prefix: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("missing line prefix {prefix}: {text}"))
}

#[test]
fn rc_local_case_flow_is_brief_first_visualized_and_next_action_blocked() {
    let repo = common::materialize("rc-local-case-flow-repo");
    fs::write(
        repo.join("package.json"),
        "{\"scripts\":{\"postinstall\":\"node setup.js\"}}\n",
    )
    .unwrap();
    let case_root = common::temp_dir("rc-local-case-root");

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
    for name in [
        "brief.md",
        "brief.json",
        "architecture.html",
        "architecture_map.json",
        "relation_map.json",
        "source_landmarks.json",
        "visualization_index.json",
    ] {
        assert!(
            case_path.join(name).is_file(),
            "missing RC artifact: {name}"
        );
    }

    let brief = Command::new(common::bin())
        .args(["case", "brief", &case_id])
        .env("GIT_SCV_CASE_ROOT", &case_root)
        .output()
        .unwrap();
    assert_eq!(brief.status.code(), Some(0));
    let brief_stdout = String::from_utf8_lossy(&brief.stdout);
    assert!(
        brief_stdout.contains("git-scv 필수 에이전트 브리핑"),
        "{brief_stdout}"
    );
    assert!(
        brief_stdout.contains("visual_outputs=architecture.html"),
        "{brief_stdout}"
    );
    assert!(brief_stdout.contains("do_not_do_yet="), "{brief_stdout}");
    assert!(
        brief_stdout.contains("mandatory_agent_rules:"),
        "{brief_stdout}"
    );

    let architecture_html = fs::read_to_string(case_path.join("architecture.html")).unwrap();
    assert!(
        architecture_html.contains("Git-SCV Architecture & Safety Synthesis"),
        "{architecture_html}"
    );
    assert!(
        architecture_html.contains("Execution Scenario Reachability"),
        "{architecture_html}"
    );

    let next = Command::new(common::bin())
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
        next.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&next.stderr)
    );
    let next_json: serde_json::Value =
        serde_json::from_slice(&next.stdout).expect("next-action should emit JSON");
    assert_eq!(next_json["allowed"], false, "{next_json}");
    assert_eq!(next_json["source_status"], "valid", "{next_json}");
    let blocked_by: Vec<&str> = next_json["blocked_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect();
    assert!(
        blocked_by.contains(&"agent-read-receipt-required"),
        "{next_json}"
    );
    assert!(
        blocked_by.contains(&"execution-command-review-required"),
        "{next_json}"
    );
    assert_eq!(next_json["safe_claim_made"], false, "{next_json}");
}
