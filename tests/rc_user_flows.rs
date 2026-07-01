mod common;

use std::fs;
use std::process::Command;

fn value_line(text: &str, prefix: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("missing line prefix {prefix}: {text}"))
}

#[test]
fn rc_review_job_export_complete_continue_flow_is_source_bound() {
    let repo = common::temp_dir("rc-review-job-flow-repo");
    fs::write(repo.join("src.js"), "export const value = 1;\n").unwrap();
    let out = common::temp_dir("rc-review-job-flow-out").join("run");

    let review = Command::new(common::bin())
        .arg("review")
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        review.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review_stdout = String::from_utf8_lossy(&review.stdout);
    assert!(review_stdout.contains("git_scv_review_status=active"));
    assert!(review_stdout.contains("next_safe_command="));
    assert!(out.join("work_order_binding.json").is_file());
    assert!(out.join(".git-scv-runtime-local.json").is_file());

    let binding: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("work_order_binding.json")).unwrap())
            .unwrap();
    assert_eq!(binding["oauth_token_stored"], false, "{binding}");
    assert_eq!(binding["oauth_token_forwarded"], false, "{binding}");
    let jobs = fs::read_to_string(out.join("analysis_jobs.jsonl")).unwrap();
    assert!(jobs.contains("\"status\":\"queued\""), "{jobs}");
    assert!(!jobs.contains("pending-until-work-order-written"), "{jobs}");

    let claim = Command::new(common::bin())
        .args(["analysis", "job", "claim"])
        .arg(&out)
        .args(["--agent", "Codex"])
        .output()
        .unwrap();
    assert_eq!(
        claim.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&claim.stderr)
    );
    let claim_stdout = String::from_utf8_lossy(&claim.stdout);
    let job_id = value_line(&claim_stdout, "claimed_job=");
    assert!(claim_stdout.contains("claim_receipt_id="), "{claim_stdout}");

    let export = Command::new(common::bin())
        .args(["analysis", "export-content"])
        .arg(&out)
        .args(["--job", &job_id])
        .output()
        .unwrap();
    assert_eq!(
        export.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let export_stdout = String::from_utf8_lossy(&export.stdout);
    let export_path = value_line(&export_stdout, "content_export=");
    let export_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(export_path).unwrap()).unwrap();
    assert_eq!(export_json["path"], "src.js", "{export_json}");
    assert_eq!(export_json["raw_content_stored"], false, "{export_json}");
    assert_eq!(
        export_json["target_repo_commands_executed"], false,
        "{export_json}"
    );

    let result_file = common::temp_dir("rc-review-job-flow-result").join("unit.jsonl");
    fs::write(
        &result_file,
        r#"{"unit_id":"U0001","allowed_paths":["src.js"],"forbidden_paths":[],"claims":[],"connections_observed":[],"unresolved_questions":[]}"#,
    )
    .unwrap();
    let complete = Command::new(common::bin())
        .args(["analysis", "job", "complete"])
        .arg(&out)
        .args(["--job", &job_id, "--result"])
        .arg(&result_file)
        .output()
        .unwrap();
    assert_eq!(
        complete.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&complete.stderr)
    );
    let completed_jobs = fs::read_to_string(out.join("analysis_jobs.jsonl")).unwrap();
    assert!(
        completed_jobs.contains("\"status\":\"completed\""),
        "{completed_jobs}"
    );
    assert!(
        completed_jobs.contains("\"result_ref\":\"analysis/job-results/"),
        "{completed_jobs}"
    );
    assert!(
        !completed_jobs.contains(result_file.to_string_lossy().as_ref()),
        "{completed_jobs}"
    );
    let receipts = fs::read_to_string(out.join("codex_invocation_receipt.jsonl")).unwrap();
    assert!(receipts.contains("\"receipt_kind\":\"codex-job-completion\""));
    assert!(receipts.contains("\"oauth_token_stored\":false"));

    let continue_run = Command::new(common::bin())
        .arg("continue")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        continue_run.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&continue_run.stderr)
    );
    assert!(out.join("final_user_report.md").is_file());
}

#[test]
fn rc_review_job_claim_blocks_after_source_change() {
    let repo = common::temp_dir("rc-review-stale-source-repo");
    fs::write(repo.join("src.js"), "export const value = 1;\n").unwrap();
    let out = common::temp_dir("rc-review-stale-source-out").join("run");

    let review = Command::new(common::bin())
        .arg("review")
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        review.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&review.stderr)
    );

    fs::write(repo.join("src.js"), "export const value = 2;\n").unwrap();
    let claim = Command::new(common::bin())
        .args(["analysis", "job", "claim"])
        .arg(&out)
        .args(["--agent", "Codex"])
        .output()
        .unwrap();
    assert_eq!(claim.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&claim.stderr);
    assert!(stderr.contains("source-fingerprint-mismatch"), "{stderr}");
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("analysis_state.json")).unwrap())
            .unwrap();
    assert_eq!(state["analysis_stage"], "blocked-stale-source", "{state}");
}

#[test]
fn rc_manual_export_import_watch_and_final_report_flow() {
    let repo = common::materialize("rc-analysis-runtime-repo");
    fs::write(
        repo.join("src.js"),
        "export function hello() { return 1; }\n",
    )
    .unwrap();
    let out = common::temp_dir("rc-analysis-runtime-out").join("run");

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

    let analyze = Command::new(common::bin())
        .args(["analyze"])
        .arg(&out)
        .args(["--backend", "manual-export"])
        .output()
        .unwrap();
    assert_eq!(
        analyze.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let analyze_stdout = String::from_utf8_lossy(&analyze.stdout);
    assert!(analyze_stdout.contains("analysis_backend=manual-export"));
    assert!(analyze_stdout.contains("gpt_work_order="));
    assert!(out.join("analysis/manual-export").is_dir());
    let export_order =
        fs::read_to_string(out.join("analysis/manual-export/GPT_WORK_ORDER.md")).unwrap();
    assert!(export_order.contains("Git-SCV GPT work order"));
    assert!(export_order.contains("Manual-export directory note"));

    let watch_before = Command::new(common::bin())
        .arg("watch")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(watch_before.status.code(), Some(0));
    let watch_before_stdout = String::from_utf8_lossy(&watch_before.stdout);
    assert!(watch_before_stdout.contains("analysis_stage=pending-unit-analysis"));
    assert!(watch_before_stdout
        .contains("final_report_status=blocked-until-analysis-map-and-meta-synthesis"));

    let jobs_text = fs::read_to_string(out.join("analysis_jobs.jsonl")).unwrap();
    let mut unit_lines = String::new();
    let mut unit_index = 1;
    for line in jobs_text.lines() {
        let job: serde_json::Value = serde_json::from_str(line).unwrap();
        if job["status"] != "queued" {
            continue;
        }
        let path = job["path"].as_str().unwrap();
        let unit = serde_json::json!({
            "unit_id": format!("U{unit_index:04}"),
            "allowed_paths": [path],
            "forbidden_paths": [],
            "claims": [],
            "connections_observed": [],
            "unresolved_questions": []
        });
        unit_lines.push_str(&serde_json::to_string(&unit).unwrap());
        unit_lines.push('\n');
        unit_index += 1;
    }
    let unit_file = common::temp_dir("rc-analysis-runtime-unit").join("unit.jsonl");
    fs::write(&unit_file, unit_lines).unwrap();

    let import = Command::new(common::bin())
        .args(["analysis", "import"])
        .arg(&out)
        .arg(&unit_file)
        .output()
        .unwrap();
    assert_eq!(
        import.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(out.join("unit_analysis.jsonl").is_file());

    let watch_after = Command::new(common::bin())
        .arg("watch")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(watch_after.status.code(), Some(0));
    let watch_after_stdout = String::from_utf8_lossy(&watch_after.stdout);
    assert!(watch_after_stdout.contains("analysis_stage=analysis-map-complete"));
    assert!(watch_after_stdout.contains("final_report_status=ready-to-generate"));

    let final_report = Command::new(common::bin())
        .args(["report", "final"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        final_report.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&final_report.stderr)
    );
    let report_md = fs::read_to_string(out.join("final_user_report.md")).unwrap();
    assert!(report_md.contains("What This Repository Appears To Do"));
    assert!(report_md.contains("Owner Questions"));
    assert!(report_md.contains("Pre-Use Checklist"));
    assert!(report_md.contains("What Git-SCV Did Not Prove"));
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
        "static_preflight_summary.json",
        "sub_slices.json",
        "sub_slices.jsonl",
        "analysis_inputs.json",
        "analysis_inputs.jsonl",
        "analysis_state.json",
        "analysis_events.jsonl",
        "analysis_map.json",
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
        brief_stdout.contains("analysis_stage=pending-unit-analysis"),
        "{brief_stdout}"
    );
    assert!(
        brief_stdout.contains("final_report_ready=false"),
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
        architecture_html.contains("pending-unit-analysis")
            || architecture_html.contains("static-preflight-only"),
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
