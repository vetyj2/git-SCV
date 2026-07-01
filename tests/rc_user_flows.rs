mod common;

use std::fs;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

#[cfg(unix)]
#[test]
fn rc_scan_fake_worker_runs_one_touch_to_final_report() {
    let repo = common::temp_dir("rc-scan-fake-worker-repo");
    fs::write(repo.join("src.js"), "export const value = 1;\n").unwrap();
    let out = common::temp_dir("rc-scan-fake-worker-out").join("run");
    let fake_dir = common::temp_dir("rc-scan-fake-worker-bin");
    let fake_worker = fake_dir.join("fake-worker.sh");
    fs::write(
        &fake_worker,
        "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then echo git-scv-fake-worker 1; exit 0; fi\n\
cat <<'JSON'\n\
{\"unit_id\":\"UFAKE\",\"allowed_paths\":[\"src.js\"],\"forbidden_paths\":[],\"claims\":[],\"connections_observed\":[],\"unresolved_questions\":[]}\n\
JSON\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake_worker).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&fake_worker, perms).unwrap();

    let scan = Command::new(common::bin())
        .arg("scan")
        .arg(&repo)
        .args(["--out"])
        .arg(&out)
        .args(["--worker", "fake", "--progress", "plain"])
        .env("GIT_SCV_FAKE_WORKER", &fake_worker)
        .output()
        .unwrap();
    assert_eq!(
        scan.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let stdout = String::from_utf8_lossy(&scan.stdout);
    assert!(stdout.contains("git_scv_scan_progress"), "{stdout}");
    assert!(stdout.contains("final_report=complete"), "{stdout}");
    assert!(out.join("final_user_report.md").is_file());
    assert!(out.join("worker_backend.json").is_file());
    assert!(out.join("analysis/worker-results").is_dir());
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("artifact_manifest.json")).unwrap())
            .unwrap();
    let manifest_names: Vec<&str> = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert!(manifest_names.contains(&"worker_backend.json"));
    let receipts = fs::read_to_string(out.join("codex_invocation_receipt.jsonl")).unwrap();
    assert!(receipts.contains("\"agent\":\"GitSCVFakeWorker\""));
    assert!(receipts.contains("\"target_repo_commands_executed\":false"));
}

#[cfg(unix)]
#[test]
fn rc_scan_rejects_worker_executable_inside_target_repo() {
    let repo = common::temp_dir("rc-scan-worker-inside-repo");
    fs::write(repo.join("src.js"), "export const value = 1;\n").unwrap();
    let fake_worker = repo.join("fake-worker.sh");
    fs::write(
        &fake_worker,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo bad; exit 0; fi\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake_worker).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&fake_worker, perms).unwrap();
    let out = common::temp_dir("rc-scan-worker-inside-out").join("run");

    let scan = Command::new(common::bin())
        .arg("scan")
        .arg(&repo)
        .args(["--out"])
        .arg(&out)
        .args(["--worker", "fake", "--progress", "plain"])
        .env("GIT_SCV_FAKE_WORKER", &fake_worker)
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&scan.stderr);
    assert!(
        stderr.contains("worker-executable-inside-source"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn rc_worker_doctor_and_clean_are_safe_auxiliary_commands() {
    let fake_dir = common::temp_dir("rc-worker-doctor-bin");
    let fake_worker = fake_dir.join("fake-worker.sh");
    fs::write(
        &fake_worker,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo git-scv-fake-worker 1; exit 0; fi\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake_worker).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&fake_worker, perms).unwrap();

    let doctor = Command::new(common::bin())
        .args(["worker", "doctor", "--backend", "fake"])
        .env("GIT_SCV_FAKE_WORKER", &fake_worker)
        .output()
        .unwrap();
    assert_eq!(
        doctor.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor_stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor_stdout.contains("worker_ready=true"));
    assert!(doctor_stdout.contains("auth_files_touched=false"));
    assert!(doctor_stdout.contains("oauth_token_stored=false"));
    assert!(doctor_stdout.contains("target_repo_commands_executed=false"));

    let repo = common::temp_dir("rc-clean-repo");
    fs::write(repo.join("src.js"), "export const value = 1;\n").unwrap();
    let out = common::temp_dir("rc-clean-out").join("run");
    let review = Command::new(common::bin())
        .arg("review")
        .arg(&repo)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(review.status.code(), Some(0));
    let temp_export = out.join("analysis").join("content-export");
    fs::create_dir_all(&temp_export).unwrap();
    fs::write(temp_export.join("J0001.json"), "{}\n").unwrap();

    let dry_run = Command::new(common::bin())
        .arg("clean")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(dry_run.status.code(), Some(0));
    let dry_stdout = String::from_utf8_lossy(&dry_run.stdout);
    assert!(dry_stdout.contains("clean_mode=dry-run"));
    assert!(temp_export.is_dir());

    let applied = Command::new(common::bin())
        .arg("clean")
        .arg(&out)
        .args(["--apply", "--ack", "clean-git-scv-run"])
        .output()
        .unwrap();
    assert_eq!(
        applied.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(!temp_export.exists());
    assert!(repo.join("src.js").is_file());
}

#[cfg(unix)]
#[test]
fn rc_init_and_root_doctor_cover_worker_linkage_without_auth_file_access() {
    let fake_dir = common::temp_dir("rc-init-doctor-worker-bin");
    let fake_worker = fake_dir.join("fake-worker.sh");
    fs::write(
        &fake_worker,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo git-scv-fake-worker 1; exit 0; fi\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake_worker).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&fake_worker, perms).unwrap();

    let init = Command::new(common::bin())
        .args(["init", "--worker", "fake", "--strict"])
        .env("GIT_SCV_FAKE_WORKER", &fake_worker)
        .output()
        .unwrap();
    assert_eq!(
        init.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let init_stdout = String::from_utf8_lossy(&init.stdout);
    assert!(init_stdout.contains("git_scv_init=active"), "{init_stdout}");
    assert!(
        init_stdout.contains("initial_setup_check=true"),
        "{init_stdout}"
    );
    assert!(
        init_stdout.contains("recommended_worker=codex"),
        "{init_stdout}"
    );
    assert!(
        init_stdout.contains("selected_worker=fake"),
        "{init_stdout}"
    );
    assert!(init_stdout.contains("worker_ready=true"), "{init_stdout}");
    assert!(
        init_stdout.contains("auth_files_touched=false"),
        "{init_stdout}"
    );
    assert!(
        init_stdout.contains("oauth_token_stored=false"),
        "{init_stdout}"
    );
    assert!(init_stdout.contains("api_cost_notice="), "{init_stdout}");
    assert!(init_stdout.contains("model_notice="), "{init_stdout}");
    assert!(init_stdout.contains("token_file_policy="), "{init_stdout}");
    assert!(
        init_stdout.contains("next_safe_command=git-scv <repo-path-or-github-url>"),
        "{init_stdout}"
    );

    let doctor = Command::new(common::bin())
        .args(["doctor", "--backend", "fake", "--strict"])
        .env("GIT_SCV_FAKE_WORKER", &fake_worker)
        .output()
        .unwrap();
    assert_eq!(
        doctor.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor_stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        doctor_stdout.contains(
            "doctor_scope=cli-linkage,worker-readiness,auth-boundary,cost-notices,next-steps"
        ),
        "{doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("quick_entry_command=git-scv <repo-path-or-github-url>"),
        "{doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("worker_linkage_built_in=codex,claude,fake,manual"),
        "{doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("adapter_template="),
        "{doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("worker_ready=true"),
        "{doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("auth_files_touched=false"),
        "{doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("oauth_token_forwarded=false"),
        "{doctor_stdout}"
    );
}

#[test]
fn rc_short_repo_command_defaults_to_pre_install_check_without_worker_cost() {
    let repo = common::temp_dir("rc-short-command-repo");
    fs::write(repo.join("src.js"), "export const value = 1;\n").unwrap();

    let quick = Command::new(common::bin()).arg(&repo).output().unwrap();
    assert_eq!(
        quick.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&quick.stderr)
    );
    let stdout = String::from_utf8_lossy(&quick.stdout);
    assert!(stdout.contains("quick_flow=pre-install-check"), "{stdout}");
    assert!(stdout.contains("recommended_worker=codex"), "{stdout}");
    assert!(stdout.contains("cost_notice="), "{stdout}");
    assert!(stdout.contains("scan_worker=manual"), "{stdout}");
    assert!(
        stdout.contains("analysis_stage=pending-unit-analysis"),
        "{stdout}"
    );
    assert!(
        stdout.contains("target_repo_commands_executed=false"),
        "{stdout}"
    );
}
