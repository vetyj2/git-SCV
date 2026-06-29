//! T11 — 검증 관문 V01–V25, 결함 주입마다 해당 V번호로만 실패.
//! 사양: docs/spec/0900-artifacts.md 3절.

mod common;

use git_scv::model::*;
use git_scv::validate::{validate, verify_outputs};
use std::fs;

/// validate()가 통과해야 하는 최소 정합 상태.
fn baseline() -> RunData {
    let run_id = "scv-test".to_string();
    let sv = || SCHEMA_VERSION.to_string();
    let rid = || run_id.clone();
    RunData {
        run_id: rid(),
        started_at: "2026-01-01T00:00:00Z".into(),
        finished_at: "2026-01-01T00:00:01Z".into(),
        command: RunCommand {
            program: "git-scv".into(),
            subcommand: "inspect".into(),
            args_redacted: vec!["<path>".into(), "--out".into(), "<path>".into()],
            raw_args_stored: false,
        },
        source: SourceArtifact {
            schema_version: sv(),
            run_id: rid(),
            input: InputInfo { raw: "/x".into(), kind: "local-path".into() },
            resolved_path: "/x".into(),
            git: None,
            snapshot: None,
            path_privacy: PathPrivacy::new(PathPrivacyMode::RepoRelative),
            source_fingerprint: None,
        },
        inventory: InventoryArtifact {
            schema_version: sv(),
            run_id: rid(),
            root: "/x".into(),
            policy: Policy::default(),
            limits: Limits::default(),
            entries: vec![],
            skipped: vec![],
            totals: Totals { discovered: 0, listed: 0, skipped: 0 },
        },
        coverage: CoverageArtifact {
            schema_version: sv(),
            run_id: rid(),
            local_limits: Limits::default(),
            limit_reason_codes: vec![],
            capabilities: vec![],
            prompt_injection_surfaces: vec![],
            files_discovered: 0,
            files_read: 0,
            files_skipped: 0,
            bytes_read_total: 0,
            read_files: vec![],
            skip_reasons: SkipReasons::default(),
            confidence_note: "시험".into(),
        },
        evidence: EvidenceArtifact { schema_version: sv(), run_id: rid(), evidence: vec![] },
        findings: FindingsArtifact {
            schema_version: sv(),
            run_id: rid(),
            findings: vec![],
            limitations: vec![LOW_CONFIDENCE_SENTENCE.into()],
        },
        dependencies: DependencyArtifact {
            schema_version: sv(),
            run_id: rid(),
            manifests: vec![],
            limitations: vec![],
            note: "시험".into(),
        },
        sectors: SectorsArtifact {
            schema_version: sv(),
            run_id: rid(),
            sectors: vec![],
            suggested_read_order: vec![],
            note: "읽기 계획 보조 자료이며 판단 근거가 아니다.".into(),
        },
        sensitive: SensitiveArtifact {
            schema_version: sv(),
            run_id: rid(),
            mode: SensitiveReviewMode::Exclude,
            first_approval: false,
            second_approval: false,
            review_ack_confirmed: false,
            raw_ack_confirmed: false,
            approved_paths: vec![],
            unapproved_paths: vec![],
            candidates: vec![],
            raw_content_stored: false,
            note: "시험".into(),
        },
        gates: GateArtifact {
            schema_version: sv(),
            run_id: rid(),
            decision_binding: GateDecisionBinding {
                requires_source_fingerprint_hash: true,
                requires_artifact_manifest_sha256: true,
                expires_on_source_change: true,
                expires_on_artifact_manifest_change: true,
                requires_path_metadata_hash_for_path_approval: true,
                requires_exact_command_envelope_for_execution: true,
            },
            sensitive_raw_review: GatePrompt {
                approval_required: false,
                message: "시험".into(),
                paths: vec![],
                acknowledgements: vec![],
            },
            execution_model_input_review: GatePrompt {
                approval_required: false,
                message: "시험".into(),
                paths: vec![],
                acknowledgements: vec![],
            },
            execution_command_review: ExecutionCommandGate {
                approval_required: false,
                message: "시험".into(),
                requires_exact_command: true,
                approved_commands: vec![],
                acknowledgements: vec![],
            },
            sensitive_candidates: vec![],
            automatic_execution_candidates: vec![],
            execution_related_candidates: vec![],
            note: "시험".into(),
        },
        slices: SliceArtifact {
            schema_version: sv(),
            run_id: rid(),
            policy: SlicePolicy {
                source_order: "시험".into(),
                max_estimated_tokens_per_slice: 8000,
                default_model_input: "시험".into(),
            },
            slices: vec![],
            note: "시험".into(),
        },
        review: ReviewArtifact {
            schema_version: sv(),
            run_id: rid(),
            verdict: "no-blocker-observed".into(),
            safe_claim_made: false,
            may_user_run_install: false,
            may_agent_request_run_approval: true,
            may_agent_run_without_user: false,
            reason_codes: vec!["observed-scope-no-blocker".into()],
            counts: ReviewCounts {
                findings_total: 0,
                high_priority_findings: 0,
                medium_priority_findings: 0,
                sensitive_candidates: 0,
                automatic_execution_candidates: 0,
                execution_related_candidates: 0,
                deep_analysis_candidates: 0,
                slices_total: 0,
                slices_over_token_limit: 0,
            },
            required_actions: baseline_required_actions(),
            default_model_excluded_paths: vec![],
            note: "시험".into(),
        },
        security: SecurityArtifact {
            schema_version: sv(),
            run_id: rid(),
            verdict: "no-blocker-observed".into(),
            safe_claim_made: false,
            may_user_run_install: false,
            may_agent_request_run_approval: true,
            may_agent_run_without_user: false,
            reason_codes: vec!["observed-scope-no-blocker".into()],
            action_required: false,
            no_exec: NO_EXEC_SENTENCE.into(),
            counts: ReviewCounts {
                findings_total: 0,
                high_priority_findings: 0,
                medium_priority_findings: 0,
                sensitive_candidates: 0,
                automatic_execution_candidates: 0,
                execution_related_candidates: 0,
                deep_analysis_candidates: 0,
                slices_total: 0,
                slices_over_token_limit: 0,
            },
            required_actions: baseline_required_actions(),
            default_model_excluded_paths: vec![],
            limitations: vec![LOW_CONFIDENCE_SENTENCE.into()],
            references: vec![
                "review.json".into(),
                "findings.json".into(),
                "evidence.json".into(),
                "gates.json".into(),
                "slices.json".into(),
                "sensitive.json".into(),
            ],
            note: "시험".into(),
        },
        supported_surfaces: SupportedSurfacesArtifact {
            schema_version: sv(),
            run_id: rid(),
            capabilities: vec![],
            note: "시험".into(),
        },
        gate_decisions: GateDecisionArtifact {
            schema_version: sv(),
            run_id: rid(),
            source_fingerprint_hash: "sha256:unknown".into(),
            artifact_manifest_sha256_required: true,
            expires_on_source_change: true,
            decisions: vec![],
            note: "시험".into(),
        },
        connection_graph: ConnectionGraphArtifact {
            schema_version: sv(),
            run_id: rid(),
            nodes: vec![],
            edges: vec![],
            scenarios: vec![],
        },
        reachability_scenarios: ReachabilityScenariosArtifact {
            schema_version: sv(),
            run_id: rid(),
            scenarios: vec![],
            note: "시험".into(),
        },
        architecture_map: ArchitectureMapArtifact {
            schema_version: sv(),
            run_id: rid(),
            repo_shape: RepoShape {
                detected_shapes: vec!["unknown-mixed".into()],
                confidence: "low".into(),
                limitations: vec![],
            },
            sectors: vec![],
            entrypoints: vec![],
            architecture_summary: ArchitectureSummary {
                human_summary: "시험".into(),
                safe_claim_made: false,
            },
            visualization_recommendations: vec!["overview".into()],
        },
        relation_map: RelationMapArtifact {
            schema_version: sv(),
            run_id: rid(),
            relations: vec![],
            unresolved_relations: vec![],
        },
        source_landmarks: SourceLandmarksArtifact {
            schema_version: sv(),
            run_id: rid(),
            recommended_reading_order: vec![],
            do_not_read_by_default: vec![],
            gate_before_reading: vec![],
        },
        visualization_index: VisualizationIndexArtifact {
            schema_version: sv(),
            run_id: rid(),
            default_visualization: "architecture.html".into(),
            views: vec![],
            privacy: VisualizationPrivacy {
                raw_sensitive_content_included: false,
                target_repo_js_executed: false,
                external_network_required: false,
            },
            graph_limits: VisualizationGraphLimits {
                max_nodes: 200,
                max_edges: 300,
                truncated: false,
            },
        },
        analysis_plan: AnalysisPlanArtifact {
            schema_version: sv(),
            run_id: rid(),
            units: vec![],
            cross_unit_tasks: vec![],
        },
        cross_unit_analysis: CrossUnitAnalysisArtifact {
            schema_version: sv(),
            run_id: rid(),
            input_units: vec![],
            aggregate_paths: vec![],
            synergy_findings: vec![],
            conflicts: vec![],
            unresolved_edges: vec![],
            followup_required: false,
        },
        synthesis: SynthesisArtifact {
            schema_version: sv(),
            run_id: rid(),
            verdict: "no-blocker-observed".into(),
            safe_claim_made: false,
            unit_analyses_complete: false,
            cross_unit_analysis_complete: "minimal-static".into(),
            architecture_visualization_complete: true,
            source_fingerprint_verified: false,
            unresolved_edges_count: 0,
            conflicts_count: 0,
            required_user_actions: vec![],
            architecture_synthesis: ArchitectureSynthesis {
                detected_shapes: vec!["unknown-mixed".into()],
                primary_sectors: vec![],
                recommended_visualization: "architecture.html".into(),
                source_landmarks_available: false,
            },
            aggregate_safety_diagnosis: AggregateSafetyDiagnosis {
                no_blocker_observed_within_scope: true,
                blocked_execution_surfaces: vec![],
                insufficient_coverage_reasons: vec![],
                what_cannot_be_concluded: vec![],
            },
        },
        followup_plan: FollowupPlanArtifact {
            schema_version: sv(),
            run_id: rid(),
            round: 1,
            reason: "시험".into(),
            required_followups: vec![],
            blocked_until: vec![],
        },
        report_md: format!(
            "# git-scv 검사 리포트\n\n## 원본\n\n## 범위\n\n## 발견사항\n\n발견사항 없음\n\n## 한계\n\n- {LOW_CONFIDENCE_SENTENCE}\n\n## 무실행 확인\n\n{NO_EXEC_SENTENCE}\n"
        ),
        architecture_html: "<!doctype html><html><body>시험</body></html>".into(),
    }
}

fn only(errs: &[String], v: &str) {
    assert_eq!(errs.len(), 1, "{v} 하나만 실패해야 한다: {errs:?}");
    assert!(errs[0].starts_with(v), "{v} 이어야 한다: {errs:?}");
}

#[test]
fn t11_baseline_passes() {
    assert!(
        validate(&baseline()).is_ok(),
        "기준 상태는 통과해야 결함 주입이 의미 있다"
    );
}

#[test]
fn t11_v02_dangling_evidence_id() {
    let mut d = baseline();
    d.findings.findings.push(
        Finding::new(
            "F0001",
            Category::Manifest,
            Priority::Info,
            "s",
            "d",
            "l",
            vec!["E9999".into()],
        )
        .unwrap(),
    );
    only(&validate(&d).unwrap_err(), "V02");
}

#[test]
fn t11_v03_totals_mismatch() {
    let mut d = baseline();
    d.inventory.totals.discovered = 5;
    only(&validate(&d).unwrap_err(), "V03");
}

#[test]
fn t11_v04_bytes_mismatch() {
    let mut d = baseline();
    d.coverage.bytes_read_total = 7;
    only(&validate(&d).unwrap_err(), "V04");
}

#[test]
fn t11_v06_low_confidence_marker_missing() {
    let mut d = baseline();
    d.findings.limitations.clear(); // 발견사항 0건인데 낮은 확신 문장이 없다
    only(&validate(&d).unwrap_err(), "V06");
}

#[test]
fn t11_v07_sensitive_gate_mismatch() {
    let mut d = baseline();
    d.sensitive.candidates.push(SensitiveCandidate {
        path: ".env".into(),
        size: Some(10),
        approved_for_raw: false,
        raw_read: false,
        read_status: SensitiveReadStatus::NotRead,
        summary: "시험".into(),
        signals: vec![],
    });
    only(&validate(&d).unwrap_err(), "V07");
}

#[test]
fn t11_v08_prompt_paths_mismatch() {
    let mut d = baseline();
    add_inventory_file(&mut d, ".env", 10);
    d.sensitive.candidates.push(SensitiveCandidate {
        path: ".env".into(),
        size: Some(10),
        approved_for_raw: false,
        raw_read: false,
        read_status: SensitiveReadStatus::NotRead,
        summary: "시험".into(),
        signals: vec![],
    });
    d.gates.sensitive_candidates.push(GateItem {
        path: ".env".into(),
        rule: "D13".into(),
        reason: "시험".into(),
    });
    only(&validate(&d).unwrap_err(), "V08");
}

#[test]
fn t11_v09_unknown_slice_path() {
    let mut d = baseline();
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![slice_file("missing.rs", false, false, false, true)],
        estimated_tokens: 1,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    only(&validate(&d).unwrap_err(), "V09");
}

#[test]
fn t11_v10_sensitive_slice_not_default_model_input() {
    let mut d = baseline();
    add_inventory_file(&mut d, ".env", 10);
    d.sensitive.candidates.push(SensitiveCandidate {
        path: ".env".into(),
        size: Some(10),
        approved_for_raw: false,
        raw_read: false,
        read_status: SensitiveReadStatus::NotRead,
        summary: "시험".into(),
        signals: vec![],
    });
    d.gates.sensitive_candidates.push(GateItem {
        path: ".env".into(),
        rule: "D13".into(),
        reason: "시험".into(),
    });
    d.gates.sensitive_raw_review.paths.push(".env".into());
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![slice_file(".env", true, false, false, true)],
        estimated_tokens: 3,
        over_token_limit: false,
        requires_sensitive_raw_approval: true,
        requires_execution_approval: false,
    });
    only(&validate(&d).unwrap_err(), "V10");
}

#[test]
fn t11_v19_execution_slice_not_default_model_input() {
    let mut d = baseline();
    add_inventory_file(&mut d, "setup.sh", 20);
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![slice_file("setup.sh", false, true, false, true)],
        estimated_tokens: 5,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: true,
    });
    d.review.counts.slices_total = 1;
    only(&validate(&d).unwrap_err(), "V19");
}

#[test]
fn t11_v20_slice_language_hint_must_match_inventory() {
    let mut d = baseline();
    add_inventory_file_with_ext(&mut d, "src/index.js", 20, Some("js"));
    let mut file = slice_file("src/index.js", false, false, false, true);
    file.language_hint = Some("python".into());
    file.deep_analysis_candidate = true;
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![file],
        estimated_tokens: 5,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    d.review.counts.slices_total = 1;
    only(&validate(&d).unwrap_err(), "V20");
}

#[test]
fn t11_v21_sector_read_order_paths_must_be_inventory_files() {
    let mut d = baseline();
    d.sectors.suggested_read_order.push("missing.rs".into());
    only(&validate(&d).unwrap_err(), "V21");
}

#[test]
fn t11_v22_slices_must_preserve_sector_read_order() {
    let mut d = baseline();
    add_inventory_file_with_ext(&mut d, "a.rs", 10, Some("rs"));
    add_inventory_file_with_ext(&mut d, "b.rs", 10, Some("rs"));
    d.sectors.suggested_read_order = vec!["a.rs".into(), "b.rs".into()];
    d.slices.policy.source_order = "sectors.suggested_read_order".into();
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![
            slice_file_with_language("b.rs", "rust"),
            slice_file_with_language("a.rs", "rust"),
        ],
        estimated_tokens: 6,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    d.review.counts.deep_analysis_candidates = 2;
    d.review.counts.slices_total = 1;
    only(&validate(&d).unwrap_err(), "V22");
}

#[test]
fn t11_v23_slice_files_must_not_repeat_paths() {
    let mut d = baseline();
    add_inventory_file_with_ext(&mut d, "src/index.js", 20, Some("js"));
    d.sectors.suggested_read_order = vec!["src/index.js".into()];
    d.slices.policy.source_order = "sectors.suggested_read_order".into();
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![slice_file_with_language("src/index.js", "javascript")],
        estimated_tokens: 5,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    d.slices.slices.push(Slice {
        id: "S0002".into(),
        files: vec![slice_file_with_language("src/index.js", "javascript")],
        estimated_tokens: 5,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    d.review.counts.deep_analysis_candidates = 2;
    d.review.counts.slices_total = 2;
    only(&validate(&d).unwrap_err(), "V23");
}

#[test]
fn t11_v11_slice_gate_flags_match_files() {
    let mut d = baseline();
    add_inventory_file(&mut d, "setup.sh", 20);
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![slice_file("setup.sh", false, true, false, false)],
        estimated_tokens: 5,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    only(&validate(&d).unwrap_err(), "V11");
}

#[test]
fn t11_v12_dependency_manifest_path_must_be_inventory_file() {
    let mut d = baseline();
    d.dependencies.manifests.push(DependencyManifest {
        path: "missing/package.json".into(),
        ecosystem: "npm".into(),
        dependencies: vec![],
    });
    only(&validate(&d).unwrap_err(), "V12");
}

#[test]
fn t11_v13_artifact_run_id_must_match_run_data() {
    let mut d = baseline();
    d.source.run_id = "other-run".into();
    only(&validate(&d).unwrap_err(), "V13");
}

#[test]
fn t11_v13_schema_version_must_match_contract() {
    let mut d = baseline();
    d.review.schema_version = "999".into();
    only(&validate(&d).unwrap_err(), "V13");
}

#[test]
fn t11_v14_review_counts_must_match_sources() {
    let mut d = baseline();
    d.review.counts.findings_total = 99;
    only(&validate(&d).unwrap_err(), "V14");
}

#[test]
fn t11_v14_review_default_excluded_paths_must_match_slices() {
    let mut d = baseline();
    add_inventory_file(&mut d, "manual-review.txt", 10);
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![slice_file("manual-review.txt", false, false, false, false)],
        estimated_tokens: 3,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    d.review.counts.slices_total = 1;
    only(&validate(&d).unwrap_err(), "V14");
}

#[test]
fn t11_v14_review_deep_analysis_count_must_match_slices() {
    let mut d = baseline();
    add_inventory_file_with_ext(&mut d, "src/index.js", 20, Some("js"));
    let mut file = slice_file("src/index.js", false, false, false, true);
    file.language_hint = Some("javascript".into());
    file.deep_analysis_candidate = true;
    d.slices.slices.push(Slice {
        id: "S0001".into(),
        files: vec![file],
        estimated_tokens: 5,
        over_token_limit: false,
        requires_sensitive_raw_approval: false,
        requires_execution_approval: false,
    });
    d.review.counts.slices_total = 1;
    d.review.counts.deep_analysis_candidates = 0;
    only(&validate(&d).unwrap_err(), "V14");
}

#[test]
fn t11_v15_review_required_actions_must_match_gates() {
    let mut d = baseline();
    add_inventory_file(&mut d, ".env", 10);
    d.sensitive.candidates.push(SensitiveCandidate {
        path: ".env".into(),
        size: Some(10),
        approved_for_raw: false,
        raw_read: false,
        read_status: SensitiveReadStatus::NotRead,
        summary: "시험".into(),
        signals: vec![],
    });
    d.gates.sensitive_candidates.push(GateItem {
        path: ".env".into(),
        rule: "D13".into(),
        reason: "시험".into(),
    });
    d.gates.sensitive_raw_review.approval_required = true;
    d.gates.sensitive_raw_review.paths.push(".env".into());
    d.review.verdict = "approval-required".into();
    d.review.reason_codes = vec!["sensitive-candidates-present".into()];
    d.review.counts.sensitive_candidates = 1;
    d.review.required_actions[0].required = false;
    d.review.required_actions[0].paths.clear();
    only(&validate(&d).unwrap_err(), "V15");
}

#[test]
fn t11_v15_review_required_actions_must_include_expected_ids() {
    let mut d = baseline();
    d.review.required_actions.pop();
    only(&validate(&d).unwrap_err(), "V15");
}

#[test]
fn t11_v15_review_acknowledgements_must_match_gates() {
    let mut d = baseline();
    d.gates.sensitive_raw_review.acknowledgements = vec!["ack-a".into(), "ack-b".into()];
    only(&validate(&d).unwrap_err(), "V15");
}

#[test]
fn t11_v24_security_summary_must_match_review_and_findings() {
    let mut d = baseline();
    d.security.verdict = "review-required".into();
    only(&validate(&d).unwrap_err(), "V24");
}

#[test]
fn t11_v16_gate_candidate_path_must_be_inventory_entry() {
    let mut d = baseline();
    d.gates.automatic_execution_candidates.push(GateItem {
        path: "missing-hook.sh".into(),
        rule: "D09".into(),
        reason: "시험".into(),
    });
    d.gates
        .execution_model_input_review
        .paths
        .push("missing-hook.sh".into());
    d.review.counts.automatic_execution_candidates = 1;
    d.review.required_actions[1]
        .paths
        .push("missing-hook.sh".into());
    only(&validate(&d).unwrap_err(), "V16");
}

#[test]
fn t11_v17_evidence_path_must_be_inventory_entry() {
    let mut d = baseline();
    d.evidence.evidence.push(Evidence {
        id: "E0001".into(),
        path: "ghost-script.sh".into(),
        kind: EvidenceKind::FilePresence,
        json_pointer: None,
        lines: None,
        summary: "시험".into(),
        value_stored: false,
        redacted_excerpt: None,
        signal_labels: vec![],
        raw_excerpt_stored: false,
        redaction_applied: false,
        redaction_labels: vec![],
    });
    only(&validate(&d).unwrap_err(), "V17");
}

#[test]
fn t11_v18_content_line_evidence_requires_lines() {
    let mut d = baseline();
    add_inventory_file(&mut d, "package.json", 100);
    d.evidence.evidence.push(Evidence {
        id: "E0001".into(),
        path: "package.json".into(),
        kind: EvidenceKind::ContentLine,
        json_pointer: Some("/scripts/postinstall".into()),
        lines: None,
        summary: "시험".into(),
        value_stored: false,
        redacted_excerpt: Some("postinstall: <redacted-command>".into()),
        signal_labels: vec!["lifecycle-script".into()],
        raw_excerpt_stored: false,
        redaction_applied: false,
        redaction_labels: vec![],
    });
    only(&validate(&d).unwrap_err(), "V18");
}

#[test]
fn t11_v18_secret_name_evidence_must_not_store_excerpt() {
    let mut d = baseline();
    add_inventory_file(&mut d, ".env", 10);
    d.evidence.evidence.push(Evidence {
        id: "E0001".into(),
        path: ".env".into(),
        kind: EvidenceKind::SecretName,
        json_pointer: None,
        lines: None,
        summary: "시험".into(),
        value_stored: false,
        redacted_excerpt: Some("원문 저장 금지".into()),
        signal_labels: vec![],
        raw_excerpt_stored: true,
        redaction_applied: false,
        redaction_labels: vec![],
    });
    only(&validate(&d).unwrap_err(), "V18");
}

const ARTIFACTS: [&str; 31] = [
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
    "supported_surfaces.json",
    "gate_decisions.json",
    "connection_graph.json",
    "reachability_scenarios.json",
    "architecture_map.json",
    "relation_map.json",
    "source_landmarks.json",
    "visualization_index.json",
    "analysis_plan.json",
    "cross_unit_analysis.json",
    "synthesis.json",
    "followup_plan.json",
    "report.md",
    "report.html",
    "architecture.html",
];

fn write_all_artifacts(dir: &std::path::Path) {
    for name in ARTIFACTS {
        let content = if name == "report.md"
            || name == "report.html"
            || name == "brief.md"
            || name == "architecture.html"
        {
            format!("## 무실행 확인\n\n{NO_EXEC_SENTENCE}\n")
        } else {
            "{}".to_string()
        };
        fs::write(dir.join(name), content).unwrap();
    }
}

fn add_inventory_file(data: &mut RunData, path: &str, size: u64) {
    add_inventory_file_with_ext(data, path, size, None);
}

fn add_inventory_file_with_ext(data: &mut RunData, path: &str, size: u64, ext: Option<&str>) {
    data.inventory.entries.push(Entry {
        path: path.into(),
        kind: EntryKind::File,
        size: Some(size),
        ext: ext.map(str::to_string),
        symlink_target: None,
    });
    data.inventory.totals.discovered += 1;
    data.inventory.totals.listed += 1;
}

fn slice_file(
    path: &str,
    sensitive_candidate: bool,
    automatic_execution_candidate: bool,
    execution_related_candidate: bool,
    default_model_input: bool,
) -> SliceFile {
    SliceFile {
        path: path.into(),
        bytes: 1,
        estimated_tokens: 1,
        sector: "(root)".into(),
        language_hint: None,
        deep_analysis_candidate: false,
        default_model_input,
        sensitive_candidate,
        automatic_execution_candidate,
        execution_related_candidate,
    }
}

fn slice_file_with_language(path: &str, language: &str) -> SliceFile {
    let mut file = slice_file(path, false, false, false, true);
    file.language_hint = Some(language.into());
    file.deep_analysis_candidate = true;
    file
}

fn baseline_required_actions() -> Vec<ReviewAction> {
    vec![
        ReviewAction {
            id: "sensitive-raw-review".into(),
            required: false,
            reason: "시험".into(),
            paths: vec![],
            acknowledgements: vec![],
        },
        ReviewAction {
            id: "execution-model-input-review".into(),
            required: false,
            reason: "시험".into(),
            paths: vec![],
            acknowledgements: vec![],
        },
        ReviewAction {
            id: "execution-command-review".into(),
            required: false,
            reason: "시험".into(),
            paths: vec![],
            acknowledgements: vec![],
        },
        ReviewAction {
            id: "oversized-slice-review".into(),
            required: false,
            reason: "시험".into(),
            paths: vec![],
            acknowledgements: vec![],
        },
    ]
}

#[test]
fn t11_v01_missing_artifact_file() {
    let dir = common::temp_dir("t11-v01");
    write_all_artifacts(&dir);
    fs::remove_file(dir.join("sectors.json")).unwrap();
    let errs = verify_outputs(&dir).unwrap_err();
    only(&errs, "V01");
    assert!(errs[0].contains("sectors.json"), "{errs:?}");
}

#[test]
fn t11_v05_no_exec_sentence_missing() {
    let dir = common::temp_dir("t11-v05");
    write_all_artifacts(&dir);
    fs::write(dir.join("report.md"), "## 무실행 확인\n\n(문장 없음)\n").unwrap();
    only(&verify_outputs(&dir).unwrap_err(), "V05");
}

#[test]
fn t11_v25_artifact_leak_scan_rejects_fake_marker() {
    let dir = common::temp_dir("t11-v25");
    write_all_artifacts(&dir);
    fs::write(
        dir.join("evidence.json"),
        "{\"leak\":\"https://example.invalid/install.sh?token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE_123456#frag\"}",
    )
    .unwrap();
    only(&verify_outputs(&dir).unwrap_err(), "V25");
}

#[test]
fn t11_disk_baseline_passes() {
    let dir = common::temp_dir("t11-ok");
    write_all_artifacts(&dir);
    assert!(verify_outputs(&dir).is_ok());
}
