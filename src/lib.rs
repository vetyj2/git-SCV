//! git-scv — 무실행 저장소 검토 하네스.
//!
//! main.rs 는 이 라이브러리를 호출하는 얇은 진입점이다.

pub mod analysis_runtime;
pub mod artifacts;
pub mod brief;
pub mod case;
pub mod cli;
pub mod dependencies;
pub mod detect;
pub mod errors;
pub mod evidence;
pub mod findings;
pub mod gates;
pub mod github_remote;
pub mod graph;
pub mod inspect;
pub mod language;
pub mod model;
pub mod orchestrator;
pub mod receipt;
pub mod redaction;
pub mod report;
pub mod review;
pub mod safety;
pub mod sectors;
pub mod sensitive;
pub mod slices;
pub mod snapshot;
pub mod source;
pub mod synthesis;
pub mod terminal_ui;
pub mod unit_analysis;
pub mod validate;
pub mod visualization;
pub mod walk;
pub mod web_report;
pub mod worker_process;
