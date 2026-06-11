//! git-scv — 무실행 저장소 검토 하네스.
//!
//! main.rs 는 이 라이브러리를 호출하는 얇은 진입점이다.

pub mod artifacts;
pub mod cli;
pub mod detect;
pub mod errors;
pub mod evidence;
pub mod findings;
pub mod gates;
pub mod inspect;
pub mod model;
pub mod report;
pub mod review;
pub mod safety;
pub mod sectors;
pub mod sensitive;
pub mod slices;
pub mod source;
pub mod validate;
pub mod walk;
pub mod web_report;
