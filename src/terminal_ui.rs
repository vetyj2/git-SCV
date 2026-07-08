//! Compact terminal dashboard rendering.
//!
//! This module keeps terminal output separate from the analysis runtime. The
//! runtime builds a small snapshot of the current state; this renderer decides
//! how much to show for TTY, log, JSONL, and quiet modes.

use crate::cli::ProgressMode;
use crate::errors::ScvError;
use serde_json::json;
use std::io::{self, IsTerminal, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DashboardStatus {
    Running,
    Waiting,
    Blocked,
    Failed,
    Complete,
}

impl DashboardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DashboardStatus::Running => "running",
            DashboardStatus::Waiting => "waiting",
            DashboardStatus::Blocked => "blocked",
            DashboardStatus::Failed => "failed",
            DashboardStatus::Complete => "complete",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DashboardSnapshot {
    pub title: String,
    pub run_dir: String,
    pub status: DashboardStatus,
    pub stage: String,
    pub stage_summary: String,
    pub source_status: String,
    pub gate_status: String,
    pub final_report_status: String,
    pub percent: u8,
    pub completed: usize,
    pub total: usize,
    pub queued: usize,
    pub claimed: usize,
    pub failed: usize,
    pub blocked: usize,
    pub current_job: String,
    pub current_path: String,
    pub next_safe_command: String,
    pub report_path: Option<String>,
    pub map_path: Option<String>,
    pub target_repo_commands_executed: bool,
    pub safe_claim_made: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChoiceOption<'a> {
    pub label: &'a str,
    pub description: &'a str,
}

pub fn select_choice_interactive(
    title: &str,
    options: &[ChoiceOption<'_>],
    default_index: usize,
) -> Result<Option<usize>, ScvError> {
    if options.is_empty() {
        return Err(ScvError::Inspect(
            "interactive choice: options must not be empty".into(),
        ));
    }
    if default_index >= options.len() {
        return Err(ScvError::Inspect(format!(
            "interactive choice: default index {default_index} is out of bounds"
        )));
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        select_choice_raw(title, options, default_index)
    }
    #[cfg(not(unix))]
    {
        let _ = (title, options, default_index);
        Ok(None)
    }
}

impl DashboardSnapshot {
    pub fn progress_text(&self) -> String {
        format!("{}/{}", self.completed, self.total)
    }

    pub fn compact_path(&self) -> String {
        truncate_middle(&self.current_path, 54)
    }
}

#[cfg(unix)]
fn select_choice_raw(
    title: &str,
    options: &[ChoiceOption<'_>],
    default_index: usize,
) -> Result<Option<usize>, ScvError> {
    let Some(_raw_mode) = RawTerminalMode::enter() else {
        return Ok(None);
    };
    let mut selected = default_index;
    println!("{title}");
    println!(
        "Use Up/Down or j/k, Enter to confirm, 1-{} to choose.",
        options.len()
    );
    draw_choice_lines(options, selected)?;

    let mut stdin = io::stdin().lock();
    let mut byte = [0_u8; 1];
    loop {
        let read = stdin
            .read(&mut byte)
            .map_err(|err| ScvError::Inspect(format!("interactive choice read failed: {err}")))?;
        if read == 0 {
            continue;
        }
        match byte[0] {
            b'\n' | b'\r' => {
                drop(_raw_mode);
                println!();
                println!("selected_flow={}", options[selected].label);
                return Ok(Some(selected));
            }
            b'1'..=b'9' => {
                let candidate = usize::from(byte[0] - b'1');
                if candidate < options.len() {
                    selected = candidate;
                    redraw_choice_lines(options, selected)?;
                    drop(_raw_mode);
                    println!();
                    println!("selected_flow={}", options[selected].label);
                    return Ok(Some(selected));
                }
            }
            b'j' | b'J' => {
                selected = move_choice_down(selected, options.len());
                redraw_choice_lines(options, selected)?;
            }
            b'k' | b'K' => {
                selected = move_choice_up(selected, options.len());
                redraw_choice_lines(options, selected)?;
            }
            0x1b => {
                if let Some(direction) = read_escape_direction(&mut stdin)? {
                    selected = match direction {
                        EscapeDirection::Up => move_choice_up(selected, options.len()),
                        EscapeDirection::Down => move_choice_down(selected, options.len()),
                    };
                    redraw_choice_lines(options, selected)?;
                }
            }
            _ => {}
        }
    }
}

#[cfg(unix)]
fn draw_choice_lines(options: &[ChoiceOption<'_>], selected: usize) -> Result<(), ScvError> {
    for (index, option) in options.iter().enumerate() {
        let marker = if index == selected { ">" } else { " " };
        println!(
            "\x1b[2K\r{marker} {}. {} - {}",
            index + 1,
            option.label,
            option.description
        );
    }
    io::stdout()
        .flush()
        .map_err(|err| ScvError::Inspect(format!("interactive choice flush failed: {err}")))
}

#[cfg(unix)]
fn redraw_choice_lines(options: &[ChoiceOption<'_>], selected: usize) -> Result<(), ScvError> {
    print!("\x1b[{}A", options.len());
    draw_choice_lines(options, selected)
}

fn move_choice_up(selected: usize, len: usize) -> usize {
    if selected == 0 {
        len.saturating_sub(1)
    } else {
        selected - 1
    }
}

fn move_choice_down(selected: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        (selected + 1) % len
    }
}

#[cfg(unix)]
enum EscapeDirection {
    Up,
    Down,
}

#[cfg(unix)]
fn read_escape_direction(reader: &mut impl Read) -> Result<Option<EscapeDirection>, ScvError> {
    let mut seq = [0_u8; 2];
    let first = reader.read(&mut seq[0..1]).map_err(|err| {
        ScvError::Inspect(format!("interactive choice escape read failed: {err}"))
    })?;
    if first == 0 || seq[0] != b'[' {
        return Ok(None);
    }
    let second = reader.read(&mut seq[1..2]).map_err(|err| {
        ScvError::Inspect(format!("interactive choice escape read failed: {err}"))
    })?;
    if second == 0 {
        return Ok(None);
    }
    match seq[1] {
        b'A' => Ok(Some(EscapeDirection::Up)),
        b'B' => Ok(Some(EscapeDirection::Down)),
        _ => Ok(None),
    }
}

#[cfg(unix)]
struct RawTerminalMode {
    fd: libc::c_int,
    original: libc::termios,
}

#[cfg(unix)]
impl RawTerminalMode {
    fn enter() -> Option<Self> {
        let fd = libc::STDIN_FILENO;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr only reads terminal attributes for STDIN_FILENO.
        // The call does not access target repository data or execute commands.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: tcgetattr succeeded, so the termios value is initialized.
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_iflag &= !(libc::ICRNL | libc::IXON);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 1;
        // SAFETY: tcsetattr updates only the current terminal mode. Drop
        // restores the original state before returning to normal output.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for RawTerminalMode {
    fn drop(&mut self) {
        // SAFETY: restoring the saved termios for the same stdin fd is the
        // matching cleanup for RawTerminalMode::enter.
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

pub fn render_scan_progress(
    snapshot: &DashboardSnapshot,
    mode: ProgressMode,
    label: &str,
) -> Result<(), ScvError> {
    match mode {
        ProgressMode::Quiet => Ok(()),
        ProgressMode::Jsonl => render_jsonl(snapshot, label),
        ProgressMode::Plain => {
            println!("{}", plain_progress_line(snapshot, label));
            Ok(())
        }
        ProgressMode::Auto => {
            if io::stdout().is_terminal() {
                if label == "worker-loop" || snapshot.status == DashboardStatus::Complete {
                    render_tty_line(snapshot, label, label != "worker-loop")
                } else {
                    render_compact_block(snapshot);
                    Ok(())
                }
            } else {
                println!("{}", plain_progress_line(snapshot, label));
                Ok(())
            }
        }
    }
}

pub fn render_watch(snapshot: &DashboardSnapshot) -> Result<(), ScvError> {
    if io::stdout().is_terminal() {
        render_compact_block(snapshot);
    } else {
        render_watch_plain(snapshot);
    }
    Ok(())
}

fn render_jsonl(snapshot: &DashboardSnapshot, label: &str) -> Result<(), ScvError> {
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event": "git_scv_scan_progress",
            "label": label,
            "status": snapshot.status.as_str(),
            "stage": snapshot.stage,
            "stage_summary": snapshot.stage_summary,
            "source_status": snapshot.source_status,
            "gate_status": snapshot.gate_status,
            "final_report_status": snapshot.final_report_status,
            "percent": snapshot.percent,
            "completed": snapshot.completed,
            "queued": snapshot.queued,
            "claimed": snapshot.claimed,
            "failed": snapshot.failed,
            "blocked": snapshot.blocked,
            "total": snapshot.total,
            "current_job": snapshot.current_job,
            "current_path": snapshot.current_path,
            "next_safe_command": snapshot.next_safe_command,
            "report_path": snapshot.report_path,
            "map_path": snapshot.map_path,
            "target_repo_commands_executed": snapshot.target_repo_commands_executed,
            "safe_claim_made": snapshot.safe_claim_made,
        }))
        .map_err(|err| ScvError::Inspect(format!("progress JSON failed: {err}")))?
    );
    Ok(())
}

fn render_tty_line(
    snapshot: &DashboardSnapshot,
    label: &str,
    finish_line: bool,
) -> Result<(), ScvError> {
    if snapshot.status == DashboardStatus::Complete && label != "worker-loop" {
        print!("\r\x1b[2K");
        render_completion_banner(snapshot, label);
        return Ok(());
    }
    print!(
        "\rGit-SCV [{:>3}%] {} {} job={} path={} next={} ",
        snapshot.percent,
        snapshot.status.as_str(),
        snapshot.stage_summary,
        snapshot.current_job,
        snapshot.compact_path(),
        truncate_middle(&snapshot.next_safe_command, 42)
    );
    io::stdout()
        .flush()
        .map_err(|err| ScvError::Inspect(format!("progress stdout flush failed: {err}")))?;
    if finish_line {
        println!();
    }
    Ok(())
}

fn render_compact_block(snapshot: &DashboardSnapshot) {
    println!("{}", compact_frame(snapshot));
}

fn render_watch_plain(snapshot: &DashboardSnapshot) {
    println!("git_scv_review_status=active");
    println!("run_dir={}", snapshot.run_dir);
    println!("dashboard_status={}", snapshot.status.as_str());
    println!("stage={}", snapshot.stage);
    println!("stage_summary={}", snapshot.stage_summary);
    println!("analysis_stage={}", snapshot.stage);
    println!("source_status={}", snapshot.source_status);
    println!("gate_status={}", snapshot.gate_status);
    println!("progress={}", snapshot.progress_text());
    println!("progress_percent={}", snapshot.percent);
    println!("jobs_total={}", snapshot.total + snapshot.blocked);
    println!("jobs_completed={}", snapshot.completed);
    println!("jobs_queued={}", snapshot.queued);
    println!("jobs_claimed={}", snapshot.claimed);
    println!("jobs_failed={}", snapshot.failed);
    println!("jobs_blocked={}", snapshot.blocked);
    println!("current_job={}", snapshot.current_job);
    println!("current_path={}", snapshot.current_path);
    println!("final_report_status={}", snapshot.final_report_status);
    if let Some(report) = &snapshot.report_path {
        println!("final_report={report}");
    }
    if let Some(map) = &snapshot.map_path {
        println!("architecture_map={map}");
    }
    println!("next_safe_command={}", snapshot.next_safe_command);
    println!(
        "target_repo_commands_executed={}",
        snapshot.target_repo_commands_executed
    );
    println!("safe_claim_made={}", snapshot.safe_claim_made);
}

fn render_completion_banner(snapshot: &DashboardSnapshot, label: &str) {
    let mut complete = snapshot.clone();
    complete.status = DashboardStatus::Complete;
    complete.stage_summary = format!("done {label}");
    println!("{}", compact_frame(&complete));
}

fn compact_frame(snapshot: &DashboardSnapshot) -> String {
    let report = snapshot
        .report_path
        .as_ref()
        .map(|path| artifact_name(path))
        .unwrap_or_else(|| short_status(&snapshot.final_report_status));
    let map = snapshot
        .map_path
        .as_ref()
        .map(|path| artifact_name(path))
        .unwrap_or_else(|| "map-pending".into());
    let action = if snapshot.status == DashboardStatus::Complete {
        format!("report={report} map={map} clean=git-scv clean <run-dir>")
    } else {
        format!("next={}", truncate_middle(&snapshot.next_safe_command, 52))
    };
    [
        format!(
            "{} {:>3}% {} {}/{} job={} path={}",
            scv_sprite(snapshot.status),
            snapshot.percent,
            short_stage(&snapshot.stage, &snapshot.stage_summary),
            snapshot.completed,
            snapshot.total,
            truncate_middle(&snapshot.current_job, 12),
            truncate_middle(&snapshot.current_path, 24)
        ),
        format!(
            "q={} c={} f={} b={} src={} gate={} report={}",
            snapshot.queued,
            snapshot.claimed,
            snapshot.failed,
            snapshot.blocked,
            short_status(&snapshot.source_status),
            short_status(&snapshot.gate_status),
            report
        ),
        action,
    ]
    .join("\n")
}

fn scv_sprite(status: DashboardStatus) -> String {
    let face = match status {
        DashboardStatus::Running => running_spinner(),
        DashboardStatus::Waiting => ".",
        DashboardStatus::Blocked => "!",
        DashboardStatus::Failed => "x",
        DashboardStatus::Complete => "*",
    };
    format!("SCV[{face}]")
}

fn running_spinner() -> &'static str {
    const FRAMES: [&str; 4] = ["/", "-", "\\", "|"];
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as usize)
        .unwrap_or(0);
    FRAMES[tick % FRAMES.len()]
}

fn short_stage(stage: &str, summary: &str) -> String {
    let label = match stage {
        "web-metadata-preflight" => "web-meta",
        "web-selected-preflight" => "web-lite",
        "static-preflight-only" => "preflight",
        "pending-unit-analysis" => "unit",
        "llm-analysis-in-progress" => "unit",
        "worker-budget-waiting-user" => "budget",
        "analysis-partial" => "followup",
        "analysis-map-complete" => "map",
        "final-report-complete" => "done",
        "blocked-stale-source" => "block",
        "blocked-failed-unit-analysis" => "fail",
        _ if stage.contains("snapshot") => "snapshot",
        _ if stage.contains("followup") => "followup",
        _ if stage.contains("synth") => "synth",
        _ if stage.contains("report") => "report",
        _ => summary,
    };
    truncate_middle(label, 16)
}

fn plain_progress_line(snapshot: &DashboardSnapshot, label: &str) -> String {
    format!(
        "git_scv_scan_progress label={label} status={} stage={} stage_summary={} percent={} progress={} queued={} claimed={} failed={} blocked={} current_job={} current_path={} final_report_status={} next_safe_command={} target_repo_commands_executed={} safe_claim_made={}",
        snapshot.status.as_str(),
        snapshot.stage,
        snapshot.stage_summary,
        snapshot.percent,
        snapshot.progress_text(),
        snapshot.queued,
        snapshot.claimed,
        snapshot.failed,
        snapshot.blocked,
        snapshot.current_job,
        snapshot.current_path,
        snapshot.final_report_status,
        snapshot.next_safe_command,
        snapshot.target_repo_commands_executed,
        snapshot.safe_claim_made,
    )
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let left_len = (max_chars - 3) / 2;
    let right_len = max_chars - 3 - left_len;
    let left: String = chars.iter().take(left_len).collect();
    let right: String = chars
        .iter()
        .skip(chars.len().saturating_sub(right_len))
        .collect();
    format!("{left}...{right}")
}

fn short_status(value: &str) -> String {
    match value {
        "not-verified-for-analysis-runtime" => "not-verified".into(),
        "blocked-until-analysis-map-and-meta-synthesis" => "waiting-synthesis".into(),
        "no-sub-slice-gate-blockers" => "ok".into(),
        "ready-to-generate" => "ready".into(),
        "final-report-complete" => "complete".into(),
        other => truncate_middle(other, 32),
    }
}

fn artifact_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            title: "Git-SCV no-exec review".into(),
            run_dir: "/tmp/run".into(),
            status: DashboardStatus::Running,
            stage: "llm-analysis-in-progress".into(),
            stage_summary: "unit analysis".into(),
            source_status: "verified".into(),
            gate_status: "no-sub-slice-gate-blockers".into(),
            final_report_status: "blocked-until-analysis-map-and-meta-synthesis".into(),
            percent: 42,
            completed: 21,
            total: 50,
            queued: 28,
            claimed: 1,
            failed: 0,
            blocked: 0,
            current_job: "J00021".into(),
            current_path: "src/really/long/module/path/example.rs".into(),
            next_safe_command: "git-scv continue <run-dir>".into(),
            report_path: None,
            map_path: None,
            target_repo_commands_executed: false,
            safe_claim_made: false,
        }
    }

    #[test]
    fn truncate_middle_keeps_short_values() {
        assert_eq!(truncate_middle("src/lib.rs", 20), "src/lib.rs");
    }

    #[test]
    fn truncate_middle_shortens_long_values() {
        assert_eq!(
            truncate_middle("abcdefghijklmnopqrstuvwxyz", 10),
            "abc...wxyz"
        );
    }

    #[test]
    fn plain_progress_line_keeps_machine_readable_contract() {
        let line = plain_progress_line(&sample_snapshot(), "worker-loop");
        assert!(line.contains("git_scv_scan_progress"));
        assert!(line.contains("status=running"));
        assert!(line.contains("stage=llm-analysis-in-progress"));
        assert!(line.contains("percent=42"));
        assert!(line.contains("progress=21/50"));
        assert!(line.contains("current_job=J00021"));
        assert!(line.contains("target_repo_commands_executed=false"));
        assert!(line.contains("safe_claim_made=false"));
    }

    #[test]
    fn terminal_frame_is_three_lines_for_core_states() {
        for status in [
            DashboardStatus::Running,
            DashboardStatus::Waiting,
            DashboardStatus::Blocked,
            DashboardStatus::Failed,
            DashboardStatus::Complete,
        ] {
            let mut snapshot = sample_snapshot();
            snapshot.status = status;
            if status == DashboardStatus::Complete {
                snapshot.report_path = Some("/tmp/run/final_user_report.md".into());
                snapshot.map_path = Some("/tmp/run/architecture.html".into());
            }
            let frame = compact_frame(&snapshot);
            assert_eq!(frame.lines().count(), 3, "{frame}");
            assert!(frame.contains("SCV["), "{frame}");
            assert!(!frame.contains("token="), "{frame}");
        }
    }

    #[test]
    fn terminal_complete_frame_shows_report_map_and_cleanup_pointer() {
        let mut snapshot = sample_snapshot();
        snapshot.status = DashboardStatus::Complete;
        snapshot.report_path = Some("/tmp/run/final_user_report.md".into());
        snapshot.map_path = Some("/tmp/run/architecture.html".into());
        let frame = compact_frame(&snapshot);
        assert!(frame.contains("report=final_user_report.md"), "{frame}");
        assert!(frame.contains("map=architecture.html"), "{frame}");
        assert!(frame.contains("clean=git-scv clean <run-dir>"), "{frame}");
    }

    #[test]
    fn terminal_waiting_budget_frame_is_static() {
        let mut snapshot = sample_snapshot();
        snapshot.status = DashboardStatus::Waiting;
        snapshot.stage = "worker-budget-waiting-user".into();
        let first = compact_frame(&snapshot);
        let second = compact_frame(&snapshot);
        assert_eq!(first, second);
        assert!(first.contains("SCV[.]"), "{first}");
        assert!(first.contains("budget"), "{first}");
    }

    #[test]
    fn short_status_uses_dashboard_words() {
        assert_eq!(
            short_status("blocked-until-analysis-map-and-meta-synthesis"),
            "waiting-synthesis"
        );
        assert_eq!(short_status("no-sub-slice-gate-blockers"), "ok");
    }

    #[test]
    fn artifact_name_keeps_terminal_output_short() {
        assert_eq!(
            artifact_name("/tmp/git-scv-run/architecture.html"),
            "architecture.html"
        );
    }

    #[test]
    fn choice_movement_wraps() {
        assert_eq!(move_choice_up(0, 3), 2);
        assert_eq!(move_choice_up(2, 3), 1);
        assert_eq!(move_choice_down(2, 3), 0);
        assert_eq!(move_choice_down(0, 3), 1);
    }
}
