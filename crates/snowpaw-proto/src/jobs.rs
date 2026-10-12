//! Jobs: tasks an agent does on a schedule ("every morning, summarize…").
//!
//! Jobs live on the server, which decides when each one runs and hands it to the
//! agent's runtime; a runtime restart or a server restart loses nothing. The user
//! creates jobs. An agent can only *propose* one: it does nothing until the user
//! approves it, so a model can't give itself standing autonomy.

use serde::{Deserialize, Serialize};

use crate::Id;

pub const MAX_JOB_TITLE_CHARS: usize = 120;
pub const MAX_JOB_PROMPT_CHARS: usize = 4000;
/// Shortest repeat interval (5 minutes) and longest (a year).
pub const MIN_EVERY_SECS: u32 = 300;
pub const MAX_EVERY_SECS: u32 = 366 * 86_400;
/// A first run at most this far ahead (a year).
pub const MAX_START_AHEAD_MS: i64 = 366 * 86_400_000;
/// Jobs one agent may have that aren't finished, and of those, proposals.
pub const MAX_OPEN_JOBS_PER_AGENT: usize = 32;
pub const MAX_PROPOSALS_PER_AGENT: usize = 5;
/// Tries per run before a job is marked failed.
pub const MAX_ATTEMPTS: u32 = 3;
pub const MAX_PROGRESS_CHARS: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Suggested by the agent; waits for the user.
    Proposed,
    /// Scheduled.
    Active,
    /// A one-off job that ran.
    Done,
    /// Gave up after `MAX_ATTEMPTS` failed tries.
    Failed,
    Cancelled,
}

impl JobState {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Proposed | Self::Active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSchedule {
    pub first_run_at_ms: i64,
    /// Repeat this often after the first run (none: run once).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every_secs: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Ok,
    Failed,
    /// The runtime disconnected or ran past its deadline.
    Lost,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRunView {
    pub started_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<RunOutcome>,
    pub detail: String,
}

/// A job as the user sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobView {
    pub id: Id,
    pub agent: Id,
    /// Where it posts (the agent's chat with the user).
    pub chat_id: Id,
    pub title: String,
    pub prompt: String,
    pub state: JobState,
    pub schedule: JobSchedule,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<i64>,
    pub attempts: u32,
    /// A run is in progress.
    pub running: bool,
    /// What the agent last said it's doing.
    pub progress: String,
    pub proposed_by_agent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<JobRunView>,
}

/// One run of a job, as handed to the agent's runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub run_id: Id,
    pub job: Id,
    pub chat_id: Id,
    pub title: String,
    pub prompt: String,
    /// 1 for the first try of this run, 2 for the retry…
    pub attempt: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobError {
    BadTitle,
    BadPrompt,
    BadSchedule,
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadTitle => "the title is empty, too long, or has a forbidden character",
            Self::BadPrompt => "the instructions are empty, too long, or have a forbidden character",
            Self::BadSchedule => "the schedule is out of range (repeat every 5 minutes to a year, start within a year)",
        })
    }
}

impl std::error::Error for JobError {}

fn text_ok(s: &str, max: usize, newlines: bool) -> bool {
    !s.trim().is_empty()
        && s.chars().count() <= max
        && s.chars().all(|c| {
            !(c.is_control() && !(newlines && (c == '\n' || c == '\t')))
                && !('\u{202A}'..='\u{202E}').contains(&c)
                && !('\u{2066}'..='\u{2069}').contains(&c)
        })
}

/// Rules for a job, checked by client and server. `now_ms` is the server's clock.
pub fn check_job(
    title: &str,
    prompt: &str,
    schedule: &JobSchedule,
    now_ms: i64,
) -> Result<(), JobError> {
    if !text_ok(title, MAX_JOB_TITLE_CHARS, false) {
        return Err(JobError::BadTitle);
    }
    if !text_ok(prompt, MAX_JOB_PROMPT_CHARS, true) {
        return Err(JobError::BadPrompt);
    }
    let every_ok =
        schedule.every_secs.is_none_or(|e| (MIN_EVERY_SECS..=MAX_EVERY_SECS).contains(&e));
    // A start slightly in the past (clock skew, a slow dialog) just means "now".
    let start_ok = schedule.first_run_at_ms >= now_ms - 86_400_000
        && schedule.first_run_at_ms <= now_ms.saturating_add(MAX_START_AHEAD_MS);
    if !every_ok || !start_ok {
        return Err(JobError::BadSchedule);
    }
    Ok(())
}

/// When a repeating job runs next after finishing at `now_ms`: the next slot on its
/// schedule that's in the future (missed slots are skipped, not caught up on).
pub fn next_slot(schedule: &JobSchedule, now_ms: i64) -> Option<i64> {
    let every = i64::from(schedule.every_secs?) * 1000;
    if every <= 0 {
        return None;
    }
    let first = schedule.first_run_at_ms;
    if now_ms < first {
        return Some(first);
    }
    let passed = (now_ms - first) / every + 1;
    first.checked_add(passed.checked_mul(every)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn job_rules() {
        let once = JobSchedule { first_run_at_ms: NOW + 60_000, every_secs: None };
        assert_eq!(check_job("Morning news", "Summarize the news.", &once, NOW), Ok(()));
        assert_eq!(check_job("", "x", &once, NOW), Err(JobError::BadTitle));
        assert_eq!(check_job("a\nb", "x", &once, NOW), Err(JobError::BadTitle));
        assert_eq!(check_job("t", "  ", &once, NOW), Err(JobError::BadPrompt));
        assert_eq!(check_job("t", "x\u{202E}y", &once, NOW), Err(JobError::BadPrompt));
        let too_often = JobSchedule { first_run_at_ms: NOW, every_secs: Some(60) };
        assert_eq!(check_job("t", "x", &too_often, NOW), Err(JobError::BadSchedule));
        let far = JobSchedule { first_run_at_ms: NOW + 2 * MAX_START_AHEAD_MS, every_secs: None };
        assert_eq!(check_job("t", "x", &far, NOW), Err(JobError::BadSchedule));
    }

    #[test]
    fn schedules_skip_missed_slots() {
        let s = JobSchedule { first_run_at_ms: NOW, every_secs: Some(3600) };
        assert_eq!(next_slot(&s, NOW - 1), Some(NOW));
        assert_eq!(next_slot(&s, NOW), Some(NOW + 3_600_000));
        assert_eq!(next_slot(&s, NOW + 10 * 3_600_000 + 5), Some(NOW + 11 * 3_600_000));
        assert_eq!(next_slot(&JobSchedule { first_run_at_ms: NOW, every_secs: None }, NOW), None);
    }
}
