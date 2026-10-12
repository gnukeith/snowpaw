//! The job scheduler. Every couple of seconds:
//! - runs that can't finish any more are closed as lost: the runtime disconnected,
//!   the deadline passed (`agents.job_run_timeout_secs`), or agents were paused (a
//!   pause doesn't count as a failed attempt);
//! - unless agents are paused, due jobs are handed to their agent's runtime, one run
//!   per agent at a time, and only to a runtime that's connected.
//!
//! Everything is in the database, so a restart of the server or a runtime loses
//! nothing: open runs are closed as lost and retried.

use std::sync::Arc;
use std::time::Duration;

use snowpaw_proto::Id;
use snowpaw_proto::jobs::{JobSpec, JobView, MAX_ATTEMPTS, RunOutcome};
use tracing::{info, warn};

use crate::api::{AppState, StateEvent};
use crate::auth;
use crate::db;

const TICK: Duration = Duration::from_secs(2);

/// Publish a job's current state to the user's windows.
pub async fn changed(st: &AppState, job: Id) {
    match st.db.call(move |c| db::job(c, job)).await {
        Ok(Some(view)) => st.publish_event(StateEvent::JobChanged(Box::new(view))),
        Ok(None) => {}
        Err(e) => warn!(error = %e, "reading a job failed"),
    }
}

pub fn spawn_scheduler(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = step(&st).await {
                warn!(error = %e, "job scheduler step failed");
            }
        }
    });
}

async fn step(st: &AppState) -> Result<(), db::DbError> {
    let now = st.clock.now_ms();
    let paused = st.db.call(|c| db::agents_paused(c)).await?;
    // 1. Close runs that can't finish.
    let open = st.db.call(|c| db::open_runs(c)).await?;
    let mut busy: Vec<Id> = vec![];
    for (run, job, agent, deadline) in open {
        let reason = if paused {
            Some(("agents were paused", false))
        } else if !st.agent_is_connected(agent) {
            Some(("the agent's runtime disconnected", true))
        } else if now > deadline {
            Some(("the run took longer than allowed", true))
        } else {
            None
        };
        match reason {
            Some((why, counts)) => {
                st.db
                    .call(move |c| db::finish_run(c, run, RunOutcome::Lost, why, counts, now))
                    .await?;
                st.publish_event(StateEvent::JobCancel { agent, run_id: run });
                info!(%job, why, "job run lost");
                changed(st, job).await;
            }
            None => busy.push(agent),
        }
    }
    if paused {
        return Ok(());
    }
    // 2. Start due jobs whose runtime is here and free.
    let due = st.db.call(move |c| db::due_jobs(c, now)).await?;
    let timeout_ms = i64::try_from(st.cfg.agents.job_run_timeout_secs * 1000).unwrap_or(i64::MAX);
    for (job, agent) in due {
        if busy.contains(&agent) || !st.agent_is_connected(agent) {
            continue;
        }
        let Ok(run_id) = auth::random_id() else { continue };
        let started = st
            .db
            .call(move |c| {
                let Some(view) = db::job(c, job)? else { return Ok(None) };
                db::start_run(c, run_id, job, now, now.saturating_add(timeout_ms))?;
                Ok(Some(view))
            })
            .await?;
        let Some(view) = started else { continue };
        busy.push(agent);
        st.publish_event(StateEvent::JobDispatch { agent, spec: Box::new(spec(&view, run_id)) });
        changed(st, job).await;
    }
    Ok(())
}

fn spec(view: &JobView, run_id: Id) -> JobSpec {
    JobSpec {
        run_id,
        job: view.id,
        chat_id: view.chat_id,
        title: view.title.clone(),
        prompt: view.prompt.clone(),
        attempt: (view.attempts + 1).min(MAX_ATTEMPTS),
    }
}

/// One line of text from a runtime (progress, a run's detail): no control
/// characters, no bidi overrides, at most `max` characters.
pub fn clean(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .filter(|c| {
            !('\u{202A}'..='\u{202E}').contains(c) && !('\u{2066}'..='\u{2069}').contains(c)
        })
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}
