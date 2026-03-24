//! Scheduled canary execution primitives.
//!
//! This module connects a trigger source (fixed interval or external) to a
//! canary tick runner, with explicit error policy controls.

use std::num::NonZeroUsize;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

use crate::canary_orchestrator::CanaryTickOutcome;
use crate::canary_orchestrator::{CanaryEventSink, CanaryMetricsSource, CanaryTrafficClient};
use crate::canary_tick::CloudflareCanaryTickService;

/// Trigger event emitted by a canary scheduler source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryTriggerEvent {
    Tick,
    Stop,
}

/// Boundary for scheduler trigger sources.
#[async_trait]
pub trait CanaryTrigger {
    async fn wait_next(&mut self) -> Result<CanaryTriggerEvent>;
}

/// Fixed-interval trigger suitable for local tests and simple cron-like loops.
#[derive(Debug)]
pub struct FixedIntervalTrigger {
    interval: Duration,
    remaining_ticks: Option<usize>,
    immediate_first_tick: bool,
    first_emitted: bool,
}

impl FixedIntervalTrigger {
    pub fn new(
        interval: Duration,
        max_ticks: Option<NonZeroUsize>,
        immediate_first_tick: bool,
    ) -> Result<Self> {
        if interval.is_zero() {
            anyhow::bail!("interval must be greater than zero");
        }
        Ok(Self {
            interval,
            remaining_ticks: max_ticks.map(NonZeroUsize::get),
            immediate_first_tick,
            first_emitted: false,
        })
    }

    fn mark_tick_emitted(&mut self) {
        if let Some(remaining) = self.remaining_ticks.as_mut() {
            *remaining = remaining.saturating_sub(1);
        }
        self.first_emitted = true;
    }
}

#[async_trait]
impl CanaryTrigger for FixedIntervalTrigger {
    async fn wait_next(&mut self) -> Result<CanaryTriggerEvent> {
        if self.remaining_ticks == Some(0) {
            return Ok(CanaryTriggerEvent::Stop);
        }

        if self.immediate_first_tick && !self.first_emitted {
            self.mark_tick_emitted();
            return Ok(CanaryTriggerEvent::Tick);
        }

        tokio::time::sleep(self.interval).await;
        self.mark_tick_emitted();
        Ok(CanaryTriggerEvent::Tick)
    }
}

/// Runner boundary invoked by the scheduler on each trigger tick.
#[async_trait]
pub trait CanaryTickRunner {
    async fn run_tick(&mut self) -> Result<CanaryTickOutcome>;
}

#[async_trait]
impl<M, C, E> CanaryTickRunner for CloudflareCanaryTickService<M, C, E>
where
    M: CanaryMetricsSource,
    C: CanaryTrafficClient,
    E: CanaryEventSink,
{
    async fn run_tick(&mut self) -> Result<CanaryTickOutcome> {
        self.tick().await
    }
}

/// Scheduler behavior controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanarySchedulerConfig {
    pub continue_on_error: bool,
    pub max_consecutive_failures: NonZeroUsize,
}

impl Default for CanarySchedulerConfig {
    fn default() -> Self {
        Self {
            continue_on_error: true,
            max_consecutive_failures: NonZeroUsize::new(3).expect("nonzero"),
        }
    }
}

/// Summary of one scheduled canary run session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CanarySchedulerSummary {
    pub ticks_attempted: usize,
    pub ticks_succeeded: usize,
    pub ticks_failed: usize,
}

/// Run scheduled canary ticks until trigger stop or scheduler failure policy.
pub async fn run_scheduled_canary<R, T>(
    runner: &mut R,
    trigger: &mut T,
    config: CanarySchedulerConfig,
) -> Result<CanarySchedulerSummary>
where
    R: CanaryTickRunner,
    T: CanaryTrigger,
{
    let mut summary = CanarySchedulerSummary::default();
    let mut consecutive_failures = 0usize;

    loop {
        match trigger.wait_next().await? {
            CanaryTriggerEvent::Stop => break,
            CanaryTriggerEvent::Tick => {
                summary.ticks_attempted = summary.ticks_attempted.saturating_add(1);
                match runner.run_tick().await {
                    Ok(_) => {
                        summary.ticks_succeeded = summary.ticks_succeeded.saturating_add(1);
                        consecutive_failures = 0;
                    }
                    Err(err) => {
                        summary.ticks_failed = summary.ticks_failed.saturating_add(1);
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if !config.continue_on_error {
                            return Err(err.context("scheduled canary tick failed"));
                        }
                        if consecutive_failures >= config.max_consecutive_failures.get() {
                            return Err(err.context(format!(
                                "scheduled canary exceeded max consecutive failures ({})",
                                config.max_consecutive_failures
                            )));
                        }
                    }
                }
            }
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::num::{NonZeroU64, NonZeroU8};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::canary::{
        BasisPoints, CanaryController, CanaryPlan, CanaryStage, CanaryThresholds, Percent,
    };
    use crate::canary_live::CloudflareCanaryWiringConfig;
    use crate::canary_metrics::CurlCanaryMetricsConfig;
    use crate::canary_orchestrator::NoopCanaryEventSink;
    use crate::canary_tick::{build_cloudflare_canary_tick_service, CloudflareOneShotCanaryConfig};

    #[derive(Default)]
    struct CountingRunner {
        fail_first: bool,
        count: usize,
    }

    #[async_trait]
    impl CanaryTickRunner for CountingRunner {
        async fn run_tick(&mut self) -> Result<CanaryTickOutcome> {
            self.count = self.count.saturating_add(1);
            if self.fail_first && self.count == 1 {
                anyhow::bail!("first tick failed");
            }
            Ok(CanaryTickOutcome {
                metrics: crate::canary::CanaryMetrics::new(10, 0, 10).unwrap(),
                decision: crate::canary::CanaryDecision::Hold {
                    stage: Percent::new(10).unwrap(),
                    reason: crate::canary::HoldReason::AwaitingHealthyIntervals {
                        required: NonZeroU8::new(2).unwrap(),
                        observed: 1,
                    },
                },
                applied_update: None,
            })
        }
    }

    fn test_controller() -> CanaryController {
        let plan = CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(10).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(25).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(100).unwrap(), NonZeroU8::new(1).unwrap()),
            ],
            CanaryThresholds::new(
                BasisPoints::new(100).unwrap(),
                500,
                NonZeroU64::new(10).unwrap(),
            ),
        )
        .unwrap();
        CanaryController::new(plan)
    }

    fn spawn_metrics_server_sequence(bodies: Vec<String>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/metrics");
        let handle = thread::spawn(move || {
            for body in bodies {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0_u8; 1024];
                    let _ = stream.read(&mut buf);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            }
        });
        (url, handle)
    }

    fn unique_temp_file(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("zeroclaw-edge-schedule-{name}-{ts}.txt"));
        p
    }

    fn shell_script_appender(output_file: &PathBuf) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("zeroclaw-edge-scheduler-recorder-{ts}.sh"));
        let script = format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" >> \"{}\"\nprintf '\\n' >> \"{}\"\n",
            output_file.display(),
            output_file.display()
        );
        fs::write(&p, script).unwrap();
        p
    }

    #[tokio::test]
    async fn fixed_interval_trigger_rejects_zero_interval() {
        let err = FixedIntervalTrigger::new(Duration::ZERO, None, true).unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    #[tokio::test]
    async fn scheduler_runs_expected_tick_count() {
        let mut runner = CountingRunner::default();
        let mut trigger = FixedIntervalTrigger::new(
            Duration::from_millis(1),
            Some(NonZeroUsize::new(3).unwrap()),
            true,
        )
        .unwrap();
        let summary = run_scheduled_canary(
            &mut runner,
            &mut trigger,
            CanarySchedulerConfig {
                continue_on_error: false,
                max_consecutive_failures: NonZeroUsize::new(1).unwrap(),
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.ticks_attempted, 3);
        assert_eq!(summary.ticks_succeeded, 3);
        assert_eq!(summary.ticks_failed, 0);
    }

    #[tokio::test]
    async fn scheduler_continue_on_error_retries_and_recovers() {
        let mut runner = CountingRunner {
            fail_first: true,
            count: 0,
        };
        let mut trigger = FixedIntervalTrigger::new(
            Duration::from_millis(1),
            Some(NonZeroUsize::new(2).unwrap()),
            true,
        )
        .unwrap();
        let summary = run_scheduled_canary(
            &mut runner,
            &mut trigger,
            CanarySchedulerConfig {
                continue_on_error: true,
                max_consecutive_failures: NonZeroUsize::new(2).unwrap(),
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.ticks_attempted, 2);
        assert_eq!(summary.ticks_succeeded, 1);
        assert_eq!(summary.ticks_failed, 1);
    }

    #[tokio::test]
    async fn scheduler_end_to_end_runs_promote_then_rollback() {
        let (metrics_url, server) = spawn_metrics_server_sequence(vec![
            r#"{"total_requests":100,"failed_requests":0,"p95_latency_ms":100}"#.to_string(),
            r#"{"total_requests":100,"failed_requests":70,"p95_latency_ms":100}"#.to_string(),
        ]);
        let args_file = unique_temp_file("e2e-args");
        let script_path = shell_script_appender(&args_file);

        let mut wrangler =
            crate::cloudflare_cli::CloudflareWranglerConfig::new("edge-smoke").unwrap();
        wrangler.wrangler_bin = "sh".to_string();
        wrangler.wrangler_bin_args = vec![script_path.to_string_lossy().to_string()];
        let wiring = CloudflareCanaryWiringConfig::new("stable-v1", "canary-v2", wrangler).unwrap();
        let metrics = CurlCanaryMetricsConfig::new(metrics_url).unwrap();
        let cfg = CloudflareOneShotCanaryConfig::new(wiring, metrics);

        let sink = Arc::new(NoopCanaryEventSink);
        let mut service =
            build_cloudflare_canary_tick_service(test_controller(), sink, cfg).unwrap();
        let mut trigger = FixedIntervalTrigger::new(
            Duration::from_millis(1),
            Some(NonZeroUsize::new(2).unwrap()),
            true,
        )
        .unwrap();
        let summary = run_scheduled_canary(
            &mut service,
            &mut trigger,
            CanarySchedulerConfig {
                continue_on_error: false,
                max_consecutive_failures: NonZeroUsize::new(1).unwrap(),
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.ticks_attempted, 2);
        assert_eq!(summary.ticks_succeeded, 2);
        assert_eq!(summary.ticks_failed, 0);

        server.join().unwrap();
        let contents = fs::read_to_string(&args_file).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("canary-v2@25%"));
        assert!(lines[0].contains("stable-v1@75%"));
        assert!(lines[1].contains("canary-v2@0%"));
        assert!(lines[1].contains("stable-v1@100%"));
    }
}
