//! Cloudflare Cron event binding for canary execution.
//!
//! This module converts Cloudflare scheduled events into one canary tick run.

use std::num::NonZeroU64;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::canary::CanaryController;
use crate::canary_orchestrator::{CanaryEventSink, CanaryTickOutcome};
use crate::canary_tick::{
    build_cloudflare_canary_tick_service_with_runners, CloudflareOneShotCanaryConfig,
};
use crate::cloudflare_cli::{CommandRunner, SystemCommandRunner};

/// Raw Cloudflare scheduled event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareCronEventPayload {
    pub cron: String,
    #[serde(rename = "scheduledTime")]
    pub scheduled_time: u64,
    #[serde(default)]
    pub r#type: Option<String>,
}

/// Validated Cron event used by canary runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareCronEvent {
    cron_expression: String,
    scheduled_time: NonZeroU64,
}

impl CloudflareCronEvent {
    pub fn from_payload(payload: CloudflareCronEventPayload) -> Result<Self> {
        if payload.cron.trim().is_empty() {
            return Err(anyhow!("cron expression must not be empty"));
        }
        if let Some(event_type) = payload.r#type.as_deref() {
            if !event_type.eq_ignore_ascii_case("scheduled") {
                return Err(anyhow!(
                    "unsupported cloudflare event type: {event_type}; expected 'scheduled'"
                ));
            }
        }
        let scheduled_time = NonZeroU64::new(payload.scheduled_time)
            .ok_or_else(|| anyhow!("scheduled_time must be greater than zero"))?;
        Ok(Self {
            cron_expression: payload.cron,
            scheduled_time,
        })
    }

    pub fn cron_expression(&self) -> &str {
        &self.cron_expression
    }

    pub fn scheduled_time(&self) -> NonZeroU64 {
        self.scheduled_time
    }
}

/// Summary of one Cloudflare cron-triggered canary execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareCronExecution {
    pub event: CloudflareCronEvent,
    pub outcome: CanaryTickOutcome,
}

/// Executes one canary tick from a Cloudflare cron event.
pub async fn run_cloudflare_cron_event<E>(
    event: CloudflareCronEvent,
    controller: CanaryController,
    event_sink: Arc<E>,
    config: CloudflareOneShotCanaryConfig,
) -> Result<CloudflareCronExecution>
where
    E: CanaryEventSink,
{
    run_cloudflare_cron_event_with_runners(
        event,
        controller,
        event_sink,
        config,
        SystemCommandRunner,
        SystemCommandRunner,
    )
    .await
}

/// Same as [`run_cloudflare_cron_event`] with injected command runners.
pub async fn run_cloudflare_cron_event_with_runners<E, MR, TR>(
    event: CloudflareCronEvent,
    controller: CanaryController,
    event_sink: Arc<E>,
    config: CloudflareOneShotCanaryConfig,
    metrics_runner: MR,
    traffic_runner: TR,
) -> Result<CloudflareCronExecution>
where
    E: CanaryEventSink,
    MR: CommandRunner,
    TR: CommandRunner,
{
    let mut service = build_cloudflare_canary_tick_service_with_runners(
        controller,
        event_sink,
        config,
        metrics_runner,
        traffic_runner,
    )
    .context("failed building canary tick service for cron event")?;
    let outcome = service.tick().await.context("cron canary tick failed")?;
    Ok(CloudflareCronExecution { event, outcome })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::num::{NonZeroU64, NonZeroU8};
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::canary::{
        BasisPoints, CanaryController, CanaryDecision, CanaryPlan, CanaryStage, CanaryThresholds,
        Percent,
    };
    use crate::canary_live::CloudflareCanaryWiringConfig;
    use crate::canary_metrics::CurlCanaryMetricsConfig;
    use crate::canary_orchestrator::NoopCanaryEventSink;
    use crate::canary_tick::CloudflareOneShotCanaryConfig;

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

    fn spawn_metrics_server(body: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/metrics");
        let handle = thread::spawn(move || {
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
        });
        (url, handle)
    }

    fn unique_temp_file(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("zeroclaw-edge-cron-{name}-{ts}.txt"));
        p
    }

    fn shell_script_recorder(output_file: &PathBuf) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("zeroclaw-edge-cron-recorder-{ts}.sh"));
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\n",
            output_file.display()
        );
        fs::write(&p, script).unwrap();
        p
    }

    #[test]
    fn cron_event_rejects_invalid_payloads() {
        let err = CloudflareCronEvent::from_payload(CloudflareCronEventPayload {
            cron: "".to_string(),
            scheduled_time: 1,
            r#type: Some("scheduled".to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("cron expression"));

        let err = CloudflareCronEvent::from_payload(CloudflareCronEventPayload {
            cron: "*/1 * * * *".to_string(),
            scheduled_time: 0,
            r#type: Some("scheduled".to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("scheduled_time"));

        let err = CloudflareCronEvent::from_payload(CloudflareCronEventPayload {
            cron: "*/1 * * * *".to_string(),
            scheduled_time: 1,
            r#type: Some("fetch".to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[tokio::test]
    async fn cron_event_runs_one_tick_end_to_end() {
        let (metrics_url, server) = spawn_metrics_server(
            r#"{"total_requests":100,"failed_requests":0,"p95_latency_ms":100}"#.to_string(),
        );
        let args_file = unique_temp_file("args");
        let script_path = shell_script_recorder(&args_file);

        let mut wrangler =
            crate::cloudflare_cli::CloudflareWranglerConfig::new("edge-smoke").unwrap();
        wrangler.wrangler_bin = "sh".to_string();
        wrangler.wrangler_bin_args = vec![script_path.to_string_lossy().to_string()];
        let wiring = CloudflareCanaryWiringConfig::new("stable-v1", "canary-v2", wrangler).unwrap();
        let metrics = CurlCanaryMetricsConfig::new(metrics_url).unwrap();
        let cfg = CloudflareOneShotCanaryConfig::new(wiring, metrics);
        let event = CloudflareCronEvent::from_payload(CloudflareCronEventPayload {
            cron: "*/1 * * * *".to_string(),
            scheduled_time: 1_700_000_000_000,
            r#type: Some("scheduled".to_string()),
        })
        .unwrap();

        let sink = Arc::new(NoopCanaryEventSink);
        let exec = run_cloudflare_cron_event(event.clone(), test_controller(), sink, cfg)
            .await
            .unwrap();
        assert_eq!(exec.event, event);
        assert!(matches!(
            exec.outcome.decision,
            CanaryDecision::Promote { .. }
        ));
        assert!(exec.outcome.applied_update.is_some());

        server.join().unwrap();
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(args.contains("versions"));
        assert!(args.contains("deploy"));
        assert!(args.contains("canary-v2@25%"));
        assert!(args.contains("stable-v1@75%"));
    }
}
