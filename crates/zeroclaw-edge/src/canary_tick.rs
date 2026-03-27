//! One-shot live canary tick runner.
//!
//! This is the first end-to-end runtime assembly path:
//! telemetry metrics -> canary decision -> Cloudflare traffic split apply.

use std::sync::Arc;

use anyhow::Result;

use crate::canary::CanaryController;
use crate::canary_live::{
    build_cloudflare_wrangler_orchestrator_with_runner, CloudflareCanaryWiringConfig,
};
use crate::canary_metrics::{CurlCanaryMetricsConfig, CurlCanaryMetricsSource};
use crate::canary_orchestrator::{
    CanaryEventSink, CanaryMetricsSource, CanaryOrchestrator, CanaryTickOutcome,
    CanaryTrafficClient,
};
use crate::cloudflare_cli::{
    CloudflareWranglerTrafficClient, CommandOutput, CommandRunner, SystemCommandRunner,
};

/// One-shot canary tick runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareOneShotCanaryConfig {
    pub wiring: CloudflareCanaryWiringConfig,
    pub metrics: CurlCanaryMetricsConfig,
}

impl CloudflareOneShotCanaryConfig {
    pub fn new(wiring: CloudflareCanaryWiringConfig, metrics: CurlCanaryMetricsConfig) -> Self {
        Self { wiring, metrics }
    }
}

/// Stateful service for executing canary ticks repeatedly with preserved canary
/// controller stage state.
pub struct CloudflareCanaryTickService<M, C, E>
where
    M: CanaryMetricsSource,
    C: CanaryTrafficClient,
    E: CanaryEventSink,
{
    orchestrator: CanaryOrchestrator<M, C, E>,
}

impl<M, C, E> CloudflareCanaryTickService<M, C, E>
where
    M: CanaryMetricsSource,
    C: CanaryTrafficClient,
    E: CanaryEventSink,
{
    pub fn new(orchestrator: CanaryOrchestrator<M, C, E>) -> Self {
        Self { orchestrator }
    }

    pub async fn tick(&mut self) -> Result<CanaryTickOutcome> {
        self.orchestrator.tick().await
    }
}

/// Builds a reusable canary tick service using system command runners.
pub fn build_cloudflare_canary_tick_service<E>(
    controller: CanaryController,
    event_sink: Arc<E>,
    config: CloudflareOneShotCanaryConfig,
) -> Result<
    CloudflareCanaryTickService<
        CurlCanaryMetricsSource<SystemCommandRunner>,
        CloudflareWranglerTrafficClient<SystemCommandRunner>,
        E,
    >,
>
where
    E: CanaryEventSink,
{
    build_cloudflare_canary_tick_service_with_runners(
        controller,
        event_sink,
        config,
        SystemCommandRunner,
        SystemCommandRunner,
    )
}

/// Same as [`build_cloudflare_canary_tick_service`] with injected runners.
pub fn build_cloudflare_canary_tick_service_with_runners<E, MR, TR>(
    controller: CanaryController,
    event_sink: Arc<E>,
    config: CloudflareOneShotCanaryConfig,
    metrics_runner: MR,
    traffic_runner: TR,
) -> Result<
    CloudflareCanaryTickService<
        CurlCanaryMetricsSource<MR>,
        CloudflareWranglerTrafficClient<TR>,
        E,
    >,
>
where
    E: CanaryEventSink,
    MR: CommandRunner,
    TR: CommandRunner,
{
    let metrics_source = Arc::new(CurlCanaryMetricsSource::new(
        config.metrics,
        metrics_runner,
    )?);
    let orchestrator = build_cloudflare_wrangler_orchestrator_with_runner(
        controller,
        metrics_source,
        event_sink,
        config.wiring,
        traffic_runner,
    )?;
    Ok(CloudflareCanaryTickService::new(orchestrator))
}

/// Runs a single canary tick with system command runners.
pub async fn run_cloudflare_one_shot_canary_tick<E>(
    controller: CanaryController,
    event_sink: Arc<E>,
    config: CloudflareOneShotCanaryConfig,
) -> Result<CanaryTickOutcome>
where
    E: CanaryEventSink,
{
    let mut service = build_cloudflare_canary_tick_service(controller, event_sink, config)?;
    service.tick().await
}

/// Same as [`run_cloudflare_one_shot_canary_tick`], but with injected command
/// runners so integration tests can simulate real process boundaries.
pub async fn run_cloudflare_one_shot_canary_tick_with_runners<E, MR, TR>(
    controller: CanaryController,
    event_sink: Arc<E>,
    config: CloudflareOneShotCanaryConfig,
    metrics_runner: MR,
    traffic_runner: TR,
) -> Result<CanaryTickOutcome>
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
    )?;
    service.tick().await
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
        BasisPoints, CanaryDecision, CanaryPlan, CanaryStage, CanaryThresholds, Percent,
    };
    use crate::canary_orchestrator::NoopCanaryEventSink;

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
        p.push(format!("zeroclaw-edge-{name}-{ts}.txt"));
        p
    }

    fn shell_script_recorder(output_file: &PathBuf) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("zeroclaw-edge-recorder-{ts}.sh"));
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\n",
            output_file.display()
        );
        fs::write(&p, script).unwrap();
        p
    }

    #[tokio::test]
    async fn one_shot_tick_runs_end_to_end_and_applies_promote_split() {
        let (metrics_url, server) = spawn_metrics_server(
            r#"{"total_requests":100,"failed_requests":0,"p95_latency_ms":100}"#.to_string(),
        );
        let args_file = unique_temp_file("promote-args");
        let script_path = shell_script_recorder(&args_file);

        let mut wrangler =
            crate::cloudflare_cli::CloudflareWranglerConfig::new("edge-smoke").unwrap();
        wrangler.wrangler_bin = "sh".to_string();
        wrangler.wrangler_bin_args = vec![script_path.to_string_lossy().to_string()];
        let wiring = CloudflareCanaryWiringConfig::new("stable-v1", "canary-v2", wrangler).unwrap();
        let metrics = CurlCanaryMetricsConfig::new(metrics_url).unwrap();
        let cfg = CloudflareOneShotCanaryConfig::new(wiring, metrics);

        let sink = Arc::new(NoopCanaryEventSink);
        let outcome = run_cloudflare_one_shot_canary_tick(test_controller(), sink, cfg)
            .await
            .unwrap();
        assert!(matches!(outcome.decision, CanaryDecision::Promote { .. }));
        assert!(outcome.applied_update.is_some());

        server.join().unwrap();
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(args.contains("versions"));
        assert!(args.contains("deploy"));
        assert!(args.contains("canary-v2@25%"));
        assert!(args.contains("stable-v1@75%"));
    }

    #[tokio::test]
    async fn one_shot_tick_runs_end_to_end_and_applies_rollback_split() {
        let (metrics_url, server) = spawn_metrics_server(
            r#"{"total_requests":100,"failed_requests":60,"p95_latency_ms":100}"#.to_string(),
        );
        let args_file = unique_temp_file("rollback-args");
        let script_path = shell_script_recorder(&args_file);

        let mut wrangler =
            crate::cloudflare_cli::CloudflareWranglerConfig::new("edge-smoke").unwrap();
        wrangler.wrangler_bin = "sh".to_string();
        wrangler.wrangler_bin_args = vec![script_path.to_string_lossy().to_string()];
        let wiring = CloudflareCanaryWiringConfig::new("stable-v1", "canary-v2", wrangler).unwrap();
        let metrics = CurlCanaryMetricsConfig::new(metrics_url).unwrap();
        let cfg = CloudflareOneShotCanaryConfig::new(wiring, metrics);

        let sink = Arc::new(NoopCanaryEventSink);
        let outcome = run_cloudflare_one_shot_canary_tick(test_controller(), sink, cfg)
            .await
            .unwrap();
        assert!(matches!(outcome.decision, CanaryDecision::Rollback { .. }));
        assert!(outcome.applied_update.is_some());

        server.join().unwrap();
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(args.contains("canary-v2@0%"));
        assert!(args.contains("stable-v1@100%"));
    }

    #[tokio::test]
    async fn one_shot_tick_errors_on_invalid_metrics_payload() {
        let (metrics_url, server) = spawn_metrics_server(
            r#"{"total_requests":1,"failed_requests":2,"p95_latency_ms":10}"#.to_string(),
        );

        let mut wrangler =
            crate::cloudflare_cli::CloudflareWranglerConfig::new("edge-smoke").unwrap();
        wrangler.wrangler_bin = "sh".to_string();
        wrangler.wrangler_bin_args = vec!["-c".to_string(), "cat >/dev/null".to_string()];
        let wiring = CloudflareCanaryWiringConfig::new("stable-v1", "canary-v2", wrangler).unwrap();
        let metrics = CurlCanaryMetricsConfig::new(metrics_url).unwrap();
        let cfg = CloudflareOneShotCanaryConfig::new(wiring, metrics);

        let sink = Arc::new(NoopCanaryEventSink);
        let err = run_cloudflare_one_shot_canary_tick(test_controller(), sink, cfg)
            .await
            .expect_err("invalid metrics payload should fail");
        assert!(err.to_string().contains("canary invariants"));
        server.join().unwrap();
    }

    #[derive(Default)]
    struct FailRunner;

    impl CommandRunner for FailRunner {
        fn run(
            &self,
            _program: &str,
            _args: &[String],
            _cwd: Option<&PathBuf>,
        ) -> Result<CommandOutput> {
            Err(anyhow::anyhow!("runner failed"))
        }
    }

    #[tokio::test]
    async fn one_shot_tick_propagates_metrics_runner_errors() {
        let wrangler = crate::cloudflare_cli::CloudflareWranglerConfig::new("edge-smoke").unwrap();
        let wiring = CloudflareCanaryWiringConfig::new("stable-v1", "canary-v2", wrangler).unwrap();
        let metrics = CurlCanaryMetricsConfig::new("https://example.com/metrics").unwrap();
        let cfg = CloudflareOneShotCanaryConfig::new(wiring, metrics);

        let sink = Arc::new(NoopCanaryEventSink);
        let err = run_cloudflare_one_shot_canary_tick_with_runners(
            test_controller(),
            sink,
            cfg,
            FailRunner,
            crate::cloudflare_cli::SystemCommandRunner,
        )
        .await
        .expect_err("metrics runner failure should propagate");
        assert!(err
            .to_string()
            .contains("failed executing curl metrics command"));
    }
}
