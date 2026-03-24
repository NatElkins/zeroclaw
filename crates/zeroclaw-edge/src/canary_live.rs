//! Live Cloudflare canary wiring for the edge rollout path.
//!
//! This module keeps canary decisioning pure while providing a typed assembly
//! path for real `wrangler versions deploy` execution.

use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::canary::CanaryController;
use crate::canary_orchestrator::{
    CanaryEventSink, CanaryMetricsSource, CanaryOrchestrator, CanaryVersionSet,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::cloudflare_cli::SystemCommandRunner;
use crate::cloudflare_cli::{
    CloudflareWranglerConfig, CloudflareWranglerTrafficClient, CommandRunner,
};

/// Inputs required to wire a live Cloudflare canary orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareCanaryWiringConfig {
    pub stable_version_id: String,
    pub canary_version_id: String,
    pub wrangler: CloudflareWranglerConfig,
}

impl CloudflareCanaryWiringConfig {
    pub fn new(
        stable_version_id: impl Into<String>,
        canary_version_id: impl Into<String>,
        wrangler: CloudflareWranglerConfig,
    ) -> Result<Self> {
        let stable_version_id = stable_version_id.into();
        let canary_version_id = canary_version_id.into();

        if stable_version_id.trim().is_empty() {
            return Err(anyhow!("stable_version_id must not be empty"));
        }
        if canary_version_id.trim().is_empty() {
            return Err(anyhow!("canary_version_id must not be empty"));
        }

        Ok(Self {
            stable_version_id,
            canary_version_id,
            wrangler,
        })
    }

    /// Convenience constructor for environments where Wrangler is available
    /// through `npx --yes wrangler`.
    pub fn for_npx(
        worker_name: impl Into<String>,
        stable_version_id: impl Into<String>,
        canary_version_id: impl Into<String>,
    ) -> Result<Self> {
        let mut wrangler = CloudflareWranglerConfig::new(worker_name)?;
        wrangler.wrangler_bin = "npx".to_string();
        wrangler.wrangler_bin_args = vec!["--yes".to_string(), "wrangler".to_string()];
        Self::new(stable_version_id, canary_version_id, wrangler)
    }
}

/// Builds a live Cloudflare canary orchestrator backed by system command
/// execution.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_cloudflare_wrangler_orchestrator<M, E>(
    controller: CanaryController,
    metrics_source: Arc<M>,
    event_sink: Arc<E>,
    config: CloudflareCanaryWiringConfig,
) -> Result<CanaryOrchestrator<M, CloudflareWranglerTrafficClient<SystemCommandRunner>, E>>
where
    M: CanaryMetricsSource,
    E: CanaryEventSink,
{
    build_cloudflare_wrangler_orchestrator_with_runner(
        controller,
        metrics_source,
        event_sink,
        config,
        SystemCommandRunner,
    )
}

/// Same as [`build_cloudflare_wrangler_orchestrator`] but with an injected
/// command runner for deterministic tests.
pub fn build_cloudflare_wrangler_orchestrator_with_runner<M, E, R>(
    controller: CanaryController,
    metrics_source: Arc<M>,
    event_sink: Arc<E>,
    config: CloudflareCanaryWiringConfig,
    runner: R,
) -> Result<CanaryOrchestrator<M, CloudflareWranglerTrafficClient<R>, E>>
where
    M: CanaryMetricsSource,
    E: CanaryEventSink,
    R: CommandRunner,
{
    let versions = CanaryVersionSet::new(config.stable_version_id, config.canary_version_id)?;
    let traffic_client = Arc::new(CloudflareWranglerTrafficClient::new(
        config.wrangler,
        runner,
    )?);
    Ok(CanaryOrchestrator::new(
        controller,
        versions,
        metrics_source,
        traffic_client,
        event_sink,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::num::{NonZeroU64, NonZeroU8};
    use std::sync::Mutex;

    use crate::canary::{
        BasisPoints, CanaryDecision, CanaryMetrics, CanaryPlan, CanaryStage, CanaryThresholds,
        Percent,
    };
    use crate::canary_orchestrator::NoopCanaryEventSink;

    #[derive(Clone)]
    struct RecordingRunner {
        calls: Arc<Mutex<Vec<(String, Vec<String>)>>>,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl CommandRunner for RecordingRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _cwd: Option<&std::path::PathBuf>,
        ) -> Result<crate::cloudflare_cli::CommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            Ok(crate::cloudflare_cli::CommandOutput {
                status_code: 0,
                stdout: "ok".to_string(),
                stderr: String::new(),
            })
        }
    }

    struct FixedMetricsSource {
        metrics: CanaryMetrics,
    }

    #[async_trait::async_trait(?Send)]
    impl CanaryMetricsSource for FixedMetricsSource {
        async fn current_window(&self) -> Result<CanaryMetrics> {
            Ok(self.metrics)
        }
    }

    fn test_controller() -> CanaryController {
        let plan = CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(10).unwrap(), NonZeroU8::new(1).unwrap()),
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

    #[tokio::test]
    async fn wiring_builds_and_ticks_with_npx_wrangler_command_shape() {
        let runner = RecordingRunner::new();
        let config =
            CloudflareCanaryWiringConfig::for_npx("edge-smoke", "stable-v1", "canary-v2").unwrap();
        let metrics = Arc::new(FixedMetricsSource {
            metrics: CanaryMetrics::new(100, 0, 100).unwrap(),
        });
        let sink = Arc::new(NoopCanaryEventSink);
        let mut orchestrator = build_cloudflare_wrangler_orchestrator_with_runner(
            test_controller(),
            metrics,
            sink,
            config,
            runner.clone(),
        )
        .unwrap();

        let outcome = orchestrator.tick().await.unwrap();
        assert!(matches!(outcome.decision, CanaryDecision::Promote { .. }));
        assert!(outcome.applied_update.is_some());

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "npx");
        assert_eq!(calls[0].1[0], "--yes");
        assert_eq!(calls[0].1[1], "wrangler");
        assert_eq!(calls[0].1[2], "versions");
        assert_eq!(calls[0].1[3], "deploy");
    }

    #[test]
    fn wiring_rejects_empty_version_ids() {
        let wrangler = CloudflareWranglerConfig::new("edge-smoke").unwrap();
        let err = CloudflareCanaryWiringConfig::new(" ", "canary-v2", wrangler).unwrap_err();
        assert!(err.to_string().contains("stable_version_id"));
    }
}
