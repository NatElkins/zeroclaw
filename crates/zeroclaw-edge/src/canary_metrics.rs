//! Runtime metrics adapters for canary decisioning.
//!
//! This module intentionally keeps a small dependency surface by using a
//! command-runner boundary (`curl`) instead of adding a dedicated HTTP client
//! dependency to the edge spike crate.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::canary::CanaryMetrics;
use crate::canary_orchestrator::CanaryMetricsSource;
use crate::cloudflare_cli::CommandRunner;

/// Wire-format payload expected from telemetry endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CanaryMetricsPayload {
    pub total_requests: u64,
    pub failed_requests: u64,
    pub p95_latency_ms: u32,
}

/// Configuration for pulling canary metrics over HTTP with `curl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlCanaryMetricsConfig {
    pub endpoint_url: String,
    pub curl_bin: String,
    pub bearer_token: Option<String>,
    pub cwd: Option<PathBuf>,
    pub extra_args: Vec<String>,
}

impl CurlCanaryMetricsConfig {
    pub fn new(endpoint_url: impl Into<String>) -> Result<Self> {
        let endpoint_url = endpoint_url.into();
        if endpoint_url.trim().is_empty() {
            return Err(anyhow!("endpoint_url must not be empty"));
        }
        if !endpoint_url.starts_with("http://") && !endpoint_url.starts_with("https://") {
            return Err(anyhow!("endpoint_url must start with http:// or https://"));
        }

        Ok(Self {
            endpoint_url,
            curl_bin: "curl".to_string(),
            bearer_token: None,
            cwd: None,
            extra_args: Vec::new(),
        })
    }
}

/// Pulls canary metrics from a JSON HTTP endpoint.
pub struct CurlCanaryMetricsSource<R>
where
    R: CommandRunner,
{
    config: CurlCanaryMetricsConfig,
    runner: R,
}

impl<R> CurlCanaryMetricsSource<R>
where
    R: CommandRunner,
{
    pub fn new(config: CurlCanaryMetricsConfig, runner: R) -> Result<Self> {
        if config.curl_bin.trim().is_empty() {
            return Err(anyhow!("curl_bin must not be empty"));
        }
        Ok(Self { config, runner })
    }

    fn build_args(&self) -> Vec<String> {
        let mut args = vec!["-fsS".to_string()];
        if let Some(token) = self.config.bearer_token.as_deref() {
            args.push("-H".to_string());
            args.push(format!("Authorization: Bearer {token}"));
        }
        args.extend(self.config.extra_args.iter().cloned());
        args.push(self.config.endpoint_url.clone());
        args
    }
}

#[async_trait(?Send)]
impl<R> CanaryMetricsSource for CurlCanaryMetricsSource<R>
where
    R: CommandRunner,
{
    async fn current_window(&self) -> Result<CanaryMetrics> {
        let args = self.build_args();
        let output = self
            .runner
            .run(&self.config.curl_bin, &args, self.config.cwd.as_ref())
            .await
            .context("failed executing curl metrics command")?;

        if output.status_code != 0 {
            return Err(anyhow!(
                "curl metrics command failed (exit={}): {}",
                output.status_code,
                output.stderr.trim()
            ));
        }

        let payload: CanaryMetricsPayload = serde_json::from_str(&output.stdout)
            .context("failed parsing telemetry metrics JSON payload")?;
        CanaryMetrics::new(
            payload.total_requests,
            payload.failed_requests,
            payload.p95_latency_ms,
        )
        .context("metrics payload failed canary invariants")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::cloudflare_cli::CommandOutput;

    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        output: CommandOutput,
    }

    impl RecordingRunner {
        fn success(stdout: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                output: CommandOutput {
                    status_code: 0,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            }
        }
    }

    #[async_trait(?Send)]
    impl CommandRunner for RecordingRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _cwd: Option<&PathBuf>,
        ) -> Result<CommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            Ok(self.output.clone())
        }
    }

    #[tokio::test]
    async fn metrics_source_builds_curl_call_and_parses_payload() {
        let mut cfg = CurlCanaryMetricsConfig::new("https://metrics.example/canary").unwrap();
        cfg.bearer_token = Some("token123".to_string());
        cfg.extra_args = vec!["--max-time".to_string(), "2".to_string()];
        let runner = RecordingRunner::success(
            r#"{"total_requests":120,"failed_requests":3,"p95_latency_ms":180}"#,
        );
        let source = CurlCanaryMetricsSource::new(cfg, runner).unwrap();

        let metrics = source.current_window().await.unwrap();
        assert_eq!(metrics.total_requests(), 120);
        assert_eq!(metrics.failed_requests(), 3);
        assert_eq!(metrics.p95_latency_ms(), 180);

        let calls = source.runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "curl");
        assert!(calls[0].1.contains(&"-H".to_string()));
        assert!(calls[0]
            .1
            .contains(&"Authorization: Bearer token123".to_string()));
    }

    #[tokio::test]
    async fn metrics_source_rejects_invalid_payload() {
        let cfg = CurlCanaryMetricsConfig::new("https://metrics.example/canary").unwrap();
        let runner = RecordingRunner::success(
            r#"{"total_requests":1,"failed_requests":2,"p95_latency_ms":10}"#,
        );
        let source = CurlCanaryMetricsSource::new(cfg, runner).unwrap();

        let err = source.current_window().await.expect_err("invalid metrics");
        assert!(err.to_string().contains("canary invariants"));
    }

    #[test]
    fn config_rejects_non_http_endpoint() {
        let err = CurlCanaryMetricsConfig::new("ftp://metrics.example").unwrap_err();
        assert!(err.to_string().contains("http:// or https://"));
    }
}
