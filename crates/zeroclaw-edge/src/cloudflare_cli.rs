//! Cloudflare CLI (`wrangler`) traffic split adapter.
//!
//! This module provides a production-oriented `CanaryTrafficClient`
//! implementation that applies canary traffic updates through:
//! `wrangler versions deploy`.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

use crate::canary::{CloudflareTrafficUpdate, TrafficPercent};
use crate::canary_orchestrator::CanaryTrafficClient;

/// Minimal command execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Command execution boundary used for deterministic tests.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[String], cwd: Option<&PathBuf>) -> Result<CommandOutput>;
}

/// Real command runner using `std::process::Command`.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[String], cwd: Option<&PathBuf>) -> Result<CommandOutput> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }

        let output = cmd
            .output()
            .with_context(|| format!("failed to run command: {program} {}", args.join(" ")))?;
        let status_code = output.status.code().unwrap_or(-1);
        Ok(CommandOutput {
            status_code,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Configuration for wrangler traffic split operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareWranglerConfig {
    pub worker_name: String,
    pub wrangler_bin: String,
    pub wrangler_bin_args: Vec<String>,
    pub config_path: Option<String>,
    pub env: Option<String>,
    pub cwd: Option<PathBuf>,
    pub message_prefix: String,
    pub dry_run: bool,
    pub use_legacy_versions_flag: bool,
    pub extra_args: Vec<String>,
}

impl CloudflareWranglerConfig {
    pub fn new(worker_name: impl Into<String>) -> Result<Self> {
        let worker_name = worker_name.into();
        if worker_name.trim().is_empty() {
            return Err(anyhow!("worker_name must not be empty"));
        }

        Ok(Self {
            worker_name,
            wrangler_bin: "wrangler".to_string(),
            wrangler_bin_args: Vec::new(),
            config_path: None,
            env: None,
            cwd: None,
            message_prefix: "zeroclaw canary".to_string(),
            dry_run: false,
            use_legacy_versions_flag: false,
            extra_args: Vec::new(),
        })
    }
}

/// `CanaryTrafficClient` implementation for Cloudflare Workers via Wrangler.
pub struct CloudflareWranglerTrafficClient<R>
where
    R: CommandRunner,
{
    config: CloudflareWranglerConfig,
    runner: R,
}

impl<R> CloudflareWranglerTrafficClient<R>
where
    R: CommandRunner,
{
    pub fn new(config: CloudflareWranglerConfig, runner: R) -> Result<Self> {
        if config.wrangler_bin.trim().is_empty() {
            return Err(anyhow!("wrangler_bin must not be empty"));
        }
        if config.worker_name.trim().is_empty() {
            return Err(anyhow!("worker_name must not be empty"));
        }
        Ok(Self { config, runner })
    }

    fn build_versions_deploy_args(&self, update: &CloudflareTrafficUpdate) -> Vec<String> {
        let canary: TrafficPercent = update.canary_traffic();
        let stable = update.stable_traffic_percent();
        let message = format!(
            "{} stable={} canary={} split={}%-{}%",
            self.config.message_prefix,
            update.stable_version_id(),
            update.canary_version_id(),
            stable,
            canary.get()
        );

        let mut args = self.config.wrangler_bin_args.clone();
        args.extend([
            "versions".to_string(),
            "deploy".to_string(),
            format!("{}@{}%", update.canary_version_id(), canary.get()),
            format!("{}@{}%", update.stable_version_id(), stable),
            "--name".to_string(),
            self.config.worker_name.clone(),
            "--message".to_string(),
            message,
            "--yes".to_string(),
        ]);

        if self.config.use_legacy_versions_flag {
            args.push("--x-versions".to_string());
        }
        if self.config.dry_run {
            args.push("--dry-run".to_string());
        }
        if let Some(config_path) = self.config.config_path.as_deref() {
            args.push("--config".to_string());
            args.push(config_path.to_string());
        }
        if let Some(env) = self.config.env.as_deref() {
            args.push("--env".to_string());
            args.push(env.to_string());
        }

        args.extend(self.config.extra_args.iter().cloned());
        args
    }
}

#[async_trait]
impl<R> CanaryTrafficClient for CloudflareWranglerTrafficClient<R>
where
    R: CommandRunner,
{
    async fn apply_split(&self, update: CloudflareTrafficUpdate) -> Result<()> {
        let args = self.build_versions_deploy_args(&update);
        let output = self
            .runner
            .run(&self.config.wrangler_bin, &args, self.config.cwd.as_ref())
            .context("wrangler versions deploy command failed to execute")?;

        if output.status_code != 0 {
            return Err(anyhow!(
                "wrangler versions deploy failed (exit={}): {}",
                output.status_code,
                output.stderr.trim()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::canary::TrafficPercent;

    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>, Option<PathBuf>)>>,
        output: Mutex<CommandOutput>,
    }

    impl RecordingRunner {
        fn success() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                output: Mutex::new(CommandOutput {
                    status_code: 0,
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                }),
            }
        }

        fn failure(stderr: &str, status_code: i32) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                output: Mutex::new(CommandOutput {
                    status_code,
                    stdout: String::new(),
                    stderr: stderr.to_string(),
                }),
            }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            cwd: Option<&PathBuf>,
        ) -> Result<CommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec(), cwd.cloned()));
            Ok(self.output.lock().unwrap().clone())
        }
    }

    fn sample_update(canary_percent: u8) -> CloudflareTrafficUpdate {
        CloudflareTrafficUpdate::new(
            "stable-v1",
            "canary-v2",
            TrafficPercent::new(canary_percent).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn apply_split_builds_expected_versions_deploy_command() {
        let mut cfg = CloudflareWranglerConfig::new("my-worker").unwrap();
        cfg.config_path = Some("wrangler.toml".to_string());
        cfg.env = Some("production".to_string());
        cfg.cwd = Some(PathBuf::from("/tmp/worker-project"));
        cfg.message_prefix = "zc canary".to_string();
        cfg.dry_run = true;
        cfg.use_legacy_versions_flag = true;
        cfg.extra_args = vec!["--experimental-auto-create=false".to_string()];

        let runner = RecordingRunner::success();
        let client = CloudflareWranglerTrafficClient::new(cfg, runner).unwrap();
        client.apply_split(sample_update(25)).await.unwrap();

        let calls = client.runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "wrangler");
        assert_eq!(
            calls[0].2.as_ref().unwrap(),
            &PathBuf::from("/tmp/worker-project")
        );

        let args = &calls[0].1;
        assert!(args.starts_with(&[
            "versions".to_string(),
            "deploy".to_string(),
            "canary-v2@25%".to_string(),
            "stable-v1@75%".to_string(),
        ]));
        assert!(args.contains(&"--name".to_string()));
        assert!(args.contains(&"my-worker".to_string()));
        assert!(args.contains(&"--config".to_string()));
        assert!(args.contains(&"wrangler.toml".to_string()));
        assert!(args.contains(&"--env".to_string()));
        assert!(args.contains(&"production".to_string()));
        assert!(args.contains(&"--yes".to_string()));
        assert!(args.contains(&"--dry-run".to_string()));
        assert!(args.contains(&"--x-versions".to_string()));
    }

    #[tokio::test]
    async fn apply_split_supports_npx_wrangler_invocation() {
        let mut cfg = CloudflareWranglerConfig::new("my-worker").unwrap();
        cfg.wrangler_bin = "npx".to_string();
        cfg.wrangler_bin_args = vec!["--yes".to_string(), "wrangler".to_string()];

        let runner = RecordingRunner::success();
        let client = CloudflareWranglerTrafficClient::new(cfg, runner).unwrap();
        client.apply_split(sample_update(10)).await.unwrap();

        let calls = client.runner.calls.lock().unwrap();
        let args = &calls[0].1;
        assert_eq!(calls[0].0, "npx");
        assert_eq!(args[0], "--yes");
        assert_eq!(args[1], "wrangler");
        assert_eq!(args[2], "versions");
        assert_eq!(args[3], "deploy");
    }

    #[tokio::test]
    async fn apply_split_supports_full_rollback_to_zero_percent_canary() {
        let cfg = CloudflareWranglerConfig::new("my-worker").unwrap();
        let runner = RecordingRunner::success();
        let client = CloudflareWranglerTrafficClient::new(cfg, runner).unwrap();
        client.apply_split(sample_update(0)).await.unwrap();

        let calls = client.runner.calls.lock().unwrap();
        let args = &calls[0].1;
        assert!(args.contains(&"canary-v2@0%".to_string()));
        assert!(args.contains(&"stable-v1@100%".to_string()));
    }

    #[tokio::test]
    async fn apply_split_propagates_wrangler_failures() {
        let cfg = CloudflareWranglerConfig::new("my-worker").unwrap();
        let runner = RecordingRunner::failure("auth failed", 1);
        let client = CloudflareWranglerTrafficClient::new(cfg, runner).unwrap();

        let err = client
            .apply_split(sample_update(50))
            .await
            .expect_err("failed wrangler command should propagate");
        assert!(err.to_string().contains("auth failed"));
    }

    #[test]
    fn config_validation_rejects_empty_values() {
        let err = CloudflareWranglerConfig::new("   ").unwrap_err();
        assert!(err.to_string().contains("worker_name must not be empty"));
    }
}
