#[cfg(target_arch = "wasm32")]
use std::num::{NonZeroU64, NonZeroU8};

#[cfg(any(test, target_arch = "wasm32"))]
use anyhow::{anyhow, Context, Result};
#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary::{
    BasisPoints, CanaryController, CanaryPlan, CanaryStage, CanaryThresholds, Percent,
};
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary_cron::{
    run_cloudflare_cron_event_with_runners, CloudflareCronEvent, CloudflareCronEventPayload,
};
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary_live::CloudflareCanaryWiringConfig;
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary_metrics::CurlCanaryMetricsConfig;
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary_orchestrator::NoopCanaryEventSink;
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary_tick::CloudflareOneShotCanaryConfig;
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::cloudflare_cli::{CloudflareWranglerConfig, CommandOutput, CommandRunner};
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::cloudflare_deploy_api::{
    build_deployments_api_body, parse_wrangler_versions_deploy,
};

#[cfg(any(test, target_arch = "wasm32"))]
const ENV_STABLE_VERSION_ID: &str = "ZEROCLAW_CANARY_STABLE_VERSION_ID";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_CANARY_VERSION_ID: &str = "ZEROCLAW_CANARY_CANARY_VERSION_ID";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_WORKER_NAME: &str = "ZEROCLAW_CANARY_WORKER_NAME";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_METRICS_ENDPOINT: &str = "ZEROCLAW_CANARY_METRICS_ENDPOINT";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_METRICS_BEARER: &str = "ZEROCLAW_CANARY_METRICS_BEARER_TOKEN";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_MESSAGE_PREFIX: &str = "ZEROCLAW_CANARY_MESSAGE_PREFIX";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_DRY_RUN: &str = "ZEROCLAW_CANARY_DRY_RUN";

#[cfg(any(test, target_arch = "wasm32"))]
const ENV_PLAN_STAGES: &str = "ZEROCLAW_CANARY_STAGES";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_PLAN_MAX_ERROR_BPS: &str = "ZEROCLAW_CANARY_MAX_ERROR_RATE_BPS";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_PLAN_MAX_P95_MS: &str = "ZEROCLAW_CANARY_MAX_P95_LATENCY_MS";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_PLAN_MIN_REQUESTS: &str = "ZEROCLAW_CANARY_MIN_REQUEST_COUNT";

#[cfg(any(test, target_arch = "wasm32"))]
const ENV_CLOUDFLARE_ACCOUNT_ID: &str = "CLOUDFLARE_ACCOUNT_ID";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_CLOUDFLARE_API_TOKEN: &str = "CLOUDFLARE_API_TOKEN";

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerCanarySettings {
    stable_version_id: String,
    canary_version_id: String,
    worker_name: String,
    metrics_endpoint: String,
    metrics_bearer_token: Option<String>,
    message_prefix: String,
    dry_run: bool,
    stages: Vec<(u8, u8)>,
    max_error_rate_bps: u16,
    max_p95_latency_ms: u32,
    min_request_count: u64,
    cloudflare_account_id: String,
    cloudflare_api_token: String,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl WorkerCanarySettings {
    fn from_lookup<F>(mut get: F) -> Result<Self>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let stable_version_id = required(&mut get, ENV_STABLE_VERSION_ID)?;
        let canary_version_id = required(&mut get, ENV_CANARY_VERSION_ID)?;
        let worker_name = required(&mut get, ENV_WORKER_NAME)?;
        let metrics_endpoint = required(&mut get, ENV_METRICS_ENDPOINT)?;
        let metrics_bearer_token = optional(&mut get, ENV_METRICS_BEARER);
        let message_prefix =
            optional(&mut get, ENV_MESSAGE_PREFIX).unwrap_or_else(|| "zeroclaw canary".to_string());
        let dry_run = parse_bool(optional(&mut get, ENV_DRY_RUN).as_deref()).unwrap_or(false);

        let stages = parse_stages(
            optional(&mut get, ENV_PLAN_STAGES)
                .unwrap_or_else(|| "10:1,25:1,100:1".to_string())
                .as_str(),
        )?;
        let max_error_rate_bps = optional(&mut get, ENV_PLAN_MAX_ERROR_BPS)
            .as_deref()
            .map(str::parse::<u16>)
            .transpose()
            .context("invalid ZEROCLAW_CANARY_MAX_ERROR_RATE_BPS")?
            .unwrap_or(100);
        let max_p95_latency_ms = optional(&mut get, ENV_PLAN_MAX_P95_MS)
            .as_deref()
            .map(str::parse::<u32>)
            .transpose()
            .context("invalid ZEROCLAW_CANARY_MAX_P95_LATENCY_MS")?
            .unwrap_or(500);
        let min_request_count = optional(&mut get, ENV_PLAN_MIN_REQUESTS)
            .as_deref()
            .map(str::parse::<u64>)
            .transpose()
            .context("invalid ZEROCLAW_CANARY_MIN_REQUEST_COUNT")?
            .unwrap_or(10);

        let cloudflare_account_id = required(&mut get, ENV_CLOUDFLARE_ACCOUNT_ID)?;
        let cloudflare_api_token = required(&mut get, ENV_CLOUDFLARE_API_TOKEN)?;

        Ok(Self {
            stable_version_id,
            canary_version_id,
            worker_name,
            metrics_endpoint,
            metrics_bearer_token,
            message_prefix,
            dry_run,
            stages,
            max_error_rate_bps,
            max_p95_latency_ms,
            min_request_count,
            cloudflare_account_id,
            cloudflare_api_token,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn controller(&self) -> Result<CanaryController> {
        let stages = self
            .stages
            .iter()
            .map(|(traffic, intervals)| {
                Ok(CanaryStage::new(
                    Percent::new(*traffic)?,
                    NonZeroU8::new(*intervals)
                        .ok_or_else(|| anyhow!("healthy interval count must be > 0"))?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let thresholds = CanaryThresholds::new(
            BasisPoints::new(self.max_error_rate_bps)?,
            self.max_p95_latency_ms,
            NonZeroU64::new(self.min_request_count)
                .ok_or_else(|| anyhow!("min request count must be > 0"))?,
        );
        let plan = CanaryPlan::new(stages, thresholds)?;
        Ok(CanaryController::new(plan))
    }

    #[cfg(target_arch = "wasm32")]
    fn runtime_config(&self) -> Result<CloudflareOneShotCanaryConfig> {
        let mut wrangler = CloudflareWranglerConfig::new(self.worker_name.clone())?;
        wrangler.message_prefix = self.message_prefix.clone();
        wrangler.dry_run = self.dry_run;
        let wiring = CloudflareCanaryWiringConfig::new(
            self.stable_version_id.clone(),
            self.canary_version_id.clone(),
            wrangler,
        )?;
        let mut metrics = CurlCanaryMetricsConfig::new(self.metrics_endpoint.clone())?;
        metrics.bearer_token = self.metrics_bearer_token.clone();
        Ok(CloudflareOneShotCanaryConfig::new(wiring, metrics))
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn required<F>(get: &mut F, key: &str) -> Result<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let value = get(key).ok_or_else(|| anyhow!("missing required env var {key}"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("env var {key} must not be empty"));
    }
    Ok(trimmed.to_string())
}

#[cfg(any(test, target_arch = "wasm32"))]
fn optional<F>(get: &mut F, key: &str) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let value = get(key)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn parse_bool(value: Option<&str>) -> Option<bool> {
    let raw = value?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn parse_stages(raw: &str) -> Result<Vec<(u8, u8)>> {
    let mut stages = Vec::new();
    for entry in raw.split(',') {
        let item = entry.trim();
        if item.is_empty() {
            continue;
        }
        let (traffic, intervals) = item
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid stage spec '{item}', expected traffic:intervals"))?;
        let traffic = traffic
            .parse::<u8>()
            .with_context(|| format!("invalid traffic percent in '{item}'"))?;
        let intervals = intervals
            .parse::<u8>()
            .with_context(|| format!("invalid healthy interval count in '{item}'"))?;
        stages.push((traffic, intervals));
    }
    if stages.is_empty() {
        return Err(anyhow!("at least one canary stage is required"));
    }
    Ok(stages)
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Serialize)]
struct TickSummary {
    decision: String,
    applied_canary_percent: Option<u8>,
    total_requests: u64,
    failed_requests: u64,
    p95_latency_ms: u32,
}

#[cfg(target_arch = "wasm32")]
mod wasm_runtime {
    use super::*;

    use async_trait::async_trait;
    use worker::{
        console_error, console_log, event, Context, Env, Fetch, Headers, Method, Request,
        RequestInit, Response, Result, ScheduleContext, ScheduledEvent,
    };

    const ENV_OPENROUTER_API_KEY: &str = "OPENROUTER_API_KEY";
    const ENV_OPENROUTER_MODEL: &str = "ZEROCLAW_OPENROUTER_MODEL";
    const ENV_OPENROUTER_REFERER: &str = "OPENROUTER_HTTP_REFERER";
    const ENV_OPENROUTER_TITLE: &str = "OPENROUTER_X_TITLE";

    #[derive(Debug, Deserialize)]
    struct ChatRequest {
        message: String,
        model: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct ChatResponse {
        model: String,
        reply: String,
    }

    #[derive(Debug, Deserialize)]
    struct OpenRouterResponse {
        choices: Vec<OpenRouterChoice>,
    }

    #[derive(Debug, Deserialize)]
    struct OpenRouterChoice {
        message: OpenRouterMessage,
    }

    #[derive(Debug, Deserialize)]
    struct OpenRouterMessage {
        content: String,
    }

    struct WorkerMetricsRunner;

    #[async_trait(?Send)]
    impl CommandRunner for WorkerMetricsRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _cwd: Option<&std::path::PathBuf>,
        ) -> anyhow::Result<CommandOutput> {
            if program != "curl" {
                return Err(anyhow!("unsupported metrics program '{}'", program));
            }

            let mut auth_header: Option<String> = None;
            let mut url: Option<String> = None;
            let mut i = 0usize;
            while i < args.len() {
                match args[i].as_str() {
                    "-H" => {
                        if let Some(value) = args.get(i + 1) {
                            if value.to_ascii_lowercase().starts_with("authorization:") {
                                auth_header = Some(value.clone());
                            }
                        }
                        i += 2;
                    }
                    token if token.starts_with("http://") || token.starts_with("https://") => {
                        url = Some(token.to_string());
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            let url = url.ok_or_else(|| anyhow!("curl args missing endpoint url"))?;
            let mut init = RequestInit::new();
            init.with_method(Method::Get);
            let headers = Headers::new();
            if let Some(header) = auth_header.as_deref() {
                if let Some((name, value)) = header.split_once(':') {
                    headers
                        .set(name.trim(), value.trim())
                        .map_err(|e| anyhow!("failed to set metrics auth header: {e}"))?;
                }
            }
            init.with_headers(headers);
            let req = Request::new_with_init(&url, &init)
                .map_err(|e| anyhow!("failed to build metrics request: {e}"))?;
            let mut resp = Fetch::Request(req)
                .send()
                .await
                .map_err(|e| anyhow!("metrics fetch failed: {e}"))?;
            let http_status = resp.status_code();
            let body = resp
                .text()
                .await
                .map_err(|e| anyhow!("failed reading metrics body: {e}"))?;
            if (200..=299).contains(&http_status) {
                Ok(CommandOutput {
                    status_code: 0,
                    stdout: body,
                    stderr: String::new(),
                })
            } else {
                Ok(CommandOutput {
                    status_code: 22,
                    stdout: String::new(),
                    stderr: format!("http {}: {}", http_status, body),
                })
            }
        }
    }

    struct WorkerDeployApiRunner {
        account_id: String,
        api_token: String,
    }

    #[async_trait(?Send)]
    impl CommandRunner for WorkerDeployApiRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _cwd: Option<&std::path::PathBuf>,
        ) -> anyhow::Result<CommandOutput> {
            let deploy = parse_wrangler_versions_deploy(program, args)
                .map_err(|e| anyhow!("failed parsing wrangler deploy command: {e}"))?;
            let endpoint = format!(
                "https://api.cloudflare.com/client/v4/accounts/{}/workers/scripts/{}/deployments",
                self.account_id, deploy.worker_name
            );
            let payload = build_deployments_api_body(&deploy).to_string();

            let mut init = RequestInit::new();
            init.with_method(Method::Post);
            let headers = Headers::new();
            headers
                .set("Authorization", &format!("Bearer {}", self.api_token))
                .map_err(|e| anyhow!("failed setting auth header: {e}"))?;
            headers
                .set("Content-Type", "application/json")
                .map_err(|e| anyhow!("failed setting content-type header: {e}"))?;
            init.with_headers(headers);
            init.with_body(Some(payload.into()));

            let req = Request::new_with_init(&endpoint, &init)
                .map_err(|e| anyhow!("failed to build deployments request: {e}"))?;
            let mut resp = Fetch::Request(req)
                .send()
                .await
                .map_err(|e| anyhow!("deployments request failed: {e}"))?;
            let status = resp.status_code();
            let body = resp
                .text()
                .await
                .map_err(|e| anyhow!("failed reading deployments response: {e}"))?;

            if (200..=299).contains(&status) {
                Ok(CommandOutput {
                    status_code: 0,
                    stdout: body,
                    stderr: String::new(),
                })
            } else {
                Ok(CommandOutput {
                    status_code: 1,
                    stdout: String::new(),
                    stderr: format!("cloudflare api status {}: {}", status, body),
                })
            }
        }
    }

    async fn run_one_tick(payload: CloudflareCronEventPayload, env: &Env) -> Result<TickSummary> {
        let settings =
            WorkerCanarySettings::from_lookup(|key| env.var(key).ok().map(|v| v.to_string()))
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let event = CloudflareCronEvent::from_payload(payload)
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let controller = settings
            .controller()
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let config = settings
            .runtime_config()
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let sink = Arc::new(NoopCanaryEventSink);
        let metrics_runner = WorkerMetricsRunner;
        let traffic_runner = WorkerDeployApiRunner {
            account_id: settings.cloudflare_account_id,
            api_token: settings.cloudflare_api_token,
        };
        let exec = run_cloudflare_cron_event_with_runners(
            event,
            controller,
            sink,
            config,
            metrics_runner,
            traffic_runner,
        )
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

        let applied_canary_percent = exec
            .outcome
            .applied_update
            .as_ref()
            .map(|u| u.canary_traffic().get());

        Ok(TickSummary {
            decision: format!("{:?}", exec.outcome.decision),
            applied_canary_percent,
            total_requests: exec.outcome.metrics.total_requests(),
            failed_requests: exec.outcome.metrics.failed_requests(),
            p95_latency_ms: exec.outcome.metrics.p95_latency_ms(),
        })
    }

    async fn run_chat(mut req: Request, env: &Env) -> Result<Response> {
        let chat_req: ChatRequest = req
            .json()
            .await
            .map_err(|e| worker::Error::RustError(format!("invalid chat payload: {e}")))?;
        if chat_req.message.trim().is_empty() {
            return Response::error("message must not be empty", 400);
        }

        let api_key = env
            .var(ENV_OPENROUTER_API_KEY)
            .map(|v| v.to_string())
            .map_err(|_| worker::Error::RustError("missing OPENROUTER_API_KEY".to_string()))?;
        let model = chat_req
            .model
            .or_else(|| env.var(ENV_OPENROUTER_MODEL).ok().map(|v| v.to_string()))
            .unwrap_or_else(|| "openai/gpt-4o-mini".to_string());

        let payload = serde_json::json!({
            "model": model,
            "messages": [
                {"role": "system", "content": "You are ZeroClaw Edge demo. Be concise and action-oriented."},
                {"role": "user", "content": chat_req.message}
            ]
        });

        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        let headers = Headers::new();
        headers
            .set("Authorization", &format!("Bearer {api_key}"))
            .map_err(|e| worker::Error::RustError(format!("failed setting auth header: {e}")))?;
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| worker::Error::RustError(format!("failed setting content-type: {e}")))?;
        if let Ok(referer) = env.var(ENV_OPENROUTER_REFERER) {
            headers
                .set("HTTP-Referer", &referer.to_string())
                .map_err(|e| worker::Error::RustError(format!("failed setting referer: {e}")))?;
        }
        if let Ok(title) = env.var(ENV_OPENROUTER_TITLE) {
            headers
                .set("X-Title", &title.to_string())
                .map_err(|e| worker::Error::RustError(format!("failed setting title: {e}")))?;
        }
        init.with_headers(headers);
        init.with_body(Some(payload.to_string().into()));

        let openrouter_req =
            Request::new_with_init("https://openrouter.ai/api/v1/chat/completions", &init)
                .map_err(|e| {
                    worker::Error::RustError(format!("failed to build openrouter request: {e}"))
                })?;
        let mut openrouter_resp = Fetch::Request(openrouter_req)
            .send()
            .await
            .map_err(|e| worker::Error::RustError(format!("openrouter request failed: {e}")))?;
        let status = openrouter_resp.status_code();
        let body = openrouter_resp.text().await.map_err(|e| {
            worker::Error::RustError(format!("failed reading openrouter response: {e}"))
        })?;
        if !(200..=299).contains(&status) {
            return Response::error(format!("openrouter error status {}: {}", status, body), 502);
        }

        let parsed: OpenRouterResponse = serde_json::from_str(&body)
            .map_err(|e| worker::Error::RustError(format!("invalid openrouter payload: {e}")))?;
        let reply = parsed
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| {
                worker::Error::RustError("openrouter returned no response choices".to_string())
            })?;
        Response::from_json(&ChatResponse { model, reply })
    }

    #[event(fetch)]
    pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        match (req.method(), req.path().as_str()) {
            (Method::Get, "/healthz") => Response::ok("ok"),
            (Method::Post, "/chat") => run_chat(req, &env).await,
            (Method::Post, "/tick") => {
                let payload = CloudflareCronEventPayload {
                    cron: "manual".to_string(),
                    scheduled_time: worker::Date::now().as_millis(),
                    r#type: Some("scheduled".to_string()),
                };
                match run_one_tick(payload, &env).await {
                    Ok(summary) => Response::from_json(&summary),
                    Err(err) => Response::error(format!("tick failed: {err}"), 500),
                }
            }
            _ => Response::error("Not Found", 404),
        }
    }

    #[event(scheduled)]
    pub async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        let payload = CloudflareCronEventPayload {
            cron: event.cron(),
            scheduled_time: (event.schedule().max(1.0)) as u64,
            r#type: Some(event.ty()),
        };
        match run_one_tick(payload, &env).await {
            Ok(summary) => {
                console_log!(
                    "zeroclaw canary tick decision={} applied={:?} req={} fail={} p95={}",
                    summary.decision,
                    summary.applied_canary_percent,
                    summary.total_requests,
                    summary.failed_requests,
                    summary.p95_latency_ms
                );
            }
            Err(err) => {
                console_error!("zeroclaw canary tick failed: {}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_stages_accepts_csv_pairs() {
        let parsed = parse_stages("10:1,25:2,100:3").unwrap();
        assert_eq!(parsed, vec![(10, 1), (25, 2), (100, 3)]);
    }

    #[test]
    fn settings_require_non_empty_required_fields() {
        let mut env = HashMap::<String, String>::new();
        env.insert(ENV_STABLE_VERSION_ID.to_string(), "stable-v1".to_string());
        env.insert(ENV_CANARY_VERSION_ID.to_string(), "canary-v2".to_string());
        env.insert(ENV_WORKER_NAME.to_string(), "edge-worker".to_string());
        env.insert(
            ENV_METRICS_ENDPOINT.to_string(),
            "https://metrics.example/canary".to_string(),
        );
        env.insert(ENV_CLOUDFLARE_ACCOUNT_ID.to_string(), "acc".to_string());
        env.insert(ENV_CLOUDFLARE_API_TOKEN.to_string(), "token".to_string());

        let settings = WorkerCanarySettings::from_lookup(|k| env.get(k).cloned()).unwrap();
        assert_eq!(settings.worker_name, "edge-worker");
        assert_eq!(settings.stages, vec![(10, 1), (25, 1), (100, 1)]);
        assert_eq!(settings.max_error_rate_bps, 100);
        assert!(!settings.dry_run);
    }
}
