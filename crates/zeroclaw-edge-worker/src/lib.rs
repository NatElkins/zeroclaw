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
#[cfg(any(test, target_arch = "wasm32"))]
use zeroclaw_edge::canary_cron::CloudflareCronEventPayload;
#[cfg(target_arch = "wasm32")]
use zeroclaw_edge::canary_cron::{run_cloudflare_cron_event_with_runners, CloudflareCronEvent};
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
#[cfg(target_arch = "wasm32")]
const ENV_CANARY_DRILL_TOKEN: &str = "ZEROCLAW_CANARY_DRILL_TOKEN";
#[cfg(target_arch = "wasm32")]
const ENV_CANARY_AUDIT_MAX_RECORDS: &str = "ZEROCLAW_CANARY_AUDIT_MAX_RECORDS";
#[cfg(any(test, target_arch = "wasm32"))]
const DEFAULT_CANARY_AUDIT_MAX_RECORDS: usize = 500;
#[cfg(any(test, target_arch = "wasm32"))]
const MAX_CANARY_AUDIT_MAX_RECORDS: usize = 5_000;
#[cfg(any(test, target_arch = "wasm32"))]
const DEFAULT_CANARY_AUDIT_RECENT_LIMIT: usize = 20;
#[cfg(any(test, target_arch = "wasm32"))]
const MAX_CANARY_AUDIT_RECENT_LIMIT: usize = 200;

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

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanaryDrillScenario {
    Promote,
    Hold,
    Rollback,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CanaryAuditRecord {
    recorded_at_ms: u64,
    cron: String,
    event_type: Option<String>,
    dry_run: bool,
    stable_version_id: String,
    canary_version_id: String,
    decision: String,
    applied_canary_percent: Option<u8>,
    total_requests: u64,
    failed_requests: u64,
    p95_latency_ms: u32,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CanaryAuditRecentResponse {
    records: Vec<CanaryAuditRecord>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CanaryAuditAppendRequest {
    record: CanaryAuditRecord,
    max_records: usize,
}

#[cfg(any(test, target_arch = "wasm32"))]
fn parse_canary_audit_max_records(raw: Option<&str>) -> Result<usize> {
    let parsed = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<usize>)
        .transpose()
        .context("invalid ZEROCLAW_CANARY_AUDIT_MAX_RECORDS")?
        .unwrap_or(DEFAULT_CANARY_AUDIT_MAX_RECORDS);
    if parsed == 0 {
        return Err(anyhow!(
            "ZEROCLAW_CANARY_AUDIT_MAX_RECORDS must be greater than zero"
        ));
    }
    Ok(parsed.min(MAX_CANARY_AUDIT_MAX_RECORDS))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn parse_canary_audit_recent_limit(raw: Option<&str>) -> Result<usize> {
    let parsed = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<usize>)
        .transpose()
        .context("invalid canary audit limit")?
        .unwrap_or(DEFAULT_CANARY_AUDIT_RECENT_LIMIT);
    if parsed == 0 {
        return Err(anyhow!("canary audit limit must be greater than zero"));
    }
    Ok(parsed.min(MAX_CANARY_AUDIT_RECENT_LIMIT))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn canary_audit_recent_limit_from_url(url: &str) -> Result<usize> {
    let query = url.split_once('?').map(|(_, query)| query);
    let Some(query) = query else {
        return parse_canary_audit_recent_limit(None);
    };
    let limit = query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "limit").then_some(value)
    });
    parse_canary_audit_recent_limit(limit)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn build_canary_audit_record(
    settings: &WorkerCanarySettings,
    payload: &CloudflareCronEventPayload,
    summary: &TickSummary,
    recorded_at_ms: u64,
) -> CanaryAuditRecord {
    CanaryAuditRecord {
        recorded_at_ms,
        cron: payload.cron.clone(),
        event_type: payload.r#type.clone(),
        dry_run: settings.dry_run,
        stable_version_id: settings.stable_version_id.clone(),
        canary_version_id: settings.canary_version_id.clone(),
        decision: summary.decision.clone(),
        applied_canary_percent: summary.applied_canary_percent,
        total_requests: summary.total_requests,
        failed_requests: summary.failed_requests,
        p95_latency_ms: summary.p95_latency_ms,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
impl CanaryDrillScenario {
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "promote" => Ok(Self::Promote),
            "hold" => Ok(Self::Hold),
            "rollback" => Ok(Self::Rollback),
            other => Err(anyhow!(
                "unsupported canary drill scenario '{other}'; expected promote|hold|rollback"
            )),
        }
    }

    fn as_slug(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Hold => "hold",
            Self::Rollback => "rollback",
        }
    }

    fn metrics_payload(self) -> serde_json::Value {
        match self {
            // Healthy window that should promote.
            Self::Promote => serde_json::json!({
                "total_requests": 120,
                "failed_requests": 0,
                "p95_latency_ms": 120
            }),
            // Insufficient volume should hold at current stage.
            Self::Hold => serde_json::json!({
                "total_requests": 5,
                "failed_requests": 0,
                "p95_latency_ms": 120
            }),
            // High error rate should trigger rollback.
            Self::Rollback => serde_json::json!({
                "total_requests": 120,
                "failed_requests": 25,
                "p95_latency_ms": 120
            }),
        }
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
const DEFAULT_CHAT_HISTORY_MESSAGES: usize = 12;
#[cfg(any(test, target_arch = "wasm32"))]
const MAX_CHAT_HISTORY_MESSAGES: usize = 100;
#[cfg(any(test, target_arch = "wasm32"))]
const MAX_CHAT_SESSION_ID_LENGTH: usize = 128;
#[cfg(any(test, target_arch = "wasm32"))]
const SYSTEM_PROMPT: &str = "You are ZeroClaw Edge demo. Be concise and action-oriented.";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_LONG_TERM_MEMORY_BASE_URL: &str = "ZEROCLAW_LONG_TERM_MEMORY_BASE_URL";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_LONG_TERM_MEMORY_AUTH_TOKEN: &str = "ZEROCLAW_LONG_TERM_MEMORY_AUTH_TOKEN";
#[cfg(any(test, target_arch = "wasm32"))]
const ENV_LONG_TERM_MEMORY_RECALL_LIMIT: &str = "ZEROCLAW_LONG_TERM_MEMORY_RECALL_LIMIT";
#[cfg(any(test, target_arch = "wasm32"))]
const DEFAULT_LONG_TERM_MEMORY_RECALL_LIMIT: usize = 6;
#[cfg(any(test, target_arch = "wasm32"))]
const MAX_LONG_TERM_MEMORY_RECALL_LIMIT: usize = 25;

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ChatRole {
    User,
    Assistant,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl ChatRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChatMessage {
    role: ChatRole,
    content: String,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl ChatMessage {
    fn new(role: ChatRole, content: impl Into<String>) -> Result<Self> {
        let content = content.into();
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("chat message content must not be empty"));
        }
        Ok(Self {
            role,
            content: trimmed.to_string(),
        })
    }

    fn to_openrouter_value(&self) -> serde_json::Value {
        serde_json::json!({
            "role": self.role.as_str(),
            "content": self.content,
        })
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MemoryContextEntry {
    key: String,
    category: String,
    content: String,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LongTermMemorySettings {
    base_url: String,
    auth_token: Option<String>,
    recall_limit: usize,
}

#[cfg(any(test, target_arch = "wasm32"))]
fn parse_long_term_memory_settings<F>(mut get: F) -> Result<Option<LongTermMemorySettings>>
where
    F: FnMut(&str) -> Option<String>,
{
    let Some(base_url) = optional(&mut get, ENV_LONG_TERM_MEMORY_BASE_URL) else {
        return Ok(None);
    };
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        return Err(anyhow!(
            "{ENV_LONG_TERM_MEMORY_BASE_URL} must start with http:// or https://"
        ));
    }
    let auth_token = optional(&mut get, ENV_LONG_TERM_MEMORY_AUTH_TOKEN);
    let recall_limit = optional(&mut get, ENV_LONG_TERM_MEMORY_RECALL_LIMIT)
        .as_deref()
        .map(str::parse::<usize>)
        .transpose()
        .context("invalid ZEROCLAW_LONG_TERM_MEMORY_RECALL_LIMIT")?
        .unwrap_or(DEFAULT_LONG_TERM_MEMORY_RECALL_LIMIT);
    if recall_limit == 0 {
        return Err(anyhow!(
            "{ENV_LONG_TERM_MEMORY_RECALL_LIMIT} must be greater than zero"
        ));
    }
    Ok(Some(LongTermMemorySettings {
        base_url: base_url.trim_end_matches('/').to_string(),
        auth_token,
        recall_limit: recall_limit.min(MAX_LONG_TERM_MEMORY_RECALL_LIMIT),
    }))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn truncate_chars(raw: &str, max_chars: usize) -> String {
    raw.chars().take(max_chars).collect()
}

#[cfg(any(test, target_arch = "wasm32"))]
fn render_memory_context_prompt(entries: &[MemoryContextEntry]) -> Option<String> {
    let mut lines = Vec::new();
    for entry in entries {
        let content = entry.content.trim();
        if content.is_empty() {
            continue;
        }
        let content = truncate_chars(content, 240);
        let key = entry.key.trim();
        let category = entry.category.trim();
        if !category.is_empty() && !key.is_empty() {
            lines.push(format!("- [{category}] {key}: {content}"));
        } else if !key.is_empty() {
            lines.push(format!("- {key}: {content}"));
        } else if !category.is_empty() {
            lines.push(format!("- [{category}] {content}"));
        } else {
            lines.push(format!("- {content}"));
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(format!(
            "Relevant long-term memory from previous sessions:\n{}",
            lines.join("\n")
        ))
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn normalize_session_id(raw: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let session_id = raw.trim();
    if session_id.is_empty() {
        return Ok(None);
    }
    if session_id.len() > MAX_CHAT_SESSION_ID_LENGTH {
        return Err(anyhow!(
            "session_id exceeds {} characters",
            MAX_CHAT_SESSION_ID_LENGTH
        ));
    }
    if !session_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
    {
        return Err(anyhow!(
            "session_id may only contain ASCII letters, digits, '-', '_', ':' or '.'"
        ));
    }
    Ok(Some(session_id.to_string()))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn parse_chat_history_limit(raw: Option<&str>) -> Result<usize> {
    let parsed = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<usize>)
        .transpose()
        .context("invalid ZEROCLAW_CHAT_HISTORY_MESSAGES")?
        .unwrap_or(DEFAULT_CHAT_HISTORY_MESSAGES);

    if parsed == 0 {
        return Err(anyhow!(
            "ZEROCLAW_CHAT_HISTORY_MESSAGES must be greater than zero"
        ));
    }

    Ok(parsed.min(MAX_CHAT_HISTORY_MESSAGES))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn trim_chat_history(mut history: Vec<ChatMessage>, max_messages: usize) -> Vec<ChatMessage> {
    if max_messages == 0 {
        return Vec::new();
    }
    if history.len() > max_messages {
        history = history.split_off(history.len() - max_messages);
    }
    history
}

#[cfg(any(test, target_arch = "wasm32"))]
fn append_and_trim_chat_history(
    mut existing: Vec<ChatMessage>,
    incoming: Vec<ChatMessage>,
    max_messages: usize,
) -> Vec<ChatMessage> {
    existing.extend(incoming);
    trim_chat_history(existing, max_messages)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn build_openrouter_messages(
    history: &[ChatMessage],
    user_message: &str,
    long_term_memory: &[MemoryContextEntry],
) -> Result<Vec<serde_json::Value>> {
    let user_message = ChatMessage::new(ChatRole::User, user_message)?;
    let mut messages = Vec::with_capacity(history.len() + long_term_memory.len() + 2);
    messages.push(serde_json::json!({
        "role": "system",
        "content": SYSTEM_PROMPT,
    }));
    if let Some(memory_prompt) = render_memory_context_prompt(long_term_memory) {
        messages.push(serde_json::json!({
            "role": "system",
            "content": memory_prompt,
        }));
    }
    messages.extend(history.iter().map(ChatMessage::to_openrouter_value));
    messages.push(user_message.to_openrouter_value());
    Ok(messages)
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, Serialize)]
struct TickSummary {
    decision: String,
    applied_canary_percent: Option<u8>,
    total_requests: u64,
    failed_requests: u64,
    p95_latency_ms: u32,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Serialize)]
struct DrillTickSummary {
    scenario: String,
    dry_run: bool,
    tick: TickSummary,
}

#[cfg(target_arch = "wasm32")]
mod wasm_runtime {
    use super::*;

    use async_trait::async_trait;
    use worker::{
        console_error, console_log, durable_object, event, wasm_bindgen, Context, DurableObject,
        Env, Fetch, Headers, Method, Request, RequestInit, Response, Result, ScheduleContext,
        ScheduledEvent, State, Stub,
    };

    const ENV_OPENROUTER_API_KEY: &str = "OPENROUTER_API_KEY";
    const ENV_OPENROUTER_MODEL: &str = "ZEROCLAW_OPENROUTER_MODEL";
    const ENV_OPENROUTER_REFERER: &str = "OPENROUTER_HTTP_REFERER";
    const ENV_OPENROUTER_TITLE: &str = "OPENROUTER_X_TITLE";
    const ENV_CHAT_HISTORY_MESSAGES: &str = "ZEROCLAW_CHAT_HISTORY_MESSAGES";
    const CHAT_SESSIONS_BINDING: &str = "ZEROCLAW_CHAT_SESSIONS";
    const CHAT_HISTORY_STORAGE_KEY: &str = "messages";
    const CHAT_DO_INTERNAL_ORIGIN: &str = "https://zeroclaw-chat-session.internal";
    const CANARY_AUDIT_BINDING: &str = "ZEROCLAW_CANARY_AUDIT";
    const CANARY_AUDIT_STORAGE_KEY: &str = "records";
    const CANARY_AUDIT_DO_INTERNAL_ORIGIN: &str = "https://zeroclaw-canary-audit.internal";
    const DRILL_TOKEN_HEADER: &str = "x-zeroclaw-drill-token";

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

    #[derive(Debug, Serialize, Deserialize)]
    struct SessionHistoryResponse {
        messages: Vec<ChatMessage>,
    }

    #[derive(Debug, Deserialize)]
    struct ChatResetRequest {
        session_id: String,
    }

    #[derive(Debug, Clone, Default)]
    struct TickOverrides {
        metrics_endpoint: Option<String>,
        metrics_bearer_token: Option<String>,
        dry_run: Option<bool>,
        message_prefix: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct AppendSessionHistoryRequest {
        messages: Vec<ChatMessage>,
        max_messages: usize,
    }

    #[derive(Debug, Serialize)]
    struct MemoryStoreRequest<'a> {
        key: &'a str,
        content: &'a str,
        category: &'a str,
        session_id: Option<&'a str>,
    }

    #[derive(Debug, Serialize)]
    struct MemoryRecallRequest<'a> {
        query: &'a str,
        limit: usize,
        session_id: Option<&'a str>,
    }

    #[derive(Debug, Deserialize)]
    struct MemoryRecallResponse {
        #[serde(default)]
        entries: Vec<MemoryRecallEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct MemoryRecallEntry {
        key: String,
        category: String,
        content: String,
    }

    #[durable_object]
    pub struct ChatSessionObject {
        state: State,
    }

    impl DurableObject for ChatSessionObject {
        fn new(state: State, _env: Env) -> Self {
            Self { state }
        }

        async fn fetch(&self, mut req: Request) -> Result<Response> {
            match (req.method(), req.path().as_str()) {
                (Method::Get, "/history") => {
                    let messages = self
                        .state
                        .storage()
                        .get::<Vec<ChatMessage>>(CHAT_HISTORY_STORAGE_KEY)
                        .await?
                        .unwrap_or_default();
                    Response::from_json(&SessionHistoryResponse { messages })
                }
                (Method::Post, "/append") => {
                    let append_req: AppendSessionHistoryRequest =
                        req.json().await.map_err(|e| {
                            worker::Error::RustError(format!("invalid append payload: {e}"))
                        })?;
                    if append_req.max_messages == 0 {
                        return Response::error("max_messages must be greater than zero", 400);
                    }
                    let existing = self
                        .state
                        .storage()
                        .get::<Vec<ChatMessage>>(CHAT_HISTORY_STORAGE_KEY)
                        .await?
                        .unwrap_or_default();
                    let messages = append_and_trim_chat_history(
                        existing,
                        append_req.messages,
                        append_req.max_messages,
                    );
                    self.state
                        .storage()
                        .put(CHAT_HISTORY_STORAGE_KEY, &messages)
                        .await?;
                    Response::from_json(&SessionHistoryResponse { messages })
                }
                (Method::Post, "/clear") => {
                    self.state
                        .storage()
                        .delete(CHAT_HISTORY_STORAGE_KEY)
                        .await?;
                    Response::ok("ok")
                }
                _ => Response::error("Not Found", 404),
            }
        }
    }

    #[durable_object]
    pub struct CanaryAuditObject {
        state: State,
    }

    impl DurableObject for CanaryAuditObject {
        fn new(state: State, _env: Env) -> Self {
            Self { state }
        }

        async fn fetch(&self, mut req: Request) -> Result<Response> {
            match (req.method(), req.path().as_str()) {
                (Method::Post, "/append") => {
                    let append_req: CanaryAuditAppendRequest = req.json().await.map_err(|e| {
                        worker::Error::RustError(format!(
                            "invalid canary audit append payload: {e}"
                        ))
                    })?;
                    if append_req.max_records == 0 {
                        return Response::error("max_records must be greater than zero", 400);
                    }
                    let mut records = self
                        .state
                        .storage()
                        .get::<Vec<CanaryAuditRecord>>(CANARY_AUDIT_STORAGE_KEY)
                        .await?
                        .unwrap_or_default();
                    records.push(append_req.record);
                    if records.len() > append_req.max_records {
                        records = records.split_off(records.len() - append_req.max_records);
                    }
                    self.state
                        .storage()
                        .put(CANARY_AUDIT_STORAGE_KEY, &records)
                        .await?;
                    Response::ok("ok")
                }
                (Method::Get, "/recent") => {
                    let limit = canary_audit_recent_limit_from_url(req.url()?.as_str())
                        .map_err(|e| worker::Error::RustError(e.to_string()))?;
                    let records = self
                        .state
                        .storage()
                        .get::<Vec<CanaryAuditRecord>>(CANARY_AUDIT_STORAGE_KEY)
                        .await?
                        .unwrap_or_default();
                    let mut records = if records.len() > limit {
                        records[records.len() - limit..].to_vec()
                    } else {
                        records
                    };
                    records.reverse();
                    Response::from_json(&CanaryAuditRecentResponse { records })
                }
                (Method::Post, "/clear") => {
                    self.state
                        .storage()
                        .delete(CANARY_AUDIT_STORAGE_KEY)
                        .await?;
                    Response::ok("ok")
                }
                _ => Response::error("Not Found", 404),
            }
        }
    }

    fn chat_do_url(path: &str) -> String {
        format!("{CHAT_DO_INTERNAL_ORIGIN}{path}")
    }

    fn canary_audit_do_url(path: &str) -> String {
        format!("{CANARY_AUDIT_DO_INTERNAL_ORIGIN}{path}")
    }

    async fn parse_required_json_response<T: DeserializeOwned>(
        mut resp: Response,
        op_name: &str,
    ) -> Result<T> {
        let status = resp.status_code();
        if !(200..=299).contains(&status) {
            let body = resp.text().await.unwrap_or_else(|_| String::new());
            return Err(worker::Error::RustError(format!(
                "{op_name} failed with status {status}: {body}"
            )));
        }
        resp.json::<T>()
            .await
            .map_err(|e| worker::Error::RustError(format!("{op_name} returned invalid JSON: {e}")))
    }

    async fn chat_session_stub(env: &Env, session_id: &str) -> Result<Stub> {
        let namespace = env.durable_object(CHAT_SESSIONS_BINDING).map_err(|e| {
            worker::Error::RustError(format!(
                "missing durable object binding {CHAT_SESSIONS_BINDING}: {e}"
            ))
        })?;
        let object_id = namespace.id_from_name(session_id).map_err(|e| {
            worker::Error::RustError(format!(
                "failed creating durable object id for session {session_id}: {e}"
            ))
        })?;
        object_id.get_stub().map_err(|e| {
            worker::Error::RustError(format!(
                "failed getting durable object stub for session {session_id}: {e}"
            ))
        })
    }

    async fn fetch_session_history(env: &Env, session_id: &str) -> Result<Vec<ChatMessage>> {
        let stub = chat_session_stub(env, session_id).await?;
        let resp = stub
            .fetch_with_str(&chat_do_url("/history"))
            .await
            .map_err(|e| worker::Error::RustError(format!("history fetch failed: {e}")))?;
        let payload: SessionHistoryResponse =
            parse_required_json_response(resp, "session history fetch").await?;
        Ok(payload.messages)
    }

    async fn append_session_history(
        env: &Env,
        session_id: &str,
        messages: Vec<ChatMessage>,
        max_messages: usize,
    ) -> Result<Vec<ChatMessage>> {
        let stub = chat_session_stub(env, session_id).await?;
        let body = serde_json::to_string(&AppendSessionHistoryRequest {
            messages,
            max_messages,
        })
        .map_err(|e| worker::Error::RustError(format!("failed serializing append body: {e}")))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| worker::Error::RustError(format!("failed setting content-type: {e}")))?;
        init.with_headers(headers);
        init.with_body(Some(body.into()));
        let req = Request::new_with_init(&chat_do_url("/append"), &init).map_err(|e| {
            worker::Error::RustError(format!("failed creating append request: {e}"))
        })?;
        let resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|e| worker::Error::RustError(format!("session append failed: {e}")))?;
        let payload: SessionHistoryResponse =
            parse_required_json_response(resp, "session append").await?;
        Ok(payload.messages)
    }

    async fn clear_session_history(env: &Env, session_id: &str) -> Result<()> {
        let stub = chat_session_stub(env, session_id).await?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        let req = Request::new_with_init(&chat_do_url("/clear"), &init)
            .map_err(|e| worker::Error::RustError(format!("failed creating clear request: {e}")))?;
        let resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|e| worker::Error::RustError(format!("session clear failed: {e}")))?;
        let mut resp = resp;
        let status = resp.status_code();
        if !(200..=299).contains(&status) {
            let body = resp.text().await.unwrap_or_else(|_| String::new());
            return Err(worker::Error::RustError(format!(
                "session clear failed with status {status}: {body}"
            )));
        }
        Ok(())
    }

    async fn canary_audit_stub(env: &Env) -> Result<Stub> {
        let namespace = env.durable_object(CANARY_AUDIT_BINDING).map_err(|e| {
            worker::Error::RustError(format!(
                "missing durable object binding {CANARY_AUDIT_BINDING}: {e}"
            ))
        })?;
        let object_id = namespace.id_from_name("global").map_err(|e| {
            worker::Error::RustError(format!(
                "failed creating canary audit durable object id: {e}"
            ))
        })?;
        object_id.get_stub().map_err(|e| {
            worker::Error::RustError(format!("failed getting canary audit object stub: {e}"))
        })
    }

    async fn append_canary_audit_record(
        env: &Env,
        record: CanaryAuditRecord,
        max_records: usize,
    ) -> Result<()> {
        let stub = canary_audit_stub(env).await?;
        let body = serde_json::to_string(&CanaryAuditAppendRequest {
            record,
            max_records,
        })
        .map_err(|e| {
            worker::Error::RustError(format!("failed serializing canary audit append body: {e}"))
        })?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| worker::Error::RustError(format!("failed setting content-type: {e}")))?;
        init.with_headers(headers);
        init.with_body(Some(body.into()));
        let req = Request::new_with_init(&canary_audit_do_url("/append"), &init).map_err(|e| {
            worker::Error::RustError(format!("failed creating canary audit append request: {e}"))
        })?;
        let mut resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|e| worker::Error::RustError(format!("canary audit append failed: {e}")))?;
        let status = resp.status_code();
        if !(200..=299).contains(&status) {
            let body = resp.text().await.unwrap_or_else(|_| String::new());
            return Err(worker::Error::RustError(format!(
                "canary audit append failed with status {status}: {body}"
            )));
        }
        Ok(())
    }

    async fn fetch_canary_audit_recent(env: &Env, limit: usize) -> Result<Vec<CanaryAuditRecord>> {
        let stub = canary_audit_stub(env).await?;
        let url = canary_audit_do_url(format!("/recent?limit={limit}").as_str());
        let resp = stub.fetch_with_str(url.as_str()).await.map_err(|e| {
            worker::Error::RustError(format!("canary audit recent fetch failed: {e}"))
        })?;
        let payload: CanaryAuditRecentResponse =
            parse_required_json_response(resp, "canary audit recent fetch").await?;
        Ok(payload.records)
    }

    async fn clear_canary_audit_records(env: &Env) -> Result<()> {
        let stub = canary_audit_stub(env).await?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        let req = Request::new_with_init(&canary_audit_do_url("/clear"), &init).map_err(|e| {
            worker::Error::RustError(format!("failed creating canary audit clear request: {e}"))
        })?;
        let mut resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|e| worker::Error::RustError(format!("canary audit clear failed: {e}")))?;
        let status = resp.status_code();
        if !(200..=299).contains(&status) {
            let body = resp.text().await.unwrap_or_else(|_| String::new());
            return Err(worker::Error::RustError(format!(
                "canary audit clear failed with status {status}: {body}"
            )));
        }
        Ok(())
    }

    async fn send_memory_request(
        settings: &LongTermMemorySettings,
        method: Method,
        path: &str,
        body: Option<String>,
    ) -> Result<Response> {
        let mut init = RequestInit::new();
        init.with_method(method);
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| {
                worker::Error::RustError(format!("failed setting memory content-type: {e}"))
            })?;
        if let Some(token) = settings.auth_token.as_deref() {
            headers
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|e| {
                    worker::Error::RustError(format!("failed setting memory auth header: {e}"))
                })?;
        }
        init.with_headers(headers);
        if let Some(body) = body {
            init.with_body(Some(body.into()));
        }
        let url = format!("{}/{}", settings.base_url, path.trim_start_matches('/'));
        let req = Request::new_with_init(url.as_str(), &init).map_err(|e| {
            worker::Error::RustError(format!("failed to build memory request: {e}"))
        })?;
        Fetch::Request(req)
            .send()
            .await
            .map_err(|e| worker::Error::RustError(format!("memory request failed: {e}")))
    }

    fn turn_memory_key(role: &str, session_id: Option<&str>) -> String {
        let session = session_id.unwrap_or("global");
        let safe_session: String = session
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        format!(
            "edge_chat:{safe_session}:{role}:{}",
            worker::Date::now().as_millis()
        )
    }

    async fn fetch_long_term_memory(
        settings: &LongTermMemorySettings,
        query: &str,
    ) -> Result<Vec<MemoryContextEntry>> {
        let payload = serde_json::to_string(&MemoryRecallRequest {
            query,
            limit: settings.recall_limit,
            session_id: None,
        })
        .map_err(|e| {
            worker::Error::RustError(format!("failed serializing memory recall payload: {e}"))
        })?;
        let response =
            send_memory_request(settings, Method::Post, "/v1/memory/recall", Some(payload)).await?;
        let parsed: MemoryRecallResponse =
            parse_required_json_response(response, "long-term memory recall").await?;
        Ok(parsed
            .entries
            .into_iter()
            .filter_map(|entry| {
                let content = entry.content.trim().to_string();
                if content.is_empty() {
                    return None;
                }
                Some(MemoryContextEntry {
                    key: entry.key.trim().to_string(),
                    category: entry.category.trim().to_string(),
                    content,
                })
            })
            .collect())
    }

    async fn store_long_term_turn(
        settings: &LongTermMemorySettings,
        session_id: Option<&str>,
        user_message: &str,
        assistant_reply: &str,
    ) -> Result<()> {
        let store_records = [
            (turn_memory_key("user", session_id), user_message),
            (turn_memory_key("assistant", session_id), assistant_reply),
        ];
        for (key, content) in store_records {
            if content.trim().is_empty() {
                continue;
            }
            let payload = serde_json::to_string(&MemoryStoreRequest {
                key: key.as_str(),
                content: content.trim(),
                category: "conversation",
                session_id,
            })
            .map_err(|e| {
                worker::Error::RustError(format!("failed serializing memory store payload: {e}"))
            })?;
            let mut response =
                send_memory_request(settings, Method::Post, "/v1/memory/store", Some(payload))
                    .await?;
            let status = response.status_code();
            if !(200..=299).contains(&status) {
                let body = response.text().await.unwrap_or_else(|_| String::new());
                return Err(worker::Error::RustError(format!(
                    "long-term memory store failed with status {status}: {body}"
                )));
            }
        }
        Ok(())
    }

    fn parse_drill_path(path: &str, prefix: &str) -> Result<Option<CanaryDrillScenario>> {
        let Some(raw) = path.strip_prefix(prefix) else {
            return Ok(None);
        };
        if raw.is_empty() || raw.contains('/') {
            return Err(worker::Error::RustError(
                "drill scenario path must be one segment".to_string(),
            ));
        }
        Ok(Some(
            CanaryDrillScenario::parse(raw).map_err(|e| worker::Error::RustError(e.to_string()))?,
        ))
    }

    fn drill_token_required(env: &Env) -> Option<String> {
        env.var(ENV_CANARY_DRILL_TOKEN)
            .ok()
            .map(|v| v.to_string())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn authorized_drill_token(req: &Request, env: &Env) -> Result<String> {
        let required = drill_token_required(env).ok_or_else(|| {
            worker::Error::RustError(format!(
                "drill endpoints disabled; missing {}",
                ENV_CANARY_DRILL_TOKEN
            ))
        })?;
        let provided_header = req
            .headers()
            .get(DRILL_TOKEN_HEADER)
            .map_err(|e| worker::Error::RustError(format!("failed reading drill header: {e}")))?
            .unwrap_or_default();
        let provided_bearer = req
            .headers()
            .get("authorization")
            .map_err(|e| {
                worker::Error::RustError(format!("failed reading authorization header: {e}"))
            })?
            .and_then(|raw| {
                let trimmed = raw.trim();
                let prefix = "Bearer ";
                if trimmed.starts_with(prefix) {
                    Some(trimmed[prefix.len()..].trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        if provided_header.trim() != required && provided_bearer.trim() != required {
            return Err(worker::Error::RustError(
                "unauthorized drill request".to_string(),
            ));
        }
        Ok(required)
    }

    fn authorize_admin_request(req: &Request, env: &Env) -> Result<()> {
        let Some(required) = drill_token_required(env) else {
            return Ok(());
        };
        let provided_header = req
            .headers()
            .get(DRILL_TOKEN_HEADER)
            .map_err(|e| worker::Error::RustError(format!("failed reading drill header: {e}")))?
            .unwrap_or_default();
        let provided_bearer = req
            .headers()
            .get("authorization")
            .map_err(|e| {
                worker::Error::RustError(format!("failed reading authorization header: {e}"))
            })?
            .and_then(|raw| {
                let trimmed = raw.trim();
                let prefix = "Bearer ";
                if trimmed.starts_with(prefix) {
                    Some(trimmed[prefix.len()..].trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        if provided_header.trim() != required && provided_bearer.trim() != required {
            return Err(worker::Error::RustError(
                "unauthorized admin request".to_string(),
            ));
        }
        Ok(())
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

    struct WorkerDrillMetricsRunner {
        payload: String,
    }

    #[async_trait(?Send)]
    impl CommandRunner for WorkerDrillMetricsRunner {
        async fn run(
            &self,
            program: &str,
            _args: &[String],
            _cwd: Option<&std::path::PathBuf>,
        ) -> anyhow::Result<CommandOutput> {
            if program != "curl" {
                return Err(anyhow!("unsupported metrics program '{}'", program));
            }
            Ok(CommandOutput {
                status_code: 0,
                stdout: self.payload.clone(),
                stderr: String::new(),
            })
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
            if deploy.dry_run {
                return Ok(CommandOutput {
                    status_code: 0,
                    stdout: serde_json::json!({
                        "dry_run": true,
                        "worker_name": deploy.worker_name,
                        "versions": deploy
                            .versions
                            .iter()
                            .map(|v| {
                                serde_json::json!({
                                    "version_id": v.version_id,
                                    "percentage": v.percentage
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .to_string(),
                    stderr: String::new(),
                });
            }
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

    async fn run_one_tick_with_runners<MR>(
        payload: CloudflareCronEventPayload,
        env: &Env,
        overrides: TickOverrides,
        metrics_runner: MR,
    ) -> Result<TickSummary>
    where
        MR: CommandRunner,
    {
        let mut settings =
            WorkerCanarySettings::from_lookup(|key| env.var(key).ok().map(|v| v.to_string()))
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
        if let Some(endpoint) = overrides.metrics_endpoint {
            settings.metrics_endpoint = endpoint;
        }
        if let Some(token) = overrides.metrics_bearer_token {
            settings.metrics_bearer_token = Some(token);
        }
        if let Some(dry_run) = overrides.dry_run {
            settings.dry_run = dry_run;
        }
        if let Some(message_prefix) = overrides.message_prefix {
            settings.message_prefix = message_prefix;
        }
        let audit_max_records = parse_canary_audit_max_records(
            env.var(ENV_CANARY_AUDIT_MAX_RECORDS)
                .ok()
                .map(|v| v.to_string())
                .as_deref(),
        )
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let payload_for_audit = payload.clone();
        let event = CloudflareCronEvent::from_payload(payload)
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let controller = settings
            .controller()
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let config = settings
            .runtime_config()
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let sink = Arc::new(NoopCanaryEventSink);
        let traffic_runner = WorkerDeployApiRunner {
            account_id: settings.cloudflare_account_id.clone(),
            api_token: settings.cloudflare_api_token.clone(),
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
        .map_err(|e| worker::Error::RustError(format!("{e:#}")))?;

        let applied_canary_percent = exec
            .outcome
            .applied_update
            .as_ref()
            .map(|u| u.canary_traffic().get());

        let summary = TickSummary {
            decision: format!("{:?}", exec.outcome.decision),
            applied_canary_percent,
            total_requests: exec.outcome.metrics.total_requests(),
            failed_requests: exec.outcome.metrics.failed_requests(),
            p95_latency_ms: exec.outcome.metrics.p95_latency_ms(),
        };
        let audit_record = build_canary_audit_record(
            &settings,
            &payload_for_audit,
            &summary,
            worker::Date::now().as_millis(),
        );
        append_canary_audit_record(env, audit_record, audit_max_records).await?;
        Ok(summary)
    }

    async fn run_one_tick_with_overrides(
        payload: CloudflareCronEventPayload,
        env: &Env,
        overrides: TickOverrides,
    ) -> Result<TickSummary> {
        run_one_tick_with_runners(payload, env, overrides, WorkerMetricsRunner).await
    }

    async fn run_one_tick(payload: CloudflareCronEventPayload, env: &Env) -> Result<TickSummary> {
        run_one_tick_with_overrides(payload, env, TickOverrides::default()).await
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

        let session_history = if let Some(session_id) = session_id.as_deref() {
            fetch_session_history(env, session_id).await?
        } else {
            Vec::new()
        };
        let long_term_memory_settings =
            parse_long_term_memory_settings(|key| env.var(key).ok().map(|v| v.to_string()))
                .map_err(|e| worker::Error::RustError(format!("invalid memory settings: {e}")))?;
        let long_term_memory = if let Some(settings) = long_term_memory_settings.as_ref() {
            match fetch_long_term_memory(settings, &chat_req.message).await {
                Ok(entries) => entries,
                Err(err) => {
                    console_error!("long-term memory recall failed: {}", err);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let openrouter_messages =
            build_openrouter_messages(&session_history, &chat_req.message, &long_term_memory)
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

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

        let history_messages = if let Some(session_id) = session_id.as_deref() {
            let user_message = ChatMessage::new(ChatRole::User, chat_req.message.clone())
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
            let assistant_message = ChatMessage::new(ChatRole::Assistant, reply.clone())
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
            let persisted = append_session_history(
                env,
                session_id,
                vec![user_message, assistant_message],
                history_limit,
            )
            .await?;
            persisted.len()
        } else {
            0
        };

        if let Some(settings) = long_term_memory_settings.as_ref() {
            if let Err(err) =
                store_long_term_turn(settings, session_id.as_deref(), &chat_req.message, &reply)
                    .await
            {
                console_error!("long-term memory store failed: {}", err);
            }
        }

        Response::from_json(&ChatResponse {
            model,
            reply,
            session_id,
            history_messages,
        })
    }

    async fn run_chat_reset(mut req: Request, env: &Env) -> Result<Response> {
        let payload: ChatResetRequest = req
            .json()
            .await
            .map_err(|e| worker::Error::RustError(format!("invalid reset payload: {e}")))?;
        let session_id = normalize_session_id(Some(payload.session_id.as_str()))
            .map_err(|e| worker::Error::RustError(format!("invalid session_id: {e}")))?
            .ok_or_else(|| worker::Error::RustError("session_id is required".to_string()))?;
        clear_session_history(env, session_id.as_str()).await?;
        Response::ok("ok")
    }

    async fn run_canary_drill_metrics(req: Request, env: &Env) -> Result<Response> {
        if let Err(err) = authorized_drill_token(&req, env) {
            let msg = err.to_string();
            if msg.contains("disabled") {
                return Response::error(msg, 404);
            }
            if msg.contains("unauthorized") {
                return Response::error(msg, 401);
            }
            return Err(err);
        }
        let scenario = parse_drill_path(req.path().as_str(), "/canary/drill/metrics/")?
            .ok_or_else(|| worker::Error::RustError("missing drill scenario".to_string()))?;
        Response::from_json(&scenario.metrics_payload())
    }

    async fn run_canary_drill_tick(req: Request, env: &Env) -> Result<Response> {
        let drill_token = match authorized_drill_token(&req, env) {
            Ok(token) => token,
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("disabled") {
                    return Response::error(msg, 404);
                }
                if msg.contains("unauthorized") {
                    return Response::error(msg, 401);
                }
                return Err(err);
            }
        };
        let scenario = parse_drill_path(req.path().as_str(), "/canary/drill/tick/")?
            .ok_or_else(|| worker::Error::RustError("missing drill scenario".to_string()))?;
        let drill_payload = scenario.metrics_payload().to_string();
        let payload = CloudflareCronEventPayload {
            cron: format!("drill:{}", scenario.as_slug()),
            scheduled_time: worker::Date::now().as_millis(),
            r#type: Some("scheduled".to_string()),
        };
        let summary = run_one_tick_with_runners(
            payload,
            env,
            TickOverrides {
                metrics_endpoint: Some("https://drill.internal/metrics".to_string()),
                metrics_bearer_token: Some(drill_token),
                dry_run: Some(true),
                message_prefix: Some(format!("zeroclaw canary drill {}", scenario.as_slug())),
            },
            WorkerDrillMetricsRunner {
                payload: drill_payload,
            },
        )
        .await?;
        Response::from_json(&DrillTickSummary {
            scenario: scenario.as_slug().to_string(),
            dry_run: true,
            tick: summary,
        })
    }

    async fn run_canary_audit_recent(req: Request, env: &Env) -> Result<Response> {
        if let Err(err) = authorize_admin_request(&req, env) {
            let msg = err.to_string();
            if msg.contains("unauthorized") {
                return Response::error(msg, 401);
            }
            return Err(err);
        }
        let url = req.url()?;
        let limit = canary_audit_recent_limit_from_url(url.as_str())
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let records = fetch_canary_audit_recent(env, limit).await?;
        Response::from_json(&CanaryAuditRecentResponse { records })
    }

    async fn run_canary_audit_clear(req: Request, env: &Env) -> Result<Response> {
        if let Err(err) = authorize_admin_request(&req, env) {
            let msg = err.to_string();
            if msg.contains("unauthorized") {
                return Response::error(msg, 401);
            }
            return Err(err);
        }
        clear_canary_audit_records(env).await?;
        Response::ok("ok")
    }

    #[event(fetch)]
    pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        if req.method() == Method::Get && req.path().starts_with("/canary/drill/metrics/") {
            return match run_canary_drill_metrics(req, &env).await {
                Ok(resp) => Ok(resp),
                Err(err) => Response::error(format!("drill metrics failed: {err}"), 500),
            };
        }
        if req.method() == Method::Post && req.path().starts_with("/canary/drill/tick/") {
            return match run_canary_drill_tick(req, &env).await {
                Ok(resp) => Ok(resp),
                Err(err) => Response::error(format!("drill tick failed: {err}"), 500),
            };
        }
        if req.method() == Method::Get && req.path() == "/canary/audit/recent" {
            return match run_canary_audit_recent(req, &env).await {
                Ok(resp) => Ok(resp),
                Err(err) => Response::error(format!("canary audit recent failed: {err}"), 500),
            };
        }
        if req.method() == Method::Post && req.path() == "/canary/audit/clear" {
            return match run_canary_audit_clear(req, &env).await {
                Ok(resp) => Ok(resp),
                Err(err) => Response::error(format!("canary audit clear failed: {err}"), 500),
            };
        }

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

    #[test]
    fn normalize_session_id_enforces_shape() {
        assert_eq!(
            normalize_session_id(Some(" room-1 ")).unwrap(),
            Some("room-1".to_string())
        );
        assert_eq!(normalize_session_id(Some("")).unwrap(), None);
        assert!(normalize_session_id(Some("bad/id")).is_err());
    }

    #[test]
    fn parse_chat_history_limit_caps_and_rejects_zero() {
        assert_eq!(
            parse_chat_history_limit(None).unwrap(),
            DEFAULT_CHAT_HISTORY_MESSAGES
        );
        assert_eq!(parse_chat_history_limit(Some("7")).unwrap(), 7);
        assert_eq!(
            parse_chat_history_limit(Some("999")).unwrap(),
            MAX_CHAT_HISTORY_MESSAGES
        );
        assert!(parse_chat_history_limit(Some("0")).is_err());
    }

    #[test]
    fn append_and_trim_history_keeps_most_recent_messages() {
        let existing = vec![
            ChatMessage::new(ChatRole::User, "u1").unwrap(),
            ChatMessage::new(ChatRole::Assistant, "a1").unwrap(),
            ChatMessage::new(ChatRole::User, "u2").unwrap(),
        ];
        let incoming = vec![
            ChatMessage::new(ChatRole::Assistant, "a2").unwrap(),
            ChatMessage::new(ChatRole::User, "u3").unwrap(),
        ];
        let merged = append_and_trim_chat_history(existing, incoming, 4);
        let got: Vec<String> = merged.into_iter().map(|m| m.content).collect();
        assert_eq!(got, vec!["a1", "u2", "a2", "u3"]);
    }

    #[test]
    fn build_openrouter_messages_includes_system_history_and_user() {
        let history = vec![
            ChatMessage::new(ChatRole::User, "hello").unwrap(),
            ChatMessage::new(ChatRole::Assistant, "hi").unwrap(),
        ];
        let payload = build_openrouter_messages(&history, "what did I ask?", &[]).unwrap();
        assert_eq!(payload.len(), 4);
        assert_eq!(payload[0]["role"], "system");
        assert_eq!(payload[1]["role"], "user");
        assert_eq!(payload[1]["content"], "hello");
        assert_eq!(payload[2]["role"], "assistant");
        assert_eq!(payload[3]["content"], "what did I ask?");
    }

    #[test]
    fn parse_long_term_memory_settings_is_optional_and_bounded() {
        let disabled = parse_long_term_memory_settings(|_key| None).unwrap();
        assert!(disabled.is_none());

        let mut env = HashMap::<String, String>::new();
        env.insert(
            ENV_LONG_TERM_MEMORY_BASE_URL.to_string(),
            "https://memory.example/service/".to_string(),
        );
        env.insert(
            ENV_LONG_TERM_MEMORY_AUTH_TOKEN.to_string(),
            "token-abc".to_string(),
        );
        env.insert(
            ENV_LONG_TERM_MEMORY_RECALL_LIMIT.to_string(),
            "999".to_string(),
        );
        let settings = parse_long_term_memory_settings(|key| env.get(key).cloned())
            .unwrap()
            .unwrap();
        assert_eq!(settings.base_url, "https://memory.example/service");
        assert_eq!(settings.auth_token.as_deref(), Some("token-abc"));
        assert_eq!(settings.recall_limit, MAX_LONG_TERM_MEMORY_RECALL_LIMIT);
    }

    #[test]
    fn build_openrouter_messages_includes_long_term_memory_context() {
        let history = vec![ChatMessage::new(ChatRole::User, "hello").unwrap()];
        let memory = vec![
            MemoryContextEntry {
                key: "user:favorite_language".to_string(),
                category: "core".to_string(),
                content: "Rust".to_string(),
            },
            MemoryContextEntry {
                key: "project:status".to_string(),
                category: "conversation".to_string(),
                content: "moving to edge".to_string(),
            },
        ];
        let payload =
            build_openrouter_messages(&history, "what should I do next?", &memory).unwrap();
        assert_eq!(payload.len(), 4);
        assert_eq!(payload[0]["role"], "system");
        assert_eq!(payload[1]["role"], "system");
        assert!(payload[1]["content"]
            .as_str()
            .unwrap_or_default()
            .contains("Relevant long-term memory"));
        assert_eq!(payload[2]["role"], "user");
        assert_eq!(payload[2]["content"], "hello");
        assert_eq!(payload[3]["role"], "user");
    }

    #[test]
    fn parse_canary_audit_max_records_defaults_caps_and_rejects_zero() {
        assert_eq!(
            parse_canary_audit_max_records(None).unwrap(),
            DEFAULT_CANARY_AUDIT_MAX_RECORDS
        );
        assert_eq!(
            parse_canary_audit_max_records(Some("999999")).unwrap(),
            MAX_CANARY_AUDIT_MAX_RECORDS
        );
        assert!(parse_canary_audit_max_records(Some("0")).is_err());
    }

    #[test]
    fn canary_audit_recent_limit_from_url_parses_limit() {
        assert_eq!(
            canary_audit_recent_limit_from_url("https://example.com/canary/audit/recent").unwrap(),
            DEFAULT_CANARY_AUDIT_RECENT_LIMIT
        );
        assert_eq!(
            canary_audit_recent_limit_from_url("https://example.com/canary/audit/recent?limit=7")
                .unwrap(),
            7
        );
        assert_eq!(
            canary_audit_recent_limit_from_url(
                "https://example.com/canary/audit/recent?foo=bar&limit=9999"
            )
            .unwrap(),
            MAX_CANARY_AUDIT_RECENT_LIMIT
        );
        assert!(canary_audit_recent_limit_from_url(
            "https://example.com/canary/audit/recent?limit=0"
        )
        .is_err());
    }

    #[test]
    fn build_canary_audit_record_captures_tick_summary() {
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
        env.insert(ENV_DRY_RUN.to_string(), "true".to_string());
        let settings = WorkerCanarySettings::from_lookup(|k| env.get(k).cloned()).unwrap();

        let payload = CloudflareCronEventPayload {
            cron: "manual".to_string(),
            scheduled_time: 123,
            r#type: Some("scheduled".to_string()),
        };
        let summary = TickSummary {
            decision: "Promote { to: Percent(25) }".to_string(),
            applied_canary_percent: Some(25),
            total_requests: 100,
            failed_requests: 1,
            p95_latency_ms: 120,
        };
        let record = build_canary_audit_record(&settings, &payload, &summary, 42);
        assert_eq!(record.cron, "manual");
        assert_eq!(record.event_type.as_deref(), Some("scheduled"));
        assert!(record.dry_run);
        assert_eq!(record.stable_version_id, "stable-v1");
        assert_eq!(record.canary_version_id, "canary-v2");
        assert_eq!(record.decision, "Promote { to: Percent(25) }");
        assert_eq!(record.applied_canary_percent, Some(25));
        assert_eq!(record.total_requests, 100);
        assert_eq!(record.failed_requests, 1);
        assert_eq!(record.p95_latency_ms, 120);
        assert_eq!(record.recorded_at_ms, 42);
    }

    #[test]
    fn canary_drill_scenario_parses_known_values() {
        assert_eq!(
            CanaryDrillScenario::parse("promote").unwrap(),
            CanaryDrillScenario::Promote
        );
        assert_eq!(CanaryDrillScenario::Promote.as_slug(), "promote");
        assert_eq!(
            CanaryDrillScenario::parse(" hold ").unwrap(),
            CanaryDrillScenario::Hold
        );
        assert_eq!(
            CanaryDrillScenario::parse("ROLLBACK").unwrap(),
            CanaryDrillScenario::Rollback
        );
        assert!(CanaryDrillScenario::parse("unknown").is_err());
    }

    #[test]
    fn canary_drill_metrics_payload_matches_expected_threshold_cases() {
        let promote = CanaryDrillScenario::Promote.metrics_payload();
        assert_eq!(promote["total_requests"], 120);
        assert_eq!(promote["failed_requests"], 0);
        assert_eq!(promote["p95_latency_ms"], 120);

        let hold = CanaryDrillScenario::Hold.metrics_payload();
        assert_eq!(hold["total_requests"], 5);
        assert_eq!(hold["failed_requests"], 0);
        assert_eq!(hold["p95_latency_ms"], 120);

        let rollback = CanaryDrillScenario::Rollback.metrics_payload();
        assert_eq!(rollback["total_requests"], 120);
        assert_eq!(rollback["failed_requests"], 25);
        assert_eq!(rollback["p95_latency_ms"], 120);
    }
}
