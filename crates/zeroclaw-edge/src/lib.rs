//! ZeroClaw edge/worker viability spike.
//!
//! This crate models a minimal worker-friendly control-plane runtime:
//! - stateless request handling
//! - explicit delegated tool boundary
//! - shared memory contract via `zeroclaw-core::Memory`
//!
//! It is intentionally narrow so we can validate wasm32 portability and hybrid
//! delegation/persistence assumptions early.

pub mod canary;
pub mod canary_cron;
pub mod canary_live;
pub mod canary_metrics;
pub mod canary_orchestrator;
#[cfg(not(target_arch = "wasm32"))]
pub mod canary_schedule;
pub mod canary_tick;
pub mod cloudflare_cli;
pub mod cloudflare_deploy_api;
pub mod delegate_http;
pub mod memory_http;

use std::collections::BTreeSet;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroclaw_core::memory::{Memory, MemoryCategory, MemoryEntry};
use zeroclaw_core::tools::ToolResult;

/// Tool names that are explicitly delegated to native workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedTool {
    Shell,
    FileRead,
    FileWrite,
    FileEdit,
    GlobSearch,
    ContentSearch,
    GitOperations,
    WebSearchTool,
    WebFetch,
}

impl DelegatedTool {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::FileEdit => "file_edit",
            Self::GlobSearch => "glob_search",
            Self::ContentSearch => "content_search",
            Self::GitOperations => "git_operations",
            Self::WebSearchTool => "web_search_tool",
            Self::WebFetch => "web_fetch",
        }
    }
}

/// Worker request operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EdgeOperation {
    /// Store memory via the shared memory trait.
    StoreMemory {
        key: String,
        content: String,
        category: Option<MemoryCategory>,
    },
    /// Recall memory via keyword search.
    RecallMemory { query: String, limit: usize },
    /// Execute a delegated tool call through the native control plane.
    DelegatedToolCall { tool: DelegatedTool, args: Value },
}

/// Worker request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeRequest {
    pub session_id: Option<String>,
    pub operation: EdgeOperation,
}

/// Worker response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeResponse {
    pub success: bool,
    pub delegated: bool,
    pub output: Option<String>,
    pub memories: Vec<MemoryEntry>,
    pub error: Option<String>,
}

impl EdgeResponse {
    fn ok(output: Option<String>, delegated: bool, memories: Vec<MemoryEntry>) -> Self {
        Self {
            success: true,
            delegated,
            output,
            memories,
            error: None,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            delegated: false,
            output: None,
            memories: Vec::new(),
            error: Some(message.into()),
        }
    }
}

/// Native worker request envelope used by local simulation transports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeWorkerRequest {
    pub session_id: Option<String>,
    pub tool: DelegatedTool,
    pub args: Value,
}

/// Native worker response envelope used by local simulation transports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeWorkerResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

/// Delegate execution boundary implemented by a native worker bridge.
#[async_trait(?Send)]
pub trait DelegateExecutor: Send + Sync {
    async fn execute_tool(
        &self,
        tool: DelegatedTool,
        args: Value,
        session_id: Option<&str>,
    ) -> Result<ToolResult>;
}

/// Planner boundary for converting user/chat text into edge operations.
#[async_trait]
pub trait EdgePlanner: Send + Sync {
    async fn plan(&self, message: &str) -> Result<EdgeOperation>;
}

/// Deterministic prefix-based planner for local simulation.
///
/// Accepted message forms:
/// - `delegate:<tool>:<payload>`
/// - `memory:store:<key>:<content>`
/// - `memory:recall:<query>`
#[derive(Debug, Default)]
pub struct PrefixPlanner;

#[async_trait]
impl EdgePlanner for PrefixPlanner {
    async fn plan(&self, message: &str) -> Result<EdgeOperation> {
        let trimmed = message.trim();
        if let Some(rest) = trimmed.strip_prefix("delegate:") {
            let mut parts = rest.splitn(2, ':');
            let tool_name = parts.next().unwrap_or_default().trim();
            let payload = parts.next().unwrap_or_default().trim();
            if tool_name.is_empty() || payload.is_empty() {
                anyhow::bail!("delegate messages require delegate:<tool>:<payload>");
            }
            let (tool, args) = match tool_name {
                "shell" => (
                    DelegatedTool::Shell,
                    serde_json::json!({ "command": payload }),
                ),
                "web_search_tool" | "web_search" => (
                    DelegatedTool::WebSearchTool,
                    serde_json::json!({ "query": payload }),
                ),
                "web_fetch" => (
                    DelegatedTool::WebFetch,
                    serde_json::json!({ "url": payload }),
                ),
                other => anyhow::bail!("unsupported delegated tool '{other}'"),
            };
            return Ok(EdgeOperation::DelegatedToolCall { tool, args });
        }
        if let Some(rest) = trimmed.strip_prefix("memory:store:") {
            let mut parts = rest.splitn(2, ':');
            let key = parts.next().unwrap_or_default().trim();
            let content = parts.next().unwrap_or_default().trim();
            if key.is_empty() || content.is_empty() {
                anyhow::bail!("memory:store requires non-empty key and content");
            }
            return Ok(EdgeOperation::StoreMemory {
                key: key.to_string(),
                content: content.to_string(),
                category: Some(MemoryCategory::Conversation),
            });
        }
        if let Some(query) = trimmed.strip_prefix("memory:recall:") {
            let query = query.trim();
            if query.is_empty() {
                anyhow::bail!("memory:recall query must not be empty");
            }
            return Ok(EdgeOperation::RecallMemory {
                query: query.to_string(),
                limit: 10,
            });
        }

        anyhow::bail!("unsupported edge planner message format")
    }
}

/// Handler for native-worker requests in local simulation.
pub trait NativeWorkerHandler: Send + Sync {
    fn handle(&self, request: NativeWorkerRequest) -> Result<NativeWorkerResponse>;
}

impl<F> NativeWorkerHandler for F
where
    F: Fn(NativeWorkerRequest) -> Result<NativeWorkerResponse> + Send + Sync,
{
    fn handle(&self, request: NativeWorkerRequest) -> Result<NativeWorkerResponse> {
        self(request)
    }
}

/// In-process native worker bridge that simulates a wire boundary.
///
/// Request/response payloads are serialized and deserialized to emulate a
/// transport hop between edge and native worker processes.
pub struct LocalNativeWorker {
    handler: Arc<dyn NativeWorkerHandler>,
}

impl LocalNativeWorker {
    pub fn new(handler: Arc<dyn NativeWorkerHandler>) -> Self {
        Self { handler }
    }
}

#[async_trait(?Send)]
impl DelegateExecutor for LocalNativeWorker {
    async fn execute_tool(
        &self,
        tool: DelegatedTool,
        args: Value,
        session_id: Option<&str>,
    ) -> Result<ToolResult> {
        let request = NativeWorkerRequest {
            session_id: session_id.map(ToString::to_string),
            tool,
            args,
        };

        let request_wire = serde_json::to_vec(&request)?;
        let decoded_request: NativeWorkerRequest = serde_json::from_slice(&request_wire)?;

        let response = self.handler.handle(decoded_request)?;
        let response_wire = serde_json::to_vec(&response)?;
        let decoded_response: NativeWorkerResponse = serde_json::from_slice(&response_wire)?;

        Ok(ToolResult {
            success: decoded_response.success,
            output: decoded_response.output,
            error: decoded_response.error,
        })
    }
}

/// Minimal worker-friendly runtime.
pub struct EdgeRuntime<M, D>
where
    M: Memory,
    D: DelegateExecutor,
{
    memory: Arc<M>,
    delegate: Arc<D>,
    allowed_delegated_tools: BTreeSet<DelegatedTool>,
}

impl<M, D> EdgeRuntime<M, D>
where
    M: Memory,
    D: DelegateExecutor,
{
    /// Create runtime with full delegated tool allowlist.
    pub fn new(memory: Arc<M>, delegate: Arc<D>) -> Self {
        Self::with_allowed_tools(
            memory,
            delegate,
            [
                DelegatedTool::Shell,
                DelegatedTool::FileRead,
                DelegatedTool::FileWrite,
                DelegatedTool::FileEdit,
                DelegatedTool::GlobSearch,
                DelegatedTool::ContentSearch,
                DelegatedTool::GitOperations,
            ],
        )
    }

    /// Create runtime with explicit delegated tool allowlist.
    pub fn with_allowed_tools(
        memory: Arc<M>,
        delegate: Arc<D>,
        tools: impl IntoIterator<Item = DelegatedTool>,
    ) -> Self {
        Self {
            memory,
            delegate,
            allowed_delegated_tools: tools.into_iter().collect(),
        }
    }

    /// Handle a single worker request.
    pub async fn handle(&self, request: EdgeRequest) -> Result<EdgeResponse> {
        let session_id = request.session_id.as_deref();

        match request.operation {
            EdgeOperation::StoreMemory {
                key,
                content,
                category,
            } => {
                if key.trim().is_empty() {
                    return Ok(EdgeResponse::err("key must not be empty"));
                }
                if content.trim().is_empty() {
                    return Ok(EdgeResponse::err("content must not be empty"));
                }

                self.memory
                    .store(
                        key.trim(),
                        content.trim(),
                        category.unwrap_or(MemoryCategory::Conversation),
                        session_id,
                    )
                    .await?;

                Ok(EdgeResponse::ok(
                    Some("stored".to_string()),
                    false,
                    Vec::new(),
                ))
            }
            EdgeOperation::RecallMemory { query, limit } => {
                if query.trim().is_empty() {
                    return Ok(EdgeResponse::err("query must not be empty"));
                }

                let capped_limit = if limit == 0 { 5 } else { limit.min(100) };
                let memories = self
                    .memory
                    .recall(query.trim(), capped_limit, session_id)
                    .await?;

                Ok(EdgeResponse::ok(None, false, memories))
            }
            EdgeOperation::DelegatedToolCall { tool, args } => {
                if !self.allowed_delegated_tools.contains(&tool) {
                    return Ok(EdgeResponse::err(format!(
                        "delegated tool '{}' is not allowed",
                        tool.as_str()
                    )));
                }

                let delegated = self.delegate.execute_tool(tool, args, session_id).await?;
                if !delegated.success {
                    let reason = delegated
                        .error
                        .unwrap_or_else(|| format!("delegated '{}' failed", tool.as_str()));
                    return Ok(EdgeResponse::err(reason));
                }

                // Persist an audit memory so edge/native handoffs are queryable.
                let key = format!("delegate:{}:{}", tool.as_str(), unix_timestamp_secs());
                let content = format!(
                    "delegated_tool={} output={}",
                    tool.as_str(),
                    delegated.output
                );
                self.memory
                    .store(&key, &content, MemoryCategory::Conversation, session_id)
                    .await?;

                Ok(EdgeResponse::ok(Some(delegated.output), true, Vec::new()))
            }
        }
    }
}

/// Build a worker-like per-request runtime and handle one request.
///
/// This simulates cloud workers where process state is ephemeral and each
/// request reconstructs lightweight control-plane state.
pub async fn handle_worker_request<M, D>(
    memory: Arc<M>,
    delegate: Arc<D>,
    request: EdgeRequest,
    allowed_tools: impl IntoIterator<Item = DelegatedTool>,
) -> Result<EdgeResponse>
where
    M: Memory,
    D: DelegateExecutor,
{
    let runtime = EdgeRuntime::with_allowed_tools(memory, delegate, allowed_tools);
    runtime.handle(request).await
}

/// Simulate a full worker turn from chat message to operation selection and execution.
pub async fn run_edge_turn<M, D, P>(
    runtime: &EdgeRuntime<M, D>,
    planner: &P,
    session_id: Option<String>,
    message: &str,
) -> Result<EdgeResponse>
where
    M: Memory,
    D: DelegateExecutor,
    P: EdgePlanner,
{
    let operation = planner.plan(message).await?;
    runtime
        .handle(EdgeRequest {
            session_id,
            operation,
        })
        .await
}

fn unix_timestamp_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        return (js_sys::Date::now() / 1000.0) as u64;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    #[derive(Default)]
    struct InMemoryStore {
        entries: Mutex<Vec<MemoryEntry>>,
    }

    #[async_trait]
    impl Memory for InMemoryStore {
        fn name(&self) -> &str {
            "test-memory"
        }

        async fn store(
            &self,
            key: &str,
            content: &str,
            category: MemoryCategory,
            session_id: Option<&str>,
        ) -> Result<()> {
            let mut entries = self.entries.lock().unwrap();
            let next_id = entries.len() + 1;
            entries.push(MemoryEntry {
                id: format!("{key}-{next_id}"),
                key: key.to_string(),
                content: content.to_string(),
                category,
                timestamp: unix_timestamp_secs().to_string(),
                session_id: session_id.map(ToString::to_string),
                score: None,
            });
            Ok(())
        }

        async fn recall(
            &self,
            query: &str,
            limit: usize,
            session_id: Option<&str>,
        ) -> Result<Vec<MemoryEntry>> {
            let mut filtered: Vec<MemoryEntry> = self
                .entries
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| {
                    (session_id.is_none() || entry.session_id.as_deref() == session_id)
                        && (entry.key.contains(query) || entry.content.contains(query))
                })
                .cloned()
                .collect();
            filtered.truncate(limit);
            Ok(filtered)
        }

        async fn get(&self, key: &str) -> Result<Option<MemoryEntry>> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .iter()
                .find(|entry| entry.key == key)
                .cloned())
        }

        async fn list(
            &self,
            category: Option<&MemoryCategory>,
            session_id: Option<&str>,
        ) -> Result<Vec<MemoryEntry>> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| {
                    (category.is_none() || Some(&entry.category) == category)
                        && (session_id.is_none() || entry.session_id.as_deref() == session_id)
                })
                .cloned()
                .collect())
        }

        async fn forget(&self, key: &str) -> Result<bool> {
            let mut guard = self.entries.lock().unwrap();
            let before = guard.len();
            guard.retain(|entry| entry.key != key);
            Ok(guard.len() < before)
        }

        async fn count(&self) -> Result<usize> {
            Ok(self.entries.lock().unwrap().len())
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    struct StubDelegate {
        calls: Mutex<Vec<(DelegatedTool, Option<String>, Value)>>,
        result: Mutex<ToolResult>,
    }

    impl StubDelegate {
        fn success(output: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                result: Mutex::new(ToolResult {
                    success: true,
                    output: output.to_string(),
                    error: None,
                }),
            }
        }
    }

    #[async_trait(?Send)]
    impl DelegateExecutor for StubDelegate {
        async fn execute_tool(
            &self,
            tool: DelegatedTool,
            args: Value,
            session_id: Option<&str>,
        ) -> Result<ToolResult> {
            self.calls
                .lock()
                .unwrap()
                .push((tool, session_id.map(ToString::to_string), args));
            Ok(self.result.lock().unwrap().clone())
        }
    }

    #[tokio::test]
    async fn worker_like_runtime_delegates_shell_and_persists_audit_memory() {
        let memory = Arc::new(InMemoryStore::default());
        let delegate = Arc::new(StubDelegate::success("README.md\nsrc\n"));

        let request = EdgeRequest {
            session_id: Some("session-a".to_string()),
            operation: EdgeOperation::DelegatedToolCall {
                tool: DelegatedTool::Shell,
                args: serde_json::json!({"command": "ls"}),
            },
        };

        let response = handle_worker_request(
            Arc::clone(&memory),
            Arc::clone(&delegate),
            request,
            [DelegatedTool::Shell],
        )
        .await
        .expect("worker request should execute");

        assert!(response.success);
        assert!(response.delegated);
        assert_eq!(response.output.as_deref(), Some("README.md\nsrc\n"));

        let recalled = memory
            .recall("delegated_tool=shell", 10, Some("session-a"))
            .await
            .expect("recall should succeed");
        assert_eq!(recalled.len(), 1);
        assert!(recalled[0].key.starts_with("delegate:shell:"));

        let calls = delegate.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, DelegatedTool::Shell);
        assert_eq!(calls[0].1.as_deref(), Some("session-a"));
    }

    #[tokio::test]
    async fn worker_like_runtime_rejects_delegated_tool_not_in_allowlist() {
        let memory = Arc::new(InMemoryStore::default());
        let delegate = Arc::new(StubDelegate::success("ignored"));

        let request = EdgeRequest {
            session_id: None,
            operation: EdgeOperation::DelegatedToolCall {
                tool: DelegatedTool::Shell,
                args: serde_json::json!({"command": "ls"}),
            },
        };

        let response = handle_worker_request(
            Arc::clone(&memory),
            Arc::clone(&delegate),
            request,
            [DelegatedTool::FileRead],
        )
        .await
        .expect("worker request should return structured error");

        assert!(!response.success);
        assert_eq!(
            response.error.as_deref(),
            Some("delegated tool 'shell' is not allowed")
        );
        assert_eq!(memory.count().await.unwrap(), 0);
        assert!(delegate.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn worker_like_runtime_store_and_recall_round_trip() {
        let memory = Arc::new(InMemoryStore::default());
        let delegate = Arc::new(StubDelegate::success("unused"));
        let runtime = EdgeRuntime::new(Arc::clone(&memory), Arc::clone(&delegate));

        let store = runtime
            .handle(EdgeRequest {
                session_id: Some("session-b".to_string()),
                operation: EdgeOperation::StoreMemory {
                    key: "project_state".to_string(),
                    content: "edge loop initialized".to_string(),
                    category: Some(MemoryCategory::Core),
                },
            })
            .await
            .expect("store request should succeed");
        assert!(store.success);
        assert!(!store.delegated);

        let recall = runtime
            .handle(EdgeRequest {
                session_id: Some("session-b".to_string()),
                operation: EdgeOperation::RecallMemory {
                    query: "initialized".to_string(),
                    limit: 10,
                },
            })
            .await
            .expect("recall request should succeed");

        assert!(recall.success);
        assert_eq!(recall.memories.len(), 1);
        assert_eq!(recall.memories[0].key, "project_state");
        assert_eq!(recall.memories[0].category, MemoryCategory::Core);
    }

    #[tokio::test]
    async fn prefix_planner_parses_delegate_and_memory_operations() {
        let planner = PrefixPlanner;

        let delegate_operation = planner
            .plan("delegate:shell:ls -la")
            .await
            .expect("delegate operation should parse");
        match delegate_operation {
            EdgeOperation::DelegatedToolCall { tool, args } => {
                assert_eq!(tool, DelegatedTool::Shell);
                assert_eq!(args["command"], "ls -la");
            }
            other => panic!("expected delegated tool operation, got {other:?}"),
        }

        let web_search_operation = planner
            .plan("delegate:web_search_tool:latest rust wasm news")
            .await
            .expect("web search operation should parse");
        match web_search_operation {
            EdgeOperation::DelegatedToolCall { tool, args } => {
                assert_eq!(tool, DelegatedTool::WebSearchTool);
                assert_eq!(args["query"], "latest rust wasm news");
            }
            other => panic!("expected delegated tool operation, got {other:?}"),
        }

        let web_fetch_operation = planner
            .plan("delegate:web_fetch:https://example.com")
            .await
            .expect("web fetch operation should parse");
        match web_fetch_operation {
            EdgeOperation::DelegatedToolCall { tool, args } => {
                assert_eq!(tool, DelegatedTool::WebFetch);
                assert_eq!(args["url"], "https://example.com");
            }
            other => panic!("expected delegated tool operation, got {other:?}"),
        }

        let store_operation = planner
            .plan("memory:store:project_state:edge loop initialized")
            .await
            .expect("store operation should parse");
        match store_operation {
            EdgeOperation::StoreMemory {
                key,
                content,
                category,
            } => {
                assert_eq!(key, "project_state");
                assert_eq!(content, "edge loop initialized");
                assert_eq!(category, Some(MemoryCategory::Conversation));
            }
            other => panic!("expected store operation, got {other:?}"),
        }

        let recall_operation = planner
            .plan("memory:recall:project_state")
            .await
            .expect("recall operation should parse");
        match recall_operation {
            EdgeOperation::RecallMemory { query, limit } => {
                assert_eq!(query, "project_state");
                assert_eq!(limit, 10);
            }
            other => panic!("expected recall operation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn prefix_planner_rejects_invalid_messages() {
        let planner = PrefixPlanner;
        for invalid in [
            "",
            "unsupported:command",
            "delegate:shell:",
            "delegate:web_search_tool:",
            "delegate:",
            "delegate:unknown:value",
            "memory:store:key_only",
            "memory:store::content",
            "memory:recall:",
        ] {
            let result = planner.plan(invalid).await;
            assert!(
                result.is_err(),
                "message '{invalid}' should be rejected by planner"
            );
        }
    }

    #[tokio::test]
    async fn local_native_worker_simulates_json_transport_round_trip() {
        let worker = LocalNativeWorker::new(Arc::new(|request: NativeWorkerRequest| {
            assert_eq!(request.session_id.as_deref(), Some("session-c"));
            assert_eq!(request.tool, DelegatedTool::Shell);
            assert_eq!(request.args["command"], "pwd");

            Ok(NativeWorkerResponse {
                success: true,
                output: "edge/native bridge ok".to_string(),
                error: None,
            })
        }));

        let response = worker
            .execute_tool(
                DelegatedTool::Shell,
                serde_json::json!({ "command": "pwd" }),
                Some("session-c"),
            )
            .await
            .expect("local worker should execute successfully");

        assert!(response.success);
        assert_eq!(response.output, "edge/native bridge ok");
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn run_edge_turn_executes_planner_delegate_and_persistence_flow() {
        let memory = Arc::new(InMemoryStore::default());
        let native_worker = Arc::new(LocalNativeWorker::new(Arc::new(
            |request: NativeWorkerRequest| match request.tool {
                DelegatedTool::Shell => {
                    let command = request
                        .args
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if command == "ls" {
                        Ok(NativeWorkerResponse {
                            success: true,
                            output: "README.md\nsrc\n".to_string(),
                            error: None,
                        })
                    } else {
                        Ok(NativeWorkerResponse {
                            success: false,
                            output: String::new(),
                            error: Some("unsupported shell command".to_string()),
                        })
                    }
                }
                other => Ok(NativeWorkerResponse {
                    success: false,
                    output: String::new(),
                    error: Some(format!("unsupported delegated tool: {}", other.as_str())),
                }),
            },
        )));
        let runtime = EdgeRuntime::with_allowed_tools(
            Arc::clone(&memory),
            Arc::clone(&native_worker),
            [DelegatedTool::Shell],
        );
        let planner = PrefixPlanner;

        let stored = run_edge_turn(
            &runtime,
            &planner,
            Some("session-turn".to_string()),
            "memory:store:topic:edge planning",
        )
        .await
        .expect("store turn should succeed");
        assert!(stored.success);
        assert!(!stored.delegated);

        let delegated = run_edge_turn(
            &runtime,
            &planner,
            Some("session-turn".to_string()),
            "delegate:shell:ls",
        )
        .await
        .expect("delegate turn should succeed");
        assert!(delegated.success);
        assert!(delegated.delegated);
        assert_eq!(delegated.output.as_deref(), Some("README.md\nsrc\n"));

        let audit_memories = run_edge_turn(
            &runtime,
            &planner,
            Some("session-turn".to_string()),
            "memory:recall:delegated_tool=shell",
        )
        .await
        .expect("recall turn should succeed");
        assert!(audit_memories.success);
        assert_eq!(audit_memories.memories.len(), 1);
        assert!(audit_memories.memories[0]
            .key
            .starts_with("delegate:shell:"));
    }
}
