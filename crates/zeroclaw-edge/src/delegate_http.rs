//! Authenticated HTTP delegation boundary between edge runtime and native worker.
//!
//! This module provides:
//! - a deterministic native-service handler (`handle_native_delegate_http_request`)
//! - an edge-side HTTP client implementing `DelegateExecutor`
//!
//! The contract is intentionally narrow and typed so illegal request states are
//! rejected at the boundary before tool execution.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::Value;

use crate::{
    DelegateExecutor, DelegatedTool, NativeWorkerHandler, NativeWorkerRequest, NativeWorkerResponse,
};
use zeroclaw_core::tools::ToolResult;

const AUTH_SCHEME_PREFIX: &str = "Bearer ";

/// Minimal command output for delegate HTTP transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateCommandOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Command runner boundary for the delegate HTTP client.
#[async_trait]
pub trait DelegateCommandRunner: Send + Sync {
    async fn run(
        &self,
        program: &str,
        args: &[String],
        cwd: Option<&PathBuf>,
    ) -> Result<DelegateCommandOutput>;
}

/// Real command runner using `std::process::Command`.
#[cfg(not(target_arch = "wasm32"))]
pub struct SystemDelegateCommandRunner;

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DelegateCommandRunner for SystemDelegateCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[String],
        cwd: Option<&PathBuf>,
    ) -> Result<DelegateCommandOutput> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let output = cmd
            .output()
            .with_context(|| format!("failed to run command: {program} {}", args.join(" ")))?;
        Ok(DelegateCommandOutput {
            status_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Authentication token for edge->native delegation requests.
#[derive(Clone, PartialEq, Eq)]
pub struct DelegationAuthToken(String);

impl DelegationAuthToken {
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let value = raw.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("delegation auth token must not be empty");
        }
        if trimmed.chars().any(char::is_whitespace) {
            bail!("delegation auth token must not contain whitespace");
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn as_bearer_header_value(&self) -> String {
        format!("{AUTH_SCHEME_PREFIX}{}", self.as_str())
    }
}

impl fmt::Debug for DelegationAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DelegationAuthToken(**redacted**)")
    }
}

/// Native service policy for handling delegated tool requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDelegateServicePolicy {
    pub auth_token: DelegationAuthToken,
    pub allowed_tools: BTreeSet<DelegatedTool>,
}

impl NativeDelegateServicePolicy {
    pub fn new(
        auth_token: DelegationAuthToken,
        allowed_tools: impl IntoIterator<Item = DelegatedTool>,
    ) -> Self {
        Self {
            auth_token,
            allowed_tools: allowed_tools.into_iter().collect(),
        }
    }
}

/// Minimal HTTP request envelope for native delegation service handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDelegateHttpRequest {
    pub method: String,
    pub authorization: Option<String>,
    pub body: String,
}

impl NativeDelegateHttpRequest {
    pub fn new(
        method: impl Into<String>,
        authorization: Option<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            authorization,
            body: body.into(),
        }
    }
}

/// Minimal HTTP response envelope for native delegation service handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDelegateHttpResponse {
    pub status_code: u16,
    pub body: String,
}

impl NativeDelegateHttpResponse {
    fn json(status_code: u16, response: &NativeWorkerResponse) -> Self {
        let body = serde_json::to_string(response).unwrap_or_else(|_| {
            r#"{"success":false,"output":"","error":"failed serializing response"}"#.to_string()
        });
        Self { status_code, body }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NativeDelegateServiceError {
    MethodNotAllowed(String),
    Unauthorized,
    InvalidJson(String),
    ToolNotAllowed(DelegatedTool),
    Handler(String),
}

impl NativeDelegateServiceError {
    fn status_code(&self) -> u16 {
        match self {
            Self::MethodNotAllowed(_) => 405,
            Self::Unauthorized => 401,
            Self::InvalidJson(_) => 400,
            Self::ToolNotAllowed(_) => 403,
            Self::Handler(_) => 500,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::MethodNotAllowed(method) => {
                format!("method '{method}' is not allowed; expected POST")
            }
            Self::Unauthorized => "unauthorized delegated tool request".to_string(),
            Self::InvalidJson(msg) => format!("invalid delegated tool request payload: {msg}"),
            Self::ToolNotAllowed(tool) => {
                format!(
                    "delegated tool '{}' is not allowed by service policy",
                    tool.as_str()
                )
            }
            Self::Handler(msg) => format!("native delegate handler failed: {msg}"),
        }
    }
}

fn parse_bearer_token(header: Option<&str>) -> Option<&str> {
    let raw = header?;
    let trimmed = raw.trim();
    let token = trimmed.strip_prefix(AUTH_SCHEME_PREFIX)?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn validate_service_request(
    policy: &NativeDelegateServicePolicy,
    req: &NativeDelegateHttpRequest,
) -> std::result::Result<NativeWorkerRequest, NativeDelegateServiceError> {
    if !req.method.eq_ignore_ascii_case("POST") {
        return Err(NativeDelegateServiceError::MethodNotAllowed(
            req.method.trim().to_string(),
        ));
    }

    let token = parse_bearer_token(req.authorization.as_deref())
        .ok_or(NativeDelegateServiceError::Unauthorized)?;
    if token != policy.auth_token.as_str() {
        return Err(NativeDelegateServiceError::Unauthorized);
    }

    let parsed: NativeWorkerRequest = serde_json::from_str(req.body.as_str())
        .map_err(|e| NativeDelegateServiceError::InvalidJson(e.to_string()))?;
    if !policy.allowed_tools.contains(&parsed.tool) {
        return Err(NativeDelegateServiceError::ToolNotAllowed(parsed.tool));
    }
    Ok(parsed)
}

/// Handle one native delegate HTTP request.
///
/// The response body is always a JSON-encoded `NativeWorkerResponse`.
pub fn handle_native_delegate_http_request(
    policy: &NativeDelegateServicePolicy,
    req: NativeDelegateHttpRequest,
    handler: &dyn NativeWorkerHandler,
) -> NativeDelegateHttpResponse {
    match validate_service_request(policy, &req) {
        Ok(request) => match handler.handle(request) {
            Ok(response) => NativeDelegateHttpResponse::json(200, &response),
            Err(err) => NativeDelegateHttpResponse::json(
                NativeDelegateServiceError::Handler(err.to_string()).status_code(),
                &NativeWorkerResponse {
                    success: false,
                    output: String::new(),
                    error: Some(NativeDelegateServiceError::Handler(err.to_string()).message()),
                },
            ),
        },
        Err(err) => NativeDelegateHttpResponse::json(
            err.status_code(),
            &NativeWorkerResponse {
                success: false,
                output: String::new(),
                error: Some(err.message()),
            },
        ),
    }
}

/// Edge-side HTTP client config for calling a native delegate service.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeDelegateHttpClientConfig {
    pub endpoint_url: String,
    pub auth_token: DelegationAuthToken,
    pub curl_bin: String,
    pub extra_args: Vec<String>,
    pub cwd: Option<PathBuf>,
}

impl fmt::Debug for NativeDelegateHttpClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDelegateHttpClientConfig")
            .field("endpoint_url", &self.endpoint_url)
            .field("auth_token", &"**redacted**")
            .field("curl_bin", &self.curl_bin)
            .field("extra_args", &self.extra_args)
            .field("cwd", &self.cwd)
            .finish()
    }
}

impl NativeDelegateHttpClientConfig {
    pub fn new(endpoint_url: impl Into<String>, auth_token: DelegationAuthToken) -> Result<Self> {
        let endpoint_url = endpoint_url.into();
        let endpoint_trimmed = endpoint_url.trim();
        if endpoint_trimmed.is_empty() {
            bail!("native delegate endpoint url must not be empty");
        }
        if !endpoint_trimmed.starts_with("http://") && !endpoint_trimmed.starts_with("https://") {
            bail!("native delegate endpoint url must start with http:// or https://");
        }

        Ok(Self {
            endpoint_url: endpoint_trimmed.to_string(),
            auth_token,
            curl_bin: "curl".to_string(),
            extra_args: Vec::new(),
            cwd: None,
        })
    }
}

/// HTTP delegate client that forwards tool calls to native workers.
pub struct NativeDelegateHttpClient<R>
where
    R: DelegateCommandRunner,
{
    config: NativeDelegateHttpClientConfig,
    runner: R,
}

impl<R> NativeDelegateHttpClient<R>
where
    R: DelegateCommandRunner,
{
    pub fn new(config: NativeDelegateHttpClientConfig, runner: R) -> Result<Self> {
        if config.curl_bin.trim().is_empty() {
            bail!("curl_bin must not be empty");
        }
        Ok(Self { config, runner })
    }

    fn build_curl_args(&self, request_body: &str) -> Vec<String> {
        let mut args = vec![
            "-fsS".to_string(),
            "-X".to_string(),
            "POST".to_string(),
            "-H".to_string(),
            format!(
                "Authorization: {}",
                self.config.auth_token.as_bearer_header_value()
            ),
            "-H".to_string(),
            "Content-Type: application/json".to_string(),
            "--data".to_string(),
            request_body.to_string(),
        ];
        args.extend(self.config.extra_args.iter().cloned());
        args.push(self.config.endpoint_url.clone());
        args
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeDelegateHttpClient<SystemDelegateCommandRunner> {
    pub fn with_system_runner(config: NativeDelegateHttpClientConfig) -> Result<Self> {
        Self::new(config, SystemDelegateCommandRunner)
    }
}

#[async_trait(?Send)]
impl<R> DelegateExecutor for NativeDelegateHttpClient<R>
where
    R: DelegateCommandRunner,
{
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
        let request_body = serde_json::to_string(&request)
            .context("failed serializing native delegation request")?;
        let curl_args = self.build_curl_args(request_body.as_str());

        let output = self
            .runner
            .run(
                self.config.curl_bin.as_str(),
                curl_args.as_slice(),
                self.config.cwd.as_ref(),
            )
            .await
            .context("failed executing native delegation curl command")?;

        if output.status_code != 0 {
            bail!(
                "native delegation curl failed (exit={}): {}",
                output.status_code,
                output.stderr.trim()
            );
        }

        let response: NativeWorkerResponse = serde_json::from_str(output.stdout.as_str())
            .map_err(|e| anyhow!("native delegation response JSON decode failed: {e}"))?;

        Ok(ToolResult {
            success: response.success,
            output: response.output,
            error: response.error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn sample_request_json(tool: DelegatedTool) -> String {
        serde_json::json!({
            "session_id": "session-1",
            "tool": tool,
            "args": { "command": "ls" }
        })
        .to_string()
    }

    fn decode_service_response(resp: &NativeDelegateHttpResponse) -> NativeWorkerResponse {
        serde_json::from_str(resp.body.as_str()).expect("response body should decode")
    }

    #[test]
    fn token_rejects_empty_and_whitespace() {
        assert!(DelegationAuthToken::new(" ").is_err());
        assert!(DelegationAuthToken::new("abc 123").is_err());
        assert_eq!(
            DelegationAuthToken::new("token-123").unwrap().as_str(),
            "token-123"
        );
    }

    #[test]
    fn service_rejects_unauthorized_request() {
        let policy = NativeDelegateServicePolicy::new(
            DelegationAuthToken::new("token-1").unwrap(),
            [DelegatedTool::Shell],
        );
        let req = NativeDelegateHttpRequest::new(
            "POST",
            Some("Bearer wrong".to_string()),
            sample_request_json(DelegatedTool::Shell),
        );
        let response =
            handle_native_delegate_http_request(&policy, req, &|_request: NativeWorkerRequest| {
                Ok(NativeWorkerResponse {
                    success: true,
                    output: "ok".to_string(),
                    error: None,
                })
            });
        assert_eq!(response.status_code, 401);
        let body = decode_service_response(&response);
        assert!(!body.success);
        assert!(body
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("unauthorized"));
    }

    #[test]
    fn service_rejects_disallowed_tool() {
        let policy = NativeDelegateServicePolicy::new(
            DelegationAuthToken::new("token-1").unwrap(),
            [DelegatedTool::FileRead],
        );
        let req = NativeDelegateHttpRequest::new(
            "POST",
            Some("Bearer token-1".to_string()),
            sample_request_json(DelegatedTool::Shell),
        );
        let response =
            handle_native_delegate_http_request(&policy, req, &|_request: NativeWorkerRequest| {
                Ok(NativeWorkerResponse {
                    success: true,
                    output: "ok".to_string(),
                    error: None,
                })
            });
        assert_eq!(response.status_code, 403);
        let body = decode_service_response(&response);
        assert!(!body.success);
        assert!(body
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("not allowed"));
    }

    #[test]
    fn service_executes_handler_for_valid_request() {
        let policy = NativeDelegateServicePolicy::new(
            DelegationAuthToken::new("token-1").unwrap(),
            [DelegatedTool::Shell],
        );
        let req = NativeDelegateHttpRequest::new(
            "POST",
            Some("Bearer token-1".to_string()),
            sample_request_json(DelegatedTool::Shell),
        );
        let response =
            handle_native_delegate_http_request(&policy, req, &|request: NativeWorkerRequest| {
                assert_eq!(request.tool, DelegatedTool::Shell);
                assert_eq!(request.args["command"], "ls");
                Ok(NativeWorkerResponse {
                    success: true,
                    output: "README.md\nsrc\n".to_string(),
                    error: None,
                })
            });
        assert_eq!(response.status_code, 200);
        let body = decode_service_response(&response);
        assert!(body.success);
        assert_eq!(body.output, "README.md\nsrc\n");
    }

    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>, Option<PathBuf>)>>,
        output: Mutex<DelegateCommandOutput>,
    }

    impl RecordingRunner {
        fn success(stdout: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                output: Mutex::new(DelegateCommandOutput {
                    status_code: 0,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                }),
            }
        }
    }

    #[async_trait]
    impl DelegateCommandRunner for RecordingRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            cwd: Option<&PathBuf>,
        ) -> Result<DelegateCommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec(), cwd.cloned()));
            Ok(self.output.lock().unwrap().clone())
        }
    }

    #[tokio::test]
    async fn client_builds_authenticated_curl_and_parses_response() {
        let token = DelegationAuthToken::new("token-abc").unwrap();
        let cfg =
            NativeDelegateHttpClientConfig::new("https://native.example/delegate", token).unwrap();
        let runner = RecordingRunner::success(r#"{"success":true,"output":"ok","error":null}"#);
        let client = NativeDelegateHttpClient::new(cfg, runner).unwrap();

        let result = client
            .execute_tool(
                DelegatedTool::Shell,
                serde_json::json!({ "command": "pwd" }),
                Some("session-z"),
            )
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output, "ok");

        let calls = client.runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "curl");
        assert!(calls[0]
            .1
            .contains(&"Authorization: Bearer token-abc".to_string()));
        assert!(calls[0]
            .1
            .contains(&"https://native.example/delegate".to_string()));
    }

    #[tokio::test]
    async fn client_surfaces_nonzero_curl_exit() {
        let token = DelegationAuthToken::new("token-abc").unwrap();
        let cfg =
            NativeDelegateHttpClientConfig::new("https://native.example/delegate", token).unwrap();
        let runner = RecordingRunner {
            calls: Mutex::new(Vec::new()),
            output: Mutex::new(DelegateCommandOutput {
                status_code: 22,
                stdout: String::new(),
                stderr: "http 401".to_string(),
            }),
        };
        let client = NativeDelegateHttpClient::new(cfg, runner).unwrap();

        let err = client
            .execute_tool(
                DelegatedTool::Shell,
                serde_json::json!({ "command": "pwd" }),
                None,
            )
            .await
            .expect_err("should fail");
        assert!(err.to_string().contains("curl failed"));
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn parse_content_length(headers: &[&str]) -> usize {
        headers
            .iter()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    Some(value.trim().parse::<usize>().ok()?)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn spawn_single_request_server(
        policy: NativeDelegateServicePolicy,
        handler: Arc<dyn NativeWorkerHandler>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}/delegate/execute");

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::<u8>::new();
            let mut buf = [0_u8; 2048];

            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if let Some(header_end) = find_subslice(&raw, b"\r\n\r\n") {
                    let header_text = String::from_utf8_lossy(&raw[..header_end]);
                    let header_lines: Vec<&str> = header_text.split("\r\n").collect();
                    let content_length = parse_content_length(&header_lines);
                    let required = header_end + 4 + content_length;
                    if raw.len() >= required {
                        break;
                    }
                }
            }

            let header_end = find_subslice(&raw, b"\r\n\r\n").unwrap();
            let header_text = String::from_utf8_lossy(&raw[..header_end]).to_string();
            let mut lines = header_text.lines();
            let request_line = lines.next().unwrap_or_default();
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();

            let mut authorization: Option<String> = None;
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("authorization") {
                        authorization = Some(value.trim().to_string());
                    }
                }
            }

            let body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();
            let response = handle_native_delegate_http_request(
                &policy,
                NativeDelegateHttpRequest::new(method, authorization, body),
                handler.as_ref(),
            );
            let reason = match response.status_code {
                200 => "OK",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                405 => "Method Not Allowed",
                _ => "Internal Server Error",
            };
            let response_head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.status_code,
                reason,
                response.body.len()
            );
            stream.write_all(response_head.as_bytes()).unwrap();
            stream.write_all(response.body.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        (endpoint, handle)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn system_curl_client_round_trip_with_local_service() {
        let _ = std::process::Command::new("curl")
            .arg("--version")
            .output()
            .expect("curl must be installed");

        let token = DelegationAuthToken::new("token-local-1").unwrap();
        let policy = NativeDelegateServicePolicy::new(token.clone(), [DelegatedTool::Shell]);
        let handler = Arc::new(|request: NativeWorkerRequest| {
            if request.tool != DelegatedTool::Shell {
                return Ok(NativeWorkerResponse {
                    success: false,
                    output: String::new(),
                    error: Some("unsupported tool".to_string()),
                });
            }
            Ok(NativeWorkerResponse {
                success: true,
                output: "native service ok".to_string(),
                error: None,
            })
        });
        let (endpoint, server) = spawn_single_request_server(policy, handler);

        let cfg = NativeDelegateHttpClientConfig::new(endpoint, token).unwrap();
        let client = NativeDelegateHttpClient::with_system_runner(cfg).unwrap();
        let result = client
            .execute_tool(
                DelegatedTool::Shell,
                serde_json::json!({ "command": "ls" }),
                Some("session-local"),
            )
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output, "native service ok");
        server.join().unwrap();
    }
}
