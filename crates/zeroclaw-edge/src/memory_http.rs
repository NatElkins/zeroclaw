//! Shared long-term HTTP memory backend for edge/native reconciliation.
//!
//! This module provides a wasm-friendly (runner-injected) HTTP memory client
//! that implements `zeroclaw_core::memory::Memory` and speaks the same wire
//! contract used by native HTTP memory adapters.

use std::fmt;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroclaw_core::memory::{Memory, MemoryCategory, MemoryEntry};

const AUTH_SCHEME_PREFIX: &str = "Bearer ";

/// Command output for HTTP memory transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryHttpCommandOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Command runner boundary for HTTP memory clients.
#[async_trait]
pub trait MemoryHttpCommandRunner: Send + Sync {
    async fn run(
        &self,
        program: &str,
        args: &[String],
        cwd: Option<&PathBuf>,
    ) -> Result<MemoryHttpCommandOutput>;
}

/// Real command runner using `std::process::Command`.
#[cfg(not(target_arch = "wasm32"))]
pub struct SystemMemoryHttpCommandRunner;

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl MemoryHttpCommandRunner for SystemMemoryHttpCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[String],
        cwd: Option<&PathBuf>,
    ) -> Result<MemoryHttpCommandOutput> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let output = cmd
            .output()
            .with_context(|| format!("failed to run command: {program} {}", args.join(" ")))?;
        Ok(MemoryHttpCommandOutput {
            status_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Optional bearer token for shared memory API calls.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryServiceAuthToken(String);

impl MemoryServiceAuthToken {
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let value = raw.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("memory service auth token must not be empty");
        }
        if trimmed.chars().any(char::is_whitespace) {
            bail!("memory service auth token must not contain whitespace");
        }
        Ok(Self(trimmed.to_string()))
    }

    fn as_bearer_header_value(&self) -> String {
        format!("{AUTH_SCHEME_PREFIX}{}", self.0)
    }
}

impl fmt::Debug for MemoryServiceAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryServiceAuthToken(**redacted**)")
    }
}

/// Config for the shared HTTP memory client.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedMemoryHttpClientConfig {
    pub base_url: String,
    pub auth_token: Option<MemoryServiceAuthToken>,
    pub curl_bin: String,
    pub extra_args: Vec<String>,
    pub cwd: Option<PathBuf>,
}

impl fmt::Debug for SharedMemoryHttpClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedMemoryHttpClientConfig")
            .field("base_url", &self.base_url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "**redacted**"),
            )
            .field("curl_bin", &self.curl_bin)
            .field("extra_args", &self.extra_args)
            .field("cwd", &self.cwd)
            .finish()
    }
}

impl SharedMemoryHttpClientConfig {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let trimmed = base_url.trim();
        if trimmed.is_empty() {
            bail!("memory service base_url must not be empty");
        }
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            bail!("memory service base_url must start with http:// or https://");
        }
        Ok(Self {
            base_url: trimmed.trim_end_matches('/').to_string(),
            auth_token: None,
            curl_bin: "curl".to_string(),
            extra_args: Vec::new(),
            cwd: None,
        })
    }

    pub fn with_auth_token(mut self, auth_token: MemoryServiceAuthToken) -> Self {
        self.auth_token = Some(auth_token);
        self
    }
}

#[derive(Debug, Clone, Copy)]
enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// HTTP memory client implementing the shared core memory trait.
pub struct SharedMemoryHttpClient<R>
where
    R: MemoryHttpCommandRunner,
{
    config: SharedMemoryHttpClientConfig,
    runner: R,
}

impl<R> SharedMemoryHttpClient<R>
where
    R: MemoryHttpCommandRunner,
{
    pub fn new(config: SharedMemoryHttpClientConfig, runner: R) -> Result<Self> {
        if config.curl_bin.trim().is_empty() {
            bail!("curl_bin must not be empty");
        }
        Ok(Self { config, runner })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.config.base_url, path.trim_start_matches('/'))
    }

    fn build_curl_args(&self, method: HttpMethod, url: &str, body: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "-fsS".to_string(),
            "-X".to_string(),
            method.as_str().to_string(),
            "-H".to_string(),
            "Content-Type: application/json".to_string(),
        ];
        if let Some(token) = self.config.auth_token.as_ref() {
            args.push("-H".to_string());
            args.push(format!("Authorization: {}", token.as_bearer_header_value()));
        }
        if let Some(body) = body {
            args.push("--data".to_string());
            args.push(body.to_string());
        }
        args.extend(self.config.extra_args.iter().cloned());
        args.push(url.to_string());
        args
    }

    async fn run_json<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
    ) -> Result<T> {
        let args = self.build_curl_args(method, self.endpoint(path).as_str(), body.as_deref());
        let output = self
            .runner
            .run(
                self.config.curl_bin.as_str(),
                args.as_slice(),
                self.config.cwd.as_ref(),
            )
            .await
            .with_context(|| format!("failed executing curl for memory endpoint {path}"))?;
        if output.status_code != 0 {
            bail!(
                "memory request to {path} failed (exit={}): {}",
                output.status_code,
                output.stderr.trim()
            );
        }
        serde_json::from_str(output.stdout.as_str())
            .map_err(|e| anyhow!("memory endpoint {path} returned invalid JSON: {e}"))
    }

    async fn run_no_content(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
    ) -> Result<()> {
        let args = self.build_curl_args(method, self.endpoint(path).as_str(), body.as_deref());
        let output = self
            .runner
            .run(
                self.config.curl_bin.as_str(),
                args.as_slice(),
                self.config.cwd.as_ref(),
            )
            .await
            .with_context(|| format!("failed executing curl for memory endpoint {path}"))?;
        if output.status_code != 0 {
            bail!(
                "memory request to {path} failed (exit={}): {}",
                output.status_code,
                output.stderr.trim()
            );
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl SharedMemoryHttpClient<SystemMemoryHttpCommandRunner> {
    pub fn with_system_runner(config: SharedMemoryHttpClientConfig) -> Result<Self> {
        Self::new(config, SystemMemoryHttpCommandRunner)
    }
}

#[derive(Debug, Serialize)]
struct StoreRequest<'a> {
    key: &'a str,
    content: &'a str,
    category: &'a str,
    session_id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct RecallRequest<'a> {
    query: &'a str,
    limit: usize,
    session_id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct GetRequest<'a> {
    key: &'a str,
}

#[derive(Debug, Serialize)]
struct ListRequest<'a> {
    category: Option<&'a str>,
    session_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct EntriesResponse {
    #[serde(default)]
    entries: Vec<MemoryEntry>,
}

#[derive(Debug, Deserialize)]
struct GetResponse {
    entry: Option<MemoryEntry>,
}

#[derive(Debug, Deserialize)]
struct ForgetResponse {
    deleted: bool,
}

#[derive(Debug, Deserialize)]
struct CountResponse {
    count: usize,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    healthy: Option<bool>,
}

#[async_trait]
impl<R> Memory for SharedMemoryHttpClient<R>
where
    R: MemoryHttpCommandRunner,
{
    fn name(&self) -> &str {
        "shared-http"
    }

    async fn store(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        session_id: Option<&str>,
    ) -> Result<()> {
        let category = category.to_string();
        let payload = serde_json::to_string(&StoreRequest {
            key,
            content,
            category: category.as_str(),
            session_id,
        })
        .context("failed serializing memory store request")?;
        self.run_no_content(HttpMethod::Post, "/v1/memory/store", Some(payload))
            .await
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        session_id: Option<&str>,
    ) -> Result<Vec<MemoryEntry>> {
        let payload = serde_json::to_string(&RecallRequest {
            query,
            limit,
            session_id,
        })
        .context("failed serializing memory recall request")?;
        let response: EntriesResponse = self
            .run_json(HttpMethod::Post, "/v1/memory/recall", Some(payload))
            .await?;
        Ok(response.entries)
    }

    async fn get(&self, key: &str) -> Result<Option<MemoryEntry>> {
        let payload = serde_json::to_string(&GetRequest { key })
            .context("failed serializing memory get request")?;
        let response: GetResponse = self
            .run_json(HttpMethod::Post, "/v1/memory/get", Some(payload))
            .await?;
        Ok(response.entry)
    }

    async fn list(
        &self,
        category: Option<&MemoryCategory>,
        session_id: Option<&str>,
    ) -> Result<Vec<MemoryEntry>> {
        let category = category.map(ToString::to_string);
        let payload = serde_json::to_string(&ListRequest {
            category: category.as_deref(),
            session_id,
        })
        .context("failed serializing memory list request")?;
        let response: EntriesResponse = self
            .run_json(HttpMethod::Post, "/v1/memory/list", Some(payload))
            .await?;
        Ok(response.entries)
    }

    async fn forget(&self, key: &str) -> Result<bool> {
        let payload = serde_json::to_string(&GetRequest { key })
            .context("failed serializing memory forget request")?;
        let response: ForgetResponse = self
            .run_json(HttpMethod::Post, "/v1/memory/forget", Some(payload))
            .await?;
        Ok(response.deleted)
    }

    async fn count(&self) -> Result<usize> {
        let response: CountResponse = self
            .run_json(HttpMethod::Get, "/v1/memory/count", None)
            .await?;
        Ok(response.count)
    }

    async fn health_check(&self) -> bool {
        match self
            .run_json::<HealthResponse>(HttpMethod::Get, "/v1/memory/health", None)
            .await
        {
            Ok(response) => response.healthy.unwrap_or(true),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct SharedNativeMemoryStore {
        entries: Mutex<Vec<MemoryEntry>>,
        next_id: AtomicU64,
    }

    impl SharedNativeMemoryStore {
        fn parse_category(raw: &str) -> MemoryCategory {
            match raw {
                "core" => MemoryCategory::Core,
                "daily" => MemoryCategory::Daily,
                "conversation" => MemoryCategory::Conversation,
                other => MemoryCategory::Custom(other.to_string()),
            }
        }

        fn now_timestamp() -> String {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string()
        }

        fn store_sync(
            &self,
            key: &str,
            content: &str,
            category: MemoryCategory,
            session_id: Option<&str>,
        ) {
            let mut entries = self.entries.lock().unwrap();
            let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
            entries.push(MemoryEntry {
                id: format!("entry-{id}"),
                key: key.to_string(),
                content: content.to_string(),
                category,
                timestamp: Self::now_timestamp(),
                session_id: session_id.map(ToString::to_string),
                score: None,
            });
        }

        fn recall_sync(
            &self,
            query: &str,
            limit: usize,
            session_id: Option<&str>,
        ) -> Vec<MemoryEntry> {
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
            filtered
        }

        fn get_sync(&self, key: &str) -> Option<MemoryEntry> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .find(|entry| entry.key == key)
                .cloned()
        }

        fn list_sync(
            &self,
            category: Option<&MemoryCategory>,
            session_id: Option<&str>,
        ) -> Vec<MemoryEntry> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| {
                    (category.is_none() || Some(&entry.category) == category)
                        && (session_id.is_none() || entry.session_id.as_deref() == session_id)
                })
                .cloned()
                .collect()
        }

        fn forget_sync(&self, key: &str) -> bool {
            let mut entries = self.entries.lock().unwrap();
            let before = entries.len();
            entries.retain(|entry| entry.key != key);
            entries.len() < before
        }

        fn count_sync(&self) -> usize {
            self.entries.lock().unwrap().len()
        }
    }

    struct NativeMemoryReader {
        store: Arc<SharedNativeMemoryStore>,
    }

    impl NativeMemoryReader {
        fn new(store: Arc<SharedNativeMemoryStore>) -> Self {
            Self { store }
        }
    }

    #[async_trait]
    impl Memory for NativeMemoryReader {
        fn name(&self) -> &str {
            "native-reader"
        }

        async fn store(
            &self,
            key: &str,
            content: &str,
            category: MemoryCategory,
            session_id: Option<&str>,
        ) -> Result<()> {
            self.store.store_sync(key, content, category, session_id);
            Ok(())
        }

        async fn recall(
            &self,
            query: &str,
            limit: usize,
            session_id: Option<&str>,
        ) -> Result<Vec<MemoryEntry>> {
            Ok(self.store.recall_sync(query, limit, session_id))
        }

        async fn get(&self, key: &str) -> Result<Option<MemoryEntry>> {
            Ok(self.store.get_sync(key))
        }

        async fn list(
            &self,
            category: Option<&MemoryCategory>,
            session_id: Option<&str>,
        ) -> Result<Vec<MemoryEntry>> {
            Ok(self.store.list_sync(category, session_id))
        }

        async fn forget(&self, key: &str) -> Result<bool> {
            Ok(self.store.forget_sync(key))
        }

        async fn count(&self) -> Result<usize> {
            Ok(self.store.count_sync())
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    #[derive(Debug, Deserialize)]
    struct TestStoreRequest {
        key: String,
        content: String,
        category: String,
        session_id: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct TestRecallRequest {
        query: String,
        limit: usize,
        session_id: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct TestGetRequest {
        key: String,
    }

    #[derive(Debug, Deserialize)]
    struct TestListRequest {
        category: Option<String>,
        session_id: Option<String>,
    }

    #[derive(Debug)]
    struct TestHttpRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        body: String,
    }

    #[derive(Debug)]
    struct TestHttpResponse {
        status_code: u16,
        body: String,
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

    fn memory_service_response(status_code: u16, body: serde_json::Value) -> TestHttpResponse {
        TestHttpResponse {
            status_code,
            body: body.to_string(),
        }
    }

    fn handle_memory_http_request(
        request: TestHttpRequest,
        store: &SharedNativeMemoryStore,
        required_auth: Option<&MemoryServiceAuthToken>,
    ) -> TestHttpResponse {
        if let Some(required_auth) = required_auth {
            let provided = parse_bearer_token(request.authorization.as_deref());
            if provided != Some(required_auth.0.as_str()) {
                return memory_service_response(
                    401,
                    serde_json::json!({ "error": "unauthorized memory request" }),
                );
            }
        }

        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v1/memory/store") => {
                let payload: TestStoreRequest = match serde_json::from_str(request.body.as_str()) {
                    Ok(payload) => payload,
                    Err(err) => {
                        return memory_service_response(
                            400,
                            serde_json::json!({ "error": format!("invalid store payload: {err}") }),
                        )
                    }
                };
                if payload.key.trim().is_empty() || payload.content.trim().is_empty() {
                    return memory_service_response(
                        400,
                        serde_json::json!({ "error": "key/content must not be empty" }),
                    );
                }
                let category = SharedNativeMemoryStore::parse_category(payload.category.trim());
                store.store_sync(
                    payload.key.trim(),
                    payload.content.trim(),
                    category,
                    payload.session_id.as_deref(),
                );
                memory_service_response(200, serde_json::json!({ "stored": true }))
            }
            ("POST", "/v1/memory/recall") => {
                let payload: TestRecallRequest = match serde_json::from_str(request.body.as_str()) {
                    Ok(payload) => payload,
                    Err(err) => {
                        return memory_service_response(
                            400,
                            serde_json::json!({ "error": format!("invalid recall payload: {err}") }),
                        )
                    }
                };
                let entries = store.recall_sync(
                    payload.query.as_str(),
                    payload.limit,
                    payload.session_id.as_deref(),
                );
                memory_service_response(200, serde_json::json!({ "entries": entries }))
            }
            ("POST", "/v1/memory/get") => {
                let payload: TestGetRequest = match serde_json::from_str(request.body.as_str()) {
                    Ok(payload) => payload,
                    Err(err) => {
                        return memory_service_response(
                            400,
                            serde_json::json!({ "error": format!("invalid get payload: {err}") }),
                        )
                    }
                };
                let entry = store.get_sync(payload.key.as_str());
                memory_service_response(200, serde_json::json!({ "entry": entry }))
            }
            ("POST", "/v1/memory/list") => {
                let payload: TestListRequest = match serde_json::from_str(request.body.as_str()) {
                    Ok(payload) => payload,
                    Err(err) => {
                        return memory_service_response(
                            400,
                            serde_json::json!({ "error": format!("invalid list payload: {err}") }),
                        )
                    }
                };
                let category = payload
                    .category
                    .as_deref()
                    .map(SharedNativeMemoryStore::parse_category);
                let entries = store.list_sync(category.as_ref(), payload.session_id.as_deref());
                memory_service_response(200, serde_json::json!({ "entries": entries }))
            }
            ("POST", "/v1/memory/forget") => {
                let payload: TestGetRequest = match serde_json::from_str(request.body.as_str()) {
                    Ok(payload) => payload,
                    Err(err) => {
                        return memory_service_response(
                            400,
                            serde_json::json!({ "error": format!("invalid forget payload: {err}") }),
                        )
                    }
                };
                let deleted = store.forget_sync(payload.key.as_str());
                memory_service_response(200, serde_json::json!({ "deleted": deleted }))
            }
            ("GET", "/v1/memory/count") => {
                memory_service_response(200, serde_json::json!({ "count": store.count_sync() }))
            }
            ("GET", "/v1/memory/health") => {
                memory_service_response(200, serde_json::json!({ "healthy": true }))
            }
            _ => memory_service_response(404, serde_json::json!({ "error": "not found" })),
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
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

    fn read_http_request(stream: &mut TcpStream) -> Result<TestHttpRequest> {
        let mut raw = Vec::<u8>::new();
        let mut buffer = [0_u8; 2048];

        loop {
            let n = stream.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..n]);
            if let Some(header_end) = find_subslice(&raw, b"\r\n\r\n") {
                let header_text = String::from_utf8_lossy(&raw[..header_end]);
                let headers: Vec<&str> = header_text.split("\r\n").collect();
                let content_length = parse_content_length(&headers);
                let required = header_end + 4 + content_length;
                if raw.len() >= required {
                    break;
                }
            }
        }

        let header_end =
            find_subslice(&raw, b"\r\n\r\n").ok_or_else(|| anyhow!("malformed request"))?;
        let header_text = String::from_utf8_lossy(&raw[..header_end]).to_string();
        let mut lines = header_text.lines();
        let request_line = lines.next().unwrap_or_default();
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or_default().to_string();
        let path = request_parts.next().unwrap_or_default().to_string();

        let mut authorization: Option<String> = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("authorization") {
                    authorization = Some(value.trim().to_string());
                }
            }
        }

        let body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();
        Ok(TestHttpRequest {
            method,
            path,
            authorization,
            body,
        })
    }

    fn write_http_response(stream: &mut TcpStream, response: TestHttpResponse) -> Result<()> {
        let reason = match response.status_code {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            _ => "Internal Server Error",
        };
        let head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.status_code,
            reason,
            response.body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(response.body.as_bytes())?;
        stream.flush()?;
        Ok(())
    }

    struct TestMemoryHttpServer {
        endpoint: String,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl TestMemoryHttpServer {
        fn spawn(
            store: Arc<SharedNativeMemoryStore>,
            required_auth: Option<MemoryServiceAuthToken>,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let endpoint = format!("http://{addr}");
            let stop = Arc::new(AtomicBool::new(false));
            let stop_for_thread = Arc::clone(&stop);

            let handle = thread::spawn(move || loop {
                if stop_for_thread.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = match read_http_request(&mut stream) {
                            Ok(request) => request,
                            Err(_) => continue,
                        };
                        let response = handle_memory_http_request(
                            request,
                            store.as_ref(),
                            required_auth.as_ref(),
                        );
                        let _ = write_http_response(&mut stream, response);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            });

            Self {
                endpoint,
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for TestMemoryHttpServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(self.endpoint.trim_start_matches("http://"));
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    type RecordedCall = (String, Vec<String>, Option<PathBuf>);

    struct RecordingRunner {
        calls: Mutex<Vec<RecordedCall>>,
        output: Mutex<MemoryHttpCommandOutput>,
    }

    impl RecordingRunner {
        fn success(stdout: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                output: Mutex::new(MemoryHttpCommandOutput {
                    status_code: 0,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                }),
            }
        }
    }

    #[async_trait]
    impl MemoryHttpCommandRunner for RecordingRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            cwd: Option<&PathBuf>,
        ) -> Result<MemoryHttpCommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec(), cwd.cloned()));
            Ok(self.output.lock().unwrap().clone())
        }
    }

    #[test]
    fn config_rejects_invalid_base_url() {
        assert!(SharedMemoryHttpClientConfig::new(" ").is_err());
        assert!(SharedMemoryHttpClientConfig::new("ftp://memory").is_err());
        assert!(SharedMemoryHttpClientConfig::new("https://memory.example").is_ok());
    }

    #[test]
    fn auth_token_rejects_empty_or_whitespace() {
        assert!(MemoryServiceAuthToken::new("").is_err());
        assert!(MemoryServiceAuthToken::new("a b").is_err());
        assert!(MemoryServiceAuthToken::new("token-1").is_ok());
    }

    #[tokio::test]
    async fn client_builds_auth_header_and_parses_count() {
        let runner = RecordingRunner::success(r#"{"count":3}"#);
        let config = SharedMemoryHttpClientConfig::new("https://memory.example")
            .unwrap()
            .with_auth_token(MemoryServiceAuthToken::new("token-1").unwrap());
        let client = SharedMemoryHttpClient::new(config, runner).unwrap();

        let count = client.count().await.unwrap();
        assert_eq!(count, 3);

        let calls = client.runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "curl");
        assert!(calls[0]
            .1
            .contains(&"Authorization: Bearer token-1".to_string()));
        assert!(calls[0]
            .1
            .contains(&"https://memory.example/v1/memory/count".to_string()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn edge_and_native_readers_reconcile_over_shared_memory_service() {
        let _ = std::process::Command::new("curl")
            .arg("--version")
            .output()
            .expect("curl must be installed");

        let shared_store = Arc::new(SharedNativeMemoryStore::default());
        let auth_token = MemoryServiceAuthToken::new("memory-token-1").unwrap();
        let server =
            TestMemoryHttpServer::spawn(Arc::clone(&shared_store), Some(auth_token.clone()));

        let edge_memory = SharedMemoryHttpClient::with_system_runner(
            SharedMemoryHttpClientConfig::new(server.endpoint.clone())
                .unwrap()
                .with_auth_token(auth_token),
        )
        .unwrap();
        let native_memory = NativeMemoryReader::new(Arc::clone(&shared_store));

        edge_memory
            .store(
                "user:favorite_language",
                "Rust",
                MemoryCategory::Core,
                Some("session-a"),
            )
            .await
            .unwrap();

        let native_read = native_memory
            .get("user:favorite_language")
            .await
            .unwrap()
            .expect("native reader should observe edge write");
        assert_eq!(native_read.content, "Rust");
        assert_eq!(native_read.category, MemoryCategory::Core);
        assert_eq!(native_read.session_id.as_deref(), Some("session-a"));

        native_memory
            .store(
                "project:status",
                "moving to edge",
                MemoryCategory::Conversation,
                Some("session-a"),
            )
            .await
            .unwrap();

        let edge_recall = edge_memory
            .recall("edge", 10, Some("session-a"))
            .await
            .unwrap();
        assert_eq!(edge_recall.len(), 1);
        assert_eq!(edge_recall[0].key, "project:status");
        assert_eq!(edge_recall[0].content, "moving to edge");

        let edge_list = edge_memory
            .list(Some(&MemoryCategory::Conversation), Some("session-a"))
            .await
            .unwrap();
        assert_eq!(edge_list.len(), 1);
        assert_eq!(edge_list[0].key, "project:status");

        let count = edge_memory.count().await.unwrap();
        assert_eq!(count, 2);
        assert!(edge_memory.health_check().await);
    }
}
