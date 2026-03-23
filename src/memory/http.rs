use super::traits::{Memory, MemoryCategory, MemoryEntry};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// HTTP-backed memory adapter for edge/runtime-separated deployments.
///
/// This backend delegates memory CRUD operations to a remote service over HTTP.
/// It is intended for runtimes where local filesystem/database access is
/// unavailable (for example, WASM edge workers).
#[derive(Debug, Clone)]
pub struct HttpMemory {
    client: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
}

impl HttpMemory {
    pub fn new(
        base_url: &str,
        auth_token: Option<&str>,
        timeout_secs: Option<u64>,
    ) -> Result<Self> {
        let raw = base_url.trim();
        if raw.is_empty() {
            bail!("http memory backend requires a non-empty api_url");
        }

        let parsed = Url::parse(raw).context("invalid http memory api_url")?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => bail!("http memory api_url must use http/https scheme, got '{other}'"),
        }

        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = timeout_secs.filter(|value| *value > 0) {
            builder = builder.timeout(std::time::Duration::from_secs(timeout));
        }
        let client = builder
            .build()
            .context("failed to build http memory client")?;

        Ok(Self {
            client,
            base_url: raw.trim_end_matches('/').to_string(),
            auth_token: auth_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn with_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = self.auth_token.as_deref() {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    async fn decode_json<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("http memory request failed with {status}: {body}");
        }

        response
            .json::<T>()
            .await
            .context("failed to decode http memory response JSON")
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
impl Memory for HttpMemory {
    fn name(&self) -> &str {
        "http"
    }

    async fn store(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        session_id: Option<&str>,
    ) -> Result<()> {
        let body = StoreRequest {
            key,
            content,
            category: &category.to_string(),
            session_id,
        };
        let request = self.with_auth(self.client.post(self.endpoint("/v1/memory/store")));
        let response = request
            .json(&body)
            .send()
            .await
            .context("http memory store request failed")?;
        let status = response.status();
        if !status.is_success() {
            let payload = response.text().await.unwrap_or_default();
            bail!("http memory store failed with {status}: {payload}");
        }
        Ok(())
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        session_id: Option<&str>,
    ) -> Result<Vec<MemoryEntry>> {
        let body = RecallRequest {
            query,
            limit,
            session_id,
        };
        let request = self.with_auth(self.client.post(self.endpoint("/v1/memory/recall")));
        let response = request
            .json(&body)
            .send()
            .await
            .context("http memory recall request failed")?;
        Ok(self.decode_json::<EntriesResponse>(response).await?.entries)
    }

    async fn get(&self, key: &str) -> Result<Option<MemoryEntry>> {
        let request = self.with_auth(self.client.post(self.endpoint("/v1/memory/get")));
        let response = request
            .json(&GetRequest { key })
            .send()
            .await
            .context("http memory get request failed")?;
        Ok(self.decode_json::<GetResponse>(response).await?.entry)
    }

    async fn list(
        &self,
        category: Option<&MemoryCategory>,
        session_id: Option<&str>,
    ) -> Result<Vec<MemoryEntry>> {
        let category = category.map(ToString::to_string);
        let body = ListRequest {
            category: category.as_deref(),
            session_id,
        };
        let request = self.with_auth(self.client.post(self.endpoint("/v1/memory/list")));
        let response = request
            .json(&body)
            .send()
            .await
            .context("http memory list request failed")?;
        Ok(self.decode_json::<EntriesResponse>(response).await?.entries)
    }

    async fn forget(&self, key: &str) -> Result<bool> {
        let request = self.with_auth(self.client.post(self.endpoint("/v1/memory/forget")));
        let response = request
            .json(&GetRequest { key })
            .send()
            .await
            .context("http memory forget request failed")?;
        Ok(self.decode_json::<ForgetResponse>(response).await?.deleted)
    }

    async fn count(&self) -> Result<usize> {
        let request = self.with_auth(self.client.get(self.endpoint("/v1/memory/count")));
        let response = request
            .send()
            .await
            .context("http memory count request failed")?;
        Ok(self.decode_json::<CountResponse>(response).await?.count)
    }

    async fn health_check(&self) -> bool {
        let request = self.with_auth(self.client.get(self.endpoint("/v1/memory/health")));
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return false,
        };

        if !response.status().is_success() {
            return false;
        }

        match response.json::<HealthResponse>().await {
            Ok(parsed) => parsed.healthy.unwrap_or(true),
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_memory_rejects_invalid_scheme() {
        let err = HttpMemory::new("ftp://example.com", None, None)
            .expect_err("non-http scheme should be rejected");
        assert!(err.to_string().contains("http/https"));
    }

    #[test]
    fn http_memory_accepts_valid_url() {
        let memory = HttpMemory::new("https://memory.example.com/", Some("token"), Some(10))
            .expect("valid URL should initialize");
        assert_eq!(memory.name(), "http");
        assert_eq!(memory.base_url, "https://memory.example.com");
    }
}
