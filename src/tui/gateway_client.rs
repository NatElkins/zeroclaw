//! HTTP + WebSocket client for TUI <-> gateway communication.

use anyhow::{Context, Result};
use tokio_tungstenite::tungstenite::Message;

/// Gateway HTTP client for REST API calls.
pub struct GatewayHttpClient {
    base_url: String,
    token: Option<String>,
    client: reqwest::Client,
}

impl GatewayHttpClient {
    pub fn new(base_url: String, token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            base_url,
            token,
            client,
        }
    }

    fn auth_header(&self) -> Option<String> {
        self.token.as_ref().map(|t| format!("Bearer {t}"))
    }

    pub async fn get_status(&self) -> Result<serde_json::Value> {
        let mut req = self.client.get(format!("{}/api/status", self.base_url));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("status request failed")?;
        Ok(resp.json().await?)
    }

    pub async fn get_health(&self) -> Result<bool> {
        match self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    pub async fn get_tools(&self) -> Result<serde_json::Value> {
        let mut req = self.client.get(format!("{}/api/tools", self.base_url));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("tools request failed")?;
        Ok(resp.json().await?)
    }

    pub async fn get_memory(&self) -> Result<serde_json::Value> {
        let mut req = self.client.get(format!("{}/api/memory", self.base_url));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("memory request failed")?;
        Ok(resp.json().await?)
    }

    pub async fn get_cron(&self) -> Result<serde_json::Value> {
        let mut req = self.client.get(format!("{}/api/cron", self.base_url));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("cron request failed")?;
        Ok(resp.json().await?)
    }

    pub async fn get_config(&self) -> Result<serde_json::Value> {
        let mut req = self.client.get(format!("{}/api/config", self.base_url));
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await.context("config request failed")?;
        Ok(resp.json().await?)
    }
}

/// Gateway WebSocket client for real-time chat.
pub struct GatewayWsClient {
    gateway_url: String,
    token: Option<String>,
}

impl GatewayWsClient {
    pub fn new(gateway_url: String, token: Option<String>) -> Self {
        Self { gateway_url, token }
    }

    /// Connect to the gateway WebSocket chat endpoint.
    pub async fn connect(
        &self,
    ) -> Result<(
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    )> {
        use futures_util::StreamExt;

        let ws_url = self
            .gateway_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let url = format!("{ws_url}/ws/chat");

        let mut request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&url)
            .header("Sec-WebSocket-Protocol", "zeroclaw.v1");

        if let Some(ref token) = self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        let request = request
            .body(())
            .context("failed to build WebSocket request")?;

        let (ws_stream, _) = tokio_tungstenite::connect_async(request)
            .await
            .context("WebSocket connection failed")?;

        Ok(ws_stream.split())
    }
}
