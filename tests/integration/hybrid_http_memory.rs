//! Hybrid runtime + HTTP memory adapter integration tests.

use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroclaw::config::{MemoryConfig, StorageProviderConfig};
use zeroclaw::memory::{create_memory_with_storage, MemoryCategory};

fn http_storage_config(base_url: &str, token: Option<&str>) -> StorageProviderConfig {
    StorageProviderConfig {
        provider: "http".to_string(),
        db_url: None,
        api_url: Some(base_url.to_string()),
        api_token: token.map(str::to_string),
        schema: "public".to_string(),
        table: "memories".to_string(),
        connect_timeout_secs: Some(10),
    }
}

#[tokio::test]
async fn http_storage_override_store_and_get_with_bearer_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/memory/store"))
        .and(header("authorization", "Bearer edge-token"))
        .and(body_partial_json(json!({
            "key": "edge_fact",
            "content": "workers can persist through HTTP memory",
            "category": "core",
            "session_id": "edge-session"
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/memory/get"))
        .and(header("authorization", "Bearer edge-token"))
        .and(body_partial_json(json!({ "key": "edge_fact" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entry": {
                "id": "mem-1",
                "key": "edge_fact",
                "content": "workers can persist through HTTP memory",
                "category": "core",
                "timestamp": "2026-03-23T00:00:00Z",
                "session_id": "edge-session",
                "score": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let memory_cfg = MemoryConfig {
        // Keep sqlite default to verify storage-provider override chooses HTTP.
        backend: "sqlite".into(),
        ..MemoryConfig::default()
    };
    let storage = http_storage_config(&server.uri(), Some("edge-token"));
    let workspace = TempDir::new().expect("temporary workspace");

    let memory = create_memory_with_storage(&memory_cfg, Some(&storage), workspace.path(), None)
        .expect("http memory should initialize from storage override");
    assert_eq!(memory.name(), "http");

    memory
        .store(
            "edge_fact",
            "workers can persist through HTTP memory",
            MemoryCategory::Core,
            Some("edge-session"),
        )
        .await
        .expect("store should succeed");

    let entry = memory
        .get("edge_fact")
        .await
        .expect("get should succeed")
        .expect("entry should exist");
    assert_eq!(entry.content, "workers can persist through HTTP memory");
    assert_eq!(entry.session_id.as_deref(), Some("edge-session"));
}

#[tokio::test]
async fn http_memory_uses_db_url_fallback_without_auth_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/memory/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "healthy": true })))
        .expect(1)
        .mount(&server)
        .await;

    let storage = StorageProviderConfig {
        provider: "http".to_string(),
        db_url: Some(server.uri()),
        api_url: None,
        api_token: None,
        schema: "public".to_string(),
        table: "memories".to_string(),
        connect_timeout_secs: Some(10),
    };
    let memory_cfg = MemoryConfig {
        backend: "http".into(),
        ..MemoryConfig::default()
    };
    let workspace = TempDir::new().expect("temporary workspace");

    let memory = create_memory_with_storage(&memory_cfg, Some(&storage), workspace.path(), None)
        .expect("http memory should initialize from db_url fallback");

    assert!(memory.health_check().await, "health check should succeed");

    let requests = server
        .received_requests()
        .await
        .expect("requests should be captured");
    assert_eq!(requests.len(), 1, "expected single health request");
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "authorization header should be omitted when api_token is unset"
    );
}

#[test]
fn http_memory_requires_api_or_db_url() {
    let storage = StorageProviderConfig {
        provider: "http".to_string(),
        db_url: None,
        api_url: None,
        api_token: None,
        schema: "public".to_string(),
        table: "memories".to_string(),
        connect_timeout_secs: None,
    };
    let memory_cfg = MemoryConfig {
        backend: "sqlite".into(),
        ..MemoryConfig::default()
    };
    let workspace = TempDir::new().expect("temporary workspace");

    let error = create_memory_with_storage(&memory_cfg, Some(&storage), workspace.path(), None)
        .err()
        .expect("missing API URL should fail");

    assert!(
        error
            .to_string()
            .contains("requires [storage.provider.config].api_url"),
        "unexpected error: {error}"
    );
}
