//! Hybrid runtime + remote persistence integration tests (service-backed).
//!
//! These tests are intended to run against a real Postgres sidecar service.
//! Set `ZEROCLAW_TEST_POSTGRES_URL` to enable them.

use tempfile::TempDir;
use uuid::Uuid;
use zeroclaw::config::{MemoryConfig, RuntimeConfig, StorageProviderConfig};
use zeroclaw::memory::{create_memory_with_storage, MemoryCategory};
use zeroclaw::runtime::create_runtime;

fn postgres_url() -> Option<String> {
    std::env::var("ZEROCLAW_TEST_POSTGRES_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn random_identifier(prefix: &str) -> String {
    // PostgreSQL identifiers in this codepath must be ASCII alnum/underscore.
    let suffix = Uuid::new_v4().simple().to_string();
    format!("{prefix}_{}", &suffix[..12])
}

fn postgres_storage_config(db_url: &str) -> StorageProviderConfig {
    StorageProviderConfig {
        provider: "postgres".to_string(),
        db_url: Some(db_url.to_string()),
        api_url: None,
        api_token: None,
        schema: random_identifier("hybrid"),
        table: random_identifier("memories"),
        connect_timeout_secs: Some(15),
    }
}

#[cfg(feature = "memory-postgres")]
#[test]
fn postgres_storage_override_persists_across_reinitialization() {
    let Some(db_url) = postgres_url() else {
        eprintln!(
            "skipping postgres_storage_override_persists_across_reinitialization: \
             ZEROCLAW_TEST_POSTGRES_URL is not set"
        );
        return;
    };

    let storage = postgres_storage_config(&db_url);
    let memory_cfg = MemoryConfig {
        // Intentionally keep sqlite as default backend to validate storage-provider override.
        backend: "sqlite".into(),
        ..MemoryConfig::default()
    };
    let workspace = TempDir::new().expect("temporary workspace");

    let memory_a = create_memory_with_storage(&memory_cfg, Some(&storage), workspace.path(), None)
        .expect("postgres memory should initialize via storage provider override");
    assert_eq!(memory_a.name(), "postgres");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        memory_a
            .store(
                "hybrid_fact",
                "edge agent checkpoint",
                MemoryCategory::Core,
                Some("edge-session"),
            )
            .await
            .expect("store should succeed");
    });

    drop(memory_a);

    let memory_b = create_memory_with_storage(&memory_cfg, Some(&storage), workspace.path(), None)
        .expect("postgres memory should reinitialize");

    let restored = runtime.block_on(async {
        memory_b
            .get("hybrid_fact")
            .await
            .expect("get should succeed")
            .expect("entry should exist after reinitialization")
    });
    assert_eq!(restored.content, "edge agent checkpoint");
    assert_eq!(restored.session_id.as_deref(), Some("edge-session"));
}

#[cfg(all(feature = "memory-postgres", feature = "runtime-wasm"))]
#[test]
fn wasm_runtime_with_postgres_memory_round_trip() {
    let Some(db_url) = postgres_url() else {
        eprintln!(
            "skipping wasm_runtime_with_postgres_memory_round_trip: \
             ZEROCLAW_TEST_POSTGRES_URL is not set"
        );
        return;
    };

    let runtime_cfg = RuntimeConfig {
        kind: "wasm".into(),
        ..RuntimeConfig::default()
    };
    let runtime = create_runtime(&runtime_cfg).expect("runtime.kind=wasm should initialize");
    let capabilities = runtime.capabilities();
    assert_eq!(runtime.name(), "wasm");
    assert!(!capabilities.shell_access);
    assert!(!capabilities.filesystem_access);
    assert!(!capabilities.long_running);

    let storage = postgres_storage_config(&db_url);
    let memory_cfg = MemoryConfig {
        backend: "postgres".into(),
        ..MemoryConfig::default()
    };
    let workspace = TempDir::new().expect("temporary workspace");
    let memory = create_memory_with_storage(&memory_cfg, Some(&storage), workspace.path(), None)
        .expect("postgres memory should initialize");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        memory
            .store(
                "worker_fact",
                "delegated worker persisted this record",
                MemoryCategory::Conversation,
                Some("hybrid-worker"),
            )
            .await
            .expect("store should succeed");
    });

    let recalled = runtime.block_on(async {
        memory
            .recall("delegated worker", 5, Some("hybrid-worker"))
            .await
            .expect("recall should succeed")
    });
    assert!(
        recalled
            .iter()
            .any(|entry| entry.key == "worker_fact" && entry.content.contains("persisted")),
        "expected to recall persisted worker_fact entry"
    );
}
