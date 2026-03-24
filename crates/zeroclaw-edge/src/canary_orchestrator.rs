//! Canary orchestration layer for edge rollout execution.
//!
//! This module composes:
//! - canary decisioning (`CanaryController`)
//! - metrics ingestion
//! - traffic split application
//! - event persistence
//!
//! Everything is intentionally interface-driven so local deterministic
//! simulations can validate behavior before any live Cloudflare API wiring.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use zeroclaw_core::memory::{Memory, MemoryCategory};

use crate::canary::{
    CanaryConfigError, CanaryController, CanaryDecision, CanaryMetrics, CloudflareTrafficUpdate,
    TrafficPercent,
};

/// Fetches the latest canary metrics window.
#[async_trait(?Send)]
pub trait CanaryMetricsSource: Send + Sync {
    async fn current_window(&self) -> Result<CanaryMetrics>;
}

/// Applies traffic-split updates to the deployment target.
#[async_trait(?Send)]
pub trait CanaryTrafficClient: Send + Sync {
    async fn apply_split(&self, update: CloudflareTrafficUpdate) -> Result<()>;
}

/// Receives canary tick outcomes for audit/observability.
#[async_trait(?Send)]
pub trait CanaryEventSink: Send + Sync {
    async fn record(&self, outcome: &CanaryTickOutcome) -> Result<()>;
}

/// No-op event sink for tests or minimal setups.
pub struct NoopCanaryEventSink;

#[async_trait(?Send)]
impl CanaryEventSink for NoopCanaryEventSink {
    async fn record(&self, _outcome: &CanaryTickOutcome) -> Result<()> {
        Ok(())
    }
}

/// Shared version identifiers used when building traffic updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryVersionSet {
    stable_version_id: String,
    canary_version_id: String,
}

impl CanaryVersionSet {
    pub fn new(
        stable_version_id: impl Into<String>,
        canary_version_id: impl Into<String>,
    ) -> Result<Self, CanaryConfigError> {
        let stable_version_id = stable_version_id.into();
        let canary_version_id = canary_version_id.into();
        if stable_version_id.trim().is_empty() {
            return Err(CanaryConfigError::EmptyStableVersionId);
        }
        if canary_version_id.trim().is_empty() {
            return Err(CanaryConfigError::EmptyCanaryVersionId);
        }

        Ok(Self {
            stable_version_id,
            canary_version_id,
        })
    }

    fn build_update(&self, canary_traffic: TrafficPercent) -> Result<CloudflareTrafficUpdate> {
        CloudflareTrafficUpdate::new(
            self.stable_version_id.clone(),
            self.canary_version_id.clone(),
            canary_traffic,
        )
        .context("failed building cloudflare traffic update")
    }
}

/// One evaluated rollout interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryTickOutcome {
    pub metrics: CanaryMetrics,
    pub decision: CanaryDecision,
    pub applied_update: Option<CloudflareTrafficUpdate>,
}

/// Stateful canary rollout runner.
pub struct CanaryOrchestrator<M, C, E>
where
    M: CanaryMetricsSource,
    C: CanaryTrafficClient,
    E: CanaryEventSink,
{
    controller: CanaryController,
    versions: CanaryVersionSet,
    metrics_source: Arc<M>,
    traffic_client: Arc<C>,
    event_sink: Arc<E>,
    last_applied_canary_traffic: Option<TrafficPercent>,
}

impl<M, C, E> CanaryOrchestrator<M, C, E>
where
    M: CanaryMetricsSource,
    C: CanaryTrafficClient,
    E: CanaryEventSink,
{
    pub fn new(
        controller: CanaryController,
        versions: CanaryVersionSet,
        metrics_source: Arc<M>,
        traffic_client: Arc<C>,
        event_sink: Arc<E>,
    ) -> Self {
        Self {
            controller,
            versions,
            metrics_source,
            traffic_client,
            event_sink,
            last_applied_canary_traffic: None,
        }
    }

    pub async fn tick(&mut self) -> Result<CanaryTickOutcome> {
        let metrics = self.metrics_source.current_window().await?;
        let decision = self.controller.observe(metrics);
        let target_canary_traffic = match decision {
            CanaryDecision::Hold { .. } => None,
            CanaryDecision::Promote { to, .. } => Some(TrafficPercent::from(to)),
            CanaryDecision::Complete { stage } => Some(TrafficPercent::from(stage)),
            CanaryDecision::Rollback { .. } => Some(TrafficPercent::ZERO),
        };

        let applied_update = if let Some(canary_traffic) = target_canary_traffic {
            if self.last_applied_canary_traffic == Some(canary_traffic) {
                None
            } else {
                let update = self.versions.build_update(canary_traffic)?;
                self.traffic_client
                    .apply_split(update.clone())
                    .await
                    .context("failed applying canary traffic split")?;
                self.last_applied_canary_traffic = Some(canary_traffic);
                Some(update)
            }
        } else {
            None
        };

        let outcome = CanaryTickOutcome {
            metrics,
            decision,
            applied_update,
        };
        self.event_sink
            .record(&outcome)
            .await
            .context("failed recording canary outcome")?;
        Ok(outcome)
    }
}

/// Event sink that persists canary outcomes into shared memory.
pub struct MemoryCanaryEventSink<M>
where
    M: Memory,
{
    memory: Arc<M>,
    session_id: Option<String>,
    key_prefix: String,
}

impl<M> MemoryCanaryEventSink<M>
where
    M: Memory,
{
    pub fn new(memory: Arc<M>, session_id: Option<String>) -> Self {
        Self {
            memory,
            session_id,
            key_prefix: "canary:event".to_string(),
        }
    }
}

#[async_trait(?Send)]
impl<M> CanaryEventSink for MemoryCanaryEventSink<M>
where
    M: Memory,
{
    async fn record(&self, outcome: &CanaryTickOutcome) -> Result<()> {
        let key = format!(
            "{}:{}:{}",
            self.key_prefix,
            unix_timestamp_secs(),
            unix_timestamp_nanos()
        );
        let applied = outcome
            .applied_update
            .as_ref()
            .map(|u| u.canary_traffic().get().to_string())
            .unwrap_or_else(|| "none".to_string());
        let content = format!(
            "decision={:?} requests={} failed={} p95_ms={} applied_canary_traffic={}",
            outcome.decision,
            outcome.metrics.total_requests(),
            outcome.metrics.failed_requests(),
            outcome.metrics.p95_latency_ms(),
            applied
        );
        self.memory
            .store(
                &key,
                &content,
                MemoryCategory::Daily,
                self.session_id.as_deref(),
            )
            .await
            .context("failed writing canary outcome to memory")
    }
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_timestamp_nanos() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::canary::{
        BasisPoints, CanaryPlan, CanaryStage, CanaryThresholds, HoldReason, Percent,
    };
    use std::collections::VecDeque;
    use std::num::{NonZeroU64, NonZeroU8};
    use std::sync::Mutex;
    use zeroclaw_core::memory::MemoryEntry;

    fn test_plan() -> CanaryPlan {
        CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(10).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(50).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(100).unwrap(), NonZeroU8::new(1).unwrap()),
            ],
            CanaryThresholds::new(
                BasisPoints::new(200).unwrap(),
                800,
                NonZeroU64::new(100).unwrap(),
            ),
        )
        .unwrap()
    }

    struct QueueMetricsSource {
        queue: Mutex<VecDeque<CanaryMetrics>>,
    }

    impl QueueMetricsSource {
        fn new(metrics: Vec<CanaryMetrics>) -> Self {
            Self {
                queue: Mutex::new(metrics.into_iter().collect()),
            }
        }
    }

    #[async_trait(?Send)]
    impl CanaryMetricsSource for QueueMetricsSource {
        async fn current_window(&self) -> Result<CanaryMetrics> {
            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .context("no metrics remaining in queue")
        }
    }

    #[derive(Default)]
    struct RecordingTrafficClient {
        updates: Mutex<Vec<CloudflareTrafficUpdate>>,
    }

    #[async_trait(?Send)]
    impl CanaryTrafficClient for RecordingTrafficClient {
        async fn apply_split(&self, update: CloudflareTrafficUpdate) -> Result<()> {
            self.updates.lock().unwrap().push(update);
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingEventSink {
        events: Mutex<Vec<CanaryTickOutcome>>,
    }

    #[async_trait(?Send)]
    impl CanaryEventSink for RecordingEventSink {
        async fn record(&self, outcome: &CanaryTickOutcome) -> Result<()> {
            self.events.lock().unwrap().push(outcome.clone());
            Ok(())
        }
    }

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
            let mut matched: Vec<MemoryEntry> = self
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
            matched.truncate(limit);
            Ok(matched)
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
            let mut entries = self.entries.lock().unwrap();
            let before = entries.len();
            entries.retain(|entry| entry.key != key);
            Ok(entries.len() < before)
        }

        async fn count(&self) -> Result<usize> {
            Ok(self.entries.lock().unwrap().len())
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn orchestrator_promotes_and_completes_with_idempotent_final_apply() {
        let source = Arc::new(QueueMetricsSource::new(vec![
            CanaryMetrics::new(200, 1, 200).unwrap(),
            CanaryMetrics::new(200, 1, 220).unwrap(),
            CanaryMetrics::new(200, 1, 240).unwrap(),
        ]));
        let traffic = Arc::new(RecordingTrafficClient::default());
        let sink = Arc::new(RecordingEventSink::default());
        let versions = CanaryVersionSet::new("stable-v1", "canary-v2").unwrap();

        let mut orchestrator = CanaryOrchestrator::new(
            CanaryController::new(test_plan()),
            versions,
            source,
            Arc::clone(&traffic),
            Arc::clone(&sink),
        );

        let first = orchestrator.tick().await.unwrap();
        let second = orchestrator.tick().await.unwrap();
        let third = orchestrator.tick().await.unwrap();

        assert!(matches!(first.decision, CanaryDecision::Promote { .. }));
        assert!(matches!(second.decision, CanaryDecision::Promote { .. }));
        assert!(matches!(third.decision, CanaryDecision::Complete { .. }));

        let updates = traffic.updates.lock().unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].canary_traffic().get(), 50);
        assert_eq!(updates[1].canary_traffic().get(), 100);

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert!(events[2].applied_update.is_none());
    }

    #[tokio::test]
    async fn orchestrator_rolls_back_to_zero_canary_traffic() {
        let source = Arc::new(QueueMetricsSource::new(vec![CanaryMetrics::new(
            200, 20, 250,
        )
        .unwrap()]));
        let traffic = Arc::new(RecordingTrafficClient::default());
        let versions = CanaryVersionSet::new("stable-v1", "canary-v2").unwrap();

        let mut orchestrator = CanaryOrchestrator::new(
            CanaryController::new(test_plan()),
            versions,
            source,
            Arc::clone(&traffic),
            Arc::new(NoopCanaryEventSink),
        );
        let outcome = orchestrator.tick().await.unwrap();
        assert!(matches!(outcome.decision, CanaryDecision::Rollback { .. }));

        let updates = traffic.updates.lock().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].canary_traffic().get(), 0);
        assert_eq!(updates[0].stable_traffic_percent(), 100);
    }

    #[tokio::test]
    async fn orchestrator_holds_when_sample_size_is_below_threshold() {
        let source = Arc::new(QueueMetricsSource::new(vec![CanaryMetrics::new(
            20, 0, 150,
        )
        .unwrap()]));
        let traffic = Arc::new(RecordingTrafficClient::default());
        let versions = CanaryVersionSet::new("stable-v1", "canary-v2").unwrap();

        let mut orchestrator = CanaryOrchestrator::new(
            CanaryController::new(test_plan()),
            versions,
            source,
            Arc::clone(&traffic),
            Arc::new(NoopCanaryEventSink),
        );
        let outcome = orchestrator.tick().await.unwrap();

        assert_eq!(
            outcome.decision,
            CanaryDecision::Hold {
                stage: Percent::new(10).unwrap(),
                reason: HoldReason::InsufficientRequests {
                    required: NonZeroU64::new(100).unwrap(),
                    observed: 20
                }
            }
        );
        assert!(traffic.updates.lock().unwrap().is_empty());
        assert!(outcome.applied_update.is_none());
    }

    #[tokio::test]
    async fn memory_event_sink_persists_canary_outcomes() {
        let memory = Arc::new(InMemoryStore::default());
        let source = Arc::new(QueueMetricsSource::new(vec![CanaryMetrics::new(
            200, 1, 200,
        )
        .unwrap()]));
        let traffic = Arc::new(RecordingTrafficClient::default());
        let versions = CanaryVersionSet::new("stable-v1", "canary-v2").unwrap();
        let sink = Arc::new(MemoryCanaryEventSink::new(
            Arc::clone(&memory),
            Some("canary-session".to_string()),
        ));

        let mut orchestrator = CanaryOrchestrator::new(
            CanaryController::new(test_plan()),
            versions,
            source,
            traffic,
            sink,
        );
        let _ = orchestrator.tick().await.unwrap();

        let events = memory
            .recall("canary:event", 10, Some("canary-session"))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category, MemoryCategory::Daily);
        assert!(events[0].content.contains("decision=Promote"));
    }
}
