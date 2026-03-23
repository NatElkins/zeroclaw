//! Cloudflare-oriented canary rollout primitives for edge deployments.
//!
//! The module is intentionally pure and deterministic so it can be validated
//! locally without external cloud dependencies.

use std::fmt;
use std::num::{NonZeroU64, NonZeroU8};

/// Percentage in the inclusive range `[1, 100]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Percent(u8);

impl Percent {
    pub fn new(value: u8) -> Result<Self, CanaryConfigError> {
        if !(1..=100).contains(&value) {
            return Err(CanaryConfigError::PercentOutOfRange { value });
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

/// Traffic percentage in the inclusive range `[0, 100]`.
///
/// Unlike [`Percent`], `0` is valid here because canary rollback can route all
/// traffic back to the stable deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrafficPercent(u8);

impl TrafficPercent {
    pub const ZERO: Self = Self(0);
    pub const FULL: Self = Self(100);

    pub fn new(value: u8) -> Result<Self, CanaryConfigError> {
        if value > 100 {
            return Err(CanaryConfigError::TrafficPercentOutOfRange { value });
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

impl From<Percent> for TrafficPercent {
    fn from(value: Percent) -> Self {
        Self(value.get())
    }
}

/// Rate encoded as basis points (`0..=10_000`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BasisPoints(u16);

impl BasisPoints {
    pub fn new(value: u16) -> Result<Self, CanaryConfigError> {
        if value > 10_000 {
            return Err(CanaryConfigError::BasisPointsOutOfRange { value });
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

/// One rollout stage with traffic percentage and healthy-interval requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryStage {
    traffic: Percent,
    required_healthy_intervals: NonZeroU8,
}

impl CanaryStage {
    pub fn new(traffic: Percent, required_healthy_intervals: NonZeroU8) -> Self {
        Self {
            traffic,
            required_healthy_intervals,
        }
    }

    pub fn traffic(self) -> Percent {
        self.traffic
    }

    pub fn required_healthy_intervals(self) -> NonZeroU8 {
        self.required_healthy_intervals
    }
}

/// SLO guardrails used for canary gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryThresholds {
    max_error_rate: BasisPoints,
    max_p95_latency_ms: u32,
    min_request_count: NonZeroU64,
}

impl CanaryThresholds {
    pub fn new(
        max_error_rate: BasisPoints,
        max_p95_latency_ms: u32,
        min_request_count: NonZeroU64,
    ) -> Self {
        Self {
            max_error_rate,
            max_p95_latency_ms,
            min_request_count,
        }
    }

    pub fn max_error_rate(self) -> BasisPoints {
        self.max_error_rate
    }

    pub fn max_p95_latency_ms(self) -> u32 {
        self.max_p95_latency_ms
    }

    pub fn min_request_count(self) -> NonZeroU64 {
        self.min_request_count
    }
}

/// Invariant-checked canary plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryPlan {
    stages: Vec<CanaryStage>,
    thresholds: CanaryThresholds,
}

impl CanaryPlan {
    pub fn new(
        stages: Vec<CanaryStage>,
        thresholds: CanaryThresholds,
    ) -> Result<Self, CanaryConfigError> {
        if stages.is_empty() {
            return Err(CanaryConfigError::EmptyStages);
        }

        for pair in stages.windows(2) {
            let current = pair[0].traffic().get();
            let next = pair[1].traffic().get();
            if next <= current {
                return Err(CanaryConfigError::StagesMustIncrease { current, next });
            }
        }

        let last = stages
            .last()
            .expect("non-empty stages validated")
            .traffic()
            .get();
        if last != 100 {
            return Err(CanaryConfigError::FinalStageMustBe100 { value: last });
        }

        Ok(Self { stages, thresholds })
    }

    pub fn stages(&self) -> &[CanaryStage] {
        &self.stages
    }

    pub fn thresholds(&self) -> CanaryThresholds {
        self.thresholds
    }
}

/// Observed metrics window for one canary evaluation interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryMetrics {
    total_requests: u64,
    failed_requests: u64,
    p95_latency_ms: u32,
}

impl CanaryMetrics {
    pub fn new(
        total_requests: u64,
        failed_requests: u64,
        p95_latency_ms: u32,
    ) -> Result<Self, CanaryMetricsError> {
        if failed_requests > total_requests {
            return Err(CanaryMetricsError::FailedExceedsTotal {
                failed_requests,
                total_requests,
            });
        }

        Ok(Self {
            total_requests,
            failed_requests,
            p95_latency_ms,
        })
    }

    pub fn total_requests(self) -> u64 {
        self.total_requests
    }

    pub fn failed_requests(self) -> u64 {
        self.failed_requests
    }

    pub fn p95_latency_ms(self) -> u32 {
        self.p95_latency_ms
    }

    pub fn error_rate_bps(self) -> u16 {
        if self.total_requests == 0 {
            return 0;
        }
        ((self.failed_requests.saturating_mul(10_000)) / self.total_requests) as u16
    }
}

/// Rollout hold reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldReason {
    InsufficientRequests { required: NonZeroU64, observed: u64 },
    AwaitingHealthyIntervals { required: NonZeroU8, observed: u8 },
}

/// Rollout rollback reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackReason {
    ErrorRateExceeded {
        limit_bps: BasisPoints,
        observed_bps: u16,
    },
    P95LatencyExceeded {
        limit_ms: u32,
        observed_ms: u32,
    },
}

/// State transition returned after one canary observation interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryDecision {
    Hold {
        stage: Percent,
        reason: HoldReason,
    },
    Promote {
        from: Percent,
        to: Percent,
    },
    Complete {
        stage: Percent,
    },
    Rollback {
        stage: Percent,
        reason: RollbackReason,
    },
}

/// Deterministic canary state machine.
#[derive(Debug, Clone)]
pub struct CanaryController {
    plan: CanaryPlan,
    stage_index: usize,
    healthy_intervals_in_stage: u8,
    completed: bool,
}

impl CanaryController {
    pub fn new(plan: CanaryPlan) -> Self {
        Self {
            plan,
            stage_index: 0,
            healthy_intervals_in_stage: 0,
            completed: false,
        }
    }

    pub fn current_stage(&self) -> CanaryStage {
        self.plan.stages[self.stage_index]
    }

    pub fn observe(&mut self, metrics: CanaryMetrics) -> CanaryDecision {
        let stage = self.current_stage();
        let thresholds = self.plan.thresholds();

        if metrics.total_requests() < thresholds.min_request_count().get() {
            return CanaryDecision::Hold {
                stage: stage.traffic(),
                reason: HoldReason::InsufficientRequests {
                    required: thresholds.min_request_count(),
                    observed: metrics.total_requests(),
                },
            };
        }

        let observed_error_rate = metrics.error_rate_bps();
        if observed_error_rate > thresholds.max_error_rate().get() {
            return CanaryDecision::Rollback {
                stage: stage.traffic(),
                reason: RollbackReason::ErrorRateExceeded {
                    limit_bps: thresholds.max_error_rate(),
                    observed_bps: observed_error_rate,
                },
            };
        }

        if metrics.p95_latency_ms() > thresholds.max_p95_latency_ms() {
            return CanaryDecision::Rollback {
                stage: stage.traffic(),
                reason: RollbackReason::P95LatencyExceeded {
                    limit_ms: thresholds.max_p95_latency_ms(),
                    observed_ms: metrics.p95_latency_ms(),
                },
            };
        }

        self.healthy_intervals_in_stage = self.healthy_intervals_in_stage.saturating_add(1);
        if self.healthy_intervals_in_stage < stage.required_healthy_intervals().get() {
            return CanaryDecision::Hold {
                stage: stage.traffic(),
                reason: HoldReason::AwaitingHealthyIntervals {
                    required: stage.required_healthy_intervals(),
                    observed: self.healthy_intervals_in_stage,
                },
            };
        }

        if self.stage_index + 1 >= self.plan.stages.len() {
            self.completed = true;
            return CanaryDecision::Complete {
                stage: stage.traffic(),
            };
        }

        let from = stage.traffic();
        self.stage_index += 1;
        self.healthy_intervals_in_stage = 0;
        let to = self.current_stage().traffic();
        CanaryDecision::Promote { from, to }
    }

    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

/// Cloudflare traffic update payload details derived from canary decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareTrafficUpdate {
    stable_version_id: String,
    canary_version_id: String,
    canary_traffic: TrafficPercent,
}

impl CloudflareTrafficUpdate {
    pub fn new(
        stable_version_id: impl Into<String>,
        canary_version_id: impl Into<String>,
        canary_traffic: TrafficPercent,
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
            canary_traffic,
        })
    }

    pub fn stable_version_id(&self) -> &str {
        &self.stable_version_id
    }

    pub fn canary_version_id(&self) -> &str {
        &self.canary_version_id
    }

    pub fn canary_traffic(&self) -> TrafficPercent {
        self.canary_traffic
    }

    pub fn stable_traffic_percent(&self) -> u8 {
        100 - self.canary_traffic.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryConfigError {
    PercentOutOfRange { value: u8 },
    TrafficPercentOutOfRange { value: u8 },
    BasisPointsOutOfRange { value: u16 },
    EmptyStages,
    StagesMustIncrease { current: u8, next: u8 },
    FinalStageMustBe100 { value: u8 },
    EmptyStableVersionId,
    EmptyCanaryVersionId,
}

impl fmt::Display for CanaryConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PercentOutOfRange { value } => {
                write!(f, "percent out of range [1, 100]: {value}")
            }
            Self::TrafficPercentOutOfRange { value } => {
                write!(f, "traffic percent out of range [0, 100]: {value}")
            }
            Self::BasisPointsOutOfRange { value } => {
                write!(f, "basis points out of range [0, 10000]: {value}")
            }
            Self::EmptyStages => write!(f, "canary plan requires at least one stage"),
            Self::StagesMustIncrease { current, next } => write!(
                f,
                "canary stages must increase strictly: current={current}, next={next}"
            ),
            Self::FinalStageMustBe100 { value } => {
                write!(f, "final canary stage must be 100%, got {value}%")
            }
            Self::EmptyStableVersionId => write!(f, "stable version id must not be empty"),
            Self::EmptyCanaryVersionId => write!(f, "canary version id must not be empty"),
        }
    }
}

impl std::error::Error for CanaryConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryMetricsError {
    FailedExceedsTotal {
        failed_requests: u64,
        total_requests: u64,
    },
}

impl fmt::Display for CanaryMetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedExceedsTotal {
                failed_requests,
                total_requests,
            } => write!(
                f,
                "failed requests ({failed_requests}) cannot exceed total requests ({total_requests})"
            ),
        }
    }
}

impl std::error::Error for CanaryMetricsError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> CanaryPlan {
        CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(5).unwrap(), NonZeroU8::new(2).unwrap()),
                CanaryStage::new(Percent::new(25).unwrap(), NonZeroU8::new(2).unwrap()),
                CanaryStage::new(Percent::new(50).unwrap(), NonZeroU8::new(2).unwrap()),
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

    #[test]
    fn canary_plan_rejects_empty_stage_list() {
        let plan = CanaryPlan::new(
            Vec::new(),
            CanaryThresholds::new(
                BasisPoints::new(100).unwrap(),
                600,
                NonZeroU64::new(10).unwrap(),
            ),
        );
        assert_eq!(plan.unwrap_err(), CanaryConfigError::EmptyStages);
    }

    #[test]
    fn canary_plan_rejects_non_monotonic_stages() {
        let plan = CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(10).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(10).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(100).unwrap(), NonZeroU8::new(1).unwrap()),
            ],
            CanaryThresholds::new(
                BasisPoints::new(100).unwrap(),
                600,
                NonZeroU64::new(10).unwrap(),
            ),
        );

        assert_eq!(
            plan.unwrap_err(),
            CanaryConfigError::StagesMustIncrease {
                current: 10,
                next: 10
            }
        );
    }

    #[test]
    fn canary_plan_requires_final_100_stage() {
        let plan = CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(10).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(90).unwrap(), NonZeroU8::new(1).unwrap()),
            ],
            CanaryThresholds::new(
                BasisPoints::new(100).unwrap(),
                600,
                NonZeroU64::new(10).unwrap(),
            ),
        );

        assert_eq!(
            plan.unwrap_err(),
            CanaryConfigError::FinalStageMustBe100 { value: 90 }
        );
    }

    #[test]
    fn metrics_reject_failed_above_total() {
        let metrics = CanaryMetrics::new(5, 6, 100);
        assert_eq!(
            metrics.unwrap_err(),
            CanaryMetricsError::FailedExceedsTotal {
                failed_requests: 6,
                total_requests: 5
            }
        );
    }

    #[test]
    fn controller_holds_when_sample_size_is_too_small() {
        let mut controller = CanaryController::new(sample_plan());
        let decision = controller.observe(CanaryMetrics::new(20, 0, 100).unwrap());

        assert_eq!(
            decision,
            CanaryDecision::Hold {
                stage: Percent::new(5).unwrap(),
                reason: HoldReason::InsufficientRequests {
                    required: NonZeroU64::new(100).unwrap(),
                    observed: 20
                }
            }
        );
    }

    #[test]
    fn controller_promotes_after_required_healthy_intervals() {
        let mut controller = CanaryController::new(sample_plan());

        let first = controller.observe(CanaryMetrics::new(200, 2, 400).unwrap());
        assert_eq!(
            first,
            CanaryDecision::Hold {
                stage: Percent::new(5).unwrap(),
                reason: HoldReason::AwaitingHealthyIntervals {
                    required: NonZeroU8::new(2).unwrap(),
                    observed: 1
                }
            }
        );

        let second = controller.observe(CanaryMetrics::new(200, 2, 410).unwrap());
        assert_eq!(
            second,
            CanaryDecision::Promote {
                from: Percent::new(5).unwrap(),
                to: Percent::new(25).unwrap()
            }
        );
    }

    #[test]
    fn controller_rolls_back_on_error_rate_breach() {
        let mut controller = CanaryController::new(sample_plan());
        let decision = controller.observe(CanaryMetrics::new(200, 10, 300).unwrap());

        assert_eq!(
            decision,
            CanaryDecision::Rollback {
                stage: Percent::new(5).unwrap(),
                reason: RollbackReason::ErrorRateExceeded {
                    limit_bps: BasisPoints::new(200).unwrap(),
                    observed_bps: 500
                }
            }
        );
    }

    #[test]
    fn controller_rolls_back_on_latency_breach() {
        let mut controller = CanaryController::new(sample_plan());
        let decision = controller.observe(CanaryMetrics::new(200, 1, 900).unwrap());

        assert_eq!(
            decision,
            CanaryDecision::Rollback {
                stage: Percent::new(5).unwrap(),
                reason: RollbackReason::P95LatencyExceeded {
                    limit_ms: 800,
                    observed_ms: 900
                }
            }
        );
    }

    #[test]
    fn controller_completes_at_100_percent_stage() {
        let plan = CanaryPlan::new(
            vec![
                CanaryStage::new(Percent::new(50).unwrap(), NonZeroU8::new(1).unwrap()),
                CanaryStage::new(Percent::new(100).unwrap(), NonZeroU8::new(1).unwrap()),
            ],
            CanaryThresholds::new(
                BasisPoints::new(300).unwrap(),
                1_000,
                NonZeroU64::new(50).unwrap(),
            ),
        )
        .unwrap();
        let mut controller = CanaryController::new(plan);

        let promote = controller.observe(CanaryMetrics::new(100, 1, 200).unwrap());
        assert_eq!(
            promote,
            CanaryDecision::Promote {
                from: Percent::new(50).unwrap(),
                to: Percent::new(100).unwrap()
            }
        );

        let complete = controller.observe(CanaryMetrics::new(100, 1, 200).unwrap());
        assert_eq!(
            complete,
            CanaryDecision::Complete {
                stage: Percent::new(100).unwrap()
            }
        );
        assert!(controller.is_completed());
    }

    #[test]
    fn cloudflare_traffic_update_rejects_empty_version_ids() {
        let invalid_stable =
            CloudflareTrafficUpdate::new("", "canary-v1", TrafficPercent::new(5).unwrap())
                .unwrap_err();
        assert_eq!(invalid_stable, CanaryConfigError::EmptyStableVersionId);

        let invalid_canary =
            CloudflareTrafficUpdate::new("stable-v1", " ", TrafficPercent::new(5).unwrap())
                .unwrap_err();
        assert_eq!(invalid_canary, CanaryConfigError::EmptyCanaryVersionId);
    }

    #[test]
    fn cloudflare_traffic_update_computes_stable_share() {
        let update = CloudflareTrafficUpdate::new(
            "stable-v1",
            "canary-v2",
            TrafficPercent::new(25).unwrap(),
        )
        .unwrap();

        assert_eq!(update.stable_version_id(), "stable-v1");
        assert_eq!(update.canary_version_id(), "canary-v2");
        assert_eq!(update.canary_traffic().get(), 25);
        assert_eq!(update.stable_traffic_percent(), 75);
    }

    #[test]
    fn traffic_percent_supports_rollback_zero_and_rejects_overflow() {
        assert_eq!(TrafficPercent::ZERO.get(), 0);
        assert_eq!(TrafficPercent::FULL.get(), 100);
        assert_eq!(
            TrafficPercent::new(101).unwrap_err(),
            CanaryConfigError::TrafficPercentOutOfRange { value: 101 }
        );
    }
}
