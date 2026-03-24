# Cloudflare Canary Playbook (PR #15 Scaffold)

This playbook defines how ZeroClaw evaluates canary safety before changing edge traffic splits.

## Scope In This PR

- Typed canary state machine in `crates/zeroclaw-edge/src/canary.rs`.
- Canary orchestrator in `crates/zeroclaw-edge/src/canary_orchestrator.rs`:
  - metrics source interface
  - traffic split client interface
  - event sink interface (including memory-backed sink)
- Cloudflare Wrangler traffic client adapter in `crates/zeroclaw-edge/src/cloudflare_cli.rs`:
  - typed command construction for `wrangler versions deploy`
  - support for direct `wrangler` and wrapped `npx wrangler` invocation
  - deterministic unit coverage for promote/rollback/error command paths
- Live orchestrator wiring in `crates/zeroclaw-edge/src/canary_live.rs`:
  - typed assembly from controller + metrics source + event sink to Wrangler traffic client
  - deterministic wiring coverage using injected command runner
- Telemetry/runtime integration:
  - `crates/zeroclaw-edge/src/canary_metrics.rs` (`curl` JSON metrics source)
  - `crates/zeroclaw-edge/src/canary_tick.rs` (one-shot runtime path)
  - integration-style tests cover: local telemetry HTTP server -> canary decision -> traffic split apply command
- Scheduler/trigger integration:
  - `crates/zeroclaw-edge/src/canary_schedule.rs`
  - fixed-interval trigger and scheduler loop policy (`continue_on_error`, max consecutive failures)
  - integration-style tests for multi-tick promote -> rollback behavior
- Cloudflare Cron binding:
  - `crates/zeroclaw-edge/src/canary_cron.rs`
  - validates scheduled event payloads and maps them to one canary tick execution
  - integration-style test verifies cron payload -> traffic split command path
- Deterministic CI gate:
  - `./scripts/ci/cloudflare_canary_check.sh`
- WASM portability check included in canary gate.

This PR now includes Cloudflare Cron event binding primitives, but does **not** yet include production deployment glue code for Worker runtime entrypoint wiring.

## Rollout Inputs

Canary evaluations consume one interval of metrics:

- `total_requests`
- `failed_requests`
- `p95_latency_ms`

Policy thresholds:

- max error rate (basis points)
- max p95 latency (milliseconds)
- minimum request sample size
- required healthy intervals per traffic stage

## Decisions

The controller emits one of:

- `Hold`
- `Promote`
- `Complete`
- `Rollback`

Rollback triggers:

- error rate over threshold
- p95 latency over threshold

## Local Validation

Run:

```bash
./scripts/ci/cloudflare_canary_check.sh
```

This validates:

1. canary invariants and state-machine behavior
2. canary orchestration behavior (hold/promote/rollback/apply/persist)
3. wasm32 compile viability for `zeroclaw-edge`
4. one-shot telemetry/runtime integration behavior
5. scheduled trigger behavior and multi-tick integration flow
6. cron payload -> tick execution binding behavior

## Intended Next Step

1. Wire Worker runtime cron handler to call `run_cloudflare_cron_event(...)`.
2. Feed production telemetry endpoint into `CurlCanaryMetricsSource`.
3. Execute scheduler loop or one-shot cron flow in production with rollout policy defaults.
4. Persist decision/audit events for postmortems and rollback drills.
