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
- Deterministic CI gate:
  - `./scripts/ci/cloudflare_canary_check.sh`
- WASM portability check included in canary gate.

This PR does **not** yet run autonomous scheduled production canary loops.
It now includes the one-shot runtime execution path, so the remaining work is scheduler wiring and production rollout policy operations.

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

## Intended Next Step

1. Trigger one-shot tick on a schedule (Cron trigger or external scheduler).
2. Feed production telemetry endpoint into `CurlCanaryMetricsSource`.
3. Execute `run_cloudflare_one_shot_canary_tick(...)` each interval.
4. Persist decision/audit events for postmortems and rollback drills.
