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
- Deterministic CI gate:
  - `./scripts/ci/cloudflare_canary_check.sh`
- WASM portability check included in canary gate.

This PR does **not** yet run autonomous scheduled production canary loops.
It now includes the typed live wiring path plus deterministic tests, so the remaining work is scheduler/telemetry integration and rollout policy operations.

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
2. wasm32 compile viability for `zeroclaw-edge`

## Intended Live Wiring (Next Step)

1. Pull interval metrics from edge telemetry.
2. Build orchestrator with `build_cloudflare_wrangler_orchestrator(...)`.
3. Execute `tick()` for each rollout interval.
4. On `Promote`, update Cloudflare version traffic split.
5. On `Rollback`, shift traffic to stable version immediately.
6. Persist decision/audit events for postmortems.
