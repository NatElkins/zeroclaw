# Cloudflare Canary Playbook (PR #15 Scaffold)

This playbook defines how ZeroClaw evaluates canary safety before changing edge traffic splits.

## Scope In This PR

- Typed canary state machine in `crates/zeroclaw-edge/src/canary.rs`.
- Deterministic CI gate:
  - `./scripts/ci/cloudflare_canary_check.sh`
- WASM portability check included in canary gate.

This PR does **not** yet perform live Cloudflare API traffic updates. It establishes the rollout decision contract that live control-plane wiring will consume.

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
2. Feed metrics into `CanaryController::observe(...)`.
3. On `Promote`, update Cloudflare version traffic split.
4. On `Rollback`, shift traffic to stable version immediately.
5. Persist decision/audit events for postmortems.
