# WASM Hybrid Rollout Plan (Stacked PRs)

This document is the durable execution plan for the ZeroClaw WASM/hybrid deployment track.
It is intentionally implementation-oriented (sequence, acceptance criteria, rollback) so work can continue safely even if chat context is compacted.

## Goals

- Run the ZeroClaw control-plane/agent loop in WASM-friendly runtimes (Cloudflare Workers-first).
- Preserve compatibility with native tool execution for filesystem/shell-heavy operations.
- Keep type contracts shared (`zeroclaw-core`) so native and WASM runtimes remain wire/type compatible.
- Optimize for scale-to-zero economics on edge ingress while retaining deep capability via delegated native workers.

## Non-Goals (For This Track)

- Full replacement of native runtime for shell/filesystem tools.
- Shipping a complete Cloudflare production environment in a single PR.
- Changing core product behavior unrelated to runtime portability.

## Target Architecture (Hybrid)

1. Edge ingress/runtime (WASM-friendly):
   - request handling
   - policy routing
   - lightweight tool calls (HTTP, memory APIs, scheduling metadata)
2. Capability-aware tool registry:
   - only registers tools valid for runtime capabilities (shell/filesystem/etc)
3. Native execution pool (delegated):
   - shell/filesystem heavy tasks
   - repo mutation, long-running build/test jobs
4. Shared persistence:
   - memory/event state through networked persistence APIs (TigerFS-like architecture)

## Stacked PR Sequence

## Completed

1. `feat(core): extract zeroclaw-core crate for WASM runtime support`
   - branch: `feat/zeroclaw-core`
   - status: merged into stack baseline
2. `feat(tools): gate tool registration by runtime capabilities`
   - PR: #2
   - status: open in stack
3. `test(tools): add filesystem-only runtime registration matrix`
   - PR: #3
   - status: open in stack
4. `feat(runtime): add feature-gated wasm runtime factory/config path`
   - PR: #4
   - status: open in stack
5. `feat(runtime): harden runtime capability contract and kind matrix tests`
   - PR: #7
   - status: open in stack
6. `test(runtime): add wasm runtime activation smoke coverage`
   - PR: #8
   - status: open in stack
7. `feat(memory): add http backend for edge storage adapters`
   - PR: #11
   - status: open in stack
8. `feat(tools): add runtime capability-fallback delegation proxies`
   - PR: #12
   - status: in progress in stack
9. `spike(edge): add zeroclaw-edge worker viability harness`
   - PR: #13
   - status: complete in stack
10. End-to-end local simulation harness
   - PR: #14
   - status: complete in stack
   - local edge runtime stubs + delegated native worker
   - deterministic scenario tests (chat -> tool selection -> delegation -> persistence)

## Next

11. Cloudflare canary deployment
   - PR: #15
   - status: in progress in stack
   - canary env + observability SLOs + rollback controls
   - typed rollout controller with deterministic promote/hold/rollback behavior
12. Canary orchestration execution path
   - PR: #16
   - status: in progress in stack
   - metrics ingestion + traffic split apply + event sink persistence
   - deterministic end-to-end canary tick simulations
13. Cloudflare CLI traffic client wiring
   - PR: #17
   - status: in progress in stack
   - typed `wrangler versions deploy` adapter for rollout split updates
   - deterministic command-assembly tests including rollback and `npx wrangler` invocation
14. Live canary orchestrator wiring
   - PR: #18
   - status: complete in stack
   - typed assembly path from canary controller + metrics source + event sink to live `wrangler` traffic client
   - deterministic orchestration tick test through injected command-runner boundary
15. One-shot canary runtime integration
   - PR: #19
   - status: in progress in stack
   - telemetry pull adapter (`curl` JSON metrics source) for canary inputs
   - one-shot runtime path: metrics -> decision -> `wrangler versions deploy`
   - integration-style tests using local HTTP telemetry + real subprocess boundaries
16. Scheduled canary trigger wiring
   - PR: #20
   - status: complete in stack
   - fixed-interval trigger + scheduler loop policy
   - reusable tick-runner boundary with stateful controller progression across intervals
   - integration-style tests for promote->rollback across scheduled ticks
17. Cloudflare Cron event binding
   - PR: #21
   - status: in progress in stack
   - typed Cloudflare scheduled event payload validation
   - cron event -> one canary tick execution bridge
   - integration-style test for cron payload to traffic-split command path

## Milestones And Exit Criteria

## Milestone A: Capability-Safe Runtime Selection

- `runtime.kind = "wasm"` is parseable/configurable.
- tool registry excludes invalid tools by capability.
- tests cover no-shell and fs-only matrices.

Exit criteria:
- all runtime/tool matrix tests pass in CI.
- no shell/fs tools leak into disallowed runtime snapshots.

## Milestone B: Edge-Compatible Persistence/Memory

- memory adapter runs in WASM without local filesystem assumptions.
- shared type compatibility guaranteed against native memory entry types.

Exit criteria:
- round-trip tests prove compatibility across native and WASM adapter boundaries.

## Milestone C: Hybrid Delegation

- shell/fs operations automatically route to native delegate workers.
- edge runtime remains stateless except for explicit persistence APIs.

Exit criteria:
- deterministic integration tests for delegation success/failure paths.
- policy checks enforced before and after delegation.

## Milestone D: Edge Feasibility Gate (New)

- worker-oriented edge runtime crate compiles for `wasm32-unknown-unknown`.
- at least one local worker-like scenario proves hybrid handoff semantics:
  request -> delegate -> memory persistence.

Exit criteria:
- `cargo check -p zeroclaw-edge --target wasm32-unknown-unknown` passes.
- `cargo test -p zeroclaw-edge` passes with deterministic round-trip coverage.

## Milestone E: Canary Production Readiness

- Cloudflare canary deployed with rollback automation.
- cost/latency/error-rate dashboards available.
- deterministic canary state machine coverage in local CI.

Exit criteria:
- SLO burn acceptable for 7-day canary.
- rollback drill completed successfully.
- `./scripts/ci/cloudflare_canary_check.sh` passes.

## Local Iteration Strategy

1. Use runtime stubs in tests to model capability subsets (`no-cap`, `fs-only`, `full`).
2. Run feature-gated checks locally:
   - `cargo check --features runtime-wasm`
   - `cargo check -p zeroclaw-edge --target wasm32-unknown-unknown`
   - `./scripts/ci/cloudflare_canary_check.sh`
3. Keep deterministic integration fixtures for:
   - tool selection decisions
   - delegation routing
   - memory schema compatibility
4. Use local native delegate worker process to simulate cloud hybrid behavior.

## Operational Guardrails

- every stacked PR must include:
  - explicit scope
  - validation commands run
  - rollback note
  - dependency relation (`Depends on #...`)
- avoid mixed refactor + behavior changes in one PR.
- keep feature flags explicit and default-safe.

## Rollback Strategy

- Runtime path rollback:
  - set `runtime.kind = "native"` and disable `runtime-wasm` feature.
- Tool path rollback:
  - disable edge delegation routes and use existing native registry path.
- Persistence rollback:
  - switch memory backend config back to current native-default adapter.

## Notes

- This plan is the canonical reference for this stack. Keep it updated as each PR lands.
- PR bodies should reference this document for progress state and acceptance criteria.
- Canary execution details live in `docs/maintainers/cloudflare-canary-playbook.md`.
