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

This playbook now includes deployed Worker runtime glue (`/tick` and cron wiring), plus
an authenticated canary drill path for deterministic promote/hold/rollback rehearsal.

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

## Local Worker Chat Demo (End-To-End)

For a minimal Worker runtime call/response demo using OpenRouter:

```bash
./scripts/edge_worker_chat_demo.sh
```

Default behavior:

1. resolves `OPENROUTER_API_KEY` from environment, or falls back to `~/Projects/moneydevkit/open-money/.env.local`
2. starts `wrangler dev` for `crates/zeroclaw-edge-worker`
3. sends one `/chat` request with prompt `reply with exactly: edge demo ok`
4. prints the JSON response and exits

To run interactive call/response mode:

```bash
ZEROCLAW_EDGE_DEMO_INTERACTIVE=1 ./scripts/edge_worker_chat_demo.sh
```

To override model or local port:

```bash
ZEROCLAW_OPENROUTER_MODEL=openai/gpt-4o-mini ZEROCLAW_EDGE_DEMO_PORT=8787 ./scripts/edge_worker_chat_demo.sh "summarize wasm advantages in 2 bullets"
```

To persist memory across separate invocations, provide a stable session id:

```bash
ZEROCLAW_EDGE_DEMO_SESSION_ID=my-team-room ./scripts/edge_worker_chat_demo.sh "remember token: ZC-1234"
ZEROCLAW_EDGE_DEMO_SESSION_ID=my-team-room ZEROCLAW_EDGE_DEMO_RESET_SESSION=0 ./scripts/edge_worker_chat_demo.sh "what token did i ask you to remember?"
```

To enable shared long-term memory (cross-session, TigerFS-like HTTP service), set:

```bash
ZEROCLAW_LONG_TERM_MEMORY_BASE_URL="https://memory.example.com" \
ZEROCLAW_LONG_TERM_MEMORY_AUTH_TOKEN="<optional-bearer-token>" \
ZEROCLAW_LONG_TERM_MEMORY_RECALL_LIMIT=6 \
ZEROCLAW_EDGE_DEMO_SESSION_ID=my-team-room \
./scripts/edge_worker_chat_demo.sh "remember: team prefers rust for edge runtimes"
```

When configured, `/chat` keeps Durable Object history as short-term context and also:

1. recalls relevant entries from `/v1/memory/recall` before model invocation
2. stores user/assistant turn records to `/v1/memory/store` after reply generation

To point the same CLI at a deployed Worker instead of local `wrangler dev`:

```bash
ZEROCLAW_EDGE_DEMO_BASE_URL="https://<worker>.<subdomain>.workers.dev" \
ZEROCLAW_EDGE_DEMO_INTERACTIVE=1 \
ZEROCLAW_EDGE_DEMO_SESSION_ID=edge-room-1 \
./scripts/edge_worker_chat_demo.sh
```

## Deployed Canary Drill (Promote/Hold/Rollback)

The Worker exposes authenticated drill endpoints:

- `GET /canary/drill/metrics/{promote|hold|rollback}`
- `POST /canary/drill/tick/{promote|hold|rollback}`
- `GET /canary/audit/recent?limit=<n>`
- `POST /canary/audit/clear`

These use a deterministic metrics payload per scenario and force dry-run traffic updates
so drills can exercise the full decision/apply path without mutating production traffic.
Each tick is also persisted in Durable Object audit storage and retrievable from
`/canary/audit/recent`.

### Prerequisites

1. Set drill token secret:

```bash
printf '%s' '<your-drill-token>' | npx wrangler secret put ZEROCLAW_CANARY_DRILL_TOKEN
```

2. Ensure deployed Worker URL is known.

### Run Drill

```bash
ZEROCLAW_EDGE_DEMO_BASE_URL="https://<worker>.<subdomain>.workers.dev" \
ZEROCLAW_CANARY_DRILL_TOKEN="<your-drill-token>" \
./scripts/edge_worker_canary_drill.sh all
```

The drill script now verifies both:

1. canary decision class (`Promote`/`Hold`/`Rollback`)
2. matching persisted decision in `/canary/audit/recent`

Expected decision classes:

- `promote` -> `Promote`
- `hold` -> `Hold`
- `rollback` -> `Rollback`

### Capture Rollback Evidence

```bash
curl -fsS -X POST "https://<worker>.<subdomain>.workers.dev/canary/drill/tick/rollback" \
  -H "x-zeroclaw-drill-token: <your-drill-token>"
```

Persist the JSON response in incident/audit notes as rollback drill evidence.

To inspect recent persisted audit records directly:

```bash
curl -fsS "https://<worker>.<subdomain>.workers.dev/canary/audit/recent?limit=20" \
  -H "x-zeroclaw-drill-token: <your-drill-token>"
```

## Intended Next Step

1. Add remote drill evidence auto-export into a signed incident artifact bundle.
2. Add retention + export policies for canary audit records (windowing and archival).
