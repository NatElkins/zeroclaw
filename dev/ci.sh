#!/usr/bin/env bash
set -euo pipefail

if [ -f "dev/docker-compose.ci.yml" ]; then
  COMPOSE_FILE="dev/docker-compose.ci.yml"
elif [ -f "docker-compose.ci.yml" ] && [ "$(basename "$(pwd)")" = "dev" ]; then
  COMPOSE_FILE="docker-compose.ci.yml"
else
  echo "❌ Run this script from repo root or dev/ directory."
  exit 1
fi

compose_cmd=(docker compose -f "$COMPOSE_FILE")
SMOKE_CACHE_DIR="${SMOKE_CACHE_DIR:-.cache/buildx-smoke}"

run_in_ci() {
  local cmd="$1"
  "${compose_cmd[@]}" run --rm local-ci bash -c "$cmd"
}

wait_for_service_ready() {
  local service="$1"
  local timeout_secs="${2:-60}"
  local container_id
  container_id="$("${compose_cmd[@]}" ps -q "$service")"

  if [ -z "$container_id" ]; then
    echo "❌ Service '$service' did not start."
    return 1
  fi

  for ((i = 0; i < timeout_secs; i++)); do
    local status
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
    if [ "$status" = "healthy" ] || [ "$status" = "running" ]; then
      return 0
    fi
    sleep 1
  done

  echo "❌ Service '$service' was not ready within ${timeout_secs}s."
  "${compose_cmd[@]}" logs "$service" || true
  return 1
}

cleanup_service() {
  local service="$1"
  "${compose_cmd[@]}" rm -sf "$service" >/dev/null 2>&1 || true
}

build_smoke_image() {
  if docker buildx version >/dev/null 2>&1; then
    mkdir -p "$SMOKE_CACHE_DIR"
    local build_args=(
      --load
      --target dev
      --cache-to "type=local,dest=$SMOKE_CACHE_DIR,mode=max"
      -t zeroclaw-local-smoke:latest
      .
    )
    if [ -f "$SMOKE_CACHE_DIR/index.json" ]; then
      build_args=(--cache-from "type=local,src=$SMOKE_CACHE_DIR" "${build_args[@]}")
    fi
    docker buildx build "${build_args[@]}"
  else
    DOCKER_BUILDKIT=1 docker build --target dev -t zeroclaw-local-smoke:latest .
  fi
}

print_help() {
  cat <<'EOF'
ZeroClaw Local CI in Docker

Usage: ./dev/ci.sh <command>

Commands:
  build-image   Build/update the local CI image
  shell         Open an interactive shell inside the CI container
  lint          Run rustfmt + clippy correctness gate (container only)
  lint-strict   Run rustfmt + full clippy warnings gate (container only)
  lint-delta    Run strict lint delta gate on changed Rust lines (container only)
  test          Run cargo test (container only)
  test-component  Run component tests only
  test-integration Run integration tests only
  test-system     Run system tests only
  test-live       Run live tests (requires credentials)
  test-wasm-runtime Run wasm runtime feature tests
  test-edge-spike Run edge spike tests + wasm32 compile check
  test-hybrid-local Run local hybrid readiness suite (component+integration+system+shell+delegate+wasm)
  test-hybrid-services Run service-backed hybrid suite (Postgres + wasm runtime + remote memory)
  test-manual     Run manual test scripts (dockerignore, etc.)
  build         Run release build smoke check (container only)
  audit         Run cargo audit (container only)
  deny          Run cargo deny check (container only)
  security      Run cargo audit + cargo deny (container only)
  docker-smoke  Build and verify runtime image (host docker daemon)
  all           Run lint, test, build, security, docker-smoke
  clean         Remove local CI containers and volumes
EOF
}

if [ $# -lt 1 ]; then
  print_help
  exit 1
fi

case "$1" in
  build-image)
    "${compose_cmd[@]}" build local-ci
    ;;

  shell)
    "${compose_cmd[@]}" run --rm local-ci bash
    ;;

  lint)
    run_in_ci "./scripts/ci/rust_quality_gate.sh"
    ;;

  lint-strict)
    run_in_ci "./scripts/ci/rust_quality_gate.sh --strict"
    ;;

  lint-delta)
    run_in_ci "./scripts/ci/rust_strict_delta_gate.sh"
    ;;

  test)
    run_in_ci "cargo test --locked --verbose"
    ;;

  test-component)
    run_in_ci "cargo test --test component --locked --verbose"
    ;;

  test-integration)
    run_in_ci "cargo test --test integration --locked --verbose"
    ;;

  test-system)
    run_in_ci "cargo test --test system --locked --verbose"
    ;;

  test-live)
    run_in_ci "cargo test --test live -- --ignored --verbose"
    ;;

  test-wasm-runtime)
    run_in_ci "cargo test --features runtime-wasm runtime::wasm::tests:: --locked --verbose"
    ;;

  test-edge-spike)
    run_in_ci "./scripts/ci/edge_wasm_spike_check.sh"
    ;;

  test-hybrid-local)
    run_in_ci "cargo test --test component --locked --verbose"
    run_in_ci "cargo test --test integration --locked --verbose"
    run_in_ci "cargo test --test system --locked --verbose"
    run_in_ci "cargo test tools::shell::tests:: --locked --verbose"
    run_in_ci "cargo test tools::delegate::tests:: --locked --verbose"
    run_in_ci "cargo test --features runtime-wasm runtime::tests::factory_wasm --locked --verbose"
    run_in_ci "cargo test --features runtime-wasm runtime::wasm::tests:: --locked --verbose"
    run_in_ci "./scripts/ci/edge_wasm_spike_check.sh"
    ;;

  test-hybrid-services)
    postgres_url="postgres://zeroclaw:zeroclaw@postgres-hybrid:5432/zeroclaw_hybrid"
    "${compose_cmd[@]}" up -d postgres-hybrid
    set +e
    wait_for_service_ready postgres-hybrid 90
    status=$?
    if [ "$status" -eq 0 ]; then
      run_in_ci "ZEROCLAW_TEST_POSTGRES_URL='${postgres_url}' cargo test --features 'memory-postgres runtime-wasm' --test integration hybrid_postgres_memory --locked --verbose"
      status=$?
    fi
    set -e

    cleanup_service postgres-hybrid
    if [ "$status" -ne 0 ]; then
      exit "$status"
    fi
    ;;

  test-hybrid-services)
    postgres_url="postgres://zeroclaw:zeroclaw@postgres-hybrid:5432/zeroclaw_hybrid"
    "${compose_cmd[@]}" up -d postgres-hybrid
    set +e
    wait_for_service_ready postgres-hybrid 90
    status=$?
    if [ "$status" -eq 0 ]; then
      run_in_ci "ZEROCLAW_TEST_POSTGRES_URL='${postgres_url}' cargo test --features 'memory-postgres runtime-wasm' --test integration hybrid_postgres_memory --locked --verbose"
      status=$?
    fi
    set -e

    cleanup_service postgres-hybrid
    if [ "$status" -ne 0 ]; then
      exit "$status"
    fi
    ;;

  test-manual)
    run_in_ci "bash tests/manual/test_dockerignore.sh"
    ;;

  build)
    run_in_ci "cargo build --release --locked --verbose"
    ;;

  audit)
    run_in_ci "cargo audit"
    ;;

  deny)
    run_in_ci "cargo deny check licenses sources"
    ;;

  security)
    run_in_ci "cargo deny check licenses sources"
    run_in_ci "cargo audit"
    ;;

  docker-smoke)
    build_smoke_image
    docker run --rm zeroclaw-local-smoke:latest --version
    ;;

  all)
    run_in_ci "./scripts/ci/rust_quality_gate.sh"
    run_in_ci "cargo test --locked --verbose"
    run_in_ci "bash tests/manual/test_dockerignore.sh"
    run_in_ci "cargo build --release --locked --verbose"
    run_in_ci "cargo deny check licenses sources"
    run_in_ci "cargo audit"
    build_smoke_image
    docker run --rm zeroclaw-local-smoke:latest --version
    ;;

  clean)
    "${compose_cmd[@]}" down -v --remove-orphans
    ;;

  *)
    print_help
    exit 1
    ;;
esac
