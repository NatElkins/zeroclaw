#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
worker_dir="${repo_root}/crates/zeroclaw-edge-worker"

port="${ZEROCLAW_EDGE_DEMO_PORT:-8799}"
base_url_override="${ZEROCLAW_EDGE_DEMO_BASE_URL:-}"
delegate_addr="${ZEROCLAW_EDGE_DELEGATE_BIND_ADDR:-127.0.0.1:8091}"
delegate_auth_token="${ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN:-zeroclaw-demo-token-$(date +%s)}"
delegate_allowed_tools="${ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS:-shell,web_search_tool}"
artifacts_root="${ZEROCLAW_EDGE_HYBRID_ARTIFACTS_DIR:-${repo_root}/artifacts}"
timestamp="$(date +%Y%m%d-%H%M%S)"
artifacts_dir="${artifacts_root}/edge-hybrid-demo-${timestamp}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

wait_for_worker() {
  local base_url="$1"
  for _ in $(seq 1 90); do
    if curl -fsS "${base_url}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_delegate() {
  local delegate_addr="$1"
  local auth_token="$2"
  local probe='{"session_id":"probe","tool":"shell","args":{"command":"true"}}'
  for _ in $(seq 1 90); do
    local status
    status="$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "http://${delegate_addr}/delegate/execute" \
      -H "content-type: application/json" \
      -H "authorization: Bearer ${auth_token}" \
      --data "${probe}" || true)"
    if [[ "${status}" == "200" || "${status}" == "400" || "${status}" == "403" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

prepare_rustup_toolchain() {
  if ! command -v rustup >/dev/null 2>&1; then
    return 0
  fi

  local toolchain
  toolchain="${EDGE_SPIKE_TOOLCHAIN:-stable}"
  rustup target add --toolchain "${toolchain}" wasm32-unknown-unknown >/dev/null

  local rustc_bin
  rustc_bin="$(rustup which --toolchain "${toolchain}" rustc)"
  local toolchain_bin
  toolchain_bin="$(dirname "${rustc_bin}")"

  export PATH="${toolchain_bin}:${PATH}"
  export RUSTC="${toolchain_bin}/rustc"
  export RUSTDOC="${toolchain_bin}/rustdoc"
}

run_chat() {
  local base_url="$1"
  local message="$2"
  local out_file="$3"
  curl -fsS -X POST "${base_url}/chat" \
    -H "content-type: application/json" \
    --data "$(jq -cn --arg message "${message}" '{message:$message}')" \
    | tee "${out_file}" >/dev/null
}

assert_json_field_eq() {
  local file="$1"
  local jq_expr="$2"
  local expected="$3"
  local actual
  actual="$(jq -r "${jq_expr}" "${file}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "assertion failed: ${jq_expr} expected '${expected}' got '${actual}' (${file})" >&2
    exit 1
  fi
}

assert_json_field_contains() {
  local file="$1"
  local jq_expr="$2"
  local expected_substring="$3"
  local actual
  actual="$(jq -r "${jq_expr}" "${file}")"
  if [[ "${actual}" != *"${expected_substring}"* ]]; then
    echo "assertion failed: ${jq_expr} expected substring '${expected_substring}' got '${actual}' (${file})" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd jq

worker_pid=""
delegate_pid=""
env_file=""
worker_log=""
delegate_log=""

cleanup() {
  if [[ -n "${worker_pid}" ]] && kill -0 "${worker_pid}" >/dev/null 2>&1; then
    kill "${worker_pid}" >/dev/null 2>&1 || true
    wait "${worker_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${delegate_pid}" ]] && kill -0 "${delegate_pid}" >/dev/null 2>&1; then
    kill "${delegate_pid}" >/dev/null 2>&1 || true
    wait "${delegate_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${env_file}" ]]; then
    : >"${env_file}" || true
    rm -f "${env_file}" || true
  fi
}
trap cleanup EXIT

mkdir -p "${artifacts_dir}"
echo "artifacts: ${artifacts_dir}"

if [[ -n "${base_url_override}" ]]; then
  base_url="${base_url_override%/}"
  if ! wait_for_worker "${base_url}"; then
    echo "deployed worker did not become ready: ${base_url}" >&2
    exit 1
  fi
  echo "using deployed worker at ${base_url}"
else
  require_cmd cargo
  require_cmd npx
  prepare_rustup_toolchain

  delegate_log="${artifacts_dir}/native-delegate.log"
  ZEROCLAW_EDGE_DELEGATE_BIND_ADDR="${delegate_addr}" \
    ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN="${delegate_auth_token}" \
    ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS="${delegate_allowed_tools}" \
    cargo run -q -p zeroclaw-edge-native-delegate >"${delegate_log}" 2>&1 &
  delegate_pid="$!"
  if ! wait_for_delegate "${delegate_addr}" "${delegate_auth_token}"; then
    echo "native delegate did not become ready: http://${delegate_addr}/delegate/execute" >&2
    echo "--- delegate log ---" >&2
    sed -n '1,220p' "${delegate_log}" >&2 || true
    exit 1
  fi

  env_file="$(mktemp /tmp/zeroclaw-edge-hybrid.XXXXXX)"
  cat >"${env_file}" <<EOF
ZEROCLAW_EDGE_DELEGATION_ENABLED=true
ZEROCLAW_EDGE_DELEGATE_ENDPOINT_URL=http://${delegate_addr}
ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN=${delegate_auth_token}
ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS=${delegate_allowed_tools}
EOF

  worker_log="${artifacts_dir}/worker.log"
  (
    cd "${worker_dir}"
    npx wrangler dev --port "${port}" --env-file "${env_file}" >"${worker_log}" 2>&1
  ) &
  worker_pid="$!"

  base_url="http://127.0.0.1:${port}"
  if ! wait_for_worker "${base_url}"; then
    echo "local worker did not become ready: ${base_url}" >&2
    echo "--- worker log ---" >&2
    sed -n '1,220p' "${worker_log}" >&2 || true
    echo "--- delegate log ---" >&2
    sed -n '1,220p' "${delegate_log}" >&2 || true
    exit 1
  fi
  echo "local worker ready at ${base_url}"
fi

scenario_a_out="${artifacts_dir}/scenario-a-memory-store.json"
scenario_b_out="${artifacts_dir}/scenario-b-delegate.json"
scenario_c_out="${artifacts_dir}/scenario-c-delegate-readback.json"

# Scenario A (pure Worker/WASM path): in-worker memory operation.
run_chat "${base_url}" "memory:store:hybrid_demo_marker:wasm_path_ok" "${scenario_a_out}"
assert_json_field_eq "${scenario_a_out}" ".delegated" "false"
assert_json_field_eq "${scenario_a_out}" ".reply" "stored"

if [[ -n "${base_url_override}" ]]; then
  # Deployed scenario: delegate command that returns stdout.
  run_chat "${base_url}" "delegate:shell:printf '%s' 'deployed_delegate_ok'" "${scenario_b_out}"
  assert_json_field_eq "${scenario_b_out}" ".delegated" "true"
  assert_json_field_contains "${scenario_b_out}" ".reply" "deployed_delegate_ok"
else
  # Local scenario: delegate command with real filesystem side effect + readback.
  side_effect_file="/tmp/zeroclaw-edge-hybrid-${timestamp}.txt"
  run_chat "${base_url}" "delegate:shell:printf '%s' 'local_hybrid_delegate_ok' > ${side_effect_file}" "${scenario_b_out}"
  assert_json_field_eq "${scenario_b_out}" ".delegated" "true"
  if [[ ! -f "${side_effect_file}" ]]; then
    echo "delegated shell side-effect file not created: ${side_effect_file}" >&2
    exit 1
  fi
  if [[ "$(cat "${side_effect_file}")" != "local_hybrid_delegate_ok" ]]; then
    echo "unexpected side-effect file content: ${side_effect_file}" >&2
    exit 1
  fi
  run_chat "${base_url}" "delegate:shell:cat ${side_effect_file}" "${scenario_c_out}"
  assert_json_field_eq "${scenario_c_out}" ".delegated" "true"
  assert_json_field_contains "${scenario_c_out}" ".reply" "local_hybrid_delegate_ok"
fi

echo "hybrid demo completed successfully"
echo "evidence:"
echo "  ${scenario_a_out}"
echo "  ${scenario_b_out}"
if [[ -f "${scenario_c_out}" ]]; then
  echo "  ${scenario_c_out}"
fi
