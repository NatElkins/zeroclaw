#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
worker_dir="${repo_root}/crates/zeroclaw-edge-worker"

port="${ZEROCLAW_EDGE_DEMO_PORT:-8799}"
delegate_addr="${ZEROCLAW_EDGE_DELEGATE_BIND_ADDR:-127.0.0.1:8091}"
delegate_auth_token="${ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN:-zeroclaw-demo-token-$(date +%s)}"
delegate_allowed_tools="${ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS:-shell}"
artifacts_root="${ZEROCLAW_EDGE_HYBRID_ARTIFACTS_DIR:-${repo_root}/artifacts}"
timestamp="$(date +%Y%m%d-%H%M%S)"
artifacts_dir="${artifacts_root}/edge-chat-repl-${timestamp}"
state_dir="${ZEROCLAW_EDGE_CHAT_STATE_DIR:-${HOME}/.zeroclaw}"
session_file="${state_dir}/edge-chat-session-id"

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

bootstrap_openrouter_key() {
  if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
    return 0
  fi

  local fallback="${HOME}/Projects/moneydevkit/open-money/.env.local"
  if [[ -f "${fallback}" ]]; then
    local line
    line="$(rg -N '^OPENROUTER_API_KEY=' "${fallback}" | head -n 1 || true)"
    if [[ -n "${line}" ]]; then
      export OPENROUTER_API_KEY="${line#OPENROUTER_API_KEY=}"
    fi
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf "%s" "${value}"
}

default_session_id() {
  local user host raw
  user="$(id -un 2>/dev/null || echo user)"
  host="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)"
  raw="edge-chat-${user}-${host}"
  printf "%s" "${raw}" | tr -c 'A-Za-z0-9._:-' '-' | cut -c1-64
}

resolve_session_id() {
  if [[ -n "${ZEROCLAW_EDGE_CHAT_SESSION_ID:-}" ]]; then
    session_id="${ZEROCLAW_EDGE_CHAT_SESSION_ID}"
    return
  fi

  mkdir -p "${state_dir}"
  if [[ -f "${session_file}" ]]; then
    session_id="$(head -n 1 "${session_file}" | tr -d '\r\n')"
  fi
  if [[ -z "${session_id:-}" ]]; then
    session_id="$(default_session_id)"
    printf "%s\n" "${session_id}" >"${session_file}"
  fi
}

chat_once() {
  local base_url="$1"
  local message="$2"
  curl -fsS -X POST "${base_url}/chat" \
    -H "content-type: application/json" \
    --data "{\"message\":\"$(json_escape "${message}")\",\"session_id\":\"$(json_escape "${session_id}")\"}"
}

chat_reset() {
  local base_url="$1"
  curl -fsS -X POST "${base_url}/chat/reset" \
    -H "content-type: application/json" \
    --data "{\"session_id\":\"$(json_escape "${session_id}")\"}" >/dev/null
}

require_cmd curl
require_cmd jq
require_cmd cargo
require_cmd npx
require_cmd rg

prepare_rustup_toolchain
bootstrap_openrouter_key
resolve_session_id

mkdir -p "${artifacts_dir}"

env_file="$(mktemp /tmp/zeroclaw-edge-chat-repl.XXXXXX)"
worker_log="${artifacts_dir}/worker.log"
delegate_log="${artifacts_dir}/native-delegate.log"
worker_pid=""
delegate_pid=""

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

ZEROCLAW_EDGE_DELEGATE_BIND_ADDR="${delegate_addr}" \
ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN="${delegate_auth_token}" \
ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS="${delegate_allowed_tools}" \
  cargo run -q -p zeroclaw-edge-native-delegate >"${delegate_log}" 2>&1 &
delegate_pid="$!"

{
  echo "ZEROCLAW_EDGE_DELEGATION_ENABLED=true"
  echo "ZEROCLAW_EDGE_DELEGATE_ENDPOINT_URL=http://${delegate_addr}"
  echo "ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN=${delegate_auth_token}"
  echo "ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS=${delegate_allowed_tools}"
  if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
    echo "OPENROUTER_API_KEY=${OPENROUTER_API_KEY}"
  fi
  if [[ -n "${ZEROCLAW_OPENROUTER_MODEL:-}" ]]; then
    echo "ZEROCLAW_OPENROUTER_MODEL=${ZEROCLAW_OPENROUTER_MODEL}"
  fi
} >"${env_file}"

(
  cd "${worker_dir}"
  npx wrangler dev --port "${port}" --env-file "${env_file}" >"${worker_log}" 2>&1
) &
worker_pid="$!"

base_url="http://127.0.0.1:${port}"
if ! wait_for_worker "${base_url}"; then
  echo "worker did not become ready: ${base_url}" >&2
  echo "--- worker log ---" >&2
  sed -n '1,220p' "${worker_log}" >&2 || true
  echo "--- delegate log ---" >&2
  sed -n '1,220p' "${delegate_log}" >&2 || true
  exit 1
fi

echo "chat ready at ${base_url}/chat"
echo "artifacts: ${artifacts_dir}"
echo "session_id: ${session_id}"
if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "note: OPENROUTER_API_KEY not set; use memory:* or delegate:* commands" >&2
fi

echo "type /quit to exit, /reset to clear session history"
while true; do
  printf "you> "
  if ! IFS= read -r line; then
    echo
    break
  fi
  if [[ "${line}" == "/quit" ]]; then
    break
  fi
  if [[ "${line}" == "/reset" ]]; then
    if chat_reset "${base_url}"; then
      echo "bot> session reset"
    else
      echo "bot> failed to reset session" >&2
    fi
    continue
  fi
  if [[ -z "${line// }" ]]; then
    continue
  fi

  if ! response="$(chat_once "${base_url}" "${line}")"; then
    echo "bot> request failed" >&2
    continue
  fi

  echo "${response}" >"${artifacts_dir}/last-response.json"
  if ! reply="$(printf '%s' "${response}" | jq -r '.reply // .error // .message // .')"; then
    reply="${response}"
  fi
  delegated="$(printf '%s' "${response}" | jq -r '.delegated // false' 2>/dev/null || echo false)"
  model="$(printf '%s' "${response}" | jq -r '.model // "unknown"' 2>/dev/null || echo unknown)"
  history_messages="$(printf '%s' "${response}" | jq -r '.history_messages // 0' 2>/dev/null || echo 0)"
  echo "bot(${model}, delegated=${delegated}, history=${history_messages})> ${reply}"
done
