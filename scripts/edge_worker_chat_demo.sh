#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
worker_dir="${repo_root}/crates/zeroclaw-edge-worker"

port="${ZEROCLAW_EDGE_DEMO_PORT:-8799}"
model="${ZEROCLAW_OPENROUTER_MODEL:-anthropic/claude-3.5-sonnet}"
interactive="${ZEROCLAW_EDGE_DEMO_INTERACTIVE:-0}"
session_id="${ZEROCLAW_EDGE_DEMO_SESSION_ID:-}"
reset_session="${ZEROCLAW_EDGE_DEMO_RESET_SESSION:-1}"
base_url_override="${ZEROCLAW_EDGE_DEMO_BASE_URL:-}"
message="${1:-reply with exactly: edge demo ok}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf "%s" "$value"
}

payload_for() {
  local msg="$1"
  if [[ -n "${session_id}" ]]; then
    printf '{"message":"%s","session_id":"%s"}' \
      "$(json_escape "$msg")" \
      "$(json_escape "${session_id}")"
  else
    printf '{"message":"%s"}' "$(json_escape "$msg")"
  fi
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

  if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "missing OPENROUTER_API_KEY (set env var or add it to ${fallback})" >&2
    exit 1
  fi
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

chat_once() {
  local base_url="$1"
  local prompt="$2"
  curl -fsS -X POST "${base_url}/chat" \
    -H "content-type: application/json" \
    --data "$(payload_for "${prompt}")"
}

chat_reset() {
  local base_url="$1"
  if [[ -z "${session_id}" ]]; then
    return 0
  fi
  curl -fsS -X POST "${base_url}/chat/reset" \
    -H "content-type: application/json" \
    --data "$(printf '{"session_id":"%s"}' "$(json_escape "${session_id}")")" >/dev/null
}

require_cmd curl

worker_pid=""
env_file=""
log_file=""
cleanup() {
  if [[ -n "${worker_pid}" ]] && kill -0 "${worker_pid}" >/dev/null 2>&1; then
    kill "${worker_pid}" >/dev/null 2>&1 || true
    wait "${worker_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${env_file}" ]]; then
    : >"${env_file}" || true
    rm -f "${env_file}" || true
  fi
  if [[ -n "${log_file}" ]]; then
    rm -f "${log_file}" || true
  fi
}
trap cleanup EXIT

if [[ -n "${base_url_override}" ]]; then
  base_url="${base_url_override%/}"
  if ! wait_for_worker "${base_url}"; then
    echo "worker did not become ready: ${base_url}" >&2
    exit 1
  fi
  echo "worker ready at ${base_url}"
else
  require_cmd npx
  require_cmd rg

  if [[ ! -d "${worker_dir}" ]]; then
    echo "worker directory not found: ${worker_dir}" >&2
    exit 1
  fi

  bootstrap_openrouter_key
  prepare_rustup_toolchain

  env_file="$(mktemp /tmp/zeroclaw-edge-demo.XXXXXX)"
  log_file_base="$(mktemp /tmp/zeroclaw-edge-demo-wrangler.XXXXXX)"
  log_file="${log_file_base}.log"
  mv "${log_file_base}" "${log_file}"
  printf "OPENROUTER_API_KEY=%s\n" "${OPENROUTER_API_KEY}" >"${env_file}"
  printf "ZEROCLAW_OPENROUTER_MODEL=%s\n" "${model}" >>"${env_file}"

  (
    cd "${worker_dir}"
    npx wrangler dev --port "${port}" --env-file "${env_file}" >"${log_file}" 2>&1
  ) &
  worker_pid="$!"

  base_url="http://127.0.0.1:${port}"
  if ! wait_for_worker "${base_url}"; then
    echo "worker did not become ready: ${base_url}" >&2
    echo "--- wrangler log ---" >&2
    sed -n "1,220p" "${log_file}" >&2
    exit 1
  fi
  echo "worker ready at ${base_url}"
fi
if [[ -z "${session_id}" && "${interactive}" == "1" ]]; then
  session_id="local-demo-$(date +%s)"
fi
if [[ -n "${session_id}" ]]; then
  echo "chat session_id=${session_id}"
  if [[ "${reset_session}" == "1" || "${reset_session}" == "true" ]]; then
    chat_reset "${base_url}"
    echo "chat session reset"
  fi
fi

if [[ "${interactive}" == "1" ]]; then
  echo "interactive chat mode enabled. enter /quit to exit."
  while true; do
    printf "you> "
    if ! IFS= read -r line; then
      echo
      break
    fi
    if [[ "${line}" == "/quit" ]]; then
      break
    fi
    if [[ -z "${line// }" ]]; then
      continue
    fi
    response="$(chat_once "${base_url}" "${line}")"
    echo "bot> ${response}"
  done
else
  response="$(chat_once "${base_url}" "${message}")"
  echo "${response}"
fi
