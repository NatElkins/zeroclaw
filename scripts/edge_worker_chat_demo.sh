#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
worker_dir="${repo_root}/crates/zeroclaw-edge-worker"

port="${ZEROCLAW_EDGE_DEMO_PORT:-8799}"
model="${ZEROCLAW_OPENROUTER_MODEL:-anthropic/claude-3.5-sonnet}"
interactive="${ZEROCLAW_EDGE_DEMO_INTERACTIVE:-0}"
message="${1:-reply with exactly: edge demo ok}"

is_truthy() {
  local raw="${1:-}"
  case "${raw,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

message_uses_edge_runtime_prefix() {
  local raw="$1"
  if [[ "${raw}" =~ ^[[:space:]]*delegate: ]]; then
    return 0
  fi
  if [[ "${raw}" =~ ^[[:space:]]*memory: ]]; then
    return 0
  fi
  return 1
}

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
  printf '{"message":"%s"}' "$(json_escape "$msg")"
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

require_cmd curl
require_cmd npx
require_cmd rg

if [[ ! -d "${worker_dir}" ]]; then
  echo "worker directory not found: ${worker_dir}" >&2
  exit 1
fi

bootstrap_openrouter_key
prepare_rustup_toolchain

env_file="$(mktemp /tmp/zeroclaw-edge-demo.XXXXXX)"
log_file="$(mktemp /tmp/zeroclaw-edge-demo-wrangler.XXXXXX.log)"
printf "OPENROUTER_API_KEY=%s\n" "${OPENROUTER_API_KEY}" >"${env_file}"
printf "ZEROCLAW_OPENROUTER_MODEL=%s\n" "${model}" >>"${env_file}"

worker_pid=""
cleanup() {
  if [[ -n "${worker_pid}" ]] && kill -0 "${worker_pid}" >/dev/null 2>&1; then
    kill "${worker_pid}" >/dev/null 2>&1 || true
    wait "${worker_pid}" >/dev/null 2>&1 || true
  fi
  : >"${env_file}" || true
  rm -f "${env_file}" "${log_file}" || true
}
trap cleanup EXIT

(
  cd "${worker_dir}"
  npx wrangler dev --port "${port}" --env-file "${env_file}" >"${log_file}" 2>&1
) &
worker_pid="$!"

  if [[ ! -d "${worker_dir}" ]]; then
    echo "worker directory not found: ${worker_dir}" >&2
    exit 1
  fi

  require_openrouter_key=1
  if [[ "${interactive}" != "1" ]] \
    && is_truthy "${ZEROCLAW_EDGE_DELEGATION_ENABLED:-0}" \
    && message_uses_edge_runtime_prefix "${message}"; then
    require_openrouter_key=0
  fi
  if [[ "${require_openrouter_key}" == "1" ]]; then
    bootstrap_openrouter_key
  fi
  prepare_rustup_toolchain

  env_file="$(mktemp /tmp/zeroclaw-edge-demo.XXXXXX)"
  log_file_base="$(mktemp /tmp/zeroclaw-edge-demo-wrangler.XXXXXX)"
  log_file="${log_file_base}.log"
  mv "${log_file_base}" "${log_file}"
  if [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
    printf "OPENROUTER_API_KEY=%s\n" "${OPENROUTER_API_KEY}" >"${env_file}"
  else
    : >"${env_file}"
  fi
  printf "ZEROCLAW_OPENROUTER_MODEL=%s\n" "${model}" >>"${env_file}"
  if [[ -n "${ZEROCLAW_LONG_TERM_MEMORY_BASE_URL:-}" ]]; then
    printf "ZEROCLAW_LONG_TERM_MEMORY_BASE_URL=%s\n" "${ZEROCLAW_LONG_TERM_MEMORY_BASE_URL}" >>"${env_file}"
  fi
  if [[ -n "${ZEROCLAW_LONG_TERM_MEMORY_RECALL_LIMIT:-}" ]]; then
    printf "ZEROCLAW_LONG_TERM_MEMORY_RECALL_LIMIT=%s\n" "${ZEROCLAW_LONG_TERM_MEMORY_RECALL_LIMIT}" >>"${env_file}"
  fi
  if [[ -n "${ZEROCLAW_LONG_TERM_MEMORY_AUTH_TOKEN:-}" ]]; then
    printf "ZEROCLAW_LONG_TERM_MEMORY_AUTH_TOKEN=%s\n" "${ZEROCLAW_LONG_TERM_MEMORY_AUTH_TOKEN}" >>"${env_file}"
  fi
  if [[ -n "${ZEROCLAW_EDGE_DELEGATION_ENABLED:-}" ]]; then
    printf "ZEROCLAW_EDGE_DELEGATION_ENABLED=%s\n" "${ZEROCLAW_EDGE_DELEGATION_ENABLED}" >>"${env_file}"
  fi
  if [[ -n "${ZEROCLAW_EDGE_DELEGATE_ENDPOINT_URL:-}" ]]; then
    printf "ZEROCLAW_EDGE_DELEGATE_ENDPOINT_URL=%s\n" "${ZEROCLAW_EDGE_DELEGATE_ENDPOINT_URL}" >>"${env_file}"
  fi
  if [[ -n "${ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN:-}" ]]; then
    printf "ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN=%s\n" "${ZEROCLAW_EDGE_DELEGATE_AUTH_TOKEN}" >>"${env_file}"
  fi
  if [[ -n "${ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS:-}" ]]; then
    printf "ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS=%s\n" "${ZEROCLAW_EDGE_DELEGATE_ALLOWED_TOOLS}" >>"${env_file}"
  fi

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

echo "worker ready at ${base_url}"

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
