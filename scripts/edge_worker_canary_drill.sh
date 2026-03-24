#!/usr/bin/env bash
set -euo pipefail

base_url="${ZEROCLAW_EDGE_DEMO_BASE_URL:-}"
drill_token="${ZEROCLAW_CANARY_DRILL_TOKEN:-}"
scenario="${1:-all}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

run_scenario() {
  local name="$1"
  local expected="$2"
  local resp
  resp="$(curl -fsS -X POST "${base_url}/canary/drill/tick/${name}" \
    -H "x-zeroclaw-drill-token: ${drill_token}")"
  local decision
  decision="$(printf "%s" "${resp}" | jq -r '.tick.decision')"
  if [[ "${decision}" != *"${expected}"* ]]; then
    echo "unexpected decision for scenario=${name}: ${decision} (expected substring ${expected})" >&2
    echo "raw: ${resp}" >&2
    exit 1
  fi
  echo "${name}: ${resp}"
}

require_cmd curl
require_cmd jq

if [[ -z "${base_url}" ]]; then
  echo "missing ZEROCLAW_EDGE_DEMO_BASE_URL (example: https://zeroclaw-edge-worker.<subdomain>.workers.dev)" >&2
  exit 1
fi
base_url="${base_url%/}"

if [[ -z "${drill_token}" ]]; then
  echo "missing ZEROCLAW_CANARY_DRILL_TOKEN" >&2
  exit 1
fi

case "${scenario}" in
  all)
    run_scenario "promote" "Promote"
    run_scenario "hold" "Hold"
    run_scenario "rollback" "Rollback"
    ;;
  promote)
    run_scenario "promote" "Promote"
    ;;
  hold)
    run_scenario "hold" "Hold"
    ;;
  rollback)
    run_scenario "rollback" "Rollback"
    ;;
  *)
    echo "unsupported scenario: ${scenario} (expected all|promote|hold|rollback)" >&2
    exit 1
    ;;
esac
