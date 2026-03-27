#!/usr/bin/env bash
set -euo pipefail

base_url="${ZEROCLAW_EDGE_DEMO_BASE_URL:-}"
drill_token="${ZEROCLAW_CANARY_DRILL_TOKEN:-}"
limit="${ZEROCLAW_CANARY_AUDIT_ARCHIVE_LIMIT:-200}"
before_ms="${ZEROCLAW_CANARY_AUDIT_ARCHIVE_BEFORE_MS:-}"
delete_archived="${ZEROCLAW_CANARY_AUDIT_ARCHIVE_DELETE:-1}"
output_root="${ZEROCLAW_CANARY_ARTIFACT_OUTPUT_DIR:-$(pwd)/artifacts}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

bool_to_json() {
  case "$1" in
    1|true|TRUE|yes|YES|on|ON) echo "true" ;;
    0|false|FALSE|no|NO|off|OFF) echo "false" ;;
    *)
      echo "invalid boolean value: $1" >&2
      exit 1
      ;;
  esac
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

if ! [[ "${limit}" =~ ^[0-9]+$ ]] || [[ "${limit}" -eq 0 ]]; then
  echo "invalid ZEROCLAW_CANARY_AUDIT_ARCHIVE_LIMIT (must be positive integer): ${limit}" >&2
  exit 1
fi

if [[ -n "${before_ms}" ]] && ! [[ "${before_ms}" =~ ^[0-9]+$ ]]; then
  echo "invalid ZEROCLAW_CANARY_AUDIT_ARCHIVE_BEFORE_MS (must be unix ms integer): ${before_ms}" >&2
  exit 1
fi

delete_json="$(bool_to_json "${delete_archived}")"

if [[ -n "${before_ms}" ]]; then
  payload="$(jq -n --argjson limit "${limit}" --argjson before_ms "${before_ms}" --argjson delete_archived "${delete_json}" '{limit:$limit,before_ms:$before_ms,delete_archived:$delete_archived}')"
else
  payload="$(jq -n --argjson limit "${limit}" --argjson delete_archived "${delete_json}" '{limit:$limit,before_ms:null,delete_archived:$delete_archived}')"
fi

response="$(curl -fsS -X POST "${base_url}/canary/audit/archive/upload" \
  -H "x-zeroclaw-drill-token: ${drill_token}" \
  -H "content-type: application/json" \
  --data "${payload}")"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive_dir="${output_root%/}/canary-audit-upload-${timestamp}"
mkdir -p "${archive_dir}"
printf '%s\n' "${response}" > "${archive_dir}/upload.json"
jq '{sink_url,sink_status,uploaded_records,deleted_records,remaining_records,payload_sha256_hex}' "${archive_dir}/upload.json" > "${archive_dir}/summary.json"

echo "audit_upload_file=${archive_dir}/upload.json"
echo "audit_upload_summary=${archive_dir}/summary.json"
