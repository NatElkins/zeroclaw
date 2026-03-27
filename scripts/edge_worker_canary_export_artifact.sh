#!/usr/bin/env bash
set -euo pipefail

base_url="${ZEROCLAW_EDGE_DEMO_BASE_URL:-}"
drill_token="${ZEROCLAW_CANARY_DRILL_TOKEN:-}"
scenario="${1:-all}"
limit="${ZEROCLAW_CANARY_AUDIT_EXPORT_LIMIT:-50}"
output_root="${ZEROCLAW_CANARY_ARTIFACT_OUTPUT_DIR:-$(pwd)/artifacts}"
verify_key="${ZEROCLAW_CANARY_ARTIFACT_VERIFY_KEY:-}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

validate_scenario() {
  case "$1" in
    all|promote|hold|rollback) ;;
    *)
      echo "unsupported scenario: $1 (expected all|promote|hold|rollback)" >&2
      exit 1
      ;;
  esac
}

sha256_file_hex() {
  local file="$1"
  openssl dgst -sha256 "$file" | awk '{print $NF}'
}

require_cmd curl
require_cmd jq
require_cmd tar

if [[ -z "${base_url}" ]]; then
  echo "missing ZEROCLAW_EDGE_DEMO_BASE_URL (example: https://zeroclaw-edge-worker.<subdomain>.workers.dev)" >&2
  exit 1
fi
base_url="${base_url%/}"

if [[ -z "${drill_token}" ]]; then
  echo "missing ZEROCLAW_CANARY_DRILL_TOKEN" >&2
  exit 1
fi

validate_scenario "${scenario}"

if ! [[ "${limit}" =~ ^[0-9]+$ ]] || [[ "${limit}" -eq 0 ]]; then
  echo "invalid ZEROCLAW_CANARY_AUDIT_EXPORT_LIMIT (must be positive integer): ${limit}" >&2
  exit 1
fi

if [[ -n "${verify_key}" ]]; then
  require_cmd openssl
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
bundle_name="canary-drill-${scenario}-${timestamp}"
bundle_dir="${output_root%/}/${bundle_name}"
mkdir -p "${bundle_dir}"

bundle_json="$(curl -fsS -X POST "${base_url}/canary/drill/export/${scenario}?limit=${limit}" \
  -H "x-zeroclaw-drill-token: ${drill_token}")"
printf '%s\n' "${bundle_json}" > "${bundle_dir}/bundle.json"

canonical_payload="$(printf '%s' "${bundle_json}" | jq -c '.payload')"
printf '%s' "${canonical_payload}" > "${bundle_dir}/payload.json"
printf '%s' "${bundle_json}" | jq '.signature' > "${bundle_dir}/signature.json"
printf '%s' "${bundle_json}" | jq '.payload.drill_runs' > "${bundle_dir}/drill_runs.json"
printf '%s' "${bundle_json}" | jq '.payload.audit_records' > "${bundle_dir}/audit_records.json"

if [[ -n "${verify_key}" ]]; then
  expected_payload_hash="$(jq -r '.signature.payload_sha256_hex' "${bundle_dir}/bundle.json")"
  expected_signature="$(jq -r '.signature.signature_hmac_sha256_hex' "${bundle_dir}/bundle.json")"
  actual_payload_hash="$(printf '%s' "${canonical_payload}" | openssl dgst -sha256 | awk '{print $NF}')"
  actual_signature="$(printf '%s' "${canonical_payload}" | openssl dgst -sha256 -hmac "${verify_key}" | awk '{print $NF}')"

  if [[ "${actual_payload_hash}" != "${expected_payload_hash}" ]]; then
    echo "artifact payload hash mismatch" >&2
    echo "expected=${expected_payload_hash}" >&2
    echo "actual=${actual_payload_hash}" >&2
    exit 1
  fi

  if [[ "${actual_signature}" != "${expected_signature}" ]]; then
    echo "artifact signature mismatch" >&2
    echo "expected=${expected_signature}" >&2
    echo "actual=${actual_signature}" >&2
    exit 1
  fi
fi

manifest_tmp="$(mktemp)"
{
  printf '{\n'
  printf '  "bundle_name": "%s",\n' "${bundle_name}"
  printf '  "generated_at": "%s",\n' "${timestamp}"
  printf '  "scenario": "%s",\n' "${scenario}"
  printf '  "base_url": "%s",\n' "${base_url}"
  printf '  "audit_limit": %s,\n' "${limit}"
  printf '  "files": [\n'
  first=1
  for file in bundle.json payload.json signature.json drill_runs.json audit_records.json; do
    hash="$(sha256_file_hex "${bundle_dir}/${file}")"
    if [[ "${first}" -eq 0 ]]; then
      printf ',\n'
    fi
    printf '    {"path":"%s","sha256":"%s"}' "${file}" "${hash}"
    first=0
  done
  printf '\n  ]\n'
  printf '}\n'
} > "${manifest_tmp}"

jq '.' "${manifest_tmp}" > "${bundle_dir}/manifest.json"
rm -f "${manifest_tmp}"

(
  cd "${output_root%/}"
  tar -czf "${bundle_name}.tar.gz" "${bundle_name}"
)

echo "artifact_bundle_dir=${bundle_dir}"
echo "artifact_bundle_tar=${output_root%/}/${bundle_name}.tar.gz"
