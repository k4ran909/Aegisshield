#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:9090}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
TEST_IP="${TEST_IP:-198.51.100.77}"

auth_header=()
if [[ -n "${AUTH_TOKEN}" ]]; then
  auth_header=(-H "Authorization: Bearer ${AUTH_TOKEN}")
fi

echo "Checking control-plane status endpoint..."
curl -fsS "${API_URL}/api/v1/status" "${auth_header[@]}" >/dev/null

echo "Blocking ${TEST_IP}..."
curl -fsS -X POST "${API_URL}/api/v1/block" \
  -H "Content-Type: application/json" \
  "${auth_header[@]}" \
  -d "{\"ip\":\"${TEST_IP}\",\"duration\":\"2m\",\"reason\":\"integration-check\"}" >/dev/null

echo "Verifying blocklist contains ${TEST_IP}..."
if ! curl -fsS "${API_URL}/api/v1/blocklist" "${auth_header[@]}" | grep -q "${TEST_IP}"; then
  echo "Expected ${TEST_IP} in blocklist but it was not found"
  exit 1
fi

echo "Unblocking ${TEST_IP}..."
curl -fsS -X POST "${API_URL}/api/v1/unblock" \
  -H "Content-Type: application/json" \
  "${auth_header[@]}" \
  -d "{\"ip\":\"${TEST_IP}\"}" >/dev/null

echo "Blocklist integration check completed successfully."
