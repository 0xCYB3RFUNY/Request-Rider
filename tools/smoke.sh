#!/usr/bin/env bash
set -euo pipefail

ENGINE_URL="${ENGINE_URL:-http://127.0.0.1:8081}"
WEB_URL="${WEB_URL:-http://127.0.0.1:8000}"
TARGET_URL="${TARGET_URL:-}"
INTRUDER_URL="${INTRUDER_URL:-}"
if [ -z "$TARGET_URL" ] || [ -z "$INTRUDER_URL" ]; then
  echo "Set TARGET_URL and INTRUDER_URL to explicitly configured permitted test targets" >&2
  exit 2
fi

python - "$ENGINE_URL/health" <<'PY'
import json, sys, urllib.request
payload = json.load(urllib.request.urlopen(sys.argv[1]))
assert payload.get("ok") is True, payload
PY

execute_response="$(curl -fsS "$WEB_URL/api/execute" -H 'Content-Type: application/json' \
  -d "{\"method\":\"GET\",\"url\":\"$TARGET_URL\",\"headers\":{},\"body\":\"\"}")"
python -c 'import json, sys; payload = json.load(sys.stdin); assert payload.get("status") is not None, payload' <<< "$execute_response"

attack_response="$(curl -fsS -X POST "$WEB_URL/api/intruder" -H 'Content-Type: application/json' \
  -d "{\"base_request\":{\"method\":\"GET\",\"url\":\"${INTRUDER_URL}?qa={{smoke}}\",\"headers\":{},\"body\":\"\"},\"mode\":\"batteringRam\",\"payloads\":[[\"smoke\"]],\"transformations\":[]}")"
attack_id="$(python -c 'import json, sys; payload = json.load(sys.stdin); assert payload.get("attack_id"), payload; print(payload["attack_id"])' <<< "$attack_response"
)"
python - "$WEB_URL/api/intruder?attack_id=$attack_id" <<'PY'
import json, sys, urllib.request
payload = json.load(urllib.request.urlopen(sys.argv[1]))
assert payload.get("attack_id"), payload
PY

history_response="$(curl -fsS "$WEB_URL/api/history")"
python -c 'import json, sys; payload = json.load(sys.stdin); assert isinstance(payload.get("items"), list), payload' <<< "$history_response"

# Establish that the gateway exposes a live SSE response. A stream naturally
# remains open; max-time turns the expected timeout into a successful check.
set +e
curl -fsSN --max-time 2 "$WEB_URL/api/traffic/stream" >/dev/null
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 28 ]; then
  echo "SSE endpoint failed with curl status $status" >&2
  exit "$status"
fi

echo "smoke checks passed"
