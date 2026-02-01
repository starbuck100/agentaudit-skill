#!/usr/bin/env bash
# Upload a scan report to the ecap Trust Registry
# Usage: bash scripts/upload.sh <report.json>
#   or:  cat report.json | bash scripts/upload.sh -
# Requires: ECAP_API_KEY env var or config/credentials.json

set -euo pipefail

# Dependencies: curl, jq
for cmd in curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "❌ Required dependency '$cmd' not found. Install it first." >&2
    exit 1
  fi
done

# Registry URL — override with ECAP_REGISTRY_URL for self-hosting
REGISTRY_URL="${ECAP_REGISTRY_URL:-https://skillaudit-api.vercel.app}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRED_FILE="$SCRIPT_DIR/../config/credentials.json"

# Resolve API key: env var > credentials file
API_KEY="${ECAP_API_KEY:-}"
if [ -z "$API_KEY" ] && [ -f "$CRED_FILE" ]; then
  API_KEY=$(jq -r '.api_key // empty' "$CRED_FILE" 2>/dev/null || true)
fi

if [ -z "$API_KEY" ]; then
  echo "❌ No API key found. Set ECAP_API_KEY or run: bash scripts/register.sh <agent-name>" >&2
  exit 1
fi

# Read report JSON
INPUT="${1:-}"
if [ -z "$INPUT" ]; then
  echo "Usage: bash scripts/upload.sh <report.json>" >&2
  echo "   or: cat report.json | bash scripts/upload.sh -" >&2
  exit 1
fi

if [ "$INPUT" = "-" ]; then
  REPORT_JSON=$(cat)
elif [ -f "$INPUT" ]; then
  REPORT_JSON=$(cat "$INPUT")
else
  echo "❌ File not found: $INPUT" >&2
  exit 1
fi

echo "Uploading report to $REGISTRY_URL/api/reports ..."

RESPONSE=$(echo "$REPORT_JSON" | curl -s -w "\n%{http_code}" -X POST "$REGISTRY_URL/api/reports" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @-)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  REPORT_ID=$(echo "$BODY" | jq -r '.report_id // "unknown"')
  FINDINGS=$(echo "$BODY" | jq -r '.findings_created | length // 0')
  echo "✅ Report uploaded successfully!"
  echo "Report ID: $REPORT_ID"
  echo "Findings created: $FINDINGS"
  echo "$BODY" | jq .
else
  echo "❌ Upload failed (HTTP $HTTP_CODE):" >&2
  echo "$BODY" >&2
  exit 1
fi
