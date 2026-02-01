#!/usr/bin/env bash
# verify.sh — Verify local skill files against the ecap Trust Registry
# Usage: ./scripts/verify.sh [API_URL]
# Dependencies: curl, jq, sha256sum (or shasum on macOS)
set -euo pipefail

API_URL="${1:-https://skillaudit-api.vercel.app/api/integrity}"
PACKAGE="ecap-security-auditor"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Detect sha256 command
if command -v sha256sum &>/dev/null; then
  SHA_CMD="sha256sum"
elif command -v shasum &>/dev/null; then
  SHA_CMD="shasum -a 256"
else
  echo "❌ No sha256sum or shasum found"; exit 1
fi

FILES=(
  "SKILL.md"
  "scripts/upload.sh"
  "scripts/register.sh"
  "prompts/audit-prompt.md"
  "prompts/review-prompt.md"
  "README.md"
)

echo "🔍 Fetching official hashes from registry..."
RESPONSE=$(curl -sf "${API_URL}?package=${PACKAGE}") || { echo "❌ API request failed"; exit 1; }

MISMATCH=0
CHECKED=0

echo ""
echo "Package: ${PACKAGE}"
echo "Repo:    $(echo "$RESPONSE" | jq -r '.repo')"
echo "Commit:  $(echo "$RESPONSE" | jq -r '.commit' | head -c 12)"
echo "Verified: $(echo "$RESPONSE" | jq -r '.verified_at')"
echo ""

for file in "${FILES[@]}"; do
  LOCAL_PATH="${ROOT_DIR}/${file}"
  REMOTE_HASH=$(echo "$RESPONSE" | jq -r ".files[\"${file}\"].sha256 // empty")

  if [ -z "$REMOTE_HASH" ] || [ "$REMOTE_HASH" = "null" ]; then
    echo "⚠️  ${file} — not tracked by registry"
    continue
  fi

  if [ ! -f "$LOCAL_PATH" ]; then
    echo "❌ ${file} — missing locally"
    MISMATCH=1
    continue
  fi

  LOCAL_HASH=$($SHA_CMD "$LOCAL_PATH" | awk '{print $1}')
  CHECKED=$((CHECKED + 1))

  if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    echo "✅ ${file}"
  else
    echo "❌ ${file} — HASH MISMATCH"
    echo "   local:  ${LOCAL_HASH}"
    echo "   remote: ${REMOTE_HASH}"
    MISMATCH=1
  fi
done

echo ""
echo "Checked: ${CHECKED} files"

if [ "$MISMATCH" -eq 0 ]; then
  echo "✅ All files verified — integrity OK"
  exit 0
else
  echo "❌ Integrity check FAILED — files differ from official repo"
  exit 1
fi
