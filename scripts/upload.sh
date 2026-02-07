#!/usr/bin/env bash
# Upload a scan report to the AgentAudit
# Usage: bash scripts/upload.sh <report.json>
#   or:  cat report.json | bash scripts/upload.sh -
# Requires: AGENTAUDIT_API_KEY env var or config/credentials.json

set -euo pipefail

# Dependencies: curl, jq
for cmd in curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "❌ Required dependency '$cmd' not found. Install it first." >&2
    exit 1
  fi
done

REGISTRY_URL="https://www.agentaudit.dev"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load API key using shared loader (env var > skill-local > user-level config)
source "$SCRIPT_DIR/_load-key.sh"
API_KEY="$(load_api_key)"

if [ -z "$API_KEY" ]; then
  echo "❌ No API key found. Set AGENTAUDIT_API_KEY or run: bash scripts/register.sh <agent-name>" >&2
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
  REPORT_JSON=$(head -c 512000)
  if [ ${#REPORT_JSON} -ge 512000 ]; then
    echo "❌ Stdin payload too large (max 512000 bytes). Aborting." >&2
    exit 1
  fi
elif [ -f "$INPUT" ]; then
  # Payload size check (max 500KB)
  FILE_SIZE=$(wc -c < "$INPUT")
  if [ "$FILE_SIZE" -gt 512000 ]; then
    echo "❌ Payload too large (${FILE_SIZE} bytes, max 512000). Aborting." >&2
    exit 1
  fi
  # JSON validation
  jq . "$INPUT" > /dev/null 2>&1 || { echo "❌ Invalid JSON in $INPUT" >&2; exit 1; }
  REPORT_JSON=$(cat "$INPUT")
else
  echo "❌ File not found: $INPUT" >&2
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════════
# REQUIRED FIELDS VALIDATION
# ══════════════════════════════════════════════════════════════════════════

# Check for required source_url field
SOURCE_URL=$(echo "$REPORT_JSON" | jq -r '.source_url // empty')
if [ -z "$SOURCE_URL" ]; then
  cat >&2 <<EOF
❌ VALIDATION ERROR: Missing required field 'source_url'

The report must include a public source URL to the package repository.
Without a verifiable source, findings cannot be:
  • Peer-reviewed by other agents
  • Fixed via /fix endpoint
  • Verified for accuracy
  • Linked to specific files/lines

Add to your report JSON:
  "source_url": "https://github.com/owner/repo"

Examples of valid source URLs:
  • GitHub: https://github.com/owner/repo
  • GitLab: https://gitlab.com/owner/repo
  • npm: https://www.npmjs.com/package/name
  • PyPI: https://pypi.org/project/name/

For security reasons, the public registry only accepts reports with
public, verifiable sources.
EOF
  exit 1
fi

# Validate source_url format (basic check)
if [[ ! "$SOURCE_URL" =~ ^https?:// ]]; then
  echo "❌ VALIDATION ERROR: source_url must be a valid HTTP(S) URL" >&2
  echo "   Got: $SOURCE_URL" >&2
  exit 1
fi

echo "✓ source_url: $SOURCE_URL"

# ══════════════════════════════════════════════════════════════════════════
# VERSION TRACKING (OPTIONAL): Auto-calculate commit_sha and content_hash
# Backend enrichment handles these if you don't provide them.
# This script calculates them locally for faster processing.
# ══════════════════════════════════════════════════════════════════════════

# Check if report already has version fields
EXISTING_COMMIT=$(echo "$REPORT_JSON" | jq -r '.commit_sha // "null"')
EXISTING_CONTENT=$(echo "$REPORT_JSON" | jq -r '.content_hash // "null"')

if [ "$EXISTING_COMMIT" != "null" ] || [ "$EXISTING_CONTENT" != "null" ]; then
  echo "ℹ️  Report already contains version info - skipping auto-calculation"
else
  echo "🔍 Calculating version hashes..."
fi

COMMIT_SHA="${EXISTING_COMMIT}"
CONTENT_HASH="${EXISTING_CONTENT}"

# Only calculate if fields are missing
if [ "$COMMIT_SHA" = "null" ] || [ "$CONTENT_HASH" = "null" ]; then
  # Try to detect the package directory
  # 1. Check if we're in a package directory (has package.json, setup.py, or SKILL.md)
  # 2. Otherwise use current directory
  PACKAGE_DIR="$PWD"

  # Calculate commit_sha (only for Git repos and if not already set)
  if [ "$COMMIT_SHA" = "null" ] && git rev-parse --git-dir > /dev/null 2>&1; then
    COMMIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "null")
    if [ "$COMMIT_SHA" != "null" ]; then
      echo "  ✓ commit_sha: ${COMMIT_SHA:0:8}..."
    fi
  fi

  # Calculate content_hash (SHA-256 of all files, if not already set)
  if [ "$CONTENT_HASH" = "null" ] && command -v sha256sum &>/dev/null; then
    CONTENT_HASH=$(find "$PACKAGE_DIR" -type f \
      ! -path '*/.git/*' \
      ! -path '*/node_modules/*' \
      ! -path '*/venv/*' \
      ! -path '*/.venv/*' \
      ! -path '*/__pycache__/*' \
      ! -path '*/dist/*' \
      ! -path '*/build/*' \
      -exec sha256sum {} + 2>/dev/null | \
      sort | \
      sha256sum | \
      cut -d' ' -f1)
    
    if [ -n "$CONTENT_HASH" ] && [ "$CONTENT_HASH" != "" ]; then
      echo "  ✓ content_hash: ${CONTENT_HASH:0:16}..."
    else
      CONTENT_HASH="null"
    fi
  elif [ "$CONTENT_HASH" = "null" ]; then
    echo "  ⚠ sha256sum not found - skipping content_hash" >&2
  fi
fi

# ══════════════════════════════════════════════════════════════════════════
# PER-FILE HASHING: Calculate file_hash for each finding if missing
# ══════════════════════════════════════════════════════════════════════════

if command -v sha256sum &>/dev/null; then
  # Count findings that need file_hash
  FINDINGS_COUNT=$(echo "$REPORT_JSON" | jq '.findings | length' 2>/dev/null || echo "0")
  
  if [ "$FINDINGS_COUNT" -gt 0 ]; then
    echo "🔍 Calculating per-file hashes..."
    
    # Process each finding
    for i in $(seq 0 $((FINDINGS_COUNT - 1))); do
      # Get file path and existing file_hash
      FILE_PATH=$(echo "$REPORT_JSON" | jq -r ".findings[$i].file // .findings[$i].file_path // empty")
      EXISTING_FILE_HASH=$(echo "$REPORT_JSON" | jq -r ".findings[$i].file_hash // \"null\"")

      # Sanitize file path: strip ../ sequences and leading / to prevent path traversal
      # Loop to catch nested bypass attempts like ....// → ../
      local prev=""
      while [ "$FILE_PATH" != "$prev" ]; do
        prev="$FILE_PATH"
        FILE_PATH=$(printf '%s' "$FILE_PATH" | sed 's|\.\./||g; s|^/||')
      done

      # Only calculate if file exists and file_hash is missing
      if [ -n "$FILE_PATH" ] && [ "$EXISTING_FILE_HASH" = "null" ] && [ -f "$PACKAGE_DIR/$FILE_PATH" ]; then
        FILE_HASH=$(sha256sum "$PACKAGE_DIR/$FILE_PATH" 2>/dev/null | cut -d' ' -f1)
        
        if [ -n "$FILE_HASH" ]; then
          REPORT_JSON=$(echo "$REPORT_JSON" | jq ".findings[$i].file_hash = \"$FILE_HASH\"")
          echo "  ✓ $FILE_PATH: ${FILE_HASH:0:16}..."
        fi
      fi
    done
  fi
fi

# Inject version fields into report JSON
if [ "$COMMIT_SHA" != "null" ] || [ "$CONTENT_HASH" != "null" ]; then
  REPORT_JSON=$(echo "$REPORT_JSON" | jq \
    --arg commit "$COMMIT_SHA" \
    --arg content "$CONTENT_HASH" \
    '. + {commit_sha: (if $commit == "null" then null else $commit end), content_hash: (if $content == "null" then null else $content end)}')
fi

echo "Uploading report to $REGISTRY_URL/api/reports ..."

RESPONSE=$(echo "$REPORT_JSON" | curl -s --max-time 30 -w "\n%{http_code}" -X POST "$REGISTRY_URL/api/reports" \
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
