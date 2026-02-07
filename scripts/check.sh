#!/usr/bin/env bash
# check.sh — Manual package check against AgentAudit registry
# Usage: bash check.sh <package-name>
# Returns trust score and findings without installing anything.
set -euo pipefail

API_URL="https://www.agentaudit.dev"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

for cmd in jq curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "❌ Required: ${cmd}" >&2; exit 1
  fi
done

if [[ $# -lt 1 ]]; then
  echo "Usage: check.sh <package-name>" >&2; exit 1
fi

# Load API key (shared loader: env var > skill-local > user-level config)
source "$SCRIPT_DIR/_load-key.sh"
API_KEY="$(load_api_key)"

PKG="$1"
PKG_ENCODED="$(printf '%s' "$PKG" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''))" 2>/dev/null \
  || printf '%s' "$PKG" | jq -sRr @uri 2>/dev/null \
  || echo "$PKG")"

echo "🔍 Checking '$PKG' against ${API_URL}..."
echo ""

# Fetch the trust score from /api/check (authoritative, accounts for by_design exclusions)
CHECK_ARGS=(-sL -f --max-time 10 "${API_URL}/api/check?package=${PKG_ENCODED}")
[[ -n "$API_KEY" ]] && CHECK_ARGS+=(-H "Authorization: Bearer ${API_KEY}")

CHECK_RESPONSE="$(curl "${CHECK_ARGS[@]}" 2>/dev/null)" || {
  echo "⚠️  Registry unreachable. Cannot verify package."
  echo "    Try again later or run a local LLM audit on the source."
  exit 2
}

# Check if the package has audit data
EXISTS=$(echo "$CHECK_RESPONSE" | jq -r '.exists // false')
if [[ "$EXISTS" != "true" ]]; then
  echo "📭 No audit data found for '$PKG'."
  echo "   This package has not been scanned yet."
  echo "   Consider submitting an audit: bash scripts/upload.sh <report.json>"
  exit 0
fi

# Use the authoritative trust_score from the API
API_SCORE=$(echo "$CHECK_RESPONSE" | jq '.trust_score // empty')

# Fetch detailed findings for severity breakdown and top findings display
FIND_ARGS=(-sL -f --max-time 10 "${API_URL}/api/findings?package=${PKG_ENCODED}")
[[ -n "$API_KEY" ]] && FIND_ARGS+=(-H "Authorization: Bearer ${API_KEY}")

RESPONSE="$(curl "${FIND_ARGS[@]}" 2>/dev/null)" || RESPONSE='{"findings":[],"total":0}'

# Use API trust_score; fall back to local calculation only if the API didn't return one.
# NOTE: The local fallback may differ from the registry score because the registry
# applies additional adjustments (e.g. by_design exclusion, score_impact weighting)
# that are not fully replicated here.
if [[ -n "$API_SCORE" ]]; then
  SCORE="$API_SCORE"
else
  SCORE=$(echo "$RESPONSE" | jq '
    [.findings // [] | .[] | select(.by_design != true and .by_design != "true") |
      (if .severity == "critical" then -25
      elif .severity == "high" then -15
      elif .severity == "medium" then -8
      elif .severity == "low" then -3
      else 0 end)
    ] | 100 + add | round
  ')
fi

# Severity counts (from /api/check response if available, else from findings)
CRIT=$(echo "$CHECK_RESPONSE" | jq '.critical // 0')
HIGH=$(echo "$CHECK_RESPONSE" | jq '.high // 0')
MED=$(echo "$CHECK_RESPONSE" | jq '.medium // 0')
LOW=$(echo "$CHECK_RESPONSE" | jq '.low // 0')
BYDESIGN=$(echo "$RESPONSE" | jq '[.findings[]|select(.by_design==true or .by_design=="true")]|length')

# Decision
if [[ "$SCORE" -ge 70 ]]; then
  ICON="✅"; VERDICT="PASS — Safe to install"
elif [[ "$SCORE" -ge 40 ]]; then
  ICON="⚠️"; VERDICT="CAUTION — Review findings before installing"
else
  ICON="🔴"; VERDICT="UNSAFE — Do not install without careful review"
fi

echo "${ICON} ${PKG} — Score: ${SCORE}/100"
echo "   ${VERDICT}"
echo ""
echo "   Findings: ${CRIT} critical | ${HIGH} high | ${MED} medium | ${LOW} low | ${BYDESIGN} by-design"
echo ""

# Show top findings
if [[ "$SCORE" -lt 70 ]]; then
  echo "   Top findings:"
  echo "$RESPONSE" | jq -r '.findings[] | select(.by_design != true and .by_design != "true") | "   • [\(.severity | ascii_upcase)] \(.title) (\(.file // "unknown"))"' | head -5
fi
