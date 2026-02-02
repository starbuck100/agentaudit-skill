#!/usr/bin/env bash
# check.sh — Manual package check against AgentAudit registry
# Usage: bash check.sh <package-name>
# Returns trust score and findings without installing anything.
set -euo pipefail

API_URL="${AGENTAUDIT_REGISTRY_URL:-https://agentaudit.dev}"

for cmd in jq curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "❌ Required: ${cmd}" >&2; exit 1
  fi
done

if [[ $# -lt 1 ]]; then
  echo "Usage: check.sh <package-name>" >&2; exit 1
fi

PKG="$1"
PKG_ENCODED="$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PKG', safe=''))" 2>/dev/null || echo "$PKG")"

echo "🔍 Checking '$PKG' against ${API_URL}..."
echo ""

RESPONSE="$(curl -sL -f --max-time 10 "${API_URL}/api/findings?package=${PKG_ENCODED}" 2>/dev/null)" || {
  echo "⚠️  Registry unreachable. Cannot verify package."
  echo "    Try again later or run a local LLM audit on the source."
  exit 2
}

TOTAL=$(echo "$RESPONSE" | jq '.total // 0')

if [[ "$TOTAL" -eq 0 ]]; then
  echo "📭 No audit data found for '$PKG'."
  echo "   This package has not been scanned yet."
  echo "   Consider submitting an audit: bash scripts/upload.sh <report.json>"
  exit 0
fi

# Calculate score
SCORE=$(echo "$RESPONSE" | jq '
  [.findings // [] | .[] | select(.by_design != true and .by_design != "true") |
    (if .severity == "critical" then -25
    elif .severity == "high" then -15
    elif .severity == "medium" then -8
    elif .severity == "low" then -3
    else 0 end)
  ] | 100 + add | round
')

# Severity counts
CRIT=$(echo "$RESPONSE" | jq '[.findings[]|select(.severity=="critical" and .by_design!=true)]|length')
HIGH=$(echo "$RESPONSE" | jq '[.findings[]|select(.severity=="high" and .by_design!=true)]|length')
MED=$(echo "$RESPONSE" | jq '[.findings[]|select(.severity=="medium" and .by_design!=true)]|length')
LOW=$(echo "$RESPONSE" | jq '[.findings[]|select(.severity=="low" and .by_design!=true)]|length')
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
