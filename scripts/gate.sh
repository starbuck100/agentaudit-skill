#!/usr/bin/env bash
# gate.sh — AgentAudit Security Gate
# Usage: bash gate.sh <package-manager> <package-name> [extra-args...]
set -euo pipefail

API_URL="https://www.agentaudit.dev"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# --- Dependency Check ---
for cmd in jq curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "{\"error\":\"Required dependency missing: ${cmd}. Install it first.\",\"exit_code\":1}" >&2
    exit 1
  fi
done

# --- Args ---
if [[ $# -lt 2 ]]; then
  echo '{"error":"Usage: gate.sh <npm|pip|clawhub> <package> [args...]","exit_code":1}' >&2
  exit 1
fi
PM="$1"; PKG="$2"; shift 2; EXTRA_ARGS=("$@")

# --- Validate Package Name ---
if [[ -z "$PKG" || "$PKG" =~ ^[[:space:]]*$ ]]; then
  echo '{"error":"Package name must not be empty.","exit_code":1}' >&2
  exit 1
fi

# --- URL-encode package name (handles @scoped/packages) ---
url_encode() {
  local string="$1"
  printf '%s' "$string" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''))" 2>/dev/null \
    || printf '%s' "$string" | jq -sRr @uri 2>/dev/null \
    || printf '%s' "$string" | sed 's/@/%40/g; s/\//%2F/g; s/ /%20/g'
}
PKG_ENCODED="$(url_encode "$PKG")"

# --- API Key (shared loader: env var > skill-local > user-level config) ---
GATE_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$GATE_SCRIPT_DIR/_load-key.sh"
API_KEY="$(load_api_key)"

# --- Query API ---
CURL_ARGS=(-sL -f --max-time 15 "${API_URL}/api/findings?package=${PKG_ENCODED}")
[[ -n "$API_KEY" ]] && CURL_ARGS+=(-H "Authorization: Bearer ${API_KEY}")
RESPONSE="$(curl "${CURL_ARGS[@]}" 2>/dev/null)" || {
  echo "{\"gate\":\"warn\",\"package\":\"${PKG}\",\"score\":null,\"message\":\"⚠️ Registry unreachable (timeout or down). Proceeding in WARN mode — package is UNVERIFIED. Consider running a local audit or waiting until the registry is back.\",\"exit_code\":2}"
  exit 2
}

# --- Parse & Score ---
TOTAL=$(echo "$RESPONSE" | jq '.total // 0')
if [[ "$TOTAL" -eq 0 ]]; then
  # UNKNOWN = No audit data yet. Opportunity to contribute!
  cat <<EOF
{
  "gate": "unknown",
  "package": "${PKG}",
  "score": null,
  "total": 0,
  "message": "🔍 Package not yet audited in registry",
  "info": "This package hasn't been scanned yet. You can be the first to audit it and contribute to the community!",
  "next_steps": {
    "option_1": "Run a security audit now and submit findings to the registry",
    "option_2": "Proceed with caution after manual verification",
    "option_3": "Choose a different, already-audited package"
  },
  "how_to_audit": {
    "step_1": "Read the audit prompt: cat $SCRIPT_DIR/prompts/audit-prompt.md",
    "step_2": "Analyze the package source code against the security checklist",
    "step_3": "Build a JSON report with findings (see SKILL.md for format)",
    "step_4": "Submit: bash $SCRIPT_DIR/scripts/upload.sh report.json"
  },
  "risk_checks": [
    "Is this package < 30 days old? (higher risk)",
    "Does it have < 100 weekly downloads? (higher risk)",
    "Is the author new with no other packages? (higher risk)",
    "Is the name similar to a popular package (typosquat)?"
  ],
  "recommendation": "Do NOT auto-install unaudited packages. Audit first, then proceed with informed decision.",
  "exit_code": 3
}
EOF
  exit 3
fi

SCORE=$(echo "$RESPONSE" | jq '
  [.findings // [] | .[] | select(.by_design != true and .by_design != "true") |
    .component_type as $ct |
    (if .severity == "critical" then -25
    elif .severity == "high" then -15
    elif .severity == "medium" then -8
    elif .severity == "low" then -3
    else 0 end) |
    if $ct == "hook" or $ct == "mcp" or $ct == "settings" or $ct == "plugin" then . * 12 / 10
    else . end
  ] | 100 + add | round
')

FINDINGS_SUMMARY=$(echo "$RESPONSE" | jq -c '{
  critical: [.findings[]|select(.severity=="critical" and .by_design!=true and .by_design!="true")]|length,
  high:     [.findings[]|select(.severity=="high" and .by_design!=true and .by_design!="true")]|length,
  medium:   [.findings[]|select(.severity=="medium" and .by_design!=true and .by_design!="true")]|length,
  low:      [.findings[]|select(.severity=="low" and .by_design!=true and .by_design!="true")]|length,
  by_design:[.findings[]|select(.by_design==true or .by_design=="true")]|length
}')

# --- Decision ---
build_output() {
  jq -nc --arg gate "$1" --arg pkg "$PKG" --argjson score "$SCORE" \
    --argjson total "$TOTAL" --argjson findings "$FINDINGS_SUMMARY" \
    --arg msg "$2" --argjson ec "$3" \
    '{gate:$gate,package:$pkg,score:$score,total:$total,findings:$findings,message:$msg,exit_code:$ec}'
}

if [[ "$SCORE" -ge 70 ]]; then
  # PASS — install
  build_output "pass" "Score ${SCORE}/100 — installing" 0
  case "$PM" in
    npm)     npm install "$PKG" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}" ;;
    pip)     pip install "$PKG" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}" ;;
    clawhub) clawhub install "$PKG" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}" ;;
    *)       echo "{\"error\":\"Unknown package manager: ${PM}\"}" >&2; exit 1 ;;
  esac
  exit 0
elif [[ "$SCORE" -ge 40 ]]; then
  build_output "warning" "Score ${SCORE}/100 — review findings before installing" 2
  # Show top findings for agent
  echo "$RESPONSE" | jq -c '[.findings[]|select(.by_design!=true and .by_design!="true")|{severity,title,by_design}][:5]' >&2
  exit 2
else
  build_output "block" "Score ${SCORE}/100 — too risky, installation blocked" 1
  exit 1
fi
