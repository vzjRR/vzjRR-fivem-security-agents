#!/usr/bin/env bash
# vzjRR Security Assessment for FiveM - Linux/macOS resource scan wrapper.
#
# Prefers the tested Python scanner. Falls back to a grep sweep when Python is absent -
# the fallback is a triage aid only, not equivalent coverage.
#
# Usage: ./vzjrr-scan.sh <SERVER_ROOT> [OUT_DIR]

set -uo pipefail
CREDIT="vzjRR Security Assessment for FiveM"
ROOT="${1:?usage: vzjrr-scan.sh <SERVER_ROOT> [OUT_DIR]}"
OUT="${2:-$PWD/vzjrr-audit/$(date +%Y%m%d-%H%M%S)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -d "$ROOT" ] || { echo "Not a directory: $ROOT" >&2; exit 1; }
mkdir -p "$OUT"

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$HERE/../vzjrr_scan.py" --path "$ROOT" --out "$OUT" "${@:3}"
fi

echo "python3 not found - running the reduced grep fallback." >&2
echo "Coverage is lower than tools/vzjrr_scan.py. Install Python 3 for a full scan." >&2

REPORT="$OUT/resource-scan-fallback.md"
{
  echo "# FiveM Resource Scan (grep fallback)"
  echo
  echo "- **Target:** \`$ROOT\`"
  echo "- **Scanned (UTC):** $(date -u '+%Y-%m-%d %H:%M:%S')"
  echo
  echo "> Reduced-coverage fallback. Multi-line loader patterns and the manifest"
  echo "> cross-reference checks are NOT performed here. Re-run with Python 3."
  echo
} > "$REPORT"

section() { echo; echo "## $1"; echo; echo '```'; } >> "$REPORT"
endsec()  { echo '```'; echo; } >> "$REPORT"

FOUND=0
run() { # run "Title" <grep args...>
  local title="$1"; shift
  local hits
  hits="$("$@" 2>/dev/null | head -200)"
  section "$title"
  if [ -n "$hits" ]; then echo "$hits"; FOUND=1; else echo "(no matches)"; fi >> "$REPORT"
  endsec
  [ -n "$hits" ] && { printf '\033[31m[HIT]\033[0m %s\n' "$title"; echo "$hits" | head -20; }
}

INC=(--include='*.lua' --include='*.js' --include='*.mjs' --include='*.cfg' --include='*.json')

run "Panel C2 domains and extortion lock strings" \
  grep -rInE "${INC[@]}" -e 'blum-panel|kercher-panel|[a-z0-9_-]{2,30}-panel\.(me|xyz|cc|su|ru|top)|Server is locked by|Purchase whitelist' "$ROOT"

run "Known loader markers" \
  grep -rInE "${INC[@]}" -e 'helpEmptyCode|onServerResourceFail|RESOURCE_EXCLUDE|JohnsUrUncle|BLUM_TXADMIN_THEFT_PAYLOAD|txadmin:js_create' "$ROOT"

run "Whitespace-padded manifest injections" \
  grep -rInE --include=fxmanifest.lua --include=__resource.lua '[ '$'\t'']{60,}[^ '$'\t'']' "$ROOT"

run "Fake build-tooling drop points" \
  grep -rIlE "${INC[@]}" -e 'sv_init\.mjs|babelrc|babel_config|node_modules/internal|\.yarn\.js' "$ROOT"

run "Dynamic code execution" \
  grep -rInE "${INC[@]}" -e 'loadstring\s*\(|\bload\s*\(\s*(Base64|base64|Decode|decode)|eval\s*\(|new Function\s*\(' "$ROOT"

run "Shell execution from server scripts" \
  grep -rInE "${INC[@]}" -e 'os\.execute\s*\(|io\.popen\s*\(|child_process' "$ROOT"

run "Credential harvesting" \
  grep -rInE "${INC[@]}" -e 'admins\.json|sv_licenseKey|rcon_password|mysql_connection_string|steam_webApiKey|txData' "$ROOT"

run "Exfiltration endpoints" \
  grep -rInE "${INC[@]}" -e 'discord(app)?\.com/api/(v[0-9]+/)?webhooks/|pastebin\.com/raw|transfer\.sh|ngrok|gofile\.io' "$ROOT"

run "ACE and principal grants (review every line)" \
  grep -rInE --include='*.cfg' -e '^\s*add_(principal|ace)\s' "$ROOT"

section "Zero-byte script stubs"
find "$ROOT" -type f \( -name '*.lua' -o -name '*.js' -o -name '*.mjs' \) -size 0 >> "$REPORT" 2>/dev/null || true
endsec

section "Script/config files modified in the last 45 days"
find "$ROOT" -type f \( -name '*.lua' -o -name '*.js' -o -name '*.mjs' -o -name '*.cfg' -o -name '*.json' \) \
  -mtime -45 -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort -r | head -80 >> "$REPORT" || true
endsec

{ echo "---"; echo "Prepared by: $CREDIT"; } >> "$REPORT"

echo
if [ "$FOUND" -eq 1 ]; then
  echo "INDICATORS FOUND - review $REPORT, then follow agents/assessment/AGENT.md"
else
  echo "No indicators in the fallback checks. This is NOT a clean bill of health -"
  echo "run the full Python scanner and the host audit before concluding anything."
fi
echo "Report: $REPORT"
echo "Prepared by: $CREDIT"
exit $FOUND
