#!/usr/bin/env bash
#
# burn-check.sh — in-depth "is this domain burned?" checker
#
# Step 2 of the toolkit. check-domains.sh tells you a name is AVAILABLE;
# this tells you whether it's CLEAN or previously burned. For each domain it
# queries:
#   * VirusTotal (v3)  — analysis stats, reputation score, categories
#   * urlscan.io       — count + recency of prior public scans
#
# and prints a combined CLEAN / CAUTION / DIRTY verdict. An unregistered name
# can still carry a burned history that gets it pre-blocked by mail gateways
# and web filters — this is what catches that.
#
# For authorized engagements only. See README.
#
# Setup:
#   cp .env.example .env      # then paste your API keys into .env
#   chmod +x burn-check.sh
#
# Usage:
#   ./burn-check.sh domains.txt     # one FULL domain per line (name.tld)
#   ./burn-check.sh -               # read domains from stdin
#
# Notes:
#   * VirusTotal free tier = ~4 requests/min. VT_SLEEP defaults to 16s to stay
#     under that. Lower it if you have a paid key.
#   * urlscan works unauthenticated but is rate-limited; a key raises limits.
#   * A VT "404 not found" is a GOOD sign here: the domain has no history.

set -u

# ---- config -------------------------------------------------------------
VT_SLEEP="${VT_SLEEP:-16}"     # seconds between VirusTotal calls (free tier)
US_SLEEP="${US_SLEEP:-3}"      # seconds between urlscan calls
MAX_TIME="${MAX_TIME:-15}"     # per-request curl timeout
# reputation score at/below this from VT flips to CAUTION
VT_REP_FLOOR="${VT_REP_FLOOR:-0}"

# ---- load .env if present ----------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
  # shellcheck disable=SC1091
  set -a; . "$SCRIPT_DIR/.env"; set +a
fi

VT_API_KEY="${VT_API_KEY:-}"
URLSCAN_API_KEY="${URLSCAN_API_KEY:-}"

# ---- JSON helper: prefer jq, fall back to python3 -----------------------
JSON_ENGINE=""
if command -v jq >/dev/null 2>&1; then JSON_ENGINE="jq"
elif command -v python3 >/dev/null 2>&1; then JSON_ENGINE="py"
else
  echo "error: need either 'jq' or 'python3' to parse API responses" >&2
  exit 1
fi

jqf() { # jqf '<jq filter>'  (reads stdin)
  jq -r "$1" 2>/dev/null
}
pyf() { # pyf '<python expression using variable d>'  (reads stdin)
  python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); sys.exit(0)
try:
    print(eval(sys.argv[1]))
except Exception:
    print("")
' "$1"
}

# ---- VirusTotal ---------------------------------------------------------
# echoes: "<http_code>|<malicious>|<suspicious>|<reputation>|<categories>"
vt_check() {
  local domain=$1
  if [ -z "$VT_API_KEY" ]; then
    echo "SKIP|||"; return
  fi
  local body code
  body=$(curl -s --max-time "$MAX_TIME" -w $'\n%{http_code}' \
    -H "x-apikey: $VT_API_KEY" \
    "https://www.virustotal.com/api/v3/domains/$domain")
  code=$(printf '%s' "$body" | tail -n1)
  body=$(printf '%s' "$body" | sed '$d')

  if [ "$code" = "404" ]; then
    echo "404|0|0|0|(no VT history)"; return
  fi
  if [ "$code" != "200" ]; then
    echo "$code|||"; return
  fi

  local mal susp rep cats
  if [ "$JSON_ENGINE" = "jq" ]; then
    mal=$(printf '%s' "$body" | jqf '.data.attributes.last_analysis_stats.malicious // 0')
    susp=$(printf '%s' "$body" | jqf '.data.attributes.last_analysis_stats.suspicious // 0')
    rep=$(printf '%s' "$body" | jqf '.data.attributes.reputation // 0')
    cats=$(printf '%s' "$body" | jqf '[.data.attributes.categories // {} | to_entries[] | .value] | unique | join(", ") | if . == "" then "(uncategorized)" else . end')
  else
    mal=$(printf '%s' "$body" | pyf 'd["data"]["attributes"]["last_analysis_stats"].get("malicious",0)')
    susp=$(printf '%s' "$body" | pyf 'd["data"]["attributes"]["last_analysis_stats"].get("suspicious",0)')
    rep=$(printf '%s' "$body" | pyf 'd["data"]["attributes"].get("reputation",0)')
    cats=$(printf '%s' "$body" | pyf '", ".join(sorted(set((d["data"]["attributes"].get("categories") or {}).values()))) or "(uncategorized)"')
  fi
  echo "${code}|${mal:-0}|${susp:-0}|${rep:-0}|${cats:-(uncategorized)}"
}

# ---- urlscan.io ---------------------------------------------------------
# echoes: "<total>|<last_scan_time_or_dash>"
us_check() {
  local domain=$1
  local hdr=()
  [ -n "$URLSCAN_API_KEY" ] && hdr=(-H "API-Key: $URLSCAN_API_KEY")
  local body
  body=$(curl -s --max-time "$MAX_TIME" "${hdr[@]}" \
    "https://urlscan.io/api/v1/search/?q=domain:$domain&size=1")
  local total last
  if [ "$JSON_ENGINE" = "jq" ]; then
    total=$(printf '%s' "$body" | jqf '.total // 0')
    last=$(printf '%s' "$body" | jqf '.results[0].task.time // "-"')
  else
    total=$(printf '%s' "$body" | pyf 'd.get("total",0)')
    last=$(printf '%s' "$body" | pyf '(d.get("results") or [{}])[0].get("task",{}).get("time","-")')
  fi
  echo "${total:-0}|${last:--}"
}

# ---- verdict logic ------------------------------------------------------
verdict() {
  local vt_mal=$1 vt_susp=$2 vt_rep=$3 us_total=$4
  # DIRTY: any confirmed-malicious signal
  if [ "${vt_mal:-0}" -gt 0 ] 2>/dev/null; then echo "DIRTY"; return; fi
  # CAUTION: softer signals worth a manual look
  if [ "${vt_susp:-0}" -gt 0 ] 2>/dev/null; then echo "CAUTION"; return; fi
  if [ "${vt_rep:-0}" -lt "$VT_REP_FLOOR" ] 2>/dev/null; then echo "CAUTION"; return; fi
  if [ "${us_total:-0}" -gt 5 ] 2>/dev/null; then echo "CAUTION"; return; fi
  echo "CLEAN"
}

# ---- main ---------------------------------------------------------------
main() {
  if [ "$#" -lt 1 ]; then
    echo "usage: $0 <domains-file|->   (one FULL domain per line, name.tld)" >&2
    exit 1
  fi
  command -v curl >/dev/null 2>&1 || { echo "error: curl not found" >&2; exit 1; }

  local src=$1 input
  if [ "$src" = "-" ]; then input=$(cat); else
    [ -f "$src" ] || { echo "error: file not found: $src" >&2; exit 1; }
    input=$(cat "$src")
  fi

  [ -z "$VT_API_KEY" ] && echo "note: VT_API_KEY not set — skipping VirusTotal (urlscan only)." >&2
  echo "parser: $JSON_ENGINE   |   VT_SLEEP=${VT_SLEEP}s  US_SLEEP=${US_SLEEP}s"
  echo "=================================================================="

  while IFS= read -r domain; do
    domain="${domain%%#*}"
    domain="$(echo "$domain" | tr -d '[:space:]')"
    [ -z "$domain" ] && continue

    IFS='|' read -r vt_code vt_mal vt_susp vt_rep vt_cats <<<"$(vt_check "$domain")"
    IFS='|' read -r us_total us_last <<<"$(us_check "$domain")"

    local v
    v=$(verdict "$vt_mal" "$vt_susp" "$vt_rep" "$us_total")

    printf '%-45s %s\n' "$domain" "$v"
    if [ "$vt_code" = "SKIP" ]; then
      printf '    VT: (skipped — no key)\n'
    elif [ "$vt_code" = "404" ]; then
      printf '    VT: no history (404) — good sign\n'
    elif [ "$vt_code" = "200" ]; then
      printf '    VT: malicious=%s suspicious=%s reputation=%s cats=[%s]\n' \
        "${vt_mal:-?}" "${vt_susp:-?}" "${vt_rep:-?}" "${vt_cats:-?}"
    else
      printf '    VT: lookup error (HTTP %s)\n' "$vt_code"
    fi
    printf '    urlscan: %s prior scan(s); last=%s\n' "${us_total:-?}" "${us_last:--}"
    echo "------------------------------------------------------------------"

    # rate-limit pacing (only sleep for the APIs actually called)
    [ -n "$VT_API_KEY" ] && sleep "$VT_SLEEP"
    sleep "$US_SLEEP"
  done <<< "$input"

  echo "Verdicts: CLEAN = no adverse history | CAUTION = manual review |"
  echo "          DIRTY = confirmed malicious history, avoid."
  echo "Reminder: also confirm web-filter category (Talos/Palo Alto/SiteReview)"
  echo "and run a USPTO TESS trademark check before registering."
}

main "$@"
