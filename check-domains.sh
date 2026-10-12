#!/usr/bin/env bash
#
# check-domains.sh — bulk domain availability checker via RDAP
#
# Checks whether domains are registered, using registry RDAP endpoints
# over HTTPS (no port-43 WHOIS, no scraping). A 404 means the name is
# unregistered/available; 200 means it's taken.
#
#
# Usage:
#   ./check-domains.sh names.txt                # checks .com and .net
#   ./check-domains.sh names.txt com net org    # custom TLD list
#   ./check-domains.sh -                        # read names from stdin
#
# names.txt = one base name per line, WITHOUT the TLD. Blank lines and
# lines starting with # are ignored.

set -u

MAX_TIME=10          # per-request curl timeout (seconds)
SLEEP=1              # pause between requests to avoid rate-limiting

# Verisign serves .com/.net directly; everything else goes through the
# rdap.org redirector (curl -L follows it to the right registry).
rdap_url() {
  local name=$1 tld=$2
  case "$tld" in
    com|net) echo "https://rdap.verisign.com/$tld/v1/domain/$name.$tld" ;;
    *)       echo "https://rdap.org/domain/$name.$tld" ;;
  esac
}

check_one() {
  local name=$1 tld=$2
  local url; url=$(rdap_url "$name" "$tld")
  local code
  code=$(curl -sL --max-time "$MAX_TIME" -o /dev/null -w "%{http_code}" "$url")
  printf '  %-45s ' "$name.$tld"
  case "$code" in
    404) echo "AVAILABLE" ;;
    200) echo "registered" ;;
    429) echo "? rate-limited (429) — rerun with a longer SLEEP" ;;
    000) echo "? no response (timeout/DNS) — check connectivity" ;;
    *)   echo "? HTTP $code" ;;
  esac
  sleep "$SLEEP"
}

main() {
  if [ "$#" -lt 1 ]; then
    echo "usage: $0 <names-file|-> [tld ...]" >&2
    echo "       names file: one base name per line, no TLD" >&2
    exit 1
  fi

  local src=$1; shift
  local tlds=("$@")
  [ "${#tlds[@]}" -eq 0 ] && tlds=(com net)

  # sanity check: curl present?
  command -v curl >/dev/null 2>&1 || { echo "error: curl not found" >&2; exit 1; }

  local input
  if [ "$src" = "-" ]; then
    input=$(cat)
  else
    [ -f "$src" ] || { echo "error: file not found: $src" >&2; exit 1; }
    input=$(cat "$src")
  fi

  echo "Checking TLDs: ${tlds[*]}"
  echo "-----------------------------------------------"
  while IFS= read -r name; do
    # strip whitespace/comments/blank lines
    name="${name%%#*}"
    name="$(echo "$name" | tr -d '[:space:]')"
    [ -z "$name" ] && continue
    echo "$name:"
    for tld in "${tlds[@]}"; do
      check_one "$name" "$tld"
    done
  done <<< "$input"
  echo "-----------------------------------------------"
  echo "Done. AVAILABLE = unregistered (404). Still run reputation +"
  echo "categorization checks before registering (see README)."
}

main "$@"
