#!/bin/sh
# ghdl.sh OUT URL: download URL to OUT; a GitHub release asset gets two routes.
#   web: github.com/O/R/releases/download/TAG/FILE (one request, the CDN; fastest normally)
#   api: api.github.com asset endpoint (separate front end; it kept working while the web
#        route returned 504s in the Nov 2026 incident)
# Both are tried in turn, each failing fast, and the route that worked last goes first next
# time (hint file per job / machine). Callers still verify the file's SHA-256.
# GH_TOKEN / GITHUB_TOKEN, when set, lifts the API's anonymous 60 requests/hour/IP limit.
set -eu
out=$1 url=$2
hint="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/.ghdl-route"
token=${GH_TOKEN:-${GITHUB_TOKEN:-}}

get() { curl -fsSL --connect-timeout 10 --max-time 600 --retry 2 --retry-delay 3 --retry-all-errors "$@"; }
api() {
  if [ -n "$token" ]; then get -H "Authorization: Bearer $token" "$@"; else get "$@"; fi
}

web() { get -o "$out" "$url"; }
api_dl() {
  p=${url#https://github.com/}
  repo=$(echo "$p" | cut -d/ -f1-2)
  file=${p##*/}
  case $p in
    */releases/latest/download/*) rel=latest ;;
    *) t=${p#*/releases/download/}; rel="tags/${t%/*}" ;;
  esac
  # Pretty or compact JSON: one key per line; an asset's "url" precedes its "name".
  a=$(api -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$repo/releases/$rel" |
    tr ',{' '\n' | awk -F'"' -v f="$file" '$2 == "url" { u = $4 } $2 == "name" && $4 == f { print u; exit }')
  [ -n "$a" ] && api -H 'Accept: application/octet-stream' -o "$out" "$a"
}

case $url in
  https://github.com/*/releases/download/*/* | https://github.com/*/releases/latest/download/*) ;;
  *) # not a GitHub release: plain download with retries
    get --retry 10 --retry-delay 10 -o "$out" "$url"; exit ;;
esac

route() { case $1 in web) web ;; api) api_dl ;; esac; }
first=web second=api
[ "$(cat "$hint" 2>/dev/null)" = api ] && first=api second=web
for wait in 0 10 20 30 60; do
  sleep "$wait"
  for r in "$first" "$second"; do
    if route "$r"; then echo "$r" > "$hint" 2>/dev/null || true; exit 0; fi
    echo "ghdl: $r route failed for $url" >&2
  done
done
echo "ghdl: giving up on $url" >&2
exit 1
