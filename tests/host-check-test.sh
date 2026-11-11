#!/bin/bash
# Tests scripts/host-check.sh against tests/host-fixture (a fake HOME). Read-only on the repo:
# the fixture is copied to a temp dir first.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HC="$ROOT/scripts/host-check.sh"
FIX="$ROOT/tests/host-fixture/home"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/host-check-test.XXXXXX") || exit 2
trap 'rm -rf "$TMP"' EXIT
FAILS=0
ok()   { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() { # desc, command...
  local d=$1; shift
  if "$@"; then ok "$d"; else fail "$d"; fi
}

H="$TMP/home"
mkdir -p "$H"
cp -R "$FIX/." "$H/"
PL="$H/Library/LaunchAgents/com.AppleFixtureSync.plist"
sed "s#__HOME__#$H#g" "$PL" > "$PL.new" && mv "$PL.new" "$PL"
chmod 644 "$H/Library/Application Support/FixtureSync/run.sh" "$H/.fixture_cache/main.js"
before=$(cd "$H" && find . -type f -exec cksum {} + | sort)

OUT="$TMP/out.txt"
HOME="$H" "$HC" --home-only --ioc fixture_cache > "$OUT" 2> "$TMP/err.txt"
rc=$?
check "exit code is 1 (HIGH/CRITICAL found)" test "$rc" -eq 1
has() { # severity category path-regex
  awk -F'\t' -v s="$1" -v c="$2" -v p="$3" '$1 == s && $2 == c && $3 ~ p { f = 1 } END { exit f ? 0 : 1 }' "$OUT"
}
check "HIGH persistence: Apple-imitating LaunchAgent"  has HIGH persistence 'LaunchAgents/com\.AppleFixtureSync\.plist'
check "HIGH persistence: hidden dir with main.js"      has HIGH persistence '\.fixture_cache'
check "HIGH persistence: .zshrc line"                  has HIGH persistence '\.zshrc'
check "CRITICAL known-ioc from --ioc string"           has CRITICAL known-ioc 'fixture_cache|\.zshrc'
check "summary follows ---"                            grep -q '^---$' "$OUT"
check "evidence is at most 160 chars"                  awk -F'\t' 'NF >= 4 && length($4) > 160 { bad = 1 } END { exit bad ? 1 : 0 }' "$OUT"
check "plist evidence names the Apple imitation"       grep -q 'label imitates Apple' "$OUT"
check "remediation suggestion present, not executed"   grep -q 'suggest (ask user first): launchctl bootout' "$OUT"
after=$(cd "$H" && find . -type f -exec cksum {} + | sort)
check "fixture tree unchanged (read-only)"             test "$before" = "$after"
check "run.sh still not executable"                    test ! -x "$H/Library/Application Support/FixtureSync/run.sh"

HOME="$H" "$HC" --home-only > "$TMP/out2.txt" 2>/dev/null
check "without --ioc: no known-ioc findings"           test -z "$(awk -F'\t' '$2 == "known-ioc"' "$TMP/out2.txt")"

mkdir -p "$TMP/empty"
HOME="$TMP/empty" "$HC" --home-only > "$TMP/out3.txt" 2>/dev/null
check "empty HOME: exit 0"                             test "$?" -eq 0

"$HC" --bogus > /dev/null 2>&1
check "unknown option: exit 2"                         test "$?" -eq 2
"$HC" --ioc > /dev/null 2>&1
check "--ioc without value: exit 2"                    test "$?" -eq 2

echo
echo "== informational: real HOME (not asserted) =="
"$HC" > "$TMP/real.txt" 2> /dev/null
echo "exit code: $?"
awk -F'\t' '$1 == "CRITICAL" || $1 == "HIGH"' "$TMP/real.txt"
sed -n '/^---$/,$p' "$TMP/real.txt"

echo
if [ "$FAILS" -eq 0 ]; then echo "PASS"; exit 0; fi
echo "FAIL ($FAILS)"; exit 1
