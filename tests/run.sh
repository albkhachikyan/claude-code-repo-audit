#!/bin/bash
# tests/run.sh - checks scripts/scan.sh against inert fixtures and sibling repos.
# Needs: bash, find, grep, awk, python3 (JSON check). git is optional (git-history test).
# Never runs fixture code. Exit 0 = all pass, 1 = failures.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(cd "$HERE/.." && pwd -P)
SCAN="$ROOT/scripts/scan.sh"
FIX="$HERE/fixtures"
SIBLINGS="$ROOT/../claude-code-task-splitter $ROOT/../nextjs-frontend-foundation"
T=$(mktemp -d "${TMPDIR:-/tmp}/repo-audit-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
FAILS=0; PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "PASS  $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL  $1"; }
check() { # description, status (0 = ok)
  if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1"; fi
}

[ -x "$SCAN" ] || { echo "FAIL  scan.sh not executable: $SCAN"; exit 1; }

# --- usage errors exit 2
"$SCAN" >/dev/null 2>&1; [ $? -eq 2 ]; check "no arguments exits 2" $?
"$SCAN" /nonexistent-dir-for-test >/dev/null 2>&1; [ $? -eq 2 ]; check "missing dir exits 2" $?
"$SCAN" --bogus "$FIX/clean-repo" >/dev/null 2>&1; [ $? -eq 2 ]; check "unknown option exits 2" $?

# --- evil repo: copy, then add parts that cannot be committed (.git dir, symlink)
EV="$T/evil"
cp -R "$FIX/evil-repo" "$EV"
mkdir -p "$EV/.git/hooks"
cat > "$EV/.git/config" <<'CFG'
[core]
	repositoryformatversion = 0
	fsmonitor = echo FIXTURE
	sshCommand = echo FIXTURE
[alias]
	co = !echo FIXTURE
[filter "fixture"]
	smudge = echo FIXTURE
CFG
printf '#!/bin/sh\necho FIXTURE\n' > "$EV/.git/hooks/pre-commit"
printf '#!/bin/sh\necho sample\n' > "$EV/.git/hooks/pre-push.sample"
ln -s /etc/hosts "$EV/hosts-link"
ln -s ../outside "$EV/escape-link"

"$SCAN" --no-tools "$EV" > "$T/evil.out" 2> "$T/evil.err"; RC=$?
[ "$RC" -eq 1 ]; check "evil-repo exits 1 (got $RC)" $?

CATS="autorun lifecycle remote-exec dynamic-exec obfuscation hidden-unicode blockchain exfil secrets-access wallet dep-risk git-config ai-agent-config prompt-injection masquerade persistence known-ioc"
MISSING=""
for c in $CATS; do
  awk -F'\t' -v c="$c" '($1 == "HIGH" || $1 == "CRITICAL") && $2 == c { f = 1 } END { exit !f }' "$T/evil.out" || MISSING="$MISSING $c"
done
[ -z "$MISSING" ]; check "evil-repo has HIGH/CRITICAL for every category${MISSING:+ (missing:$MISSING)}" $?

awk -F'\t' '$1 == "CRITICAL" && $2 == "git-config" { f = 1 } END { exit !f }' "$T/evil.out"; check "CRITICAL git-config from .git/config" $?
grep -q "$(printf 'HIGH\tgit-config\t.git/hooks/pre-commit')" "$T/evil.out"; check "non-sample hook reported, sample ignored" $?
grep -q 'pre-push.sample' "$T/evil.out"; [ $? -ne 0 ]; check "sample hook not reported" $?
grep -q "$(printf 'HIGH\tmasquerade\thosts-link')" "$T/evil.out"; check "absolute symlink reported HIGH" $?
grep -q "$(printf 'HIGH\tmasquerade\tescape-link')" "$T/evil.out"; check "escaping symlink reported HIGH" $?
awk -F'\t' 'NF != 4 && $0 != "---" && $0 !~ /^[A-Za-z ()-]+: / { bad = 1 } END { exit bad }' "$T/evil.out"; check "finding lines have 4 tab-separated fields" $?
grep -q '^---$' "$T/evil.out"; check "summary separator present" $?

# --- git history: future dates (only if git exists)
if command -v git >/dev/null 2>&1; then
  mkdir -p "$T/hist" && cd "$T/hist" || exit 1
  git init -q . 2>/dev/null
  echo x > f.txt
  git add f.txt
  GIT_AUTHOR_DATE="2099-01-01T00:00:00" GIT_COMMITTER_DATE="2099-01-01T00:00:00" \
    git -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture 2>/dev/null
  cd "$ROOT" || exit 1
  "$SCAN" --no-tools --git "$T/hist/.git" "$FIX/clean-repo" > "$T/hist.out" 2>/dev/null
  awk -F'\t' '$1 == "HIGH" && $2 == "git-history" { f = 1 } END { exit !f }' "$T/hist.out"; check "HIGH git-history for future commit date" $?
else
  echo "SKIP  git not installed, git-history test skipped"
fi

# --- clean repo
"$SCAN" --no-tools "$FIX/clean-repo" > "$T/clean.out" 2>&1; RC=$?
[ "$RC" -eq 0 ]; check "clean-repo exits 0 (got $RC)" $?
awk -F'\t' '$1 == "HIGH" || $1 == "CRITICAL"' "$T/clean.out" | grep -q .; [ $? -ne 0 ]; check "clean-repo has no HIGH/CRITICAL" $?

# --- sibling repos: report HIGH/CRITICAL, target zero
for s in $SIBLINGS; do
  [ -d "$s" ] || { echo "SKIP  $s not found"; continue; }
  "$SCAN" --no-tools "$s" > "$T/sib.out" 2>&1
  n=$(awk -F'\t' '$1 == "HIGH" || $1 == "CRITICAL"' "$T/sib.out" | wc -l | tr -d ' ')
  if [ "$n" -eq 0 ]; then pass "sibling $(basename "$s"): no HIGH/CRITICAL"
  else
    fail "sibling $(basename "$s"): $n HIGH/CRITICAL (false positives?)"
    awk -F'\t' '$1 == "HIGH" || $1 == "CRITICAL"' "$T/sib.out" | cut -c1-200 | sed 's/^/        /'
  fi
done

# --- JSON output is valid
"$SCAN" --json --no-tools "$EV" > "$T/evil.json" 2>/dev/null
python3 -I -m json.tool "$T/evil.json" > /dev/null 2>&1; check "--json output is valid JSON (evil-repo)" $?
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d and set(d[0])=={"severity","category","location","evidence"} else 1)' "$T/evil.json" 2>/dev/null
check "--json objects have severity/category/location/evidence" $?
"$SCAN" --json --no-tools "$FIX/clean-repo" > "$T/clean.json" 2>/dev/null
python3 -I -m json.tool "$T/clean.json" > /dev/null 2>&1; check "--json output is valid JSON (empty result)" $?

# --- scan.sh must not modify the target
BEFORE=$(find "$FIX/evil-repo" -type f -exec cksum {} + | sort | cksum)
"$SCAN" --no-tools "$FIX/evil-repo" > /dev/null 2>&1
AFTER=$(find "$FIX/evil-repo" -type f -exec cksum {} + | sort | cksum)
[ "$BEFORE" = "$AFTER" ]; check "scan leaves the target unchanged" $?

echo "----"
echo "passed: $PASSES  failed: $FAILS"
if [ "$FAILS" -eq 0 ]; then echo "PASS"; exit 0; fi
echo "FAIL"; exit 1
