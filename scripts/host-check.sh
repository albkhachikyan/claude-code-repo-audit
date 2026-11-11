#!/bin/bash
# host-check.sh - read-only check of THIS machine for persistence left by a malicious repo.
# Usage: host-check.sh [--ioc <string>]... [--home-only] [-h|--help]
# Output: SEVERITY<TAB>CATEGORY<TAB>path:line<TAB>evidence (<=160 chars), then "---" and counts.
# Exit: 0 = no HIGH/CRITICAL, 1 = HIGH/CRITICAL found, 2 = usage error.
# Never modifies, kills or unloads anything. For HIGH/CRITICAL the evidence ends with a
# suggested command. Ask the user before running it.
# --home-only: skip system-level checks (ps, lsof, sfltool, crontab, /Library, /etc).
# Honors $HOME so tests can point it at a fake tree. Works on bash 3.2 and BSD userland.

usage() {
  echo "usage: host-check.sh [--ioc <string>]... [--home-only]" >&2
  exit 2
}

USER_IOCS=()
HOME_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ioc) [ $# -ge 2 ] && [ -n "$2" ] || usage; USER_IOCS+=("$2"); shift 2 ;;
    --home-only) HOME_ONLY=1; shift ;;
    *) usage ;;
  esac
done

HC_HOME=${HOME:-}
HC_HOME=${HC_HOME%/}
if [ -z "$HC_HOME" ] || [ ! -d "$HC_HOME" ]; then
  echo "host-check: HOME is not set or not a directory" >&2
  exit 2
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/host-check.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
TILDE='~'

# Names from real cases (same list as scan.sh known-ioc).
IOC_NAMES="express-json-database inline-array cafrino-feed com.AppleAccountSync AppleAccountSync .vs_cache _force_bootstrap _force_client x-secret-header scoped_dir com.avatar.update shai-hulud setup_bun.js bun_environment.js truffleSecrets .legacy_keyboard_logs_cleaned"
for p in $IOC_NAMES; do printf '%s\n' "$p"; done > "$T/known.txt"
: > "$T/user.txt"
if [ ${#USER_IOCS[@]} -gt 0 ]; then
  for p in "${USER_IOCS[@]}"; do printf '%s\n' "$p"; done > "$T/user.txt"
fi

# Well-known tool dirs in $HOME (not flagged as suspicious hidden dirs).
KNOWN=" .npm .nvm .vscode .vscode-server .vscode-insiders .cursor .cache .local .config .cargo .rustup .pyenv .bun .deno .docker .claude .git .github .idea .vs .ssh .gnupg .aws .azure .kube .gradle .m2 .sdkman .gem .rbenv .rvm .asdf .volta .fnm .pnpm .pnpm-store .yarn .node-gyp .npm-global .oh-my-zsh .zsh_sessions .Trash .android .dotnet .nuget .cocoapods .swiftpm .terraform.d .vagrant.d .conda .virtualenvs .venv .poetry .pipx .ipython .jupyter .matplotlib .keras .huggingface .ollama .lmstudio .codeium .copilot .continue .gemini .codex .windsurf .antigravity .kiro .trae .opencode .expo .eas .nx .angular .next .nuxt .svelte-kit .turbo .parcel-cache .tox .mypy_cache .pytest_cache .bundle .minikube .helm .wrangler .vercel .netlify .supabase .firebase .stripe .fly .railway .heroku .gcloud .ngrok .tldr .Spotlight-V100 .fseventsd .DocumentRevisions-V100 "
is_known() { case "$KNOWN" in *" $1 "*) return 0 ;; esac; return 1; }

C_CRIT=0; C_HIGH=0; C_MED=0; C_INFO=0
emit() { # sev cat path line detail [suggestion]
  local sev=$1 cat=$2 p=$3 ln=$4 d=$5 sg=${6:-} ev max
  d=$(printf '%s' "$d" | tr '\t\r\n' '   ')
  case "$sev" in CRITICAL|HIGH) ;; *) sg= ;; esac
  if [ -n "$sg" ]; then
    sg=" => suggest (ask user first): ${sg:0:100}"
    max=$((160 - ${#sg})); [ "$max" -lt 30 ] && max=30
    ev="${d:0:$max}$sg"
  else
    ev=$d
  fi
  printf '%s\t%s\t%s:%s\t%s\n' "$sev" "$cat" "$p" "$ln" "${ev:0:160}"
  case "$sev" in
    CRITICAL) C_CRIT=$((C_CRIT + 1)) ;;
    HIGH) C_HIGH=$((C_HIGH + 1)) ;;
    MEDIUM) C_MED=$((C_MED + 1)) ;;
    *) C_INFO=$((C_INFO + 1)) ;;
  esac
}

qpath() { case "$1" in "$HC_HOME"/*) printf '"$HOME%s"' "${1#"$HC_HOME"}" ;; *) printf '"%s"' "$1" ;; esac; }
short() { case "$1" in "$HC_HOME"/*) printf '~%s' "${1#"$HC_HOME"}" ;; *) printf '%s' "$1" ;; esac; }
norm() { # replace the home path and $HOME / %h forms with ~
  local c=$1
  c=${c//"$HC_HOME"/$TILDE}; c=${c//'${HOME}'/$TILDE}; c=${c//'$HOME'/$TILDE}; c=${c//'%h'/$TILDE}
  printf '%s' "$c"
}
unknown_hidden() { # normalised text; prints first hidden dir under ~ that is not a known tool dir
  local n
  for n in $(printf '%s\n' "$1" | grep -oE '~/\.[A-Za-z0-9_-]+' | sed 's#^~/##'); do
    if ! is_known "$n"; then printf '%s' "$n"; return 0; fi
  done
  return 1
}

RE_TMP='(^|[[:space:]=:"])/(private/)?(var/)?tmp/|/dev/shm/'
RE_PIPE='(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh'
RE_B64='base64[[:space:]]+(-d|-D|--decode)'
RE_INTERP='(^|[[:space:]/])(node|nodejs|python[0-9.]*|bun|deno)[[:space:]]+[^|;&]*\.(js|mjs|cjs|py)'
RE_RC_HINT='(curl|wget|base64|eval|node|python)'
cmd_reason() { # command text; prints a reason and returns 0 if risky
  local c h
  c=$(norm "$1")
  if [[ $c =~ $RE_TMP ]]; then printf 'runs from tmp'; return 0; fi
  if [[ $c =~ $RE_PIPE ]]; then printf 'pipes download to shell'; return 0; fi
  if [[ $c =~ $RE_B64 ]]; then printf 'base64 decode in command'; return 0; fi
  if [[ $c =~ $RE_INTERP ]] && h=$(unknown_hidden "$c"); then
    printf 'interpreter runs file in hidden dir ~/%s' "$h"; return 0
  fi
  return 1
}

ioc_content() { # file displaypath : grep known + user IOC strings inside a file
  local f=$1 disp=$2 m
  [ -r "$f" ] || return 0
  m=$(grep -n -i -F -f "$T/known.txt" "$f" 2>/dev/null | head -1)
  [ -n "$m" ] && emit CRITICAL known-ioc "$disp" "${m%%:*}" "known IOC string: ${m#*:}" "stop and quarantine the item that holds this line"
  if [ -s "$T/user.txt" ]; then
    m=$(grep -n -i -F -f "$T/user.txt" "$f" 2>/dev/null | head -1)
    [ -n "$m" ] && emit CRITICAL known-ioc "$disp" "${m%%:*}" "--ioc string: ${m#*:}" "stop and quarantine the item that holds this line"
  fi
  return 0
}

plist_vals() { # xml key : print string value(s) of a key (scalar or array), or "true"/"false"
  printf '%s\n' "$1" | awk -v k="$2" '
    function item(s) {
      if (s ~ ("<key>" k "</key>")) { st = 1; return }
      if (st == 1) {
        if (s ~ /<array>/) { st = 2; return }
        if (s ~ /<string>/) { sub(/^.*<string>/, "", s); sub(/<\/string>.*$/, "", s); print s; st = 0; return }
        if (s ~ /<true\/>/) { print "true"; st = 0; return }
        if (s ~ /<false\/>/) { print "false"; st = 0; return }
        if (s ~ /<key>/) { st = 0; return }
      } else if (st == 2) {
        if (s ~ /<\/array>/) { st = 0; return }
        if (s ~ /<string>/) { sub(/^.*<string>/, "", s); sub(/<\/string>.*$/, "", s); print s }
      }
    }
    { gsub(/></, ">\n<"); n = split($0, L, "\n"); for (i = 1; i <= n; i++) item(L[i]) }'
}

is_script_node() { # file : 0 if a small script file that starts node or python
  local f=$1 first sz
  [ -f "$f" ] && [ -r "$f" ] || return 1
  first=$(head -n 1 "$f" 2>/dev/null)
  case "$first" in '#!'*) ;; *) return 1 ;; esac
  sz=$(( $(wc -c < "$f") ))
  [ "$sz" -le 65536 ] || return 1
  grep -Eq '(^|[^[:alnum:]_.-])(node|nodejs|python[0-9.]*)([^[:alnum:]_]|$)' "$f" 2>/dev/null
}

scan_plist() { # file scope(user|system|daemon)
  local f=$1 scope=$2 xml label prog args progs s n lower sev=INFO why="" ln sg out h
  xml=$(plutil -convert xml1 -o - "$f" 2>/dev/null) || xml=$(cat "$f" 2>/dev/null)
  if [ -z "$xml" ]; then emit INFO persistence "$(short "$f")" 1 "unreadable plist"; return 0; fi
  label=$(plist_vals "$xml" Label | head -1)
  prog=$(plist_vals "$xml" Program | head -1)
  args=$(plist_vals "$xml" ProgramArguments)
  progs=$(printf '%s\n%s\n' "$prog" "$args")
  ln=$(grep -n '<key>Label</key>' "$f" 2>/dev/null | head -1 | cut -d: -f1); ln=${ln:-1}
  lower=$(printf '%s' "$label" | tr 'A-Z' 'a-z')
  case "$lower" in
    com.apple*)
      case "$label" in
        com.apple.*)
          if [ "$scope" = user ]; then sev=MEDIUM; why="$why; com.apple.* label in user folder"; fi ;;
        *) sev=HIGH; why="$why; label imitates Apple" ;;
      esac ;;
  esac
  while IFS= read -r s; do
    case "$s" in /*) ;; *) continue ;; esac
    n=$(norm "$s")
    if [[ $n =~ $RE_TMP ]]; then sev=HIGH; why="$why; program in tmp"
    elif h=$(unknown_hidden "$n"); then sev=HIGH; why="$why; program in hidden dir ~/$h"
    elif is_script_node "$s"; then sev=HIGH; why="$why; script launches node/python"
    elif [[ $n == "$TILDE"/* ]]; then
      if [ -f "$s" ] && [ "$(head -c 2 "$s" 2>/dev/null)" = '#!' ]; then sev=HIGH; why="$why; shell script in HOME"
      elif [ "$sev" = INFO ]; then sev=MEDIUM; why="$why; program in HOME"; fi
    fi
  done <<EOF_PROGS
$progs
EOF_PROGS
  if out=$(cmd_reason "$(printf '%s' "$args" | tr '\n' ' ')"); then sev=HIGH; why="$why; $out"; fi
  if [ "$(plist_vals "$xml" RunAtLoad | head -1)" = true ] && [ "$(plist_vals "$xml" StandardOutPath | head -1)" = /dev/null ]; then
    sev=HIGH; why="$why; RunAtLoad with output to /dev/null"
  fi
  if [ "$scope" = daemon ]; then sg="sudo launchctl bootout system/$label"; else sg="launchctl bootout gui/\$(id -u)/$label"; fi
  [ -n "$label" ] || label="(none)"
  why=${why#; }
  emit "$sev" persistence "$(short "$f")" "$ln" "${why:+$why | }label=$label prog=$(norm "$(printf '%s' "$progs" | tr '\n' ' ')")" "$sg"
  ioc_content "$f" "$(short "$f")"
}

scan_launchd() {
  local dir scope f
  for dir in "$HC_HOME/Library/LaunchAgents:user" "/Library/LaunchAgents:system" "/Library/LaunchDaemons:daemon"; do
    scope=${dir##*:}; dir=${dir%:*}
    if [ "$HOME_ONLY" = 1 ] && [ "$scope" != user ]; then continue; fi
    [ -d "$dir" ] || continue
    for f in "$dir"/*.plist; do [ -e "$f" ] && scan_plist "$f" "$scope"; done
  done
  return 0
}

scan_btm() {
  local out rec exe
  [ "$HOME_ONLY" = 1 ] && return 0
  if [ "$(uname -s)" != Darwin ] || ! command -v sfltool >/dev/null 2>&1; then return 0; fi
  out=$(sfltool dumpbtm 2>/dev/null) || return 0
  [ -n "$out" ] || return 0
  # Best effort: the record layout of "sfltool dumpbtm" is not documented.
  rec=$(printf '%s\n' "$out" | awk '
    function flush() { if (leg && unk && exe != "") print exe; leg = 0; unk = 0; exe = "" }
    /^[[:space:]]*#[0-9]+:/ { flush() }
    /[Tt]ype:.*legacy/ { leg = 1 }
    /Unknown Developer/ { unk = 1 }
    /Executable Path:/ { sub(/^.*Executable Path:[[:space:]]*/, ""); exe = $0 }
    END { flush() }')
  while IFS= read -r exe; do
    [ -n "$exe" ] || continue
    if [ ! -e "$exe" ]; then
      emit INFO persistence "btm" 0 "stale legacy login item, executable gone: $(short "$exe")"
    else
      case "$exe" in
        "$HC_HOME"/*) emit HIGH persistence "btm" 0 "legacy login item, Unknown Developer, executable in HOME: $(short "$exe")" "find its plist in LaunchAgents, then launchctl bootout" ;;
      esac
    fi
  done <<EOF_BTM
$rec
EOF_BTM
  return 0
}

scan_exec_file() { # file key(ExecStart|Exec)
  local f=$1 key=$2 n=0 line r="" hit=0 unit
  unit=$(basename "$f")
  while IFS= read -r line; do
    n=$((n + 1))
    case "$line" in "$key"*=*) ;; *) continue ;; esac
    if r=$(cmd_reason "${line#*=}"); then
      hit=1
      case "$key" in
        ExecStart) emit HIGH persistence "$(short "$f")" "$n" "$line ($r)" "systemctl --user disable --now $unit" ;;
        *) emit HIGH persistence "$(short "$f")" "$n" "$line ($r)" "remove $(short "$f") after review" ;;
      esac
    fi
  done < "$f"
  [ "$hit" = 0 ] && emit INFO persistence "$(short "$f")" 1 "autostart item: $unit"
  ioc_content "$f" "$(short "$f")"
}

scan_systemd() {
  local f
  for f in "$HC_HOME"/.config/systemd/user/*.service; do [ -e "$f" ] && scan_exec_file "$f" ExecStart; done
  for f in "$HC_HOME"/.config/autostart/*.desktop; do [ -e "$f" ] && scan_exec_file "$f" Exec; done
  return 0
}

scan_cron_lines() { # file displaypath
  local f=$1 disp=$2 n=0 line r
  while IFS= read -r line; do
    n=$((n + 1))
    case "$line" in ''|'#'*) continue ;; esac
    if r=$(cmd_reason "$line"); then
      emit HIGH persistence "$disp" "$n" "$line ($r)" "crontab -e (remove the line)"
    else
      case "$line" in '@reboot'*) emit MEDIUM persistence "$disp" "$n" "$line" ;; esac
    fi
  done < "$f"
  ioc_content "$f" "$disp"
}

scan_cron() {
  local f
  [ "$HOME_ONLY" = 1 ] && return 0
  if command -v crontab >/dev/null 2>&1 && crontab -l > "$T/crontab.txt" 2>/dev/null; then
    scan_cron_lines "$T/crontab.txt" "crontab"
  fi
  for f in /etc/cron.d/*; do
    if [ -f "$f" ] && [ -r "$f" ]; then scan_cron_lines "$f" "$f"; fi
  done
  if [ -s /etc/ld.so.preload ]; then
    emit HIGH persistence "/etc/ld.so.preload" 1 "non-empty ld.so.preload: $(head -c 100 /etc/ld.so.preload)" "inspect it; entries are normally absent"
  fi
  return 0
}

scan_rc() {
  local rc line n h
  for rc in .zshrc .bashrc .profile .zprofile .bash_profile .zshenv .zlogin; do
    [ -f "$HC_HOME/$rc" ] || continue
    n=0
    while IFS= read -r line || [ -n "$line" ]; do
      n=$((n + 1))
      case "$line" in ''|[[:space:]]'#'*|'#'*) continue ;; esac
      line=$(norm "$line")
      if [[ $line =~ $RE_PIPE ]] || [[ $line =~ $RE_B64 ]]; then
        emit HIGH persistence "~/$rc" "$n" "$line" "remove line $n from ~/$rc after review"
      elif [[ $line =~ $RE_RC_HINT ]] && h=$(unknown_hidden "$line"); then
        emit HIGH persistence "~/$rc" "$n" "$line (hidden dir ~/$h)" "remove line $n from ~/$rc after review"
      fi
    done < "$HC_HOME/$rc"
    ioc_content "$HC_HOME/$rc" "~/$rc"
  done
  return 0
}

scan_hidden() {
  local list d rel top base why
  list=$(find "$HC_HOME" -maxdepth 2 -type d -name '.?*' 2>/dev/null)
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    rel=${d#"$HC_HOME"/}; top=${rel%%/*}; base=${d##*/}
    is_known "$top" && continue
    is_known "$base" && continue
    why=""
    [ -f "$d/main.js" ] && why="$why main.js"
    [ -d "$d/node_modules" ] && why="$why node_modules"
    ls "$d"/*.py >/dev/null 2>&1 && why="$why *.py"
    if [ -n "$why" ]; then
      emit HIGH persistence "$(short "$d")" 0 "hidden dir in HOME with loader files:$why" "zip -r -P infected ~/MALWARE_Q.zip $(qpath "$d") (stop its process first)"
    fi
  done <<EOF_HIDDEN
$list
EOF_HIDDEN
  return 0
}

ioc_find() { # root maxdepth
  local root=$1 depth=$2 args=() p list f
  [ -d "$root" ] || return 0
  for p in $IOC_NAMES; do
    [ ${#args[@]} -gt 0 ] && args+=(-o)
    args+=(-iname "*$p*")
  done
  if [ ${#USER_IOCS[@]} -gt 0 ]; then
    for p in "${USER_IOCS[@]}"; do args+=(-o -iname "*$p*"); done
  fi
  list=$(find "$root" -maxdepth "$depth" \( "${args[@]}" \) 2>/dev/null)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    emit CRITICAL known-ioc "$(short "$f")" 0 "known IOC name: ${f##*/}" "zip -r -P infected ~/MALWARE_Q.zip $(qpath "$f") (stop its process first)"
  done <<EOF_FIND
$list
EOF_FIND
  return 0
}

scan_procs() {
  local pid cmd tok n r h conns
  [ "$HOME_ONLY" = 1 ] && return 0
  ps -axo pid,command 2>/dev/null | grep -v 'host-check' > "$T/ps.txt"
  [ -s "$T/ps.txt" ] || return 0
  ioc_content "$T/ps.txt" "ps"
  while read -r pid cmd; do
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    tok=${cmd%% *}
    case "${tok##*/}" in node|nodejs|python*|Python*|bun|deno) ;; *) continue ;; esac
    n=$(norm "$cmd"); r=""
    if [[ $n =~ $RE_TMP ]]; then
      r="runs from tmp"
    elif h=$(unknown_hidden "$n"); then
      r="runs from hidden dir ~/$h"
    fi
    [ -n "$r" ] || continue
    emit HIGH persistence "process" "$pid" "$r: ${cmd:0:100}" "kill $pid"
    if command -v lsof >/dev/null 2>&1; then
      conns=$(lsof -nP -a -p "$pid" -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR > 1 { print $9 }' | head -3 | tr '\n' ' ')
      [ -n "$conns" ] && emit HIGH exfil "process" "$pid" "established TCP: $conns" "disconnect the network, then kill $pid"
    fi
  done < "$T/ps.txt"
  return 0
}

scan_launchd
scan_btm
scan_systemd
scan_cron
scan_rc
scan_hidden
ioc_find "$HC_HOME" 2
ioc_find "$HC_HOME/Library/LaunchAgents" 1
ioc_find "$HC_HOME/Library/Application Support" 1
ioc_find "$HC_HOME/.zsh_sessions" 1
if [ "$HOME_ONLY" != 1 ]; then
  ioc_find /Library/LaunchAgents 1
  ioc_find /Library/LaunchDaemons 1
fi
scan_procs

echo "---"
echo "CRITICAL: $C_CRIT"
echo "HIGH: $C_HIGH"
echo "MEDIUM: $C_MED"
echo "INFO: $C_INFO"
if [ $((C_CRIT + C_HIGH)) -gt 0 ]; then exit 1; fi
exit 0
