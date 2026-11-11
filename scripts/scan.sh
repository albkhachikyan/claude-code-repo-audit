#!/bin/bash
# scan.sh - static, read-only scan of an untrusted directory. Never executes target code.
# Usage: scan.sh [--json] [--no-tools] [--all] [--git <git-dir>] <dir>
# Output: SEVERITY<TAB>CATEGORY<TAB>path:line<TAB>evidence, then "---" and a summary.
# Exit: 0 no HIGH/CRITICAL, 1 HIGH/CRITICAL present, 2 usage error.
# Portable: macOS bash 3.2 + BSD userland, and Linux GNU userland. No grep -P, no mapfile.
set -u
export LC_ALL=C
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0

usage() { echo "usage: scan.sh [--json] [--no-tools] [--all] [--git <git-dir>] <dir>" >&2; exit 2; }
JSON=0; TOOLS=1; ALL=0; GITDIR=""; TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --no-tools) TOOLS=0 ;;
    --all) ALL=1 ;;
    --git) [ $# -ge 2 ] || usage; GITDIR=$2; shift ;;
    -h|--help) usage ;;
    -*) echo "scan.sh: unknown option: $1" >&2; usage ;;
    *) [ -z "$TARGET" ] || usage; TARGET=$1 ;;
  esac
  shift
done
[ -n "$TARGET" ] && [ -d "$TARGET" ] || usage
if [ -n "$GITDIR" ]; then
  GITDIR=$(cd "$GITDIR" 2>/dev/null && pwd -P) || { echo "scan.sh: bad --git dir" >&2; exit 2; }
fi
DIR=$(cd "$TARGET" && pwd -P) || usage
T=$(mktemp -d "${TMPDIR:-/tmp}/repo-audit-scan.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
trap 'exit 130' INT TERM
OUT="$T/raw"; : > "$OUT"
cd "$DIR" || exit 2

Q="[\"'\`]"                       # one quote character
SP='[[:space:]]'
BIGKB=5000                         # files larger than this (KiB) are not content-scanned

# ---------- helpers ----------
clean() { printf '%s' "$1" | tr -c '\040-\176' '?' | awk '{ if (length($0) > 160) $0 = substr($0, 1, 157) "..."; print; exit }'; }
emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$(clean "$3")" "$(clean "$4")" >> "$OUT"; }
fmt_hits() { # stdin: path:line:text -> findings
  awk -v sev="$1" -v cat="$2" '{
    if (!match($0, /:[0-9]+:/)) next
    loc = substr($0, 1, RSTART + RLENGTH - 2); ev = substr($0, RSTART + RLENGTH)
    sub(/^\.\//, "", loc); gsub(/[^ -~]/, " ", ev); sub(/^ +/, "", ev)
    if (length(ev) > 160) ev = substr(ev, 1, 157) "..."
    printf "%s\t%s\t%s\t%s\n", sev, cat, loc, ev }' | tr -c '\011\012\040-\176' '?'
}
EXCL=""
hits() { # list sev cat ERE [grep options]; honours $EXCL (drop matching hit lines)
  [ -s "$1" ] || return 0
  local l=$1 s=$2 c=$3 r=$4; shift 4
  xargs -0 grep -H -n -I -E "$@" -e "$r" < "$l" 2>/dev/null |
    { if [ -n "$EXCL" ]; then grep -v -E -e "$EXCL"; else cat; fi; } | fmt_hits "$s" "$c" >> "$OUT"
  EXCL=""
}
mk() { # name include-ERE [exclude-ERE]  (filters $T/text0, case-insensitive)
  if [ -n "${3:-}" ]; then
    grep -z -i -E -e "$2" "$T/text0" | grep -z -v -i -E -e "$3" > "$T/$1"
  else
    grep -z -i -E -e "$2" "$T/text0" > "$T/$1"
  fi
  return 0
}
nm() { # sev cat name-ERE message : by file name over all files
  grep -z -i -E -e "$3" "$T/all0" 2>/dev/null | while IFS= read -r -d '' p; do emit "$1" "$2" "${p#./}:1" "$4"; done
}
has() { grep -q -I -E "$2" "$1" 2>/dev/null; }

# ---------- file inventory (find -P: never follows symlinks) ----------
if [ "$ALL" -eq 1 ]; then PRUNE=( -name .git ); else PRUNE=( -name .git -o -name node_modules -o -name vendor -o -name .venv -o -name venv ); fi
find -P . \( "${PRUNE[@]}" \) -prune -o -type f -size +0 -size -${BIGKB}k -print0 > "$T/all0" 2>/dev/null
find -P . \( "${PRUNE[@]}" \) -prune -o -type f -size +${BIGKB}k -print 2>/dev/null | while IFS= read -r p; do
  emit INFO obfuscation "${p#./}:1" "file larger than ${BIGKB} KiB, content not scanned"; done
xargs -0 grep -I -l --null -e '' < "$T/all0" 2>/dev/null > "$T/text0"
NFILES=$(tr -cd '\0' < "$T/text0" | wc -c | tr -d ' ')

LOCKRX='(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|composer\.lock|Cargo\.lock|poetry\.lock|Gemfile\.lock|go\.sum|Pipfile\.lock|\.map)$'
DOCRX='\.(md|markdown|mdx|txt|rst|adoc)$'
CODERX='\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|rs|java|kt|sh|bash|zsh|ps1|pl|lua|cs|vue|svelte|html?|ejs|pug|cmd|bat)$'
mk NL '.' "$LOCKRX"
mk NODOC '.' "$LOCKRX|$DOCRX"
mk DOC "$DOCRX" "$LOCKRX"
mk NOMIN '.' "$LOCKRX|$DOCRX|\.min\.(js|css)$"
mk CODE "$CODERX" "\.min\.(js|css)$"
mk OTHER '.' "$LOCKRX|$DOCRX|\.min\.(js|css)$|$CODERX"
mk JSX '\.(jsx|tsx|html?|vue|svelte|ejs)$'
mk PKG '(^|/)package\.json$'
mk LOCK '(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$'
mk NPMRC '(^|/)\.npmrc$'
mk CFGJS '(^|/)(next|vite|webpack|rollup|babel|postcss|tailwind|jest|vitest|playwright|nuxt|astro|eslint|cypress|craco|gulpfile|Gruntfile|rspack|tsup|karma|stylelint|prettier|commitlint|lint-staged|svelte|metro)(\.[A-Za-z0-9_-]+)*\.(c|m)?[jt]s$|(^|/)\.(eslintrc|babelrc|prettierrc|mocharc|lintstagedrc)\.c?js$|(^|/)(setupTests|jest\.setup|vitest\.setup)[A-Za-z.]*$'

# ---------- known IOCs (real campaigns) ----------
IOCRX='express-json-database|inline-array|cafrino-feed|com\.AppleAccountSync|\.vs_cache|_force_bootstrap|x-secret-header|scoped_dir|com\.avatar\.update|shai-hulud|setup_bun\.js|bun_environment\.js|truffleSecrets|SHA1HULUD|\.n2[/\\]|eth-mainnet-alchemy'
hits "$T/text0" CRITICAL known-ioc "$IOCRX" -i
nm CRITICAL known-ioc '(shai-hulud|setup_bun\.js|bun_environment\.js|trufflesecrets|_force_bootstrap|\.vs_cache|com\.appleaccountsync|com\.avatar\.update)' "file name matches known campaign IOC"

# ---------- symlinks ----------
find -P . \( "${PRUNE[@]}" \) -prune -o -type l -print0 2>/dev/null | while IFS= read -r -d '' p; do
  t=$(readlink "$p" 2>/dev/null); rel=${p#./}
  case "$t" in
    /*) emit HIGH masquerade "$rel:1" "symlink to absolute path: $t" ;;
    *)
      esc=$(printf '%s/%s' "$(dirname "$rel")" "$t" | awk '{ n = split($0, a, "/"); sp = 0; e = 0
        for (i = 1; i <= n; i++) { if (a[i] == "" || a[i] == ".") continue
          if (a[i] == "..") { if (sp == 0) e = 1; else sp-- } else sp++ } print e }')
      if [ "$esc" = 1 ]; then emit HIGH masquerade "$rel:1" "symlink escapes scan dir: $t"
      else emit INFO masquerade "$rel:1" "symlink inside scan dir: $t"; fi ;;
  esac
done

# ---------- dependency directories not scanned ----------
if [ "$ALL" -eq 0 ]; then
  find -P . -name .git -prune -o -type d \( -name node_modules -o -name vendor -o -name .venv -o -name venv \) -print -prune 2>/dev/null |
    while IFS= read -r p; do emit MEDIUM dep-risk "${p#./}:1" "dependency dir committed/present, not scanned (use --all)"; done
fi

# ---------- hidden Unicode (byte sequences; grep -P is not portable) ----------
E2=$'\xe2'; EF=$'\xef'; BB=$'\xbb'; BF=$'\xbf'; B8=$'\xb8'; F3=$'\xf3'
X80=$'\x80'; X81=$'\x81'; X84=$'\x84'; X87=$'\x87'; X8B=$'\x8b'; X8C=$'\x8c'; X8D=$'\x8d'; X8E=$'\x8e'; X8F=$'\x8f'
XA0=$'\xa0'; XA4=$'\xa4'; XA6=$'\xa6'; XA9=$'\xa9'; XAA=$'\xaa'; XAE=$'\xae'; XBF=$'\xbf'
# bidi (202A-202E, 2066-2069) and zero-width (200B, 200E, 200F, 2060-2064)
hits "$T/text0" HIGH hidden-unicode "$E2$X80[$X8B$X8E$X8F]|$E2$X80[$XAA-$XAE]|$E2$X81[$XA6-$XA9]|$E2$X81[$XA0-$XA4]"
hits "$T/text0" HIGH hidden-unicode ".$EF$BB$BF"                                    # BOM inside a line
hits "$T/text0" HIGH hidden-unicode "($EF$B8[$X80-$X8F]){2,}"                       # runs of variation selectors FE00-FE0F
hits "$T/text0" HIGH hidden-unicode "$F3$XA0[$X84-$X87][$X80-$XBF]"                 # U+E0100-E01EF
hits "$T/text0" HIGH hidden-unicode "$F3$XA0[$X80$X81][$X80-$XBF]"                  # tag characters U+E0000-E007F
ZJ="$E2$X80[$X8C$X8D]"                                                              # ZWNJ/ZWJ: normal in emoji and some scripts
hits "$T/text0" HIGH hidden-unicode "[A-Za-z0-9_\$]$ZJ|$ZJ[A-Za-z0-9_\$]"
EXCL="[A-Za-z0-9_\$]$ZJ|$ZJ[A-Za-z0-9_\$]"
hits "$T/text0" MEDIUM hidden-unicode "$ZJ"

# ---------- long lines, whitespace-pushed code ----------
xargs -0 awk 'length($0) >= 1000 && !(FILENAME in done) { done[FILENAME] = 1; printf "%s:%d:line of %d chars\n", FILENAME, FNR, length($0) }' < "$T/text0" 2>/dev/null |
  awk '{ s = "MEDIUM"; if ($0 ~ /(\.min\.(js|css)|\.map|\.svg|\.ipynb|[-.]lock|lock\.json|lock\.yaml|\.lockb?):[0-9]+:/) s = "INFO"; print s "\t" $0 }' |
  while IFS=$'\t' read -r s rest; do printf '%s\n' "$rest" | fmt_hits "$s" obfuscation >> "$OUT"; done
hits "$T/CODE" MEDIUM obfuscation '[^[:space:]][[:space:]]{80,}[^[:space:]]'

# ---------- remote execution ----------
RX_PIPE='(curl|wget)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh([[:space:]]|$|;|\))'
RX_PS='(powershell|pwsh)[^|]*[[:space:]]-(e|enc|encodedcommand)[[:space:]]|(iex|Invoke-Expression)[^;]{0,80}(DownloadString|WebClient|Invoke-WebRequest|iwr)|base64[[:space:]]+(-d|--decode|-D)[^|]*\|[[:space:]]*(ba)?sh|(mshta|bitsadmin|regsvr32)[^|]*https?://|certutil[^|]*-urlcache'
hits "$T/NODOC" HIGH remote-exec "$RX_PIPE|$RX_PS"
hits "$T/DOC" MEDIUM remote-exec "$RX_PIPE|$RX_PS"
hits "$T/NODOC" HIGH remote-exec 'child_process.{0,80}(curl|wget|npm (install|i) |powershell|cmd /c|osascript|bash -c|sh -c)'
hits "$T/NODOC" HIGH remote-exec "(exec|execSync|spawn|system|popen|Popen|run)\\(.{0,10}$Q[^'\"]{0,60}(npm (install|i) |pip3? install|curl |wget )"
hits "$T/NODOC" HIGH remote-exec '(npx|npm (i|install))[[:space:]]+(-g[[:space:]]+)?(git\+|https?://)'
hits "$T/NOMIN" MEDIUM remote-exec '(node|python3?|ruby|perl|php|bun|deno)[[:space:]]+(-e|-c|-p|--eval)[[:space:]]|npx[[:space:]]+(-y|--yes)[[:space:]]'

# ---------- dynamic execution ----------
hits "$T/NODOC" HIGH dynamic-exec "new Function$SP*\\($SP*${Q}require${Q}"
hits "$T/NODOC" HIGH dynamic-exec '(eval|Function)\(.{0,40}(atob|Buffer\.from)\('
hits "$T/NODOC" HIGH dynamic-exec '(exec|eval)\(.{0,60}(b64decode|decompress|fromhex|marshal|base64|codecs\.decode)|module\._compile|\.constructor\.constructor\('
hits "$T/CODE" MEDIUM dynamic-exec '(^|[^A-Za-z0-9_.$])eval[[:space:]]*\(|new Function[[:space:]]*\(|(^|[^A-Za-z0-9_$.])Function[[:space:]]*\(|vm\.(runIn[A-Za-z]*|Script|compileFunction)|new vm\.Script'
hits "$T/CODE" MEDIUM dynamic-exec "require$SP*\\([^'\")]*(\\+|\\\$\\{|Buffer|atob|decode)|(child_process|process\\.binding|process\\.dlopen)"
hits "$T/CODE" MEDIUM dynamic-exec '(^|[^A-Za-z0-9_.])(exec|eval|compile)[[:space:]]*\(|__import__[[:space:]]*\(|pickle\.loads?\(|marshal\.loads|os\.system\(|subprocess\.(Popen|run|call|check_output)\(|exec\.Command\('

# ---------- obfuscation ----------
hits "$T/NODOC" HIGH obfuscation '_0x[0-9a-fA-F]{4,6}\[0x[0-9a-fA-F]+\]|var _0x[0-9a-fA-F]{4,6}[[:space:]]*=|eval\(function\(p,a,c,k,e,[dr]\)|\(!\[\]\+\[\]\)'
hits "$T/NOMIN" MEDIUM obfuscation '(\\x[0-9a-fA-F]{2}){10,}|(\\u[0-9a-fA-F]{4}){10,}|String\.fromCharCode\(([0-9xa-fA-F]+,[[:space:]]*){8,}|charCodeAt\([^)]*\)[[:space:]]*\^'
EXCL='data:[a-z/+.-]+;base64|sha(256|384|512)-'
hits "$T/CODE" MEDIUM obfuscation "$Q[A-Za-z0-9+/]{300,}={0,2}$Q"
hits "$T/CODE" MEDIUM obfuscation "(atob|Buffer\\.from)\\([^)]*,$SP*${Q}(base64|hex)${Q}"

# ---------- blockchain loaders (EtherHiding) ----------
hits "$T/NODOC" HIGH blockchain 'bsc-dataseed|bsc-rpc\.publicnode|trongrid|aptoslabs\.com|eth_getTransactionByHash|bscscan\.com/api|api\.etherscan\.io/api'
hits "$T/DOC" MEDIUM blockchain 'bsc-dataseed|trongrid|aptoslabs\.com|eth_getTransactionByHash'
BCGEN='eth_call|infura\.io|alchemy\.com|publicnode\.com|rpc\.ankr\.com|cloudflare-eth\.com|JsonRpcProvider|getDefaultProvider'
hits "$T/NOMIN" MEDIUM blockchain "$BCGEN"
xargs -0 grep -l -I -E -e "$BCGEN" < "$T/NOMIN" 2>/dev/null | while IFS= read -r f; do
  if has "$f" '(^|[^A-Za-z0-9_.$])eval[[:space:]]*\(|new Function|Function\(|vm\.run'; then
    emit HIGH blockchain "${f#./}:1" "blockchain RPC read and dynamic execution in the same file"; fi; done

# ---------- exfiltration ----------
EXHI='webhook\.site|api\.telegram\.org/bot|discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin\.com/raw|jsonkeeper\.com|jsonsilo\.com|npoint\.io|requestbin|pipedream\.net|interact\.sh|burpcollaborator|oast\.(pro|live|site|online|fun|me)|transfer\.sh|anonfiles|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net'
EXMD='vercel\.app|onrender\.com|herokuapp\.com|glitch\.me|repl\.co|railway\.app|workers\.dev|netlify\.app|pages\.dev|fly\.dev|replit\.dev'
hits "$T/NODOC" HIGH exfil "$EXHI"
hits "$T/DOC" MEDIUM exfil "$EXHI"
hits "$T/CODE" MEDIUM exfil "$EXMD"
EXCL='https?://(127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)'
hits "$T/NOMIN" MEDIUM exfil 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}'
hits "$T/CODE" MEDIUM exfil 'JSON\.stringify\(process\.env\)|Object\.(keys|entries|values)\(process\.env\)|os\.environ\.(copy|items)\(\)|dict\(os\.environ\)|printenv'

# ---------- secrets and browser/keychain access ----------
hits "$T/CODE" HIGH secrets-access '(\.ssh[/\\]|id_rsa|id_ed25519|id_ecdsa|\.aws[/\\]credentials|\.git-credentials|\.netrc|\.kube[/\\]config|\.config[/\\]gcloud|\.gnupg|\.docker[/\\]config\.json)'
hits "$T/CODE" HIGH secrets-access 'Default[/\\](Login Data|Cookies|Web Data|Local Storage)|Login Data[`"'"'"']|cookies\.sqlite|logins\.json|key4\.db|Google[/\\]Chrome|BraveSoftware|Microsoft[/\\]Edge|Application Support[/\\](Firefox|Google|BraveSoftware)|Library[/\\]Keychains|login\.keychain|find-generic-password|find-internet-password|dump-keychain|Cookies\.binarycookies|trufflehog'
hits "$T/OTHER" MEDIUM secrets-access '(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.git-credentials|\.netrc|\.kube[/\\]config|\.gnupg)'
hits "$T/CODE" MEDIUM secrets-access 'pbpaste|clipboardy|clipboardListener|node-global-key-listener|iohook|keylogger|uiohook|screenshot-desktop|robotjs|pynput|pyperclip|ImageGrab|GetAsyncKeyState|node-machine-id|machineIdSync|keytar'

# ---------- wallets ----------
WALLETID='nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|egjidjbpglichdcondbcbdnbeeppgdph|fhbohimaelbohpjbbldcngcnapndodjp|fnjhmkhhmkbjkkabndcnnogagogbneec|dmkamcknogkgcdfhhbddcghachkejeap|aholpfdialjgjfhomihkjbmgjidlcdno|acmacodkjbdgmoleebolmdjonilkdbch|mcohilncbfahbmgdjkbpemcciiolgcge|bhhhlbepdkbapadjdnnojkbgioiodbic'
hits "$T/NL" HIGH wallet "$WALLETID"
hits "$T/CODE" HIGH wallet 'Local Extension Settings|wallet\.dat|\.electrum|\.exodus|exodus\.wallet|\.config[/\\]solana|Application Support[/\\](Exodus|atomic|Electrum|Coinomi|Ledger)|Atomic[/\\]Local Storage'
hits "$T/JSX" HIGH wallet "<(input|textarea)[^>]*(seed|mnemonic|recovery[ _-]?phrase|private[ _-]?key|secret[ _-]?recovery)|(placeholder|label|aria-label)=${Q}[^'\"\`]*(12|24)[ -]word" -i
hits "$T/JSX" MEDIUM wallet '(seed[ _-]?phrase|mnemonic|recovery[ _-]?phrase|secret[ _-]?recovery)' -i

# ---------- masquerading files ----------
mk MASQ '\.(woff2?|ttf|otf|eot|ttc|png|jpe?g|gif|ico|webp|bmp|mp[34]|wav|pdf|zip|gz|wasm|bin|dat)$'
if [ -s "$T/MASQ" ]; then
  while IFS= read -r -d '' f; do
    ty=$( (file -b "$f" 2>/dev/null || head -c 60 "$f") | head -n1 )
    if has "$f" 'require\(|function|eval|module\.exports|import |=>|process\.|#!/'; then
      emit HIGH masquerade "${f#./}:1" "binary extension but text with code: $ty"
    else emit MEDIUM masquerade "${f#./}:1" "binary extension but text content: $ty"; fi
  done < "$T/MASQ"
fi
hits "$T/NODOC" HIGH masquerade 'node[^;&|"]*\.(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp)([^A-Za-z0-9]|$)'
grep -z -i -E '\.(js|json|ts|css|html?|md|txt)$' "$T/all0" 2>/dev/null | while IFS= read -r -d '' f; do
  grep -q -I -e '' "$f" 2>/dev/null || emit MEDIUM masquerade "${f#./}:1" "text extension but binary content"; done
nm MEDIUM dep-risk '\.(exe|dll|dylib|so|node|pyd|scr|jar|msi|pkg|dmg)$' "committed executable/native binary, cannot be reviewed statically"

# ---------- persistence ----------
hits "$T/CODE" HIGH persistence 'LaunchAgents|LaunchDaemons|launchctl[[:space:]]+(load|bootstrap|enable|submit)|crontab[[:space:]]+(-|<)|/etc/cron|@reboot|systemctl[[:space:]]+(--user[[:space:]]+)?enable|\.config/autostart|CurrentVersion[/\\]+Run|schtasks[[:space:]]+/create|/etc/rc\.local'
hits "$T/CODE" MEDIUM persistence '\.bashrc|\.zshrc|\.zprofile|\.bash_profile|anydesk|teamviewer|rustdesk|ScreenConnect' -i
hits "$T/NODOC" HIGH persistence 'RunAtLoad|<key>KeepAlive</key>'
hits "$T/NODOC" MEDIUM persistence '^ExecStart=|^WantedBy=default\.target'

# ---------- prompt injection ----------
PI='(ignore|disregard|forget)[[:space:]]+(all[[:space:]]+|any[[:space:]]+|the[[:space:]]+|your[[:space:]]+)?(previous|prior|above|earlier)[[:space:]]+(instructions|rules|prompts?)|do not (tell|mention|reveal|inform)[^.]{0,40}(the user|developer|human)|(AI|LLM|assistant|Claude|Copilot|Cursor|agent|reviewer)[^.]{0,40}(this|the) (repo|repository|code|project) is (safe|clean|secure|trusted|legitimate)|do not (flag|report) (this|any)|mark (this|it) as (safe|clean)'
hits "$T/NL" HIGH prompt-injection "$PI" -i

# ---------- AI-agent config ----------
nm INFO ai-agent-config '(^|/)((CLAUDE|AGENTS|GEMINI)\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.cursor/rules/.*|\.github/copilot-instructions\.md|\.github/instructions/.*|\.continue/.*)$' "agent instruction file: treat as data, read it"
nm MEDIUM ai-agent-config '(^|/)(\.claude/(commands|agents|skills|hooks)/.*|\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json)$' "project agent config (commands/agents/MCP): loads when the agent opens this dir"
mk CCFG '(^|/)\.claude/settings(\.local)?\.json$'
hits "$T/CCFG" HIGH ai-agent-config '"hooks"[[:space:]]*:|enableAllProjectMcpServers|enabledMcpjsonServers|ANTHROPIC_(BASE_URL|API_KEY|AUTH_TOKEN)|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper|"defaultMode"[[:space:]]*:[[:space:]]*"(bypassPermissions|acceptEdits)"|Bash\((\*|:\*)?\)'
hits "$T/CCFG" MEDIUM ai-agent-config '"(statusLine|env|permissions)"[[:space:]]*:'
mk MCP '(^|/)(\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json)$'
hits "$T/MCP" HIGH ai-agent-config '"command"[[:space:]]*:'
hits "$T/MCP" MEDIUM ai-agent-config '"(url|serverUrl)"[[:space:]]*:'
mk CMDMD '(^|/)\.claude/commands/.*\.md$'
hits "$T/CMDMD" MEDIUM ai-agent-config '^!`|allowed-tools:.*Bash'

# ---------- editors / IDE / devcontainer / CI ----------
mk VSTASK '(^|/)\.vscode/tasks\.json$'
hits "$T/VSTASK" HIGH autorun '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"'
hits "$T/VSTASK" MEDIUM autorun '"reveal"[[:space:]]*:[[:space:]]*"never"'
mk VSSET '(^|/)\.vscode/settings\.json$'
hits "$T/VSSET" HIGH autorun '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*"on"'
hits "$T/VSSET" MEDIUM autorun '"(php\.validate\.executablePath|php\.executablePath|eslint\.runtime|eslint\.nodePath|npm\.exec\.path|typescript\.tsdk|git\.path|python\.defaultInterpreterPath|python\.pythonPath|terminal\.integrated\.(shell|automationProfile|profiles)\.[a-z]+)"'
nm INFO autorun '(^|/)\.vscode/extensions\.json$' "recommended extensions"
nm MEDIUM autorun '(^|/)\.idea/(runConfigurations/.*\.xml|workspace\.xml)$' "IDE run configuration"
nm MEDIUM autorun '(^|/)\.husky/[a-z-]+$' "husky git hook (installed by npm prepare)"
mk DEVC '(^|/)(\.devcontainer/([^/]+/)?devcontainer\.json|\.devcontainer\.json)$'
hits "$T/DEVC" HIGH autorun '"initializeCommand"[[:space:]]*:'
hits "$T/DEVC" HIGH autorun '"(postCreate|postStart|postAttach|onCreate|updateContent)Command"[[:space:]]*:.*(curl|wget|bash|node |python|\|[[:space:]]*sh)'
hits "$T/DEVC" MEDIUM autorun '"(postCreate|postStart|postAttach|onCreate|updateContent)Command"[[:space:]]*:'
hits "$T/DEVC" HIGH autorun '--privileged|--cap-add|--security-opt|--pid=host|--network=host'
hits "$T/DEVC" HIGH secrets-access 'docker\.sock|\.ssh|\.aws|\.gnupg|\$\{(localEnv:HOME|localEnv:USERPROFILE)\}|"source=/(Users|home)/'
mk COMPOSE '(^|/)(docker-compose|compose)[^/]*\.ya?ml$'
hits "$T/COMPOSE" HIGH secrets-access '(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.netrc|\.npmrc|docker\.sock|\.config/gcloud)[^[:space:]:]*:[^[:space:]]|-[[:space:]]*["'"'"']?(~|\$\{?HOME\}?|\$\{?USERPROFILE\}?|/Users/[^:/[:space:]]+|/home/[^:/[:space:]]+|/root|/etc|/)["'"'"']?/?:'
hits "$T/COMPOSE" HIGH autorun 'privileged:[[:space:]]*true|cap_add|(apparmor|seccomp)[:=]unconfined'
hits "$T/COMPOSE" MEDIUM autorun '(pid|network_mode|ipc|userns_mode):[[:space:]]*["'"'"']?host'
hits "$T/NODOC" HIGH autorun 'docker[[:space:]]+run[^|;&]*(--privileged|docker\.sock|--pid=host|-v[[:space:]]*(~|\$HOME|/):)'
mk CI '(^|/)\.github/workflows/[^/]+\.ya?ml$'
hits "$T/CI" MEDIUM autorun 'pull_request_target|runs-on:.*self-hosted|permissions:[[:space:]]*write-all'
hits "$T/CI" MEDIUM autorun '\$\{\{[[:space:]]*github\.event\.(issue|pull_request|comment|review|head_commit|commits)[^}]*(title|body|message|name|ref|label)'
if [ -s "$T/CI" ]; then
  xargs -0 grep -l -E -e 'pull_request_target' < "$T/CI" 2>/dev/null | while IFS= read -r f; do
    has "$f" 'github\.event\.pull_request\.head\.(sha|ref)' && emit HIGH autorun "${f#./}:1" "pull_request_target checks out untrusted PR head"; done
fi
mk DOCKERF '(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile)$'
hits "$T/DOCKERF" MEDIUM autorun '^ADD[[:space:]]+https?://'
mk MAKEF '(^|/)(Makefile|makefile|GNUmakefile|[^/]*\.mk)$'
hits "$T/MAKEF" MEDIUM autorun '\$\((shell|eval)[[:space:]]'

# ---------- JS config files that execute ----------
hits "$T/CFGJS" HIGH autorun '(^|[^A-Za-z0-9_.])(fetch|axios)\(|XMLHttpRequest|https?\.(get|request)\(|require\(.(https?|net|dgram|node:https?)[^)]*\)|eval\(|new Function|vm\.run|atob\(|Buffer\.from\([^)]*(base64|hex)'
hits "$T/CFGJS" MEDIUM autorun 'child_process|execSync|spawnSync|execFile|[^A-Za-z0-9_.]exec\('
mk NODEMON '(^|/)nodemon\.json$'
hits "$T/NODEMON" MEDIUM autorun '"(exec|execMap|events)"[[:space:]]*:'
nm MEDIUM lifecycle '(^|/)(\.pnpmfile\.cjs|binding\.gyp|extconf\.rb|bunfig\.toml)$' "file executed or consulted at install time"
nm MEDIUM lifecycle '(^|/)\.yarn/(releases|plugins)/.*' "committed yarn release/plugin runs on every yarn command"

# ---------- install-time hooks per ecosystem ----------
LIFEKEY='"(preinstall|install|postinstall|prepare|prepublish)"[[:space:]]*:[[:space:]]*"'
hits "$T/PKG" HIGH lifecycle "$LIFEKEY"'([^"]*[^[:alnum:]_"-])?(curl|wget|node|bun|bash|sh|zsh|powershell|pwsh|python3?|npx|deno)([^[:alnum:]_-]|$)'
hits "$T/PKG" MEDIUM lifecycle "$LIFEKEY"
mk SETUPPY '(^|/)setup\.py$'
hits "$T/SETUPPY" HIGH lifecycle 'os\.system|subprocess|exec\(|eval\(|urlopen|urllib|requests|socket|base64'
hits "$T/SETUPPY" MEDIUM lifecycle 'cmdclass'
mk PYPROJ '(^|/)pyproject\.toml$'
EXCL='setuptools|hatchling|poetry|flit_core|pdm|maturin|scikit_build_core|mesonpy|uv_build'
hits "$T/PYPROJ" HIGH lifecycle '^build-backend[[:space:]]*=|^backend-path[[:space:]]*='
mk PYSTART '(^|/)(sitecustomize|usercustomize)\.py$'
hits "$T/PYSTART" HIGH autorun '.'
mk PTH '\.pth$'
hits "$T/PTH" HIGH autorun '^import[[:space:]]'
mk CONFTEST '(^|/)conftest\.py$'
hits "$T/CONFTEST" MEDIUM autorun 'subprocess|os\.system|requests|urllib|socket|base64|exec\(|eval\('
mk REQS '(^|/)(requirements[^/]*\.txt|constraints[^/]*\.txt|Pipfile)$'
hits "$T/REQS" HIGH dep-risk '^(-e[[:space:]]+)?git\+|@[[:space:]]*https?://|--(extra-)?index-url|--trusted-host|--find-links'
mk GOFILES '\.go$'
hits "$T/GOFILES" MEDIUM autorun '^//go:generate|#cgo[[:space:]]|import "C"'
mk GOMOD '(^|/)go\.mod$'
hits "$T/GOMOD" MEDIUM dep-risk '^replace[[:space:]]|=>[[:space:]]*(\.|/|[a-z]+\.[a-z]+/)'
mk CARGO '(^|/)Cargo\.toml$'
hits "$T/CARGO" MEDIUM lifecycle '^build[[:space:]]*=|proc-macro[[:space:]]*=[[:space:]]*true'
hits "$T/CARGO" MEDIUM dep-risk 'git[[:space:]]*=[[:space:]]*"|\[patch\.'
mk BUILDRS '(^|/)build\.rs$'
nm MEDIUM lifecycle '(^|/)build\.rs$' "Rust build script runs at cargo build"
hits "$T/BUILDRS" HIGH lifecycle 'Command::new|reqwest|ureq|TcpStream|curl|std::process'
mk CARGOCFG '(^|/)\.cargo/config(\.toml)?$'
hits "$T/CARGOCFG" HIGH lifecycle 'runner|rustc-wrapper|rustc-workspace-wrapper|linker|\[source\.|replace-with'
mk GEMFILE '(^|/)(Gemfile|Rakefile|[^/]*\.gemspec|[^/]*\.rake)$'
hits "$T/GEMFILE" HIGH lifecycle 'system[[:space:](]|`[^`]+`|Net::HTTP|open-uri|URI\.open|(^|[^A-Za-z_.])(exec|eval)[[:space:](]|%x\{'
hits "$T/GEMFILE" HIGH dep-risk '^source[[:space:]]+["'"'"']https?://([^r]|r[^u])'
hits "$T/GEMFILE" MEDIUM dep-risk '(git|github|path):[[:space:]]'
mk COMPOSER '(^|/)composer\.json$'
CMDKEY='"(pre|post)-[a-z-]*-(cmd|dump)"[[:space:]]*:'
hits "$T/COMPOSER" HIGH lifecycle "$CMDKEY"'.*(curl|wget|php |sh |bash|base64)'
hits "$T/COMPOSER" MEDIUM lifecycle "$CMDKEY|\"type\"[[:space:]]*:[[:space:]]*\"composer-plugin\""
hits "$T/COMPOSER" MEDIUM dep-risk '"type"[[:space:]]*:[[:space:]]*"(vcs|path|package)"'
mk GRADLE '(^|/)(build|settings)\.gradle(\.kts)?$|(^|/)init\.gradle(\.kts)?$'
hits "$T/GRADLE" HIGH lifecycle '(curl|wget|https?://[^ ]*\.(sh|jar|exe))'
hits "$T/GRADLE" MEDIUM lifecycle 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|(^|[^A-Za-z])exec[[:space:]]*\{|commandLine|openStream|user\.home'
mk POM '(^|/)pom\.xml$'
hits "$T/POM" MEDIUM lifecycle 'exec-maven-plugin|maven-antrun-plugin|gmaven|groovy-maven-plugin'
mk WRAPPROP '(^|/)(gradle/wrapper/gradle-wrapper|\.mvn/wrapper/maven-wrapper)\.properties$'
EXCL='services\.gradle\.org|repo\.maven\.apache\.org|repo1\.maven\.org'
hits "$T/WRAPPROP" HIGH lifecycle '(distributionUrl|wrapperUrl)[[:space:]]*='
nm MEDIUM lifecycle '(^|/)(gradle/wrapper/gradle-wrapper\.jar|\.mvn/wrapper/maven-wrapper\.jar|\.mvn/extensions\.xml)$' "wrapper binary/extension runs at build; compare hash with the official release"

# ---------- npm: .npmrc, lockfiles, dependency specs ----------
hits "$T/NPMRC" HIGH dep-risk '^[[:space:]]*(audit|strict-ssl)[[:space:]]*=[[:space:]]*false'
hits "$T/NPMRC" HIGH lifecycle '^[[:space:]]*(ignore-scripts[[:space:]]*=[[:space:]]*false|script-shell[[:space:]]*=)'
EXCL='registry\.npmjs\.org|registry\.yarnpkg\.com'
hits "$T/NPMRC" HIGH dep-risk '^[[:space:]]*registry[[:space:]]*='
hits "$T/NPMRC" MEDIUM dep-risk '^[[:space:]]*@[^:]+:registry[[:space:]]*=|^[[:space:]]*package-lock[[:space:]]*=[[:space:]]*false'
mk YARNRC '(^|/)\.yarnrc(\.yml)?$'
hits "$T/YARNRC" MEDIUM lifecycle 'yarnPath|npmRegistryServer|^plugins:'
mk GITIGN '(^|/)\.gitignore$'
hits "$T/GITIGN" HIGH dep-risk '^[[:space:]]*/?(\*\*/)?(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json|bun\.lockb?)[[:space:]]*$'
mk GITATTR '(^|/)\.gitattributes$'
hits "$T/GITATTR" MEDIUM git-config 'filter=|diff=|merge='
mk GITMOD '(^|/)\.gitmodules$'
hits "$T/GITMOD" HIGH git-config 'url[[:space:]]*=[[:space:]]*(ext::|-|file:|/)|update[[:space:]]*=[[:space:]]*!'
hits "$T/GITMOD" INFO git-config 'url[[:space:]]*='
# resolved hosts in lockfiles
if [ -s "$T/LOCK" ]; then
  xargs -0 grep -H -n -I -E -e '(resolved"?:?|tarball:)[[:space:]]*"?(git\+[a-z]+://|git://|file:|https?://)' < "$T/LOCK" 2>/dev/null |
    awk '{ if (!match($0, /(https?|git\+[a-z]+|git):\/\/[^\/"'"'"' ]*|file:/)) next
      h = substr($0, RSTART, RLENGTH); sub(/^[a-z+]+:\/\//, "", h); sub(/^[^@]*@/, "", h); sub(/:[0-9]+$/, "", h)
      if (h == "registry.npmjs.org" || h == "registry.yarnpkg.com") next
      print }' | fmt_hits HIGH dep-risk >> "$OUT"
fi
# per package.json: dependency specs, lockfile presence, unused dependencies
: > "$T/hay"
if [ -s "$T/PKG" ]; then
  mk HAY '.' "$LOCKRX|(^|/)package\.json$|\.min\.(js|css)$"
  while IFS= read -r -d '' pj; do
    rel=${pj#./}
    awk '{ line = $0 }
      match(line, /"(dependencies|devDependencies|optionalDependencies|peerDependencies|overrides|resolutions)"[[:space:]]*:[[:space:]]*\{/) {
        blk = substr(line, RSTART + 1); sub(/".*/, "", blk); depth = 0; inb = 1; line = substr(line, RSTART + RLENGTH - 1) }
      inb { s = line
        while (match(s, /"[^"]+"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
          e = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
          k = e; sub(/^"/, "", k); sub(/".*/, "", k)
          v = e; sub(/^"[^"]+"[[:space:]]*:[[:space:]]*"/, "", v); sub(/"$/, "", v)
          print FNR "\t" blk "\t" k "\t" v }
        t = line; o = gsub(/\{/, "{", t); c = gsub(/\}/, "}", t); depth += o - c; if (depth <= 0) inb = 0 }' "$pj" > "$T/deps.tsv"
    ndeps=0
    while IFS=$'\t' read -r ln blk nm_ sp; do
      case "$blk" in dependencies|devDependencies|optionalDependencies) ndeps=$((ndeps + 1)) ;; esac
      case "$sp" in
        git+*|git:*|github:*|gitlab:*|bitbucket:*|http:*|https:*|file:*|link:*|ssh:*|*.tgz)
          emit HIGH dep-risk "$rel:$ln" "$blk: \"$nm_\": \"$sp\" (non-registry source)" ;;
        latest|\*|"")
          [ "$blk" = overrides ] || emit MEDIUM dep-risk "$rel:$ln" "$blk: \"$nm_\": \"$sp\" (unpinned)" ;;
        *) if printf '%s' "$sp" | grep -q -E '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$'; then
             emit HIGH dep-risk "$rel:$ln" "$blk: \"$nm_\": \"$sp\" (GitHub shorthand source)"; fi ;;
      esac
    done < "$T/deps.tsv"
    if [ "$ndeps" -gt 0 ]; then
      d=$(dirname "$pj"); found=0
      while :; do
        for lf in package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock bun.lockb; do [ -e "$d/$lf" ] && found=1; done
        [ "$found" = 1 ] || [ "$d" = "." ] && break
        d=$(dirname "$d")
      done
      [ "$found" = 1 ] || emit MEDIUM dep-risk "$rel:1" "package.json has dependencies but no lockfile in this dir or above"
    fi
    # unused runtime dependencies (best effort; skipped for big dependency lists)
    n=$(awk -F'\t' '$2 == "dependencies"' "$T/deps.tsv" | wc -l | tr -d ' ')
    if [ "$n" -gt 0 ] && [ "$n" -le 120 ] && [ -s "$T/HAY" ]; then
      awk -F'\t' '$2 == "dependencies" { print $1 "\t" $3 }' "$T/deps.tsv" | while IFS=$'\t' read -r ln name; do
        case "$name" in @types/*|eslint*|prettier*|typescript|react-scripts|tailwindcss|autoprefixer|postcss*|sass|webpack*|babel*|@babel/*|nodemon|ts-node|jest*|vitest*|vite|tsx|esbuild|@swc/*|swc*|core-js|tslib|@next/*|next|react|react-dom) continue ;; esac
        [ -n "$(xargs -0 grep -l -I -F -e "$name" < "$T/HAY" 2>/dev/null | head -n1)" ] && continue
        grep -F -e "$name" "$pj" | grep -v -E "\"$name\"[[:space:]]*:" >/dev/null 2>&1 && continue
        emit MEDIUM dep-risk "$rel:$ln" "dependency \"$name\" is declared but never referenced in source or scripts"
      done
    fi
  done < "$T/PKG"
fi

# ---------- git: .git/config, hooks, history ----------
gitcfg() { # file label
  awk -v lbl="$2" '
    function out(sev, why) { e = why " :: " l; gsub(/[\t\r]/, " ", e); if (length(e) > 160) e = substr(e, 1, 157) "..."
      printf "%s\tgit-config\t%s:%d\t%s\n", sev, lbl, NR, e }
    { l = $0; sub(/^[ \t]+/, "", l) }
    l ~ /^\[/ { sec = tolower(l); sub(/^\[/, "", sec); sub(/[ \]].*/, "", sec); next }
    l ~ /^[#;]/ || l == "" { next }
    { k = tolower(l); sub(/[ \t]*=.*/, "", k); v = l; sub(/^[^=]*=[ \t]*/, "", v); lv = tolower(v)
      if (sec == "core" && index(" fsmonitor sshcommand pager editor askpass gitproxy hookspath ", " " k " ")) {
        if (k == "fsmonitor" && (lv == "true" || lv == "false" || lv == "")) next
        out("CRITICAL", "core." k " can run a command"); next }
      if (sec == "filter" && (k == "clean" || k == "smudge" || k == "process")) {
        if (lv ~ /git-lfs/) out("INFO", "git-lfs filter"); else out("CRITICAL", "filter." k " runs a command"); next }
      if (sec == "alias" && substr(v, 1, 1) == "!") { out("CRITICAL", "shell alias"); next }
      if (sec == "diff" && (k == "textconv" || k == "command" || k == "external")) { out("CRITICAL", "diff." k " runs a command"); next }
      if ((sec == "merge" && k == "driver") || (sec == "sequence" && k == "editor") || (sec == "gpg" && k == "program")) { out("CRITICAL", sec "." k " runs a command"); next }
      if (sec == "credential" && k == "helper" && substr(v, 1, 1) == "!") { out("CRITICAL", "credential helper runs a command"); next }
      if ((sec == "difftool" || sec == "mergetool") && k == "cmd") { out("HIGH", sec ".cmd runs a command"); next }
      if (sec == "remote" && (k == "uploadpack" || k == "receivepack")) { out("HIGH", "remote command override"); next }
      if (sec == "submodule" && k == "update" && substr(v, 1, 1) == "!") { out("HIGH", "submodule update runs a command"); next }
      if (sec == "include" || sec == "includeif") { out("MEDIUM", "included config file"); next }
      if (sec == "url" && k == "insteadof") { out("MEDIUM", "URL rewrite"); next }
    }' "$1" | tr -c '\011\012\040-\176' '?' >> "$OUT"
}
gitscan() { # git-dir-path label
  [ -f "$1/config" ] && gitcfg "$1/config" "$2/config"
  if [ -d "$1/hooks" ]; then
    for hk in "$1"/hooks/*; do
      [ -f "$hk" ] || continue
      case "$hk" in *.sample) continue ;; esac
      emit HIGH git-config "$2/hooks/$(basename "$hk"):1" "non-sample git hook: $(head -n 3 "$hk" 2>/dev/null | tr '\n' ' ')"
    done
  fi
}
find -P . -name .git -prune -print 2>/dev/null | while IFS= read -r g; do
  lab=${g#./}
  if [ -d "$g" ] && [ ! -L "$g" ]; then gitscan "$g" "$lab"
  elif [ -f "$g" ]; then emit INFO git-config "$lab:1" ".git is a file: $(head -n 1 "$g" 2>/dev/null)"; fi
done
if [ -n "$GITDIR" ]; then
  gitscan "$GITDIR" "(git-dir)"
  if command -v git >/dev/null 2>&1; then
    NOW=$(date +%s)
    fmt_epoch() { date -u -r "$1" +%Y-%m-%d 2>/dev/null || date -u -d "@$1" +%Y-%m-%d 2>/dev/null || echo "$1"; }
    git -c core.hooksPath=/dev/null -c core.fsmonitor= -c core.pager=cat -c core.symlinks=false \
      --git-dir="$GITDIR" log --all --format='%h|%at|%ct|%an' 2>/dev/null > "$T/gitlog"
    while IFS='|' read -r h at ct an; do
      case "$at$ct" in *[!0-9]*|"") continue ;; esac
      [ "$at" -gt "$NOW" ] && emit HIGH git-history "git-history:$h" "author date $(fmt_epoch "$at") is in the future (author $an)"
      [ "$ct" -gt "$NOW" ] && emit HIGH git-history "git-history:$h" "committer date $(fmt_epoch "$ct") is in the future (author $an)"
      gap=$((ct - at)); [ "$gap" -lt 0 ] && gap=$((0 - gap))
      [ "$gap" -gt 2592000 ] && emit MEDIUM git-history "git-history:$h" "author/committer dates differ by $((gap / 86400)) days"
    done < "$T/gitlog"
    nc=$(wc -l < "$T/gitlog" | tr -d ' ')
    emit INFO git-history "git-history:1" "$nc commits reachable from all refs"
  else
    echo "scan.sh: git not found, history checks skipped" >&2
  fi
fi

# ---------- optional tools (never fatal) ----------
if [ "$TOOLS" -eq 1 ]; then
  if command -v osv-scanner >/dev/null 2>&1; then
    osv-scanner scan source -r "$DIR" 2>/dev/null | grep -E 'GHSA-|CVE-|OSV-|MAL-' | head -n 50 |
      while IFS= read -r l; do emit MEDIUM dep-risk "(osv-scanner):1" "$l"; done
  fi
  if command -v semgrep >/dev/null 2>&1; then
    semgrep --config p/secrets --metrics=off --quiet --emacs "$DIR" 2>/dev/null | head -n 50 |
      while IFS= read -r l; do emit MEDIUM secrets-access "(semgrep):1" "$l"; done
  fi
  if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --no-git --source "$DIR" --redact --no-banner 2>&1 | awk '
      /^RuleID:/ { r = $2 } /^File:/ { f = $2 } /^Line:/ { print r " " f ":" $2 }' | head -n 50 |
      while IFS= read -r l; do emit MEDIUM secrets-access "(gitleaks):1" "$l"; done
  fi
  if command -v guarddog >/dev/null 2>&1; then
    guarddog npm scan "$DIR" 2>/dev/null | grep -i -E 'found|malicious|rule|issue' | head -n 50 |
      while IFS= read -r l; do emit MEDIUM dep-risk "(guarddog):1" "$l"; done
  fi
fi

# ---------- assemble: sort by severity, dedupe, cap ----------
: > "$T/sorted"
for s in CRITICAL HIGH MEDIUM INFO; do awk -F'\t' -v s="$s" '$1 == s' "$OUT" >> "$T/sorted"; done
awk -F'\t' 'NF >= 4 && !seen[$2 "\t" $3]++' "$T/sorted" |
  awk -F'\t' '{ f = $3; sub(/:[0-9]+$/, "", f); k = $1 "\t" $2 "\t" f; if (++n[k] <= 12) print }' > "$T/final"
TOTAL_RAW=$(awk -F'\t' 'NF >= 4 && !seen[$2 "\t" $3]++' "$T/sorted" | wc -l | tr -d ' ')
TOTAL=$(wc -l < "$T/final" | tr -d ' ')
cnt() { awk -F'\t' -v s="$1" '$1 == s' "$T/final" | wc -l | tr -d ' '; }
NC=$(cnt CRITICAL); NH=$(cnt HIGH); NM=$(cnt MEDIUM); NI=$(cnt INFO)

if [ "$JSON" -eq 1 ]; then
  awk -F'\t' 'function esc(s,   i, c, o) { o = ""; for (i = 1; i <= length(s); i++) { c = substr(s, i, 1)
        if (c == "\\") o = o "\\\\"; else if (c == "\"") o = o "\\\""; else o = o c } return o }
    BEGIN { printf "[" } { printf "%s\n  {\"severity\": \"%s\", \"category\": \"%s\", \"location\": \"%s\", \"evidence\": \"%s\"}", (NR > 1 ? "," : ""), $1, $2, esc($3), esc($4) }
    END { printf "%s]\n", (NR > 0 ? "\n" : "") }' "$T/final"
else
  cat "$T/final"
  echo "---"
  echo "CRITICAL: $NC"
  echo "HIGH: $NH"
  echo "MEDIUM: $NM"
  echo "INFO: $NI"
  echo "files scanned (text): $NFILES"
  echo "findings suppressed by per-file cap: $((TOTAL_RAW - TOTAL))"
  echo "target: $DIR"
fi
[ $((NC + NH)) -gt 0 ] && exit 1
exit 0
