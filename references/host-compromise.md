# Host compromise: persistence and theft locations

Used in phase 7. `scripts/host-check.sh` reads these places and never changes anything.
Run it when anything from the target may have executed, or the user had an earlier similar task.
Output format and exit codes match `scan.sh`.

## 1. macOS persistence

| Location | What to look for | host-check.sh |
|---|---|---|
| `~/Library/LaunchAgents/*.plist` | Any plist the user did not install. User-folder agents are the usual place for this malware. | yes |
| `/Library/LaunchAgents/*.plist` | Same, system-wide for all users. | yes |
| `/Library/LaunchDaemons/*.plist` | Root-level. Needs admin rights to write, so rarer. | yes |
| Login Items / BTM (`sfltool dumpbtm`) | Legacy agent with "Unknown Developer" whose executable is in `$HOME`. | yes, if allowed |
| `~/Library/Application Support/<Name>/<Name>.app/Contents/MacOS/<Name>` | A "bundle" whose executable is a text script (`#!/bin/sh`) that starts node or python. Real apps are Mach-O binaries. | partly (via plist program path) |
| Hidden dirs in `$HOME` with `node_modules` and `main.js`: `~/.vs_cache`, `~/.n2`, `~/.npl`, `~/.npm/scoped_dir*`, `~/.sysinfo` | Payload and its dependencies. | yes |
| `crontab -l`, `/etc/cron.d`, `/var/at/tabs` | `@reboot`, lines running node/python/curl. | crontab -l only |
| `~/.zshrc`, `~/.zprofile`, `~/.bash_profile`, `~/.bashrc`, `~/.profile` | Lines with `curl`, `wget`, `base64`, `eval`, `node ~/.hidden/x.js`. | yes |
| `~/.zsh_sessions/` | Copies of shell state written by the malware's shell; a dir named after the label is a lead. | no |
| Browser extension dirs (`~/Library/Application Support/Google/Chrome/*/Extensions`) | Unknown extension IDs, sideloaded extensions. | no |

Label tells:
- The label imitates Apple but is not `com.apple.*` (`com.AppleAccountSync`, `com.Apple.update`,
  `com.apple-sync`). Apple agents are `com.apple.*`, and they are not in the user LaunchAgents folder.
- Related label from a published report: `com.avatar.update.wake.plist` (MITRE S1245:
  https://attack.mitre.org/software/S1245).
- `RunAtLoad` true, `StandardOutPath` and `StandardErrorPath` set to `/dev/null`,
  `LimitLoadToSessionType` Aqua, `WorkingDirectory` in a hidden dir.
- `ProgramArguments` points into `$HOME`, `/tmp`, `/private/tmp` or a hidden dir.

Hidden-dir names from reports: `~/.n2/` (modules pay, bow, mlip, adc), `.sysinfo`, `.npl`
(eSentire: https://www.esentire.com/blog/bored-beavertail-invisibleferret-yacht-club-a-lazarus-lure-pt-2).
`~/.npm/scoped_dir*/main.js` is dropped by the fake-font VS Code task
(https://opensourcemalware.com/blog/dprk-contagious-interview-campaign-fake-font-uses-malicious-vs-code-fonts).
Newer builds may be `.pyd` or `.so` files
(Trend Micro 2026: https://www.trendmicro.com/en/research/26/e/analyzing-void-dokkaebi-invisibleferret-malware.html).

## 2. Linux persistence

| Location | Look for |
|---|---|
| `~/.config/systemd/user/*.service` | `ExecStart=` into `$HOME`, `/tmp`, hidden dir; node/python/sh -c |
| `~/.config/autostart/*.desktop` | `Exec=` same as above |
| `crontab -l`, `/etc/cron.d/*`, `/etc/crontab` | `@reboot`, curl/wget piped to sh, node/python in hidden dirs |
| `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.zshrc` | Same as macOS |
| `/etc/ld.so.preload` | Any entry at all. Normally absent. Root-level rootkit sign. |
| `/etc/systemd/system/`, `/etc/rc.local`, `/etc/profile.d/` | Needs root to write. Check mtime. |

## 3. Windows (notes only; host-check.sh does not run there)

| Location | Look for |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` | Values pointing to `%APPDATA%`, `%TEMP%`, `node.exe`, `pythonw.exe`, `powershell -enc` |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Any `.lnk`, `.bat`, `.vbs` the user did not add |
| Scheduled Tasks (`schtasks /query /fo LIST /v`) | Tasks running node/python from user paths |
| `%APPDATA%` and `%LOCALAPPDATA%` | Hidden folders with a portable `node.exe`, `python.exe`, `main.js`, `.pyd` |
| Remote tools | Unexpected AnyDesk or similar install |

Use Autoruns (Sysinternals) for a full view. Run it from a clean medium.

## 4. What these families steal

Reports on BeaverTail, InvisibleFerret and OtterCookie describe the same target list.

| Target | Typical path (macOS) | Why it matters |
|---|---|---|
| Browser logins and cookies | `~/Library/Application Support/Google/Chrome/*/Login Data`, `Cookies`; Brave, Edge, Firefox `logins.json`, `key4.db` | Saved passwords, live sessions without a password. `better-sqlite3` in a payload is a sign. |
| Wallet extensions | `.../Chrome/*/Local Extension Settings/<ext id>` (MetaMask id `nkbihfbeogaeaoehlefnkodbefgpgknn`, unverified) | Seed and vault. |
| Desktop wallets | `~/Library/Application Support/Exodus`, `Electrum`, `atomic` | Wallet files. |
| Keychain | `~/Library/Keychains/login.keychain-db` | Needs the login password, often phished or keylogged. |
| SSH keys | `~/.ssh/id_*` | Push access to repos and servers. |
| Cloud credentials | `~/.aws/credentials`, `~/.config/gcloud`, `~/.azure` | Cloud takeover. |
| GitHub CLI | `~/.config/gh/hosts.yml` | Token with repo rights. |
| `.env` files | Any `.env`, `.env.local` under `$HOME` | API keys, DB URLs. |
| npm tokens | `~/.npmrc` (`_authToken`) | Publish rights; used to spread (Shai-Hulud). |
| Clipboard, keystrokes | Live capture | Seed phrases, passwords. |
| Remote access | socket.io, AnyDesk | Full control. |

## 5. How host-check.sh maps to this

| Check | Category | Severity |
|---|---|---|
| Plist label imitates Apple (not `com.apple.`) | persistence | HIGH |
| Plist program in `$HOME`, hidden dir, `/tmp`, or a shell script launching node/python | persistence | HIGH |
| `RunAtLoad` with `/dev/null` output | persistence | HIGH |
| Any other plist | persistence | INFO |
| BTM entry, Unknown Developer, executable gone | persistence | INFO |
| BTM entry, Unknown Developer, executable in `$HOME` | persistence | HIGH |
| systemd user unit / autostart / crontab with risky target | persistence | HIGH |
| Hidden dir in `$HOME` with `main.js` / `node_modules` / python loader, not a known tool dir | persistence | HIGH |
| Known IOC dir or file name | known-ioc | CRITICAL |
| `--ioc <string>` found in any scanned item | known-ioc | CRITICAL |
| Shell rc line with curl/wget/base64/eval/node from a hidden dir | persistence | HIGH |
| node/python process whose path is in a hidden `$HOME` dir or `/tmp` | persistence | HIGH |
| Same process has an ESTABLISHED TCP connection (`lsof`) | exfil | HIGH |

## 6. What host-check.sh cannot see

- Anything it cannot read without admin rights (other users' agents, `/var/at/tabs`, some BTM data).
- Memory-only implants, kernel or firmware changes.
- Payloads that already deleted their own files.
- Browser extension tampering and OAuth grants (check account security pages from a clean device).
- Windows hosts.
- Successful past runs: loaders log failures but rarely successes. A missing log is not proof.
- Data already stolen. Persistence removal does not undo theft. Rotate secrets (see
  `references/incident-response.md`).

A clean host-check result is not proof of a clean host.
