# Case study: two linked fake-interview incidents (2026-09 to 2026-11)

IOCs are real and de-fanged. The owner approved naming them. Paths use `~`. Do not visit any
URL below.

## Summary

| | A: GameNetwork-MVP | B: earlier take-home |
|---|---|---|
| When | Nov 2026 | Sep 2026 (infected 2026-09-04) |
| Lure | Interview call, camera off, "share your screen and install the repo" | "Full Stack Take-Home Task: Marketplace Watchlist" brief |
| Result | Audited before running. Never ran. | Ran. Persistent backdoor for about two months. |
| Mechanism | Poisoned npm dependency, started at server listen | LaunchAgent, then EtherHiding loader |

Both are the same pattern: a normal-looking product, a hidden loader, a lure that pushes you to
run it.

## A. GitHub repo ChainGamer2/GameNetwork-MVP (never run)

### Mechanism
1. `server.js` (lines 6 and 20) calls `require('express-json-database').setTimestart()` when the
   server starts listening. The app uses it for nothing else.
2. `express-json-database@2.1.4` (first published 2026-11-11, maintainer `donna3465657fr`) polls
   `hxxps://cafrino-feed[.]onrender[.]com/api/feed` every 30 seconds.
3. It passes the response text to `inline-array(text, true)`.
4. `inline-array@2.1.3` (same maintainer, published 2026-10-25) is a "run JavaScript from a
   string" loader. With `true` it hands the code `require`, `process` and the Node globals.
5. Result: remote code execution on the host every 30 seconds, with whatever the attacker serves.
6. The C2 name `cafrino-feed` matches the `package.json` name `"cafrino"`. The backdoor was
   built for this repo.

### How it hid

| Trick | Evidence |
|---|---|
| Unrelated commit messages | Backdoor added in commits titled like "Adjust harvest desk metrics (2)" and "Improve form validation... (2)" |
| Fabricated future date | Last commit dated 2026-11-12 (the clone was made on 2026-11-11) |
| Audit disabled | `.npmrc` has `audit=false` |
| Lockfile hidden | `package-lock.json` is in `.gitignore`, so new package versions install silently |
| README mismatch | README claims Next.js, TypeScript and MongoDB; none are used |
| Seed-phrase form | `client/src/pages/product/ForgotPasswordModal.jsx` is a ready-made seed-phrase/private-key form (not wired up yet) |
| Lifted UI | Template footer links to an unrelated developer's site |

### Ordinary bugs (real, but irrelevant next to the loader)
- Default JWT secret.
- "Hashing" is `hashed_${password}`.
- CORS reflects any origin with credentials enabled.
- CSP off.
- POST routes without auth.
- A carousel library loaded from a CDN without SRI.

### IOCs (A)

| Type | Value |
|---|---|
| npm package | `express-json-database@2.1.4` (maintainer `donna3465657fr`, first published 2026-11-11) |
| npm package | `inline-array@2.1.3` (same maintainer, 2026-10-25) |
| C2 | `hxxps://cafrino-feed[.]onrender[.]com/api/feed` |
| Call pattern | `require('express-json-database').setTimestart()` |
| Repo | `ChainGamer2/GameNetwork-MVP` |
| Config | `.npmrc` `audit=false`; lockfile in `.gitignore` |

### Status
`node_modules` was absent and no matching tarballs were in the npm cache, so it never executed.

## B. Earlier infection from a fake take-home (Sep 2026)

### Chain
1. `~/Library/LaunchAgents/com.AppleAccountSync.plist`. `RunAtLoad` true, stdout and stderr to
   `/dev/null`, `LimitLoadToSessionType` Aqua, `WorkingDirectory` `~/.vs_cache`.
2. It starts `~/Library/Application Support/AppleAccountSync/AppleAccountSync.app/Contents/MacOS/AppleAccountSync`.
   That file is an 8-line `#!/bin/sh` script (not a Mach-O binary): `cd ~/.vs_cache`, then
   `exec /usr/local/bin/node ~/.vs_cache/main.js`.
3. `~/.vs_cache/main.js` is an obfuscated EtherHiding loader:
   - `api.trongrid.io` gives a pointer.
   - A BSC transaction is read via `bsc-dataseed.binance.org` or `bsc-rpc.publicnode.com`.
   - The input data is XOR-decrypted and gunzipped.
   - It is run with `new Function(require, ...)`.
4. `_force_bootstrap.js` reads `_force_client.pending` and runs it with `new Function`.
5. `main.js.pending` is a copy of `main.js`: a self-update slot.
6. Dependencies show the capabilities: `axios` (network), `better-sqlite3` (browser databases),
   `node-machine-id` (fingerprint), `socket.io-client` (remote control).
7. Marker file `.legacy_keyboard_logs_cleaned_1.6.14` suggests an earlier keylogger stage was
   cleaned up by the malware.
8. `loader.log` has entries dated 2026-09-20, 2026-10-05 and 2026-11-07. All are DNS failures
   for `api.trongrid.io`. Successes are not logged, so assume it ran successfully many times.

The payload lives on a public blockchain, so it can be changed at any time and cannot be taken
down. Only the on-host loader is removable.

### Why the label is wrong
Apple agents use `com.apple.*` and are not in the user's `~/Library/LaunchAgents`. A label
`com.AppleAccountSync` in a user folder imitates Apple by name only.

### IOCs (B)

| Type | Value |
|---|---|
| LaunchAgent label | `com.AppleAccountSync` |
| App folder | `~/Library/Application Support/AppleAccountSync/` |
| Hidden dir | `~/.vs_cache/` |
| Files | `main.js`, `main.js.pending`, `_force_bootstrap.js`, `_force_client.pending`, `loader.log`, `.legacy_keyboard_logs_cleaned_1.6.14` |
| Hosts | `api.trongrid.io`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com` (public services; the abuse is the pattern, not the hosts) |
| Deps | `axios`, `better-sqlite3`, `node-machine-id`, `socket.io-client` (mostly `latest`, unpinned, in a loader `package.json`) |
| Related names (other reports) | `com.avatar.update`, `scoped_dir`, `x-secret-header`, `shai-hulud`, `setup_bun.js`, `bun_environment.js`, `truffleSecrets` |

### SHA-256

| File | SHA-256 |
|---|---|
| `~/.vs_cache/main.js` | `fb4e59cdbedf157753b6226c8cc1c756af18499aaeabd7946460a1ea21f3a117` |
| `~/.vs_cache/main.js.pending` | `fb4e59cdbedf157753b6226c8cc1c756af18499aaeabd7946460a1ea21f3a117` |
| `~/.vs_cache/_force_bootstrap.js` | `1490bb58648ef96b5a0463265fdf1194d94510e38c4ab619f15630f0fbdf158` |
| `~/.vs_cache/.legacy_keyboard_logs_cleaned_1.6.14` | `d6af3455b79f90626286b0ea9e6554a05416f6c169bc8f4e0589154691af9b86` |
| `~/.vs_cache/package.json` | `f9ec87fc90a3fe6f0e223778545277a828d53e2dc8cc5fa407482c9bef18cc58` |
| `~/.vs_cache/package-lock.json` | `3cac635cf9027be1ef250afadb62d49bf75433c1b3844257ad7e5ba5a259f985` |
| `~/.vs_cache/loader.log` | `ab94ec4a1b11434c0b49fbc17bcca9b6b21856ddb0ecbf1620e6d68a7c0cebe4` |
| `~/Library/LaunchAgents/com.AppleAccountSync.plist` | `069a4c064853971c686e86abb4ec37362e25a0f00b243a56c3a6c6529d4c4603` |

## Timeline

| Date | Event |
|---|---|
| 2026-09-04 evening | Take-home brief downloaded (PDF and Markdown). Persistence agent, app folder and `~/.vs_cache` created at 23:43. |
| 2026-09-11 | `main.js` last modified. |
| 2026-09-20 | `_force_bootstrap.js`, `main.js.pending` and the keyboard-log marker written. First logged DNS failure. |
| 2026-10-05 | Second logged DNS failure. |
| 2026-10-25 | `inline-array@2.1.3` published. |
| 2026-11-07 | Third logged DNS failure. `loader.log` last written. |
| 2026-11-11 | `express-json-database@2.1.4` first published. Repo A cloned. Audit run. Infection B found. |

## How each phase would have caught it

| Phase | Case A | Case B |
|---|---|---|
| 0 Intake | Camera off, "share screen and install", Web3/gaming theme, whole-product task: lure score high | Brief for a whole product with a time box and "npm install / npm run dev" |
| 1 Quarantine | Bare clone, no hooks, nothing executed | Not available: the repo was run |
| 2 `scan.sh` | `.npmrc` `audit=false` (dep-risk), seed-phrase form (wallet), `known-ioc` for package names | n/a to the host; `known-ioc` names once the list has them |
| 3 Execution surfaces | `server.js` listen callback calls a dependency that the app never uses | Would show what `npm install` / `npm run dev` start |
| 4 Dependencies | `express-json-database`: published the day of the audit, single maintainer, never used by the app. Its dependency `inline-array`: fresh, single maintainer, loader | `latest` unpinned deps in a hidden dir; `better-sqlite3` and `socket.io-client` in a task that needs neither |
| 5 Sinks | Fetch then `inline-array(text, true)`: fetch-to-exec | `new Function(require, ...)`, XOR + gunzip, `trongrid`/`bsc-dataseed`: read-blockchain-to-exec |
| 6 Git | Future commit date, unrelated messages, lockfile ignored | n/a |
| 7 `host-check.sh` | Would have shown infection B | Label imitating Apple, program in `$HOME`, hidden dir with `main.js` and `node_modules`, output to `/dev/null` |
| 8 Verdict | MALICIOUS: remote-code loader | MALICIOUS: persistence plus decode-then-exec |

## What the user did
1. Stopped before running repo A and asked for an audit.
2. Audit confirmed repo A as malware and, from the host check, found infection B.
3. Network off, agent unloaded, processes checked, files moved to a password-protected archive
   (originals removed only after verifying the archive), reboot and re-check.
4. From a clean device: rotated email, browser passwords and sessions, GitHub keys and tokens,
   npm tokens, cloud and `.env` keys, Keychain-protected items; moved wallet funds to a new seed
   made on a clean device; enabled 2FA; considered an OS reinstall.
5. Reported the two npm packages, the repo and the account, and the "employer".

See `references/incident-response.md` for the generic steps.

## Lessons
- The lure is the vulnerability. "Run it now on a call" is the single strongest signal.
- Do not trust the polish: a full product with README, UI and routes costs the attacker little.
- A package that is required once and never used is the top lead.
- A first-publish date of today, one maintainer, and a feed URL named after the project is a
  targeted backdoor.
- Check the lockfile and `.npmrc`. A gitignored lockfile and `audit=false` are on purpose.
- Commit messages and commit dates are attacker-controlled. Read the diffs.
- Persistence names imitate Apple. Check the label, the folder it is in, and what the "app" is.
- Blockchain-hosted payloads cannot be taken down. Removing the loader and rotating secrets is
  what you can do.
- Failure logs prove the loader ran. Absence of success logs proves nothing.
- Rotate from a clean device. Never from the infected machine.
