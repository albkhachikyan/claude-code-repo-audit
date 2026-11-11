# Incident response

Used when the verdict is MALICIOUS, or when anything from the target ran or host-check.sh finds
persistence. Every destructive or outward step below needs "ask the user first". The skill
finds and explains. The user acts.

## 1. Pick the branch

| Situation | Go to |
|---|---|
| MALICIOUS, nothing ran (cloned only, not installed, not started, not opened in an IDE) | section 2 |
| Something ran, or host-check.sh shows persistence or an IOC | section 3 |
| Unsure whether it ran | Treat as section 3 until host-check.sh and a review of shell history say otherwise |

## 2. MALICIOUS, nothing ran

### What to tell the "interviewer"
- Best: nothing. Do not argue and do not confirm that you found anything. Warning them gives them
  time to delete evidence and change tactics.
- If you must reply: a short neutral line. "Thanks, I will pass on this opportunity." No detail.
- Do not click further links, install apps, or open attachments they send.
- Do not send the audit report to them.

### Keep evidence (ask the user before deleting anything)
- Keep the quarantine dir (`$Q`) and `$Q/REPORT.md`.
- Save: screenshots of the profile, chat logs with message links, the brief (PDF/MD), the repo URL
  and commit hash, invite emails with headers, call link.
- Record IOCs de-fanged (`hxxps://evil[.]example`).

### Report (ask the user before sending anything)

| Where | What | How |
|---|---|---|
| npm | Malicious package(s) | Package page, "Report malware" (or security@npmjs.com). Give name, version, maintainer, why. |
| PyPI | Malicious project | Project page, "Report project as malware". Or security@pypi.org. |
| GitHub, repo | The repo | Repo page, "Report repository" or https://github.com/contact/report-abuse, choose malware. |
| GitHub, account | The owner account | Profile page, "Block or report", report abuse. |
| LinkedIn | Recruiter profile and company page | Profile "..." menu, "Report / Block", reason fake profile or scam. |
| Job platform or Telegram/Discord | The thread or account | In-app report; include the repo link. |
| Hosting provider of the C2 | The C2 service (for example a PaaS app URL) | Provider abuse form. Give the URL de-fanged and the evidence. |
| Local cyber agency | Optional | National CERT or police cybercrime form. |

Never visit or fetch the C2 URL to "confirm". Report it as found.

## 3. Something ran

Order matters. Stop spread first, keep evidence, then fix. Ask the user before each step.

### Step 1: Isolate
- Turn off Wi-Fi and unplug Ethernet. Do not log in to anything on this machine from now on.
- Do not push to git, publish packages or sign in to cloud consoles from this machine.

### Step 2: Record before changing (read-only)
- Run `scripts/host-check.sh` and save the output to a file outside the quarantine.
- Copy the plist, launcher script and the loader dir listing paths and sha256 into the report.
- Note times: file mtimes, `loader.log` entries, shell history.

### Step 3: Stop persistence (ask the user first)

| OS | Command |
|---|---|
| macOS agent | `launchctl bootout gui/$(id -u)/<label>` |
| macOS daemon | `sudo launchctl bootout system/<label>` |
| Linux user unit | `systemctl --user disable --now <unit>` |
| Linux cron | `crontab -e`, remove the line (or `crontab -l > backup` first) |
| Process | `kill <pid>`; use `kill -9 <pid>` only if it does not stop |

Find the PID with `ps -axo pid,command` (match the path), not by killing all `node` processes
(editors and tools use node too).

### Step 4: Quarantine, do not delete (ask the user first)
```bash
zip -r -P infected ~/MALWARE_QUARANTINE_<date>.zip \
  "<plist path>" "<launcher dir>" "<hidden payload dir>" "<quarantine dir>"
unzip -l ~/MALWARE_QUARANTINE_<date>.zip     # verify the archive lists what you expect
```
Only after the archive is verified and the user agrees, remove the originals. The password
`infected` is the usual convention for malware archives. It stops accidental opening. It is not
security.

### Step 5: Verify and reboot
- `launchctl list | grep -i <label>` returns nothing (macOS).
- `sfltool dumpbtm | grep -i <label>` returns nothing (macOS; may need admin).
- `ps -axo pid,command | grep -i <hidden dir name>` returns nothing.
- Reboot. Run `scripts/host-check.sh` again. Compare with Step 2.

### Step 6: Rotate secrets from a CLEAN device
Do this from a different, trusted device. Assume everything stored or typed on the infected
machine since the first run is exposed. Make the list from `references/host-compromise.md`
section 4.

| Order | Item | Action |
|---|---|---|
| 1 | Email accounts (primary, recovery) | Change password, sign out all sessions, check forwarding rules and recovery options. |
| 2 | Password manager master and browser-saved passwords | Change master; treat every browser-saved password as stolen; change them by importance (banks, exchanges first). |
| 3 | Sessions and cookies | "Sign out of all devices" on each major service. |
| 4 | GitHub | Remove all SSH keys and PATs; add new ones; review authorized OAuth apps and Actions secrets; check recent pushes. |
| 5 | npm / PyPI / crates | Revoke tokens; check recent publishes. |
| 6 | Cloud (AWS, GCP, Azure, others) | Rotate access keys; review CloudTrail or audit logs. |
| 7 | `.env` secrets and API keys | Rotate each (database, payment, third-party APIs). |
| 8 | Keychain items | Treat as exposed; change what they protect. |
| 9 | Crypto wallets | Create a new wallet and seed on a clean device. Move funds. Do not reuse the old seed. Revoke token approvals on the old addresses. |
| 10 | 2FA | Enable it everywhere. Prefer hardware keys or an authenticator app, not SMS. Reissue recovery codes. |

### Step 7: Decide on reinstall
- If attacker code ran with user rights for days or weeks, or ran a remote-control channel: a full
  OS erase and reinstall is the only way to be sure. Strongly consider it. Restore only plain data
  files, never apps, dotfiles or scripts from the old machine.
- If it was caught within minutes and nothing sensitive was open: removal plus rotation may be
  enough. The user decides.

### Step 8: After
- Do not push from the infected machine until keys are rotated and the machine is rebuilt or
  confirmed clean.
- Report as in section 2.
- Write down the timeline and lessons (see `references/case-study-2026-11.md` for the shape).
