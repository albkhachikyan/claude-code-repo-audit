# Social engineering: the fake-interview playbook

Used in phase 0 (score the lure) and phase 8 (what to say). Lure signals raise the bar for a
CLEAN verdict. They are never evidence on their own. Only code is evidence.

## 1. The playbook as seen in the wild

Known as "Contagious Interview" (DPRK-linked clusters) and many copycats. The goal is to get the
candidate to run attacker code on a personal machine that holds keys, wallets and sessions.

| Step | What happens | Why it works |
|---|---|---|
| 1. Contact | "Recruiter" or "hiring manager" writes on LinkedIn, Telegram, Discord, WhatsApp or email. Often a cloned or hijacked profile of a real person. Pays well, remote, fast. | Job seekers answer quickly. |
| 2. Theme | Web3, crypto, DeFi, NFT, betting, gaming or a "marketplace" product. | Targets developers who hold wallets and keys. |
| 3. Task | "Fix a bug" or "add a feature" in a repo, or a whole mini-product ("Full Stack Take-Home"). Sent as a private repo invite, a public repo, a ZIP, or a Bitbucket/GitLab link. | A real product hides a few lines of loader. |
| 4. Document | A PDF or Markdown brief with a time box (2-3 hours), a stack list and "npm install / npm run dev". | Looks like a real company process. |
| 5. Meeting | Calendly link, or a "meeting app" or "video test" they ask you to install. Camera off or a deepfake/stock face. | Fake meeting apps are malware droppers. |
| 6. Pressure | "Share your screen and run it now." Short deadline. "Our CTO is waiting." | Removes the time to read code. |
| 7. Run | `npm install` fires a lifecycle script, an IDE task fires on folder open, or the server start calls a poisoned dependency. | Code runs with your user rights. |

Sources:
- Unit 42, fake recruiters targeting tech job seekers: https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters
- Cisco Talos, BeaverTail and OtterCookie: https://blog.talosintelligence.com/beavertail-and-ottercookie/
- The Hacker News, 197 malicious npm packages (Nov 2025): https://thehackernews.com/2025/11/north-korean-hackers-deploy-197-npm.html

## 2. Red-flag checklist (score each item 0, 1 or 2)

0 = absent, 1 = partly present, 2 = clearly present. Write the score in the report.

| # | Signal | Score 2 example |
|---|---|---|
| 1 | Contact channel | First contact on Telegram/Discord/WhatsApp, or a LinkedIn profile under 1 year old or with few connections. |
| 2 | Identity | Recruiter name does not match company site staff page; company has no real footprint; email on a free domain or look-alike domain. |
| 3 | Role fit | Offer is much better than your profile deserves; you did not apply. |
| 4 | Theme | Web3, crypto, betting or gaming product. |
| 5 | Task size | Take-home is a whole product, 2+ hours, with a time box. |
| 6 | Delivery | Private repo invite, ZIP, or a repo on a new account with little history. |
| 7 | Run instruction | "npm install and npm run dev", "run it and share your screen". |
| 8 | Camera / voice | Interviewer camera off, audio only, stock face, scripted answers. |
| 9 | Urgency | "Do it now", "today only", "the CTO is waiting". |
| 10 | Tool install | Asked to install a meeting app, "video test", browser extension or driver. |
| 11 | Repo mismatch | README stack differs from package.json; unrelated commit messages; project not from the company named. |
| 12 | Refusal | Pushback when you ask to review the code first or to use a VM. |

How to read the total (max 24):

| Total | Reading | Action |
|---|---|---|
| 0-5 | Ordinary hiring noise | Normal audit. |
| 6-11 | Several lure signals | Full audit. Do not run on the host even if CLEAN. Use the safe-run recipe in `SKILL.md`. |
| 12+ | Strong lure pattern | Treat as hostile. Audit anyway for evidence. Do not run on a personal machine. |

A high score with clean code is still not a CLEAN-and-safe-to-run result on the host. A low
score with a confirmed loader is still MALICIOUS. Code decides the verdict.

## 3. Questions to ask the "recruiter" before running anything

Ask in writing. A real company answers these without trouble.

1. Which company is this for, and what is the team's official page and hiring URL?
2. Who is the hiring manager? Can I see their company email and a company-hosted calendar link?
3. Which job ID on the company careers page matches this role?
4. Why is the task a full product and not a small exercise? What is scored?
5. Can I get the task as a read-only document or a gist, without a runnable repo?
6. May I run it in a VM or container with no access to my files and keys?
7. Who reviews the submission and when? Can I speak to that engineer by company email?
8. Is the meeting on Zoom, Google Meet or Teams with a link from the company domain? (No custom app.)

## 4. Safe lines to say on a live call

| Situation | Say |
|---|---|
| "Run it now while sharing your screen." | "I review unfamiliar code before I run it, and I only run it in a sandbox. Give me 10 minutes." |
| "Just do npm install." | "I install with scripts disabled in a throwaway VM first. I can walk you through that on screen." |
| "Install this meeting app / extension." | "I only use Zoom, Meet or Teams from a link on your company domain." |
| "Camera is off, we are short on time." | "I would like to see who I am speaking with. Can you turn the camera on, and send the invite from your company email?" |
| "Do it today or we move on." | "I do not run code under time pressure. I can send my results tomorrow." |
| "Why do you need to read it first?" | "It is a standard security practice for any code from outside my own team." |

What a real company usually answers: "Of course", "take your time", "use a VM, that is fine",
"we can send a smaller exercise", "here is the job post and my company email". A fake one
repeats the pressure, changes channel, goes quiet, or drops the offer. Pushback on a VM or a
code review is a strong signal (checklist item 12).

If it feels wrong, end the call. Do not install, open or run anything first. Keep the chat logs.

## 5. Cases

### Case A: 2026-11, live call (never run)
- A repo `ChainGamer2/GameNetwork-MVP` was sent for an interview.
- On the call the interviewer kept the camera off, asked the candidate to share the screen and
  to install the repo.
- The user stopped and asked for an audit instead. The audit confirmed a remote-code loader. See
  `references/case-study-2026-11.md`.
- Checklist score for this case (author's reading): camera 2, run instruction 2, task size 1,
  theme 2, repo mismatch 2.

### Case B: 2026-09, "Full Stack Take-Home Task: Marketplace Watchlist" (ran, infected)
- A brief (PDF and Markdown) for a "Full Stack Take-Home Task: Marketplace Watchlist".
- Time box 2-3 hours, Zustand and TypeScript, "npm install / npm run dev", submit a fork or a ZIP.
- The brief downloaded the same evening a persistence agent was installed on the Mac.
- Lesson: a polite, normal-looking brief is the lure. The brief is not malicious. The repo behind
  it was. See `references/case-study-2026-11.md` section B and `references/incident-response.md`.
