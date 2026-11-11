# Repo audit: <repo name>

| | |
|---|---|
| Verdict | **CLEAN / SUSPICIOUS / MALICIOUS**: <one line> |
| Source | <URL / zip name / path>, received via <channel> from <sender as described, no personal data> |
| Audited commit | `<sha>` (<date of audit>). Later pushes are not covered. |
| Mode | quick / full |
| Executed anything? | no (static only) |
| Quarantine | `<path>` |

## Deciding findings
| # | Severity | Category | Location | Evidence | Why it matters |
|---|---|---|---|---|---|
| 1 | CRITICAL | remote-exec | `server.js:20` | `require('x').init()` | unused dep called at startup, fetches and runs remote code |

## Execution surfaces
| Surface | File | Runs | Verdict |
|---|---|---|---|
| npm lifecycle | `package.json` | `postinstall: …` | ok / flag |
| app start | `server.js` | … | |
| IDE autorun | `.vscode/tasks.json` | … | |
| configs that execute | `next.config.js`, … | … | |
| AI-agent config | `.claude/`, `.mcp.json`, `CLAUDE.md`, `.cursorrules` | … | |
| git | `.git/config`, hooks, `.gitattributes` | … | |
| containers / CI | `Dockerfile`, `.devcontainer/`, `.github/workflows/` | … | |

## Dependencies
| Package | Version | First published | Maintainers | Imported by app? | Scripts | Verdict |
|---|---|---|---|---|---|---|

## Git history
- Commits: <n>, range <first date> → <last date>. Anomalies: <future dates, author mismatch, unrelated messages>.

## Lure assessment
<red flags from the intake, each one line; lure signals alone are not evidence>

## IOCs (de-fanged)
- Hosts / URLs: `hxxps://…[.]…`
- Packages: `name@version`
- Files / persistence names:
- Hashes (sha256):

## Next steps
- [ ] <for CLEAN: safe-run recipe / for MALICIOUS: incident-response steps>
- [ ] Report: <npm / PyPI / GitHub / platform> (user's action)

## Limits of this audit
Static review only. Obfuscated code that could not be decoded: <list or "none">. Not reviewed: <list>.
