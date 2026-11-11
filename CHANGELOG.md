# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-11

### Added

- Repo Audit skill: quarantine acquisition without hooks, eight-phase static audit, execution-surface map, dependency triage, deep read of sinks and sources, git forensics, optional host check, CLEAN / SUSPICIOUS / MALICIOUS verdict with `path:line` evidence.
- Read-only triage scanner `scripts/scan.sh` (bash 3.2 and GNU userland) with `--json`, `--no-tools`, `--all` and `--git` options.
- Read-only host persistence check `scripts/host-check.sh`.
- Reference files for execution surfaces, malicious patterns, dependency triage, social engineering, host compromise, incident response and the 2026-11 case study.
- Inert fixture repos under `tests/fixtures/` and test runners `tests/run.sh` and `tests/host-check-test.sh`.
- Plugin manifest and single-plugin marketplace (`/plugin install repo-audit --marketplace albkhachikyan/claude-code-repo-audit`).
- Manual installer (`install.sh`), `llms.txt`, `CITATION.cff`.

[1.0.0]: https://github.com/albkhachikyan/claude-code-repo-audit/releases/tag/v1.0.0
