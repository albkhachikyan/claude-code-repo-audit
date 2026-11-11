# Dependency triage

Phase 4 reference. The 2026-11 case was a poisoned npm package, not code in the repo (`case-study-2026-11.md`).
Goal: for each direct dependency, decide "known and fine", or pull it into quarantine and read it.

Rules:

- Network is read-only and limited to registry metadata and package downloads (`SKILL.md` rule 5).
- Never `npm install`, `pip install`, `pip download` of an sdist, `cargo build`, `go get` or `go mod download` of unknown modules into the working tree. These run or build code.
- Work in `$Q/deps/`. Pass paths as arguments. Run `scan.sh` on the unpacked copy.
- Set `Q` first: `Q=$HOME/repo-audit-quarantine/<slug>-<date>; mkdir -p "$Q/deps"`.
- Use a neutral cwd (for example `cd "$Q/deps"` after extraction, never inside the target).

## 1. Lockfile and source rules (no network)

| Check | How | Result |
|---|---|---|
| Lockfile exists | `ls package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock` in each dir with `package.json` | none: MEDIUM |
| Lockfile is ignored | `grep -nE '^[[:space:]]*/?(\*\*/)?(package-lock\.json\|yarn\.lock\|pnpm-lock\.yaml)' .gitignore` | HIGH: the attacker can swap versions any time |
| Lockfile was edited late | `git log --format='%h %ad %s' -- package-lock.json` (safe prefix, `--git-dir`) | lockfile changes in a commit whose message does not mention dependencies: HIGH lead |
| Non-registry specs | `grep -nE '"[^"]+"[[:space:]]*:[[:space:]]*"(git\+\|git:\|github:\|gitlab:\|bitbucket:\|https?:\|file:\|link:\|ssh:)' package.json`, also `"[^"]*\.tgz"` | HIGH |
| GitHub shorthand | `"name": "user/repo"` or `"user/repo#ref"` | HIGH |
| Floating versions | `"latest"`, `"*"`, `""`, `">=`, `x`-ranges in direct deps | MEDIUM: the real case used `"latest"` for axios, socket.io-client, node-machine-id |
| Resolved host | `grep -nE '"resolved"[[:space:]]*:' package-lock.json` / `resolved "` in `yarn.lock` / `tarball:` in `pnpm-lock.yaml`; host not `registry.npmjs.org` or `registry.yarnpkg.com` | HIGH |
| Missing integrity | `package-lock.json` entries without `"integrity"` | MEDIUM |
| `overrides` / `resolutions` | `package.json` | MEDIUM; read each target |
| Registry config | `.npmrc`, `.yarnrc.yml`: `registry=`, `@scope:registry=`, `audit=false`, `ignore-scripts=false`, `strict-ssl=false` | HIGH (scoped registry MEDIUM) |
| Lockfile and manifest agree | every direct dep in `package.json` appears in the lockfile with a matching range | mismatch: MEDIUM |
| Same name, two sources | name appears both as registry and git entry | HIGH |
| `bundledDependencies` / `bundleDependencies` | `package.json` | HIGH: code ships inside the tarball and is not checked against the registry |
| Vendored `node_modules/` committed | `find . -name node_modules -maxdepth 3` | MEDIUM: run `scan.sh --all`; compare against the registry tarball |
| Dep never imported | `scan.sh` reports "declared but never referenced"; by hand: `grep -rIlF -- 'pkg' src/ scripts/ *.config.*` | MEDIUM, top lead |
| Dep imported once, used for nothing | one `require('pkg')` and a bare call such as `.setTimestart()` | HIGH lead (real case) |
| Dep does not match the app | DB package in a front-end-only repo, "analytics" or "feed" package in a game | MEDIUM |

Other ecosystems:

| Ecosystem | Lock/manifest files | Non-registry source indicator |
|---|---|---|
| Python | `requirements*.txt`, `Pipfile(.lock)`, `poetry.lock`, `uv.lock`, `pyproject.toml` | `git+`, `@ https://`, `--index-url`, `--extra-index-url` (dependency confusion), `--find-links`, `--trusted-host` |
| Rust | `Cargo.toml`, `Cargo.lock` | `git =`, `path =`, `[patch.`, `[source.` / `replace-with` in `.cargo/config.toml` |
| Go | `go.mod`, `go.sum` | `replace ... =>` to a path or odd host; missing `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` | `git:`, `github:`, `path:`, `source "https://..."` not rubygems.org |
| PHP | `composer.json`, `composer.lock` | `repositories` of type `vcs`, `path`, `package`; `composer-plugin` |
| Java | `pom.xml`, `build.gradle(.kts)` | `<repository>` / `maven { url ... }` to unknown hosts; `mavenLocal()` |

## 2. Registry metadata (read-only)

Pick the dependencies to check: every direct dependency you cannot vouch for, plus every one flagged above. For a small project, check all.

```bash
npm view <pkg> time maintainers repository scripts dist.tarball --json
npm view <pkg>@<ver> dist.tarball dist.integrity dist.attestations --json
npm view <pkg> dist-tags.latest versions --json
```

`npm view` only reads registry metadata. Do not use `npm info` with `--registry` pointing at a URL taken from the target.

Read the output with these questions:

| Signal | Where | Suspicious when |
|---|---|---|
| First publish date | `time.created` | under ~90 days before today, or created the same week as the repo |
| Version burst | `time` | many versions in a few days, or a new version right before the repo was shared (real case: published 2026-11-11, repo audited 2026-11-11) |
| Maintainers | `maintainers` | one maintainer; name looks random (`donna3465657fr`); same maintainer owns the dependency and its helper (`express-json-database` and `inline-array`) |
| Repository | `repository` | missing; points to a repo that does not exist, is empty, or has a different name; repo has no commits matching the published code |
| Scripts | `scripts` | `preinstall`/`install`/`postinstall`/`prepare` present |
| Tarball URL | `dist.tarball` | host is not `registry.npmjs.org` |
| Provenance | `dist.attestations` | absent for a package that claims to be a big project's helper (INFO alone) |
| Description | `description` | "run javascript from a string", "eval", "loader", "dynamic require" for a package that an Express app has no reason to import |
| Name | | one edit away from a popular package (typosquat), or plausible but unknown (slopsquat); see section 5 |
| Downloads | `https://api.npmjs.org/downloads/point/last-week/<pkg>` (read-only JSON) | under ~100 per week for something the app imports for core work (INFO alone; fresh + low is the pattern) |
| Deprecation / removal | `npm view` returns 404 | the package was taken down: treat the repo as MALICIOUS and record the name |

Combine signals. Fresh + single maintainer + imported once + not in the README = pull the tarball.
A famous package with one maintainer is normal.

## 3. Pull the tarball into quarantine and scan it

`npm pack` downloads the tarball. `--ignore-scripts` stops any lifecycle script. Nothing is installed.

```bash
cd "$Q/deps"
npm pack <pkg>@<ver> --ignore-scripts --pack-destination "$Q/deps"
mkdir -p "$Q/deps/<pkg>-<ver>"
tar -xzf "$Q/deps/<pkg>-<ver>.tgz" -C "$Q/deps/<pkg>-<ver>"
<skill-dir>/scripts/scan.sh "$Q/deps/<pkg>-<ver>"
```

Notes:

- Scoped names: the tarball file is `scope-pkg-<ver>.tgz`. List with `ls "$Q/deps"`.
- Tarballs unpack into a `package/` dir. Scan that dir, or the parent; both work.
- Before `tar -xzf`, list it: `tar -tzf <file>.tgz | grep -E '(^|/)\.\./|^/'` must print nothing. If it does, stop: path traversal.
- To fetch without npm at all: `curl -fsSL -o "$Q/deps/x.tgz" "<dist.tarball from npm view>"`. Only for hosts under `registry.npmjs.org`.
- Compare with the repo the package claims: if `repository` exists, clone it bare into quarantine and diff the published `main` file against the repo source. Published code that is not in the repo is a strong signal.
- Check `scan.sh` output first: `known-ioc`, `dynamic-exec`, `remote-exec`, `lifecycle`. Then read `main` from `package.json` and every file it requires.
- What to look for in a loader package (real case `inline-array`): a function that takes a string and compiles it (`new Function`, `vm.runInContext`, `eval`) and hands it `require` or `process`; and in the caller package (`express-json-database`): a timer that fetches a URL and passes the body to that function.

### Recursion rule

Recurse when a package is suspicious. For each of its own `dependencies` (from its `package.json`), apply sections 1, 2 and 3. Stop when:

- the package is a well-known, widely used library (high downloads, many maintainers, matching public repo, provenance), or
- you have already found a confirmed loader: the verdict is MALICIOUS; further recursion only adds IOCs.

Limit: depth 3 and about 10 packages in `--quick` mode. List what you skipped in the report; skipped suspicious packages make the verdict SUSPICIOUS at best.

### What `scan.sh` cannot see inside a tarball

- Binary `.node`, `.so`, `.dll` files. List them: `find "$Q/deps/<dir>" -type f \( -name '*.node' -o -name '*.so' -o -name '*.dll' -o -name '*.dylib' \)`. Each is an unreviewable blob; say so.
- Code fetched at runtime from a host in the package. Record the URL, do not visit it.
- Minified bundles. Beautify them yourself with a script you write, or read the unminified source from the repo.

## 4. Other registries

### PyPI

Metadata (read-only):

```bash
curl -fsSL "https://pypi.org/pypi/<pkg>/json" -o "$Q/deps/<pkg>.json"
curl -fsSL "https://pypi.org/pypi/<pkg>/<ver>/json" -o "$Q/deps/<pkg>-<ver>.json"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["info"]["author"], d["info"]["home_page"], d["info"]["project_urls"]); [print(f["packagetype"], f["filename"], f["upload_time_iso_8601"], f["url"]) for f in d["urls"]]' "$Q/deps/<pkg>-<ver>.json"
```

Read: first upload date (`releases` keys with `upload_time_iso_8601`), uploader, project URLs, yanked flags, whether it ships a wheel and an sdist.

Download the file **by URL** into quarantine with `curl`, and unpack it without installing:

```bash
curl -fsSL -o "$Q/deps/<file>" "<url from the JSON, host files.pythonhosted.org>"
unzip -l "$Q/deps/<file>.whl"            # list first; refuse '..' or absolute entries
unzip -q "$Q/deps/<file>.whl" -d "$Q/deps/<pkg>-<ver>"
tar -tzf "$Q/deps/<file>.tar.gz"         # sdist: list first
tar -xzf "$Q/deps/<file>.tar.gz" -C "$Q/deps/<pkg>-<ver>"
<skill-dir>/scripts/scan.sh "$Q/deps/<pkg>-<ver>"
```

**Never use `pip download` for sdists.** To read an sdist's metadata pip builds it, which runs `setup.py` or the build backend. Wheels are zip files and contain no build step, but still do not `pip install` them.

What to read in a wheel: `*.dist-info/RECORD` (file list and hashes), `*.pth` files (lines starting with `import ` run on every interpreter start), `top_level.txt`, entry points in `entry_points.txt`, and any `.so`/`.pyd`. In an sdist: `setup.py`, `pyproject.toml` `build-backend`, `backend-path`.

### crates.io

```bash
curl -fsSL "https://crates.io/api/v1/crates/<crate>" -o "$Q/deps/<crate>.json"
curl -fsSL "https://crates.io/api/v1/crates/<crate>/<ver>/download" -L -o "$Q/deps/<crate>-<ver>.crate"
tar -tzf "$Q/deps/<crate>-<ver>.crate" | head ; tar -xzf "$Q/deps/<crate>-<ver>.crate" -C "$Q/deps"
```

Send a descriptive `User-Agent` if the API asks for one (crates.io requires one); use a generic name, not your own. Read `build.rs`, `Cargo.toml` `[build-dependencies]`, `proc-macro = true`, and `created_at`, `downloads`, owners (`/api/v1/crates/<crate>/owners`). Never `cargo fetch`/`cargo build` here.

### Go

```bash
curl -fsSL "https://proxy.golang.org/<module>/@v/list"
curl -fsSL "https://proxy.golang.org/<module>/@v/<ver>.info"      # time published
curl -fsSL "https://proxy.golang.org/<module>/@v/<ver>.mod"       # its go.mod
curl -fsSL -o "$Q/deps/mod.zip" "https://proxy.golang.org/<module>/@v/<ver>.zip"
unzip -l "$Q/deps/mod.zip" ; unzip -q "$Q/deps/mod.zip" -d "$Q/deps/<mod>-<ver>"
```

Module paths with capital letters are escaped with `!` plus lowercase in proxy URLs. Read `init()` functions, `//go:generate`, cgo (`import "C"`), `exec.Command`. Never `go get` or `go generate`.

### Ruby, PHP, Java

Use the registry web APIs the same way (`https://rubygems.org/api/v1/gems/<gem>.json`, `https://repo.packagist.org/p2/<vendor>/<pkg>.json`, Maven Central search/`maven-metadata.xml`). Download the archive with `curl`, list, extract, scan. Never run `bundle`, `composer install`, `mvn` or `gradle` on it.

## 5. Typosquats and slopsquats

Typosquat: a name close to a popular one. Slopsquat: a plausible name an LLM invented; an attacker registers it after seeing it suggested.

| Check | How | Suspicious when |
|---|---|---|
| Edit distance | compare each dep name with the top packages you know (`express`, `axios`, `lodash`, `react`, `moment`, `request`, `chalk`, `debug`, `colors`, `socket.io-client`) | one edit, swapped letters, `-js`/`js-` suffix, `.` vs `-`, `l`/`1`/`I`, `rn`/`m` |
| Scope confusion | `@types/foo` vs `types-foo`, `@org/pkg` vs `org-pkg` | unscoped twin of a scoped official package |
| Homoglyphs | non-ASCII in a dependency name or an import string | any (`LC_ALL=C grep -nP` is not portable; use the byte patterns in `malicious-patterns.md` section 4) |
| Plausible but unknown | name reads like a feature ("json-database", "inline-array") but the README does not use it | unknown to you AND fresh AND few downloads |
| Wrong ecosystem name | npm package named like a PyPI one, or the reverse | |
| Look-alike org | repository owner differs by one character from the real project | |
| Install count vs name | a generic helper name with a handful of weekly downloads | |

Never judge by name alone. A match is a reason to run section 2 on it.

## 6. Optional tools

`scan.sh` runs these if installed (unless `--no-tools`) and reports lines as MEDIUM. Run them yourself for detail. None of them should be installed just for this audit without asking the user.

| Tool | Command | Notes |
|---|---|---|
| guarddog (Datadog) | `guarddog npm scan <dir-or-tarball>`; `guarddog npm verify package.json`; `guarddog pypi verify requirements.txt` | Source-code heuristics and metadata rules. https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/ . `verify` contacts the registry. |
| osv-scanner | `osv-scanner scan source -r <dir>` | Known vulnerabilities (CVEs/GHSA) and some MAL- advisories. Syntax unverified for your installed version; check `--help`. Does not find new malware. |
| Socket CLI | `socket ...` | Supply-chain scores. Command syntax unverified; needs an account. |
| semgrep | `semgrep --config p/secrets --metrics=off <dir>` | Pulls rules from the semgrep registry (network). Supply-chain rule pack names unverified. |
| gitleaks | `gitleaks detect --no-git -s <dir>` | Secrets in files. Real secrets in a take-home mean someone else's account; do not use them. |
| trufflehog | `trufflehog filesystem <dir>` | Do not enable verification (`--no-verification`), it would contact services with found secrets. |
| npm audit signatures | `npm audit signatures` | Needs an installed tree; skip. For one tarball use `npm view <pkg>@<ver> dist.attestations`. |
| OpenSSF Scorecard | `scorecard --repo=github.com/<owner>/<repo>` | Repo hygiene score for the package's source repo (INFO). |

A clean result from any of them is not proof. They miss new packages by definition.

## 7. Report lines

| Dependency | Evidence | Verdict |
|---|---|---|
| `express-json-database@2.1.4` | `time.created` 2026-11-11; maintainer `donna3465657fr`; required at `server.js:6`, called at `server.js:20`; tarball fetches a URL on a 30 s timer and passes the body to `inline-array` | MALICIOUS |
| `<pkg>@<ver>` | not pulled (reason) | SUSPICIOUS until pulled |

Always cite the registry fields you read and the date you read them (registry data changes; a package can be removed later).
