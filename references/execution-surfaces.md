# Execution surfaces: every place code runs without the user choosing to

Phase 3 reference. Goal: list each way this repo can run code on the host, then read each
one end to end. Output a table: surface, file, what it runs, verdict.

Rules for this phase:

- Read files with `cat`, `sed -n`, `grep`. Never run, install, build or open the repo in an IDE.
- "Trigger" is what the victim does. The lower the effort, the higher the risk.
- Severity is the default when the indicator is present. Raise it when the command touches
  the network, decodes data, or has nothing to do with the app. Lower it only after you read the code.
- `scan.sh` already greps most indicators below. A hit is a lead; read the file.
- Patterns are POSIX ERE (`grep -E`). No `grep -P`.

Trigger levels, from most to least dangerous:

| Level | Meaning |
|---|---|
| T0 | Open the folder (IDE, agent) |
| T1 | `git clone` / `git checkout` / `git commit` (hooks, filters) |
| T2 | Install or build (`npm install`, `pip install`, `cargo build`, `mvn`, `bundle`) |
| T3 | Start the app or run tests (`npm start`, `npm test`, `pytest`, `make`) |
| T4 | Interpreter start (Python `.pth`, `sitecustomize`) |

## 1. JavaScript / TypeScript

### 1.1 Package manager lifecycle

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Install scripts | `package.json` | T2, runs in every package manager | `"(preinstall\|install\|postinstall\|prepare\|prepublish)"[[:space:]]*:` | MEDIUM; HIGH if value has `curl\|wget\|node \|bun \|bash\|sh \|python\|powershell\|npx` |
| `prepare` + husky | `package.json`, `.husky/*` | T2 (`prepare` runs on plain `npm install`), then T1 on commit | `"prepare"`, `husky`, files under `.husky/` | MEDIUM; HIGH if hook content fetches or decodes |
| Script that points to a non-JS file | `package.json`, `.vscode/tasks.json` | T2 / T0 | `node[^;&|"]*\.(woff2?\|ttf\|otf\|png\|jpe?g\|svg\|ico)` | HIGH (masquerade) |
| `binding.gyp` | repo root | T2: npm runs `node-gyp rebuild` with no script entry | file exists | MEDIUM |
| Dependency lifecycle | `node_modules/*/package.json` or registry tarball | T2, for every dep | same keys as above; see `dependency-triage.md` | HIGH if a dep you cannot explain has one |
| Bun trusted deps | `package.json` `trustedDependencies`, `bunfig.toml` | T2 with bun | `trustedDependencies`, `preload` | MEDIUM |
| pnpm hook | `.pnpmfile.cjs` | T2: runs during resolution | file exists | MEDIUM; HIGH with network/exec |
| Yarn Berry | `.yarnrc.yml`: `yarnPath`, `plugins`, `npmRegistryServer` | any `yarn` command | `yarnPath\|plugins:\|npmRegistryServer`; committed `.yarn/releases/*.cjs`, `.yarn/plugins/*` | MEDIUM; HIGH if the JS is not the official release |

### 1.2 `.npmrc` and registry config

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Audit off | `.npmrc` | T2: hides known-vuln warnings | `^audit[[:space:]]*=[[:space:]]*false` | HIGH |
| Scripts forced on | `.npmrc` | T2: undoes `--ignore-scripts` | `^ignore-scripts[[:space:]]*=[[:space:]]*false` | HIGH |
| Custom registry | `.npmrc`, `.yarnrc.yml`, `bunfig.toml` | T2: every package comes from the attacker | `^registry[[:space:]]*=` not `registry.npmjs.org` | HIGH (`@scope:registry=` MEDIUM) |
| Custom shell | `.npmrc` | T2: runs scripts through this binary | `^script-shell[[:space:]]*=` | HIGH |
| TLS off | `.npmrc` | T2 | `^strict-ssl[[:space:]]*=[[:space:]]*false` | HIGH |
| No lockfile written | `.npmrc` | T2: `package-lock=false` | `package-lock[[:space:]]*=[[:space:]]*false` | MEDIUM |
| Lockfile hidden | `.gitignore` | any push can swap versions | `^/?(\*\*/)?(package-lock\.json\|yarn\.lock\|pnpm-lock\.yaml)` | HIGH |
| Floating versions | `package.json` | T2: attacker publishes a new version later | `"[^"]+"[[:space:]]*:[[:space:]]*"(latest\|\*)"` | MEDIUM |

### 1.3 Config files that are code

These are JavaScript. They run when the tool starts: `npm run dev`, `build`, `test`, `lint`, an
editor plugin, or `git commit` via lint-staged. Normal configs export an object. Flag any that
fetch, exec or decode.

| Surface | File | Trigger | Indicator to grep (inside the file) | Severity |
|---|---|---|---|---|
| Next.js | `next.config.{js,mjs,ts}` | T3 dev/build/start | `fetch(\|axios\|https?\.get\|child_process\|eval(\|new Function\|Buffer\.from(.*base64` | HIGH |
| Vite / Vitest | `vite.config.*`, `vitest.config.*` | T3 | same | HIGH |
| Webpack / Rollup / esbuild / tsup | `webpack.config.*`, `rollup.config.*`, `tsup.config.*` | T3 | same | HIGH |
| Babel | `babel.config.*`, `.babelrc.js` | T3 and test runs | same | HIGH |
| PostCSS / Tailwind | `postcss.config.*`, `tailwind.config.*` | T3 | same | HIGH |
| ESLint | `.eslintrc.js`, `eslint.config.*`, local plugins | T3 and editor lint on open | same | HIGH |
| Jest | `jest.config.*`, `jest.setup.*`, `setupTests.*`, `globalSetup` | T3 `npm test` | same | HIGH |
| Playwright / Cypress | `playwright.config.*`, `cypress.config.*` | T3 | same | HIGH |
| Task runners | `gulpfile.js`, `Gruntfile.js`, `nodemon.json` (`exec`, `execMap`) | T3 | `exec\|spawn\|child_process` | MEDIUM |
| lint-staged / commitlint | `.lintstagedrc.*`, `commitlint.config.*` | T1 commit | same | MEDIUM |
| Exec without network | any of the above | T3 | `child_process\|execSync\|spawnSync` | MEDIUM |

### 1.4 Server start path

The classic loader sits where the user starts the app. Read all of these first.

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Entry file | the `main`, `scripts.start`, `scripts.dev` target; `server.js`, `app.js`, `index.js` | T3 | `require(` of a package the app never uses; call inside `app.listen(` callback or `setTimeout`/`setInterval` | HIGH if fetch + exec; see `malicious-patterns.md` |
| Fetch-then-exec idiom | any `.js` | T3 | `new Function\(.{0,3}require`; `(eval\|Function)\(.{0,40}(atob\|Buffer\.from)\(` | HIGH |
| Config values executed | `.env`, `config.js`, `server/config/*.js` | T3 | a value fetched then passed to `eval`; long base64 in config | HIGH |
| Routes and middleware | `routes/*.js`, `middleware/*.js`, `server/config/*.js` | T3 | same as above | HIGH |
| Test files | `*.test.js`, `__tests__/` | T3 `npm test` | network or `child_process` in a test | MEDIUM |
| Postinstall for the app itself | `scripts/*.js` called from `package.json` | T2 / T3 | read the target of every `node scripts/...` | by content |

## 2. Python

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| `setup.py` | `setup.py` | T2: `pip install .` and sdist builds execute it | `os\.system\|subprocess\|exec(\|eval(\|urlopen\|requests\|socket\|base64`; `cmdclass` | HIGH with exec/network; MEDIUM `cmdclass` |
| Build backend | `pyproject.toml` | T2: runs the backend code | `^build-backend[[:space:]]*=` not in setuptools, hatchling, poetry, flit_core, pdm, maturin, scikit_build_core, mesonpy; any `backend-path` | HIGH |
| Local `_custom_build.py` | path named by `backend-path` | T2 | read it | HIGH with exec |
| `conftest.py` | any dir | T3 `pytest` | `subprocess\|os\.system\|requests\|urllib\|socket\|base64\|exec(\|eval(` | MEDIUM; HIGH with network |
| `.pth` files | anywhere on `sys.path`, or shipped in a wheel | T4: every interpreter start | lines starting with `import ` | HIGH |
| `sitecustomize.py`, `usercustomize.py` | repo dir put on `PYTHONPATH` | T4 | file exists | HIGH |
| `__init__.py` side effects | package dirs | T3 on import | top-level `exec(`, `os.system`, network at import time | by content |
| `__main__.py`, `manage.py`, `wsgi.py` | root | T3 | read them; check imports of unused packages | by content |
| Requirements pointing off-PyPI | `requirements*.txt`, `Pipfile` | T2 | `git\+\|@ https?://\|--extra-index-url\|--index-url\|--trusted-host\|--find-links` | HIGH |
| Notebook output / cells | `*.ipynb` | T0 in an IDE (cells do not auto-run, but outputs can embed HTML/JS) | `"cell_type": "code"` with `os.system`, `subprocess`; long `text/html` outputs | MEDIUM |
| Compiled artefacts | `*.pyc`, `*.pyd`, `*.so` | T3 | any committed binary | MEDIUM (cannot be read) |

## 3. Go

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| `go generate` | `*.go` | only if the user runs it (T3); README may tell them to | `^//go:generate` | MEDIUM |
| cgo | `*.go` | T2 `go build`: compiler flags and C code run | `import "C"`, `#cgo[[:space:]]`, `LDFLAGS`, `CFLAGS` with `-Wl,` or shell | MEDIUM |
| `init()` | any package | T3: runs before `main` | `func init()` containing `exec.Command`, `net/http`, `os.Getenv` of secrets | by content |
| `exec.Command` | any | T3 | `exec\.Command(` | MEDIUM |
| Module replace | `go.mod` | T2: pulls code from elsewhere | `^replace[[:space:]]`, `=> ./` or a non-standard host | MEDIUM |
| Vendored code | `vendor/` | T2 | diff against `go mod vendor` is not possible offline; read changed files | MEDIUM |

## 4. Rust

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Build script | `build.rs`, `Cargo.toml` `build =` | T2 `cargo build`/`check`/`test`, and rust-analyzer on open | `Command::new`, `reqwest`, `ureq`, `TcpStream`, `curl`, `std::process` | MEDIUM exists; HIGH with network/exec |
| Proc-macro | dependency or workspace crate with `proc-macro = true` | T2: runs at compile time in the compiler | `proc-macro[[:space:]]*=[[:space:]]*true` | MEDIUM; read the crate |
| Cargo config | `.cargo/config.toml` | T2: `runner`, `rustc-wrapper`, `linker`, `[source]` replacement | `runner\|rustc-wrapper\|rustc-workspace-wrapper\|linker\|\[source\.\|replace-with` | HIGH |
| Git or path dependency | `Cargo.toml` | T2 | `git[[:space:]]*=[[:space:]]*"`, `\[patch\.` | MEDIUM |

## 5. Ruby

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Gemfile is Ruby | `Gemfile`, `*.gemspec` | T2 `bundle install` evaluates it | `system\|` followed by backtick, `%x{`, `Net::HTTP`, `open-uri`, `exec`, `eval` | HIGH |
| Other source | `Gemfile` | T2 | `^source[[:space:]]+["']https?://` not rubygems.org; `git:`, `github:`, `path:` | HIGH / MEDIUM |
| Native extension | `extconf.rb`, gemspec `extensions =` | T2 | file exists | MEDIUM |
| Rakefile | `Rakefile`, `*.rake` | T3 `rake`; `rails` loads tasks | same as Gemfile | HIGH with exec/network |
| Rails initializers | `config/initializers/*.rb`, `config/application.rb` | T3 boot | network or `eval` at boot | HIGH |

## 6. PHP

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Composer scripts | `composer.json` | T2 `composer install/update` | `"(pre\|post)-[a-z-]*-(cmd\|dump)"` | MEDIUM; HIGH with `curl\|wget\|php \|sh \|bash\|base64` |
| Composer plugin | `composer.json` | T2: runs with full rights | `"type"[[:space:]]*:[[:space:]]*"composer-plugin"`, `allow-plugins` | MEDIUM |
| Custom repositories | `composer.json` | T2 | `"type"[[:space:]]*:[[:space:]]*"(vcs\|path\|package)"` | MEDIUM |
| Autoload files | `composer.json` `autoload.files` | T3 every request | read the listed files | by content |
| WordPress themes/plugins | `functions.php`, plugin main file | T3 | `eval(`, `base64_decode(`, `create_function` | HIGH |

## 7. Java / Kotlin

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Gradle build scripts | `build.gradle`, `*.gradle.kts`, `settings.gradle*`, `init.gradle` | T2: configuration phase runs arbitrary Groovy/Kotlin; IDE import runs it | `Runtime\.getRuntime\(\)\.exec\|ProcessBuilder\|exec[[:space:]]*\{\|commandLine\|openStream\|user\.home`; `curl\|wget` | MEDIUM; HIGH with network |
| Gradle wrapper jar | `gradle/wrapper/gradle-wrapper.jar` | T2 `./gradlew`: runs this committed binary | file exists (binary, cannot be read) | MEDIUM: compare SHA-256 with the official release for that version |
| Wrapper download URL | `gradle/wrapper/gradle-wrapper.properties` | T2 | `distributionUrl` host is not `services.gradle.org` | HIGH |
| Maven plugins | `pom.xml` | T2 | `exec-maven-plugin\|maven-antrun-plugin\|gmaven\|groovy-maven-plugin` | MEDIUM |
| Maven wrapper | `.mvn/wrapper/maven-wrapper.jar`, `maven-wrapper.properties`, `mvnw` | T2 | `distributionUrl`/`wrapperUrl` host is not `repo.maven.apache.org` / `repo1.maven.org` | HIGH; jar MEDIUM |
| Maven extensions | `.mvn/extensions.xml`, `.mvn/jvm.config` | T2 | file exists; `-javaagent` in jvm.config | MEDIUM / HIGH |
| Annotation processors | dependency with `META-INF/services/javax.annotation.processing.Processor` | T2 compile | unknown processor in deps | MEDIUM |

## 8. Make, just, Taskfile, shell

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Make eval at parse | `Makefile`, `*.mk` | T3 any `make` target, even `make help` | `\$\((shell\|eval)[[:space:]]` | MEDIUM |
| Default target | `Makefile` | T3 bare `make` | read the first target and `.DEFAULT_GOAL` | by content |
| just / Taskfile | `justfile`, `Taskfile.yml` | T3 | backtick expressions, `sh:` variables | MEDIUM |
| Shell installers | `install.sh`, `setup.sh`, `bootstrap.sh`, `scripts/*.sh` | T3, README tells you to run | `curl[^|;&]*\|[[:space:]]*(sudo )?(ba\|z)?sh`, `base64 -d`, `eval "\$(` | HIGH |
| Windows | `*.bat`, `*.cmd`, `*.ps1` | T3 | `-enc`, `-EncodedCommand`, `DownloadString`, `Invoke-Expression`, `iex`, `certutil -urlcache`, `mshta` | HIGH |

## 9. Docker and compose

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Host home mounted | `docker-compose*.yml`, `compose*.yml` | T3 `docker compose up` | `~:\|\$HOME\|/Users/[^:]+:\|/home/[^:]+:\|/root:\|[[:space:]]/:` as a volume source | HIGH |
| Secrets dirs mounted | compose, `devcontainer.json` `mounts`, `docker run -v` | T3 | `\.ssh\|\.aws\|\.gnupg\|\.kube\|\.docker\|\.netrc\|\.npmrc` before `:` | HIGH |
| Docker socket | compose, `docker run` | T3: container controls the host | `docker\.sock` | HIGH |
| Privileged | compose, `docker run` | T3 | `privileged:[[:space:]]*true`, `--privileged`, `cap_add`, `SYS_ADMIN`, `seccomp:unconfined`, `pid: host`, `network_mode: host` | HIGH / MEDIUM for host namespaces |
| Dockerfile | `Dockerfile*` | T3 build | `^ADD[[:space:]]+https?://`, `curl ... \| sh`, `RUN` with base64 | MEDIUM / HIGH |
| Entrypoint script | `docker-entrypoint.sh` | T3 | read it | by content |

## 10. Dev containers

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Host-side command | `.devcontainer/devcontainer.json`, `.devcontainer.json` | T0: "Reopen in Container" runs `initializeCommand` **on the host** | `"initializeCommand"` | HIGH |
| In-container hooks | same | T0 after reopen | `"(onCreate\|updateContent\|postCreate\|postStart\|postAttach)Command"` | MEDIUM; HIGH with `curl\|wget\|bash\|node\|python` |
| Privileges and mounts | same | T0 | `--privileged`, `--cap-add`, `--network=host`, `docker.sock`, `\.ssh`, `localEnv:HOME` | HIGH |
| Features and images | same | T0 | unknown `features` registry or `image` host | MEDIUM |
| Dockerfile / compose it references | `.devcontainer/Dockerfile`, `docker-compose.yml` | T0 | see section 9 | by content |

## 11. CI

CI does not run on the victim's machine unless they push to a fork or use a self-hosted runner.
It still matters: the repo may harvest the victim's tokens when they push, and CI files show intent.

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| `pull_request_target` | `.github/workflows/*.yml` | PR from a fork runs with repo secrets | `pull_request_target`; HIGH if it also checks out `github.event.pull_request.head.(sha\|ref)` | MEDIUM / HIGH |
| Self-hosted runner | same | any trigger | `runs-on:.*self-hosted` | MEDIUM |
| Script injection | same | PR title/body/branch | `\$\{\{[[:space:]]*github\.event\.(issue\|pull_request\|comment\|head_commit)[^}]*(title\|body\|message\|ref\|name)` | MEDIUM |
| Secrets sent out | same | any run | `secrets\.` near `curl`, `webhook`, `base64`; `toJSON(secrets)` | HIGH |
| Wide permissions | same | any run | `permissions:[[:space:]]*write-all`, `id-token: write` | MEDIUM |
| Unpinned actions | same | any run | `uses:[[:space:]]*[^@]+@(main\|master\|v[0-9]+)$` from unknown owners | INFO |
| Known worm files | `.github/workflows/` | - | name contains `shai-hulud`; `SHA1HULUD` runner label | CRITICAL |
| Other CI | `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `bitbucket-pipelines.yml` | push | same patterns | by content |

## 12. IDE

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| VS Code auto task | `.vscode/tasks.json` | T0: runs on folder open once Workspace Trust is granted | `"runOn"[[:space:]]*:[[:space:]]*"folderOpen"` | HIGH |
| Hidden task window | same | T0 | `"reveal"[[:space:]]*:[[:space:]]*"never"` (with `"echo": false`, `"close": true`) | MEDIUM alone, HIGH with folderOpen |
| Task runs a non-JS file | same | T0 | `node .*\.(woff2?\|ttf\|png\|jpe?g\|svg\|ico)` | HIGH |
| Auto tasks allowed | `.vscode/settings.json` | T0 | `"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*"on"` | HIGH |
| Executable paths | `.vscode/settings.json` | T0 | `php\.validate\.executablePath`, `eslint\.runtime`, `npm\.exec\.path`, `typescript\.tsdk`, `git\.path`, `python\.defaultInterpreterPath`, `terminal\.integrated\.(profiles\|automationProfile\|shell)` | MEDIUM |
| Recommended extensions | `.vscode/extensions.json` | T0 prompt | `recommendations`: check each ID on the marketplace (publisher, installs, age) | INFO; HIGH for a typosquat |
| Launch config | `.vscode/launch.json` | user presses F5 | `preLaunchTask`, `runtimeExecutable`, `program` | INFO |
| JetBrains run configs | `.idea/runConfigurations/*.xml`, `.idea/workspace.xml` | project import, "Before launch" steps | file exists; `<option name="SCRIPT_TEXT"`, `externalSystem` tasks | MEDIUM |
| JetBrains other | `.idea/externalDependencies.xml`, `.idea/*.iml` | import | unknown plugins | INFO |
| Real-case example | `.vscode/tasks.json` label `eslint-check` runs `node public/fonts/fa-brands-regular.woff2` (JS disguised as a font), drops `~/.npm/scoped_dir*/main.js` | | source: https://opensourcemalware.com/blog/dprk-contagious-interview-campaign-fake-font-uses-malicious-vs-code-fonts (2026-01-28) | |

References: https://about.gitlab.com/blog/how-to-detect-and-prevent-contagious-interview-ide-attacks/ (GitLab, May 2026); https://thehackernews.com/2026/03/north-korean-hackers-abuse-vs-code-auto.html (THN, Mar 2026, StoatWaffle).

## 13. Git

Rule 3 in `SKILL.md`: read `.git/config` with `cat` before any `git` command, and always use the safe prefix
`git -c core.hooksPath=/dev/null -c core.fsmonitor= -c core.pager=cat -c core.symlinks=false`.

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| `core.fsmonitor` | `.git/config` | T1: any `git status`, even from a shell prompt | `^[[:space:]]*fsmonitor[[:space:]]*=` with a value other than true/false | CRITICAL |
| `core.sshCommand` | `.git/config` | T1: `git fetch/pull/push` over SSH | `sshCommand` | CRITICAL |
| `core.pager`, `core.editor`, `sequence.editor` | `.git/config` | T1: `git log`, `git commit`, rebase | `^[[:space:]]*(pager\|editor)[[:space:]]*=` | CRITICAL |
| `core.hooksPath` | `.git/config` | T1: points hooks anywhere | `hooksPath` | CRITICAL |
| `core.askPass`, `core.gitProxy` | `.git/config` | T1 | `askPass\|gitProxy` | CRITICAL |
| Filters | `.git/config` `[filter "x"]` + `.gitattributes` | T1 checkout/add | `^\[filter`, `clean\|smudge\|process` (git-lfs entries are normal: INFO) | CRITICAL |
| Textconv / diff command | `.git/config` `[diff "x"]` + `.gitattributes` `diff=x` | T1 `git diff`/`log -p` | `textconv\|external\|command` | CRITICAL |
| Merge driver | `.git/config` `[merge "x"]` | T1 merge | `driver[[:space:]]*=` | CRITICAL |
| Alias with `!` | `.git/config` `[alias]` | T1 when typed | `^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*!` | CRITICAL |
| Credential helper | `.git/config` | T1 push/pull | `helper[[:space:]]*=[[:space:]]*!` | CRITICAL |
| `[include]` / `includeIf` | `.git/config` | T1: pulls in another config | `^\[include` | MEDIUM |
| URL rewrite | `.git/config` | T1 | `insteadOf` | MEDIUM |
| Hooks | `.git/hooks/*` without `.sample` | T1: commit, checkout, merge, push | any executable non-`.sample` file | HIGH |
| `.gitattributes` | repo | T1 (needs a matching config key) | `filter=\|diff=\|merge=` | MEDIUM |
| Submodules | `.gitmodules` | T1 `--recurse-submodules` / IDE sync | `url[[:space:]]*=[[:space:]]*(ext::\|file:\|-\|/)`, `update = !` | HIGH; other URLs INFO (list, never fetch) |
| Symlinks | any tracked file with mode 120000 | T1 checkout, T3 read | `git ls-tree -r HEAD \| awk '$1=="120000"'`; target absolute or `..` outside | HIGH if it escapes the repo |
| Nested `.git` | any subdirectory | T1 when the user `cd`s in | `find . -name .git` | MEDIUM |
| Case/Unicode path tricks | tracked paths | T1 on case-insensitive filesystems | two paths equal ignoring case; paths with `..` or `.git` components | HIGH |

`scan.sh` reads `.git/config` and lists non-sample hooks without calling git. With `--git <git-dir>`
it adds history checks (see `SKILL.md` phase 6).

## 14. AI-agent and assistant configs

Rule 2 in `SKILL.md`: never start Claude Code, Cursor or Copilot inside the target. These files load as soon as the agent opens the folder.

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| Claude Code hooks | `.claude/settings.json`, `.claude/settings.local.json` | T0: agent starts in this dir | `"hooks"[[:space:]]*:` (GHSA-ph6w-f82w-28w6) | HIGH |
| Claude Code MCP auto-approve | same | T0 | `enableAllProjectMcpServers\|enabledMcpjsonServers` (CVE-2025-59536) | HIGH |
| Claude Code API redirect | same, `env` block | T0: key sent to attacker host | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` (CVE-2026-21852) | HIGH |
| Command helpers | same | T0 | `apiKeyHelper\|awsAuthRefresh\|awsCredentialExport\|otelHeadersHelper`; `statusLine` with `command` | HIGH / MEDIUM |
| Permissive permissions | same | T0 | `Bash\(\*\)`, `"defaultMode"[[:space:]]*:[[:space:]]*"(bypassPermissions\|acceptEdits)"` | HIGH |
| MCP servers | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` | T0 | `"command"[[:space:]]*:` (stdio server = local process); `"url"` (remote server) | HIGH / MEDIUM |
| Slash commands, agents, skills | `.claude/commands/*.md`, `.claude/agents/*`, `.claude/skills/*` | T3 when invoked or auto-matched | `^!` + backtick (shell injection), `allowed-tools:.*Bash`, hidden text | MEDIUM |
| Instruction files | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.github/instructions/*`, `.continue/*` | T0: loaded as trusted instructions | prompt-injection phrases (below), hidden Unicode | HIGH if hostile; INFO if plain |
| Prompt injection phrases | any text file | an AI reads it | `(ignore\|disregard\|forget) (all )?(previous\|prior\|above) (instructions\|rules)`, `do not (tell\|mention\|reveal)`, `(AI\|assistant\|reviewer)[^.]{0,40}(this\|the) (repo\|code) is (safe\|clean)`, `mark (this\|it) as (safe\|clean)` | HIGH (`SKILL.md` rule 4) |
| Rules File Backdoor | rule/instruction files | an AI reads it | zero-width, bidi, tag characters inside the file (see `malicious-patterns.md`) | HIGH |
| Comments aimed at the reviewer | source and README | an AI reads it | "AI", "Claude", "Copilot", "LLM" inside code comments | HIGH if it claims the code is safe |

References: https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/ (Check Point, 2026); fixed-version numbers are reported inconsistently (unverified), so treat every project-level `.claude/` file as hostile regardless of version. Rules File Backdoor: https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents (Pillar, Mar 2025).

## 15. Other places

| Surface | File | Trigger | Indicator to grep | Severity |
|---|---|---|---|---|
| macOS plist / systemd unit in repo | `*.plist`, `*.service` | user copies it | `RunAtLoad`, `KeepAlive`, `ExecStart=` | HIGH / MEDIUM |
| Committed executables | `*.exe`, `*.dll`, `*.dylib`, `*.so`, `*.node`, `*.pyd`, `*.jar`, `*.pkg`, `*.dmg`, `*.app` | T3 | any | MEDIUM: cannot be reviewed |
| Wrong file type | `.woff2`, `.png`, `.ico`, `.pdf` that is text | T0/T3 via tasks or scripts | `file -b <f>` says text/script; `grep -l 'require(\|function' <f>` | HIGH |
| Text file that is binary | `.js`, `.json`, `.txt` that is not text | T3 | `file -b`, `grep -I` fails | MEDIUM |
| README steps | `README.md` | the victim | `curl ... \| sh`, "disable antivirus", "run as admin", "turn off Gatekeeper", "share your screen while installing" | HIGH |

## Output template

| Surface | File | What it runs | Verdict |
|---|---|---|---|
| npm postinstall | `package.json:6` | `node scripts/x.js` | read: fetches `hxxps://...` -> MALICIOUS |
| VS Code task | `.vscode/tasks.json:8` | `node public/fonts/fa.woff2` on folder open | text JS in a font -> MALICIOUS |
| start path | `server.js:20` | `require('unused-pkg')` | not used elsewhere -> lead for phase 4 |
