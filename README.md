# Bulwark

Open-source, self-updating application security and code quality scanning in one tool:
dependency vulnerabilities and SBOMs (SCA), licenses, SAST with taint tracking, C/C++ defects,
secrets (including git history), infrastructure-as-code, container base images, complexity,
duplication and coverage. An open alternative to Black Duck, Coverity, SonarQube and Fortify.

Bulwark doesn't reinvent scanners. It runs proven open-source engines at **signed, pinned
versions**, normalizes their output into one finding model, removes duplicates across engines,
and gives you one report, one quality gate and one dashboard. It then keeps itself current
and keeps watching what you shipped.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.sh | sh
bulwark scan path/to/project
```

Or from source: `dotnet run --project src/Bulwark.Cli -- scan path/to/project`. Docker is
required: engines run from their pinned container images (or from a local install on `PATH`;
`--container` forces the pinned image). Images Bulwark builds itself are built automatically
the first time they're needed.

The dashboard (`dotnet run --project src/Bulwark.Web`) shows every scanned project, lets you
triage findings, and re-checks dependencies for new advisories every day while it runs.

```
bulwark scan [path] [--format table|json|sarif|markdown|codeclimate] [--output file]
             [--fail-on critical|high|medium|low|none] [--since <git-ref> | --baseline <report.json|last>]
             [--min-coverage 80] [--max-duplication 5] [--max-complexity 15]
             [--image ref,ref] [--rules dir] [--history full|off|<range>] [--engines a,b] [--container]
             [--sarif-output f] [--summary-output f] [--codeclimate-output f] [--no-update]
bulwark triage <id> false-positive|accepted-risk|confirmed|fixed|reset --reason "..." [--expires date] [--shared]
bulwark monitor [--webhook url] [--fail-on high]     re-check saved SBOMs for new advisories
bulwark fix [path] [--dry-run] [--pr]                upgrade vulnerable dependencies
bulwark update | canary | self-update | engines [watch]
```

Exit codes: `0` passed, `1` a gate failed, `2` error.

## How it fits together

| Project | Role |
|---|---|
| `Bulwark.Core` | Finding model, fingerprints, merging, policy, triage, gates, monitoring, fix planning, signed-manifest updater |
| `Bulwark.Engines` | One adapter per engine (`IEngine`), `ToolRunner` (local binary or pinned container), the rule pack and the canary corpus |
| `Bulwark.Ai` | LLM clients (Claude, Ollama) for the AI pen-test review |
| `Bulwark.Cli` | `bulwark` command |
| `Bulwark.Web` | Blazor dashboard over saved reports, with triage and daily advisory monitoring |

**Fingerprints** are stable across scans and engines: vulnerabilities key on package and
canonical advisory id (CVE preferred), and code findings key on rule, file and normalized
snippet rather than line number. So triage decisions stick, and the same CVE reported by two
engines appears once.

Reports, SBOMs, triage, caches and the installed manifest live in `~/.bulwark` (override
with `BULWARK_HOME`), never inside the scanned repo.

## Staying current automatically

Every engine version is declared once, in [`engines/engines.json`](engines/engines.json).

- **Weekly upstream watch** ([`engine-watch.yml`](.github/workflows/engine-watch.yml)). The
  workflow moves each engine to the newest upstream release that is **at least 14 days old**,
  which gives the community time to catch broken or compromised releases. It also rewrites
  Dockerfile pins (release hashes, base images), rebuilds the engines and runs the canary
  check, then opens a PR.
- **Signed manifest** ([`engines-release.yml`](.github/workflows/engines-release.yml)). On
  merge, the workflow builds the self-built engine images for amd64 and arm64 and resolves every
  image to a digest. It runs the canary check against exactly those digests, then signs the
  manifest (ECDSA P-256, compatible with `cosign sign-blob --key`) and publishes it.
- **Clients update themselves.** `bulwark scan` checks for a newer manifest once a day. The
  updater rejects:
  - unsigned or wrongly signed manifests
  - engines without image digests
  - unknown schema versions
  - anything older than what is installed (rollback protection)
- **Canary check, then rollback.** After installing, Bulwark scans a built-in vulnerable corpus.
  If any engine no longer finds what it must, the previous manifest is restored and the bad one
  is skipped from then on. You can run the check yourself with `bulwark canary`.
- **Binary updates.** The signed manifest also names the latest Bulwark release with a SHA-256
  for each platform. `bulwark self-update` installs it only if the hash matches.

Opt out of automatic checks with `BULWARK_AUTO_UPDATE=0` or `--no-update`.

**Setting it up for your fork:**

1. Run `bulwark manifest keygen keys/`, commit `keys/bulwark-signing.pub`, and store the private
   key as the repository secret `BULWARK_SIGNING_KEY`.
2. Make the GHCR packages under `bulwark-engines` public after the first run, so clients can pull
   them.
3. Replace `OWNER/REPO` in `scripts/install.sh` and `ci/gitlab/bulwark.gitlab-ci.yml`.
4. Push a `v*` tag. The release workflow builds the binaries and refreshes the manifest, and
   release binaries then find the manifest and the public key on their own.

## Handling findings

- **Triage that sticks.** Mark a finding as a false positive or accepted risk (with a reason
  and an optional expiry date) in the dashboard or with `bulwark triage`. Decisions are keyed by
  fingerprint, so they survive rescans and code moves. With `--shared` they're written to
  `.bulwark/triage.json` in the repository, where they're reviewed like code and CI sees them
  too.
- **Ignored paths.** `.bulwark/ignore` uses gitignore-style patterns for fixtures, vendored code
  and deliberately vulnerable samples.
- **Gate on new code only.** `--since origin/main` fails only on findings on lines the change
  touched, or on dependency versions it introduced. `--baseline last` (or a saved report) fails
  only on findings not seen before. Existing debt stays visible but doesn't block merges.
- **Continuous monitoring.** Every scan saves the SBOM. `bulwark monitor` (or the running
  dashboard, daily) asks OSV.dev about every saved dependency. When a new advisory affects
  something you already ship, it's added to the report and posted to `--webhook` /
  `BULWARK_WEBHOOK` (Slack, Teams, Discord, Mattermost). Only package names and versions are
  sent, as with OSV-Scanner.
- **Automatic fixes.** `bulwark fix` upgrades each vulnerable dependency to the smallest version
  that fixes all of its advisories. It first checks that version against OSV and moves higher if
  the target has advisories of its own. It supports npm (lockfile-only, scripts disabled,
  `overrides` for transitive dependencies), NuGet, pip `requirements*.txt` pins and Go modules.
  `--pr` commits to a branch and opens a pull request.

## CI

**GitHub Actions**:

```yaml
permissions: { contents: read, security-events: write, pull-requests: write }
steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }
  - uses: OWNER/REPO@v1          # this repository's action.yml
    with: { fail-on: high }
```

On pull requests the action:
- fails only on new findings
- updates a single summary comment
- writes the job summary
- uploads SARIF, so findings appear inline in the diff (code scanning)
- scans only the PR's commits for secrets

**GitLab**: include [`ci/gitlab/bulwark.gitlab-ci.yml`](ci/gitlab/bulwark.gitlab-ci.yml).
Findings show in the merge request widget and diff through the code quality report.

## AI pen-test review

```bash
bulwark scan . --ai claude                     # Claude (ANTHROPIC_API_KEY or `ant auth login`)
bulwark scan . --ai claude-code                # Claude via your Claude Code login (`claude -p`); no API key
bulwark scan . --ai ollama --ai-model qwen3-coder   # local model; no code leaves the machine
         [--ai-min-severity medium] [--ai-max 25]
```

Scanners report that a vulnerable thing is *present*. A pen tester asks whether an attacker can
*reach* it. With `--ai`, Bulwark gives each finding at or above `--ai-min-severity` (most
severe first, up to `--ai-max`) to a model with the evidence a tester would look at: the flagged
code, and for dependency CVEs, every place the project imports or calls the package. The model
returns a verdict (`likely`, `possible`, `not_exploitable` or `unknown`), its confidence, its
reasoning, the attack path, how to verify the finding against a test environment, and a fix.
These appear in the table, the JSON report and SARIF (`aiExploitability`, `aiReasoning`, ...).

Guardrails:

- **Advisory only.** An assessment never changes a finding's severity or the quality gate, so
  a wrong model answer can't hide a real vulnerability. Use it to choose what to fix first.
- **Repository content is untrusted.** Code and advisory text go to the model inside tagged
  blocks, and the prompt tells the model to ignore any instructions inside them. Evidence
  paths that point outside the scanned tree are refused.
- **Secrets never go to a model.** Secret findings aren't reviewed, and the evidence collector
  refuses to excerpt code around them. A leaked credential is exploitable by definition: rotate it.
- **Descriptive, not weaponized.** Verification steps describe what to test. They aren't
  working exploits.
- **The model can only answer.** `--ai claude-code` runs the CLI with all tools, MCP servers
  and settings disabled, from an empty directory.
- **Data locality is explicit.** `--ai claude` and `--ai claude-code` print a notice that excerpts leave the
  machine. `--ai ollama` (honours `OLLAMA_HOST`) keeps everything local.

Code: `Bulwark.Core/Ai` (provider-neutral reviewer and evidence collection) and `Bulwark.Ai`
(the Claude API, Claude Code and Ollama clients behind `ILlmClient`).

## Active testing (AI-planned DAST)

```bash
bulwark pentest init                                  # writes bulwark-scope.json to fill in
docker build -t bulwark-engines/nuclei:v3.11.1 engines/nuclei   # once: nuclei + pinned templates
bulwark pentest https://staging.example.com --scope bulwark-scope.json --i-am-authorized \
        [--ai claude|claude-code|ollama] [--source path/to/repo] [--openapi openapi.json]
```

The static review predicts what is exploitable. `bulwark pentest` tests a **running** instance
to confirm it:

1. **Discovery.** A ZAP baseline scan spiders the target and runs passive checks (headers,
   cookies, information leaks). It sends no attack payloads.
2. **Planning.** With `--ai`, a model reads the discovered URLs and, with `--source`, the
   findings that `bulwark scan --ai` marked `likely` or `possible`. It proposes nuclei template
   tags, paths to focus on, and which static findings each check should confirm. Without
   `--ai`, a default plan runs (`exposure`, `misconfig`). The planner can add `cve`, `tech`
   and others when discovery shows specific software.
3. **API scan** (with `--openapi`). ZAP imports the spec, so it reaches endpoints a crawler
   can't find. It runs in safe mode (no attack payloads) unless the scope sets
   `"allowActiveScan": true`. The spec's server URLs are replaced with the scope target, so a
   spec that names production can't redirect the test.
4. **Targeted checks.** nuclei runs the plan's HTTP templates. The plan is capped at 6 tags and
   3 focus paths, and the planner is told the rate limit and time left, so it sizes the run
   to fit.
5. **Correlation.** With `--ai` and `--source`, the model checks each planned hypothesis
   against the dynamic findings and marks the static finding `confirmed`, `refuted` or
   `inconclusive`. "Confirmed" must cite a dynamic finding that exists, or it is downgraded.
   Not finding something is not counted as refuting it. nuclei doesn't fuzz parameters, so
   bugs like SQL injection usually come back `inconclusive`, with a note on the manual test
   that would settle them.

**Authenticated scans.** Add `"auth": { "header": "Authorization", "valueFromEnv": "BULWARK_AUTH" }`
(or `"header": "Cookie"`) to the scope and export the full header value in that variable. The
secret never goes in the scope file, and an inline value is rejected. ZAP gets it through its
`ZAP_AUTH_HEADER*` variables and nuclei through a secrets file restricted to the target host.
Both are handed to the containers by name, so the value doesn't appear in `ps`, the request
log or the report. The report records only the header name.

Findings get category `Dynamic` and land in the same report, dashboard and SARIF as static
ones. The report also records who authorized the test, the scope file's SHA-256, the plan,
counts of sent and blocked requests, and the correlation results. The dashboard shows them on
the target's page.

**Guardrails.** These are enforced in code, not by a prompt:

- **No run without authorization.** It needs a scope file naming the owner, a ticket or
  contract reference, and an expiry, plus `--i-am-authorized`. An expired scope, a placeholder,
  an unknown field (a typo like `exlude`), a wildcard host, or a target outside the scope all
  stop the run before any request.
- **Every engine request goes through Bulwark's scope proxy.** It checks method, scheme, host,
  port and the path after resolving `..` and `%2e%2e`. It rate-limits to `maxRequestsPerSecond`
  and logs every request, allowed or blocked, to `~/.bulwark/pentests/*.requests.jsonl`. HTTPS
  tunnels are allowed only to `https` targets and are checked by host and port, since the proxy
  doesn't decrypt TLS. Path rules for HTTPS rely on the engines' own targeting.
- **Read-only by default.** Only GET, HEAD and OPTIONS are allowed until the scope adds more.
  Excludes are prefix matches, so `/logout` also covers `/logout.php`.
- **The model only proposes.** Tags must be on an allowlist, and `dos`, `intrusive`, `fuzz`,
  brute-force and default-login templates are always excluded. Every focus path must pass the
  scope check. Anything refused is listed in the report.
- **No traffic outside the scope.** Only HTTP templates run, out-of-band (interactsh) callbacks
  and update checks are off, and nuclei's templates are pinned and hash-verified in the image.
- **A time budget bounds the whole run.** Engines get a deadline slightly before the budget
  ends. An engine that is cut off keeps the results it already wrote, and the report says it
  was stopped. Engine containers are removed, not just their docker clients.
- Secrets from static findings never reach the planner.

The proxy binds to loopback (or, on Linux, the Docker bridge gateway), never `0.0.0.0`.

## Engines

| Engine | Covers | License |
|---|---|---|
| Syft | SBOM (CycloneDX) and licenses | Apache-2.0 |
| OSV-Scanner | Known vulnerabilities in dependencies | Apache-2.0 |
| Opengrep | SAST with Bulwark's rule pack, including taint tracking (C#, JS/TS, Python, Java, Go, C/C++) | LGPL-2.1 |
| cppcheck | C/C++ defects: out-of-bounds, use-after-free, double free, uninitialized data, leaks | GPL-3.0 (run as a separate process only) |
| gitleaks | Secrets in current files and git history | MIT |
| Trivy | IaC (Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Ansible) and container base images | Apache-2.0 |
| lizard | Cyclomatic complexity and duplicated code (30+ languages) | MIT |
| ZAP (baseline) | DAST: discovery and passive checks (`bulwark pentest`) | Apache-2.0 |
| nuclei | DAST: targeted template checks (`bulwark pentest`) | MIT |

Adding an engine means one class implementing `IEngine` and one entry in `engines/engines.json`.
Any engine that can output SARIF can use the shared `SarifParser`. Engines without an official
image (opengrep, cppcheck, lizard, nuclei) get a Dockerfile under [`engines/`](engines) that
verifies the pinned release by SHA-256.

### SAST rules

Bulwark ships its own Apache-2.0 rule pack in
[`src/Bulwark.Engines/Rules`](src/Bulwark.Engines/Rules), embedded in the binary:

- **Pattern rules** for SQL and command injection, eval, insecure deserialization, disabled TLS
  validation, XSS sinks, weak hashes, and unsafe C string/format/command APIs.
- **Taint rules** ([`taint.yaml`](src/Bulwark.Engines/Rules/taint.yaml)). These follow request
  data in Flask/Django, Express, ASP.NET Core, servlets and net/http to SQL, shell, eval, file
  paths and HTML responses. Sanitizers such as `int()` and `parseInt` end the flow, so a hit is a
  real data path.

Semgrep's registry rules are deliberately not used, because their license forbids bundling
them in a competing tool. Add your own Opengrep/Semgrep-syntax rules with `--rules path/to/rules`.

### C and C++

cppcheck needs no build system or compile database. Its findings are graded by defect class:
memory corruption is Critical, uninitialized reads and null dereferences are High, leaks are
Medium. Opengrep's C rules add `strcpy`/`sprintf`/`gets`, non-constant format strings and
`system()` with runtime strings.

### Container images

Bulwark finds the final-stage base image of every Dockerfile (resolving `ARG` defaults and
skipping build stages and `scratch`) and scans it with Trivy, along with any image passed
with `--image`. Only vulnerabilities with a fix are reported unless you pass
`--image-include-unfixed`. Images are pulled from their registry, and Trivy's vulnerability
database is cached in `~/.bulwark/cache`.

### Code quality

lizard reports functions over `--max-complexity` (default 15) and duplicated blocks as `Quality`
findings. They're Low/Medium, so they never trip the default security gate. Project totals
appear in the CLI, the PR summary and the dashboard:
- average and highest complexity
- duplication rate
- line coverage, read from reports your tests already produce (Cobertura XML or `lcov.info`)

Gate on them with `--min-coverage` and `--max-duplication`.

### Infrastructure as code

Trivy runs whenever the project has Terraform, a Dockerfile, a Helm chart or a compose file,
or YAML/JSON that looks like Kubernetes, CloudFormation or ARM (detected by peeking at file
contents). It uses the checks built into the pinned Trivy version (`--skip-check-update`), so
results change only when the manifest moves Trivy forward, and the scan works offline.

### Secrets

gitleaks' raw report contains the secrets, so Bulwark parses it and deletes it right away.
Findings keep only a hash of the value (for a stable id) and the first 4 characters (to
identify the key type). The value itself is never written to reports, SARIF or the dashboard.
When the scan root is a git repository, Bulwark also scans its **full history** by default. A
secret found in both the current files and history becomes one finding noting the commit that
first added it. A secret that was deleted but still lives in history gets its own "Secret in git
history" finding, because anyone with a clone can still read it. Commit author names and emails
are not stored.

- `--history off` scans only the current files.
- `--history origin/main..HEAD` (any `git log` range) scans just a PR's commits, which is fast in CI.
- For options that start with `--`, use the `=` form: `--history=--since=2025-01-01`.

## Roadmap

Done: signed self-updating engines with canary check and rollback, self-update, the upstream
watch bot, sticky triage, the new-code gate, SBOM monitoring with alerts, automatic dependency
fix PRs, GitHub/GitLab integration, taint rules, C/C++ analysis, base-image scanning and code
quality metrics. Next:

1. Deeper interprocedural C/C++/Java analysis (Infer, Clang Static Analyzer with a compile
   database).
2. Reachability for dependency CVEs: only flag vulnerable functions the code actually calls.
3. Base-image upgrade suggestions (newer tag or digest) in `bulwark fix`.
4. Organization view in the dashboard: many repositories, trends over time, authentication.
5. More taint sources and sinks (Spring, Django ORM raw queries, Go frameworks) and more languages
   (Ruby, PHP, Kotlin).
6. Keyless (Sigstore) verification of upstream engine releases in addition to hash pinning.
7. ~~Optional LLM triage (local via Ollama, or bring your own key).~~ Done: `--ai` exploitability review.
8. ~~AI-driven active pen testing (DAST)~~ Done: `bulwark pentest`, with header-based
   authenticated scans, OpenAPI-driven API scans and AI correlation of dynamic results to static
   findings. Next: scripted login flows (form and OAuth) for apps without a static token, and
   ZAP active scans aimed at the planner's focus paths.

## License

Bulwark is licensed under [Apache-2.0](LICENSE). Each engine keeps its own license (see the
engines table). Bulwark only runs engines as separate processes or containers and never links
them, so GPL engines like cppcheck don't affect Bulwark's license.
