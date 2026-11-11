# Bulwark

Open-source, self-updating application security scanning: dependency vulnerabilities (SCA),
SBOMs, license compliance, SAST, secrets and infrastructure-as-code, in one tool.
An open alternative to Black Duck, Coverity, SonarQube and Fortify.

Bulwark doesn't reinvent scanners. It runs proven open-source engines at **signed, pinned
versions**, normalizes their output into one finding model, removes duplicates across engines,
and gives you one report, one quality gate and one dashboard.

## Quick start

```bash
dotnet run --project src/Bulwark.Cli -- scan path/to/project
dotnet run --project src/Bulwark.Web            # dashboard of all scans
```

Engines run from a local install when they're on `PATH`, otherwise from their pinned
container image (Docker required). Use `--container` to always use the pinned image.

```
bulwark scan [path] [--format table|json|sarif] [--output file]
                    [--fail-on critical|high|medium|low|none] [--engines a,b] [--container]
bulwark engines                     pinned engines and how each will run
bulwark update [--url url | --from-file manifest.json] [--key public.pem]
bulwark manifest keygen [dir]       (maintainers) create a signing key pair
bulwark manifest sign <file> --private-key <key>
```

Exit codes: `0` passed, `1` quality gate failed, `2` error. SARIF output drops straight
into GitHub code scanning.

## How it fits together

| Project | Role |
|---|---|
| `Bulwark.Core` | Finding model, fingerprints, merging, policy, reports, signed-manifest updater |
| `Bulwark.Engines` | One adapter per engine (`IEngine`), plus `ToolRunner` (local binary or pinned container) |
| `Bulwark.Ai` | LLM clients (Claude, Ollama) for the AI pen-test review |
| `Bulwark.Cli` | `bulwark` command |
| `Bulwark.Web` | Blazor dashboard over saved reports |

**Fingerprints** are stable across scans and engines: vulnerabilities key on package and
canonical advisory id (CVE preferred), and code findings key on rule, file and normalized
snippet rather than line number. So triage decisions stick, and the same CVE reported by two
engines appears once.

**Auto-update.** Engine versions come from a manifest signed with ECDSA P-256. The signature
format is compatible with `cosign sign-blob --key`. The updater rejects unsigned or wrongly
signed manifests, engines without image digests, unknown schema versions, and any manifest
older than the installed one (rollback protection).

Reports and the installed manifest live in `~/.bulwark` (override with `BULWARK_HOME`),
never inside the scanned repo.

## AI pen-test review

```bash
bulwark scan . --ai claude                     # Claude (ANTHROPIC_API_KEY or `ant auth login`)
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
- **Data locality is explicit.** `--ai claude` prints a notice that excerpts leave the
  machine. `--ai ollama` (honours `OLLAMA_HOST`) keeps everything local.

Code: `Bulwark.Core/Ai` (provider-neutral reviewer and evidence collection) and `Bulwark.Ai`
(the Claude and Ollama clients behind `ILlmClient`).

### Next: AI-driven active testing (DAST), designed but not yet built

The review above is static. The next phase points an AI agent at a **running** instance:

- `bulwark pentest <url> --scope scope.yaml --i-am-authorized`. The scope file lists the hosts,
  path prefixes and methods that may be tested. Requests outside it are blocked in the HTTP
  layer, not by the prompt. With no scope file or authorization flag, it doesn't run.
- The agent drives pinned, signed engines (ZAP baseline/API scan, nuclei with a curated
  template set) through tools, the same way static engines run today. It never sends raw
  requests.
- Seeded by the static results: `likely` findings become targeted test cases, so the active
  run confirms or refutes what the static review predicted.
- Safe by default: no destructive methods or templates, rate limits, a time budget, and a
  full request log saved with the report. Confirmed issues become `Finding`s with category
  `Dynamic`, deduplicated against static ones by fingerprint.

## Engines

| Engine | Covers | Status |
|---|---|---|
| Syft | SBOM (CycloneDX) and licenses | ✅ |
| OSV-Scanner | Known vulnerabilities | ✅ |
| Opengrep | SAST (C#, JS/TS, Python, Java, Go) | ✅ |
| gitleaks | Secrets in current files and git history | ✅ |
| Trivy | IaC: Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Ansible | ✅ |
| Infer / Clang Static Analyzer | Deep C/C++/Java analysis | planned |

Adding an engine means one class implementing `IEngine` and one manifest entry. Any engine
that can output SARIF can use the shared `SarifParser`.

### SAST rules

Bulwark ships its own Apache-2.0 rule pack in
[`src/Bulwark.Engines/Rules`](src/Bulwark.Engines/Rules), embedded in the binary. It covers
SQL and command injection, eval, insecure deserialization, disabled TLS validation, XSS sinks
and weak hashes. Semgrep's registry rules are deliberately not used, because their license
forbids bundling them in a competing tool. Add your own Opengrep/Semgrep-syntax rules with
`--rules path/to/rules`.

Opengrep has no official container image, so build Bulwark's once (the Dockerfile verifies the
pinned release binary by SHA-256):

```bash
docker build -t bulwark-engines/opengrep:v1.33.1 engines/opengrep
```

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

1. Release pipeline: a bot watches upstream engine releases, runs a canary corpus, and opens a
   PR that updates the signed manifest.
2. Canary check before switching engine versions, with automatic rollback.
3. Container image vulnerability scanning (Trivy image mode), more SAST rules.
4. Re-check stored SBOMs against new advisories without rescanning code.
5. Triage persistence (false positive / accepted risk) in the dashboard.
6. GitHub/GitLab app: PR comments, status checks, auto-fix PRs for dependency bumps.
7. ~~Optional LLM triage (local via Ollama, or bring your own key).~~ Done: `--ai` exploitability review.
8. AI-driven active pen testing (DAST) against authorized, scoped targets (design above).

## License

Apache-2.0 (add the `LICENSE` file before publishing).
