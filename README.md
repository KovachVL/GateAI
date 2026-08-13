# GateAI

Security gate with AI: **AI SAST → AI SCA → AI BCA**.

Scanners report noise. GateAI triages every finding with a model and lets a stage pass only when nothing survives as exploitable.

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Each stage scans, triages every finding with a model, and then decides whether the run continues. The point of the gate is that **a stage passes when nothing survives triage as exploitable — not when the scanner found nothing.** Semgrep reporting 200 hits does not fail the build; three of them surviving triage does.

```
  code ──► [ SAST ]  scan → AI triage → gate ──fail──► report, stop
                                          │pass
                                          ▼
                     [ SCA ]   scan → AI triage → gate ──fail──► report, stop
                                          │pass
                                          ▼
                     [ BCA ]   scan → AI triage → gate ──► ✅
```

## Run with Docker

The image bundles the binary and all three scanners at pinned versions, so there is nothing to install and every run uses the same scanner versions — which matters, because a scanner upgrade changes findings and therefore invalidates cached verdicts.

```bash
docker build -t gateai .

docker run --rm \
  -e ANTHROPIC_API_KEY \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.gateai:/workspace/.gateai" \
  gateai /workspace
```

The repository is mounted read-only: gateai never writes to the code under analysis. The second mount is writable so the verdict cache survives between runs — drop it and every run re-pays for every finding.

For the BCA stage the container also needs the Docker socket, since syft inspects an image:

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.gateai:/workspace/.gateai" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gateai --artifact myapp:latest /workspace
```

Mounting the Docker socket grants the container control of the host daemon. Only do it when you actually need the BCA stage, and prefer a rootless daemon or `syft`'s registry mode against a pushed image.

Pin scanner versions at build time when you need to:

```bash
docker build --build-arg SEMGREP_VERSION=1.146.0 --build-arg SYFT_VERSION=v1.34.0 -t gateai .
```

## Run locally

```bash
go build -o bin/gateai ./cmd/gateai
brew install semgrep osv-scanner syft
```

A missing scanner **skips** its stage (and says so) rather than silently passing it. If every stage skips, the result is `no_coverage`, not `pass` — pass `--fail-on-skip` in CI to make a missing scanner a hard failure.

Credentials come from `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or an `ant auth login` profile — the SDK resolves them in that order.

## Use

```bash
gateai /path/to/repo
gateai --config policy.yaml --artifact myapp:latest --json report.json /path/to/repo
```

Adopting the tool on an existing repository: record the current backlog first, so only new findings can block.

```bash
gateai --write-baseline .gateai/baseline.json /path/to/repo   # no model calls
gateai --baseline .gateai/baseline.json /path/to/repo
```

Exit codes: `0` all stages passed · `1` a gate blocked the run · `2` findings need human review, or no stage ran · `3` usage error.

## The three layers

| Stage | Scanner | What the model is asked |
|---|---|---|
| SAST | semgrep (`p/default` + `p/secrets`, 30+ languages) | Can attacker-controlled data reach this line, and is the operation dangerous as written? |
| SCA | osv-scanner (every common manifest/lockfile) | Is the vulnerable symbol actually called from this codebase? |
| BCA | syft | Does the built artifact contain components no manifest declares, or a different version than was pinned? |

## Design decisions worth knowing

**Language-agnostic by construction.** The collectors already cover every mainstream language. Reachability is the one part that cannot be: a call graph is per-language. Instead of half-implementing several, the agent gets language-independent tools — `search_code`, `find_definition`, `find_callers`, `list_entrypoints`, `read_file` — and interprets the results. A precise per-language call graph can be added later behind the same interface, starting with Go.

**Absence of evidence is not evidence of absence.** The triage prompt is explicit that a failed search means `needs_human`, never `not_exploitable`. Text search misses dynamic dispatch, reflection, framework routing and codegen. A false negative here ships a real vulnerability.

**Two guardrails sit between the model and the gate.** A verdict citing no `file:line` evidence is downgraded to `needs_human` automatically, as is any decisive verdict below the confidence threshold. On top of that, `skeptic: true` runs a second adversarial pass over every dismissal; if the two passes disagree, the result is `needs_human` rather than either confident answer.

**The repository is untrusted input.** All file access is confined to the repo root (`..`, absolute paths and symlinks pointing outside are refused — see `codeview_test.go`). Scanner output and file contents are fenced in the prompt and labeled as data, and the system prompt tells the model not to obey instructions found inside them.

**Verdicts are cached.** Keyed by the finding's content fingerprint plus model, effort and prompt version — so an unchanged file costs nothing on the next CI run, and bumping `PromptVersion` correctly invalidates everything.

## Configuration

See `policy.yaml`. Per stage you can set the model, effort, iteration cap, whether the skeptic pass runs, and the gate itself (`block_on`, `require_reachable`, `needs_human`, `on_fail`).

Model is per stage on purpose. The default is Sonnet 5 for the code-reading stages and Haiku 4.5 for BCA, which only diffs SBOMs. Moving a stage to Opus later is a one-line config change.

Semgrep runs `p/default` + `p/secrets`, overridable with a comma-separated `GATEAI_SEMGREP_CONFIG`. It is deliberately **not** `--config auto`: auto uploads project metadata to pick rules and therefore refuses to run with telemetry disabled, which is the wrong trade for a tool pointed at private code. The image sets `SEMGREP_SEND_METRICS=off`. A fixed rule set is also more cache-friendly, since the verdict cache assumes the same finding means the same thing between runs. Rule sets are fetched from the semgrep registry, so the scan needs network access.

## Not done yet

- **Measurement.** There is no eval harness, so there is no number for how many false positives the triage layer actually removes. Until that exists on a labeled corpus, treat the quality claims here as untested. This is the next thing to build.
- Cross-layer correlation (an SCA finding confirmed or contradicted by the BCA SBOM) is not wired up; each stage triages independently.
- No SARIF output and no PR-comment integration.
