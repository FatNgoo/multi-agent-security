# Implementation status — 2026-11-21

This status supersedes the implementation snapshot from October in the historical handoff. Source, tests and current runtime observations remain authoritative.

Provider reliability update on 2026-11-21: fixed the observed Gemini timeouts and
invalid assessment JSON. Specialists now receive scoped evidence before calling the
model, can complete small cases in one call, and retain bounded tool use for larger
inputs. Gemini final outputs use JSON Schema, including array-typed limitations;
DeepSeek uses JSON mode. Evidence reference checks remain mandatory. Shared provider
runtime counts each retry, retries only transient failures, checks cancellation and
deadlines, reserves time/calls for the response advisor, and counts reasoning tokens
when reported through total usage. Failures carry sanitized Vietnamese diagnostics.
Configured model and API keys were preserved; timeout is now 90 seconds, total deadline
600 seconds, output limit 3000 tokens, maximum one retry, and two agent iterations.

All 78 regression tests passed. Real Gemini checks with synthetic records and temporary
SQLite databases completed successfully: the Sysmon-only case completed Persistence
and Response in two calls (102.4 seconds); the combined Sysmon/Zeek case completed
Persistence, C2, Correlation and Response in four calls (198.5 seconds), with an AI
response plan and no incomplete assessments. Artifacts are
`verification/artifacts/ai-fix-sysmon-schema.json` and
`verification/artifacts/ai-fix-combined.json`. Earlier diagnostic failures are retained
separately and are not treated as passing runs. No live DeepSeek check was performed.
API and frontend were rebuilt. Product data remained one dataset, ten events, one
completed investigation and one alert; tests did not add to or rerun this user data.

Data isolation update on 2026-11-21: the previously shared running stack contained
10 datasets, 46 events, 12 investigations and 10 alerts, including demo uploads from
earlier checks. Its API/frontend were stopped before archiving. A custom-format
PostgreSQL dump, dataset index, per-dataset stored-event exports and SHA-256 manifest
were saved under `verification/logs/archive/legacy-20261121T142944Z/`. The dump table
of contents was read with pg_restore and exported event counts matched dataset counts.
The original `multi-agent-security_pgdata` volume and stopped legacy containers remain.

The default product now uses project `multi-agent-security-product` with a fresh volume
and the same 8000/8501 ports. Read-only checks confirmed zero datasets, events,
investigations and alerts after build/start. No demo was uploaded to this product.
`verification/compose.yaml` defines a separate project/volume on 18000/18501; its
configuration was validated but it is not started automatically. Seed/stack/UI tools
default to the verification API and refuse writes unless health explicitly identifies
the deployment as verification. A real read-only guard check rejected the product API.
All 57 regression tests passed, including four target-guard cases.

Input logs now live under `verification/logs/`: samples, captures, archive. Sample path
references, lab instructions and test loaders were updated. The manual product guide
is `docs/MANUAL_PRODUCT_TEST.md`. Older runtime/project/path statements below describe
historical verification runs and do not override these current instructions.

Response advisor update on 2026-11-17: a `response` graph stage now follows verification
and risk assessment. In provider mode it makes one bounded call with scoped evidence,
findings, risk and relationships, validates the structured plan and each step's references,
and saves `response_plan` in the result. One call is reserved within the existing overall
budget. Missing keys, provider failures and invalid output use an explicitly labeled
consolidated local playbook. Offline mode makes no provider call. The result page shows
the complete plan without a recommendation selector or per-item progress form; Markdown
exports it once. Legacy investigations remain readable through a local display fallback.
The proposal never executes endpoint or network changes. Provider behavior is covered
with mocked calls, including the complete API/graph/report path, hallucinated references,
invalid JSON, failures, budget limits and cancellation. The deployed PostgreSQL stack
and Streamlit interactions were verified offline; this change did not send a live
provider request. Artifacts: `verification/artifacts/demo-response-plan.json` and
`verification/artifacts/ui-response-plan.json`.

UI update on 2026-11-17: the current product uses a light white/blue theme with a
three-step import/analyze/review flow. The dashboard emphasizes three counts, priority
alerts and recent investigations. The analysis form keeps host/time and agent strategy
in optional sections. Results have four tabs (results, timeline, evidence, reports),
with recommendations, source links and AI diagnostics in expandable sections. Familiar
rule titles have Vietnamese explanations; original evidence and reports remain intact.
The older Dark Crimson design below is historical. Streamlit AppTest passed all six
screens and the four-tab result flow, including form validation, evidence filtering,
analyst review, recommendation updates, alert acknowledgment, audit and downloads.
The running frontend was rebuilt, and the light dashboard and analysis screen were
visually checked in Microsoft Edge. Verification output: `verification/artifacts/ui-light-simple.json`.

Update on 2026-11-17: runtime code, Dockerfiles, Compose and the existing environment
file now live in `product/`. Tests, shared helpers, synthetic fixtures, demo/evaluation
commands and artifacts live in `verification/`. The former fixture-only Sysmon loader
was moved out of the backend. Product builds no longer copy synthetic fixtures or
install pytest. Verification dependencies are declared separately; the backend reads
`product/.env` regardless of the caller's working directory. Existing local edits and
artifact backups were retained. Older paths in historical artifact contents are not
rewritten.

Validation: all 38 regression tests passed; 12 offline evaluations matched rule sets,
severity and relationship labels. Docker built and started from `product/`, using the
existing `multi-agent-security` project and PostgreSQL volume. The two existing datasets
and two investigations were present after rebuilding, before new synthetic checks.
The existing database password mismatch was synchronized to the configured password.
A fresh offline investigation passed HTTP stack checks and Streamlit AppTest passed all
six screens, seven result panels and analyst interactions. The API image was checked
to contain neither pytest nor verification fixtures. Outputs are
`verification/artifacts/evaluation-directory-split.json`,
`verification/artifacts/stack-directory-split.json` and
`verification/artifacts/ui-directory-split.json`. No live provider request was needed.

Update on 2026-11-14: Supervisor, Persistence, C2 and Correlation node implementations now live in dedicated modules under `product/app/agents/`. The graph imports these agents and shared state from `product/app/schemas/investigation_state.py`. The existing Python persistence entry point remains available. The regression suite passed all 38 tests after this reorganization.

Directory consolidation on 2026-11-14 reduced `product/app/` to six packages: `agents`, `ingestion`, `db`, `schemas`, `tools` and `services`. FastAPI starts from `app.main:app`, workflow code lives in `product/app/services/workflow.py`, and shared settings/UTC/logging use `product/app/config.py` and `product/app/common.py`. Evaluation runs with `python -m scripts.evaluate`. Generated outputs moved to `verification/artifacts/`; SHA-256 checks verified all ten pre-existing artifact files after the move. The command policy rejected deletion of leftover package initializers/caches, so those files were archived at `verification/artifacts/layout-backup-20261114/`.

After consolidation, all 38 tests passed and 36 offline evaluations matched their expected rule sets, severity and relationship labels. The rebuilt PostgreSQL stack completed a new synthetic background investigation and all stack checks. Streamlit AppTest passed all six screens and investigation submission through result rendering. New verification outputs are `verification/artifacts/evaluation-layout-refactor.json`, `verification/artifacts/demo-layout-refactor.json` and `verification/artifacts/stack-layout-refactor.json`.

UI redesign on 2026-11-14: the six Streamlit screens now use a consistent Dark Crimson shell with a styled sidebar, KPI cards, 14-day activity chart, severity distribution, prioritized alerts and explicit empty states. Investigation setup uses date/time pickers, dataset-derived UTC bounds, a live selected-data summary and an explicit host–IP confirmation. Results have seven tabs with selected-finding detail, recommendation progress, an adaptive UTC timeline, evidence chains, searchable evidence/raw records, agent/tool activity and direct Markdown/JSON downloads. Opening another investigation clears stale results; review updates invalidate cached results/reports. Styling lives in `product/frontend/style.css` beside the app, without additional folders.

The expanded AppTest passed all six screens and seven result tabs, new-investigation navigation, missing/invalid scope validation, date/time submission, host mapping, background completion, finding selection, empty/search/source-filtered evidence, recommendation updates, severity review, audit, reports, alert acknowledgment and navigation to results. It creates a fresh synthetic offline investigation for mutable checks. The verification record is `verification/artifacts/ui-redesign-check.json`. All 38 regression tests also passed. The frontend image was rebuilt and started in the existing verification stack; AppTest inside that image verified packaged CSS, the Docker API connection, result tabs and Streamlit health.

Visual inspection was attempted again for this redesign. The browser access host was unavailable, and native Edge access was stopped because Computer Use could not determine the current browser URL confidently enough to enforce policy. No browser actions continued after that block. Desktop screenshots, CSS appearance and mobile rendering remain visually unverified; AppTest confirms application behavior, not pixel layout.

## Delivered

- Additive versioned schema migration with legacy-record backfill, dataset file hashes and explicit duplicate-upload policy.
- Sysmon XML/JSONL and Zeek conn/DNS/HTTP JSON Lines/TSV ingestion with raw fields, record provenance, validation and atomic import.
- Multi-dataset/time/host/IP scope, time-bounded host mappings, event browsing pagination and investigation coverage warnings.
- Shared tools for events, process lineage, Python periodicity statistics and curated ATT&CK retrieval.
- Source-aware LangGraph Supervisor with Persistence, C2, Correlation, evidence verification and report stages.
- Gemini/DeepSeek tool-calling adapter with request-enforced scope, per-agent loops, provider-call limits, timeouts, output limits and reported-token stop conditions.
- Versioned severity rubric and separate confidence, conditional response recommendations and audit-backed analyst review.
- Persisted background queue with atomic claims, renewable leases, interrupted-job recovery and cancellation.
- Application alerts with severity/confidence thresholds, acknowledgment/history, detection-to-server-alert-creation timing and dashboard distributions.
- Streamlit Dark Crimson workspace with six navigation screens, finding/evidence/timeline/relationship panels, progress tracking and JSON/Markdown reports.
- Synthetic demo generation, HTTP stack verification and repeatable heuristic/Single-Agent/Multi-Agent evaluation.

The user removed MCP from the accepted scope. Shared tools are called directly.

## Verification performed

- Python unit/API/regression suite passed 38 tests at this checkpoint. Run the suite again after later changes.
- Offline evaluation ran 36 investigations across four labeled synthetic scenarios, three strategies and three repetitions. Rule-set, severity and relationship matches were 36/36 for each metric. Raw results are saved locally in `verification/artifacts/evaluation-offline.json`.
- A real Docker Compose verification stack with PostgreSQL completed upload, a background investigation, lookup of 20 evidence records, alerts, analyst progress updates, audit and both report formats. The check output is in `verification/artifacts/stack-check.json`.
- Legacy PostgreSQL schema migration, normalized-field backfill, original evidence identity preservation and repeated migration were checked inside an isolated temporary schema.
- Streamlit AppTest passed all six screens against the running PostgreSQL API, including completed-investigation panels and form submission through background completion and result rendering.
- Gemini was contacted with synthetic records and the configured model. Runs encountered HTTP 503 responses, request timeouts and an earlier iteration-limit outcome. The adapter was adjusted to reserve its final iteration for an answer. A successful full narrative run remains unverified. Local artifacts include `verification/artifacts/gemini-smoke-final.json` and the initial `verification/artifacts/gemini-smoke.json`.
- DeepSeek has mocked adapter coverage. A configured live DeepSeek key was unavailable.
- An isolated `gemini-2.5-flash` experiment returned HTTP 404 and is recorded separately in `verification/artifacts/gemini-25-smoke.json`. Its explicit model override applied only to that experiment.
- Browser visual inspection was blocked because the Computer Use tool reported that Google Chrome access was not approved. Layout behavior was exercised through AppTest; screenshots and mobile visual rendering remain unverified.

## Limits relevant to the thesis

Severity is a versioned triage heuristic. Critical severity needs analyst review. Asset criticality can elevate persistence review priority. Recommendations are a local analyst playbook with conditional steps and operational impact.

The curated ATT&CK corpus covers five techniques. Model-selected retrieval is available through `attack_lookup`. Semantic correctness of generated hypotheses still requires analyst evaluation. Reference validation ensures cited IDs were seen through scoped tools.

Detection-to-alert timing ends at server alert construction, before commit and browser display. Historical event timestamps, investigation runtime, tool runtime and acknowledgment are separate measurements.

The supplied experiments use labeled simulations. Real lab capture, threat/benign ground truth, narrative unsupported-claim annotations and a statistically justified model comparison remain research work. Offline evaluation exercises the common deterministic substrate and does not establish Multi-Agent superiority.

The application binds to loopback and uses a shared local analyst identity. Remote production access and multi-user authorization require additional work beyond the approved local prototype scope.

## Continuing development

Read `README.md`, `docs/ARCHITECTURE.md`, `docs/EVALUATION.md` and current Git status before changes. The directory consolidation is currently in the local working tree. Preserve the user's `product/.env` and local changes.

The verification stack uses Compose project `multi-agent-security-verify` with its own PostgreSQL volume. Its frontend is at `http://localhost:8501` and API at `http://localhost:8000`. Synthetic artifacts and databases under `verification/artifacts/` are ignored by Git. Standard `docker compose` uses a separate project volume if its project name differs.
