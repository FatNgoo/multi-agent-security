# Implementation status — 2026-11-12

This status supersedes the implementation snapshot from October in the historical handoff. Source, tests and current runtime observations remain authoritative.

Update on 2026-11-14: Supervisor, Persistence, C2 and Correlation node implementations now live in dedicated modules under `app/agents/`. The graph imports these agents and shared state from `app/schemas/investigation_state.py`. The existing Python persistence entry point remains available. The regression suite passed all 38 tests after this reorganization.

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
- Offline evaluation ran 36 investigations across four labeled synthetic scenarios, three strategies and three repetitions. Rule-set, severity and relationship matches were 36/36 for each metric. Raw results are saved locally in `artifacts/evaluation-offline.json`.
- A real Docker Compose verification stack with PostgreSQL completed upload, a background investigation, lookup of 20 evidence records, alerts, analyst progress updates, audit and both report formats. The check output is in `artifacts/stack-check.json`.
- Legacy PostgreSQL schema migration, normalized-field backfill, original evidence identity preservation and repeated migration were checked inside an isolated temporary schema.
- Streamlit AppTest passed all six screens against the running PostgreSQL API, including completed-investigation panels and form submission through background completion and result rendering.
- Gemini was contacted with synthetic records and the configured model. Runs encountered HTTP 503 responses, request timeouts and an earlier iteration-limit outcome. The adapter was adjusted to reserve its final iteration for an answer. A successful full narrative run remains unverified. Local artifacts include `artifacts/gemini-smoke-final.json` and the initial `artifacts/gemini-smoke.json`.
- DeepSeek has mocked adapter coverage. A configured live DeepSeek key was unavailable.
- An isolated `gemini-2.5-flash` experiment returned HTTP 404 and is recorded separately in `artifacts/gemini-25-smoke.json`. Its explicit model override applied only to that experiment.
- Browser visual inspection was blocked because the Computer Use tool reported that Google Chrome access was not approved. Layout behavior was exercised through AppTest; screenshots and mobile visual rendering remain unverified.

## Limits relevant to the thesis

Severity is a versioned triage heuristic. Critical severity needs analyst review. Asset criticality can elevate persistence review priority. Recommendations are a local analyst playbook with conditional steps and operational impact.

The curated ATT&CK corpus covers five techniques. Model-selected retrieval is available through `attack_lookup`. Semantic correctness of generated hypotheses still requires analyst evaluation. Reference validation ensures cited IDs were seen through scoped tools.

Detection-to-alert timing ends at server alert construction, before commit and browser display. Historical event timestamps, investigation runtime, tool runtime and acknowledgment are separate measurements.

The supplied experiments use labeled simulations. Real lab capture, threat/benign ground truth, narrative unsupported-claim annotations and a statistically justified model comparison remain research work. Offline evaluation exercises the common deterministic substrate and does not establish Multi-Agent superiority.

The application binds to loopback and uses a shared local analyst identity. Remote production access and multi-user authorization require additional work beyond the approved local prototype scope.

## Continuing development

Read `README.md`, `docs/ARCHITECTURE.md`, `docs/EVALUATION.md` and current Git status before changes. Existing uncommitted files include parsers/tests that were previously hidden by `.gitignore`. Preserve the user's `.env` and local changes.

The verification stack uses Compose project `multi-agent-security-verify` with its own PostgreSQL volume. Its frontend is at `http://localhost:8501` and API at `http://localhost:8000`. Synthetic artifacts and databases under `artifacts/` are ignored by Git. Standard `docker compose` uses a separate project volume if its project name differs.
