# Reproducible evaluation

Run from the repository root with Python 3.12.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m evaluation.run --runs 3 --output artifacts/evaluation-offline.json
```

The evaluation runner uses a fresh temporary SQLite database and uploads synthetic labeled records through FastAPI. Four scenarios cover a supported cross-source association, an ambiguous join without Event 3, a periodic connection with analyst-supplied benign context, and irregular negative-control traffic. Three strategies share the same tools, rule substrate, model configuration and per-investigation budgets. The runner saves raw per-run metrics and provider assessment statuses.

The unit for finding precision/recall is a distinct deterministic `rule_id` within a labeled scenario. Expected evidence includes the persistence event, applicable endpoint network events and applicable Zeek connection records. Evidence completeness measures references actually cited in findings/relationships against that labeled set. Evidence validity checks whether cited IDs resolve in the scoped result. Severity agreement compares the result to the scenario's expected triage level.

Offline runs test pipeline correctness and reproducibility. Their common deterministic substrate produces the same detector decisions across strategies. A comparative claim about LLM investigation quality requires provider runs and analyst-labeled narrative claims. `unsupported_claim_rate` remains null until those annotations exist. Missing metrics and empty denominators remain null.

For provider experiments using the synthetic cases, configure the provider key in the backend `.env`, then run the following command. The command makes billed requests to the configured API.

```powershell
.\.venv\Scripts\python.exe -m evaluation.run --mode gemini --runs 3 --output artifacts/evaluation-gemini.json
```

Inspect every provider status alongside latency and token usage. Provider failure, deadline or missing assessments affect interpretation of the comparison. Pricing and semantic claim accuracy require separately recorded inputs. Preserve the model version, corpus version, rubric version, dataset ground truth and configuration with experimental artifacts.

The application records detection-to-server-alert-creation latency. This interval starts after evidence verification and excludes the earlier investigation duration. It also excludes transaction commit, UI polling and browser display. Report total investigation duration separately. Population summaries sample the latest 1000 completed investigations and include the sample count.
