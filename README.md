# Multi-Agent Security Investigation — v0.2 Upload + Database

This is an incremental upgrade of v0.1, preserving LangGraph Supervisor → Persistence Agent and Gemini/DeepSeek/offline modes.

## Local Windows PowerShell quick start

```powershell
uv python install 3.12
uv venv .venv --python 3.12
.\.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
Copy-Item .env.example .env
python -m pytest -q
python -m uvicorn app.api.main:app --reload
```

Local Python uses SQLite for quick tests (`DATABASE_URL=sqlite:///./local-dev.db`). Docker Compose uses PostgreSQL by overriding that variable inside the container.

## Docker Compose (PostgreSQL + FastAPI)

1. Change `POSTGRES_PASSWORD` in `.env` to your own password (use letters/numbers for this demo).
2. Stop the local Uvicorn instance with Ctrl+C.
3. In PowerShell:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs --tail=50 api
```

Open http://localhost:8000/docs and follow this order:

1. **POST `/api/v1/logs/upload`** → Choose File → `data/fixtures/sysmon.jsonl` → Execute.
2. Copy the returned `dataset_id`.
3. **GET `/api/v1/datasets`** → verify the upload.
4. **GET `/api/v1/events`** → dataset_id + host `WIN-LAB-01` + start `2026-10-14T08:00:00Z` + end `2026-10-14T09:00:00Z`.
5. **POST `/api/v1/investigate`** with:

```json
{
  "dataset_id": "PASTE_DATASET_UUID_HERE",
  "host": "WIN-LAB-01",
  "start_time": "2026-10-14T08:00:00Z",
  "end_time": "2026-10-14T09:00:00Z"
}
```

Initially `AGENT_MODE=offline` gives deterministic, **not AI** results. Change `.env` to `AGENT_MODE=gemini` and set `GEMINI_API_KEY` to use Gemini tool calling. Recreate the API container to pick up changes: `docker compose up -d --force-recreate api`. Do not commit `.env`.

## Current capabilities / limitations

- Accepts **only simplified Sysmon JSONL** records matching fields `timestamp`, `host`, `event_id`, `description`. These are test records, not raw Sysmon XML/Windows Event exports.
- Uploaded files up to 5 MB, UTF-8, atomic import (any invalid line rejects entire file).
- Stores dataset and normalized event rows with original JSON in PostgreSQL when running Compose.
- Searches strictly inside selected `dataset_id`; evidence IDs are database-generated UUIDs.
- No Zeek, XML/EVTX parsing, bulk workers, migrations, or UI yet. API only.
- DB schema is created automatically at startup for prototype; use Alembic migrations later.
- Treat uploaded logs as untrusted; no arbitrary command execution is exposed.


## v0.3 Streamlit UI (Windows + Docker Desktop)

1. Copy `.env.example` to `.env`; set `POSTGRES_PASSWORD`. For real Gemini calls set `AGENT_MODE=gemini`, `GEMINI_API_KEY` and `GEMINI_MODEL`. `offline` mode is a deterministic workflow demonstration, not an AI analysis.
2. In Windows PowerShell run `docker compose up --build -d`.
3. Open **http://localhost:8501** for the Streamlit UI and **http://localhost:8000/docs** for FastAPI Swagger.
4. On **Upload & Datasets**, upload `data/fixtures/sysmon.jsonl`. On **AI Investigation**, choose that dataset, enter host `WIN-LAB-01`, set start 2026-10-14 08:00 UTC and end 2026-10-14 09:00 UTC; run investigation. On **Evidence & Results**, inspect the log evidence and tool trace.
5. Run `docker compose ps` and `docker compose logs --tail=100 frontend api` for diagnostics.

The UI calls the FastAPI backend from inside Docker (`http://api:8000`). No database credentials or Gemini API key are sent to the browser. The UI supports the existing v0.2 APIs and the Sysmon JSONL fixture schema; EVTX/XML and Zeek are not implemented yet.

To run the frontend without Docker, install `uv pip install -r frontend/requirements.txt`, start the backend separately and run `python -m streamlit run frontend/app.py` with `API_BASE_URL=http://localhost:8000` (default).


## v0.4: Native Sysmon Windows Event XML support

This upgrade adds Python `defusedxml` parsing + normalization for **Sysmon Windows Event XML** exports (`<Event>` or a collection `<Events>...</Events>`). It preserves v0.3's JSONL ingest, PostgreSQL models, Evidence IDs, API routes, Gemini/DeepSeek/offline modes, LangGraph and Streamlit UI. `.evtx` binary and Zeek logs remain unsupported.

### Upgrade an existing v0.3 instance without losing datasets

1. Back up your project and `.env`. Unzip v0.4 into a **new project directory**, then copy your existing `.env` to it. You may instead copy modified code files into your existing repository.
2. In Windows PowerShell at the project root, run `docker compose up --build -d` (reuses the existing named PostgreSQL volume if Compose project name stays `multi-agent-security`). **Do not run `docker compose down -v`**; it deletes database volumes.
3. Open `http://localhost:8501` → **Upload & Datasets** → upload `data/fixtures/sysmon-event-viewer.xml` or Windows Sysmon XML export. The UI sends it to `/api/v1/logs/upload` and receives `dataset_id` and imported count.
4. Select the uploaded dataset and `WIN-LAB-01`, UTC start `2026-10-14T08:00:00Z` and end `2026-10-14T09:00:00Z` → Run Investigation → Evidence & Results.
5. For tests: `uv pip install -r requirements.txt`; `python -m pytest -q tests/test_sysmon_xml.py tests/test_xml_upload_api.py`.

### Notes on exported XML

- Supported XML: Windows Event XML schema with `System/Provider Name=Microsoft-Windows-Sysmon`, `EventID`, `TimeCreated SystemTime`, `Computer`, plus `EventData/Data Name` attributes. Exported XML must be **well-formed**; some Event Viewer copy/paste workflows put several `<Event>` elements next to each other without a root. Wrap these in `<Events>...</Events>` or export a single event. In Windows, use PowerShell to create a collection:

```powershell
$events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100
$xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
[System.IO.File]::WriteAllText("$PWD\sysmon-export.xml", $xml, [System.Text.UTF8Encoding]::new($false))
```

- Keep the originals as evidence. Parsed data is stored in `events.raw` as structured original fields, **not byte-for-byte original XML**. XML entity expansion/DTD is rejected by `defusedxml`. Only upload trusted authorized lab data; the prototype uses a 5 MB upload limit.
- An Event ID is not itself a maliciousness verdict; the Agent must evaluate context and evidence.
