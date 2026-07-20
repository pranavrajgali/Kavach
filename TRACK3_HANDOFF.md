# Kavach.ai Track 3 Handoff

Owner: Pranav Krishna  
Branch: `feature/track-3-fastapi-backend`  
Last updated: 2026-07-20

This file summarizes the Track 3 backend foundation work completed so far and what should happen next. It is meant to be uploaded or shared so work can continue without needing the full chat history.

## Goal

Track 3 owns the FastAPI backend, SQLModel database layer, Redis/ARQ task queue, and Stage 6 telemetry merger for Kavach.ai.

The immediate goal was to create a working backend foundation that lets other tracks build against stable contracts:

- Track 1 can call `/upload`, `/status/{job_id}`, and `/report/{job_id}` from Streamlit.
- Track 2 can plug static/ML/SHAP outputs into the shared contracts and merger.
- Track 4 can start endpoint, database, and merger tests.

## Git State

Local feature branch:

```bash
feature/track-3-fastapi-backend
```

Configured remotes:

```bash
origin   https://github.com/aaauuugggghhhh/Kavach
upstream https://github.com/pranavrajgali/Kavach.git
```

The branch has uncommitted work. Commit and push only after reviewing/running tests.

## Files Added

- `ROADMAP.md`
  - Track 3 roadmap and shared checklist.

- `kavach_ai/backend/app/api/endpoints.py`
  - FastAPI routes:
    - `POST /upload`
    - `GET /status/{job_id}`
    - `GET /report/{job_id}`

- `kavach_ai/backend/app/db/session.py`
  - Async SQLModel engine/session setup.
  - SQLite default for local development.
  - PostgreSQL URL normalization for runtime/Docker use.

- `kavach_ai/backend/app/schemas/contracts.py`
  - Shared Pydantic contracts:
    - `UploadResponse`
    - `JobStatusResponse`
    - `ReportResponse`
    - `StaticAnalysisResult`
    - `DynamicAnalysisResult`
    - `MergedTelemetry`
    - `ShapTokenAttribution`

- `kavach_ai/backend/pipeline/stage6_synthesis/merge.py`
  - Static + dynamic + SHAP telemetry merger.
  - Deterministic final score calculation.
  - Contradiction labels:
    - `CONFIRMED_MALWARE`
    - `PACKED_DROPPER`
    - `DORMANT_MALWARE`
    - `SANDBOX_EVASION_DETECTED`
    - `LIKELY_BENIGN`

- `kavach_ai/backend/tests/test_track3_backend.py`
  - Pytest coverage for health, upload, status, report-not-ready, mock worker completion, idempotent report synthesis, and Stage 6 contradiction labels.

- `kavach_ai/backend/tests/test_track3_contracts.py`
  - Pytest coverage for contract validation and fixture payload compatibility.

- `kavach_ai/backend/tests/fixtures/*.json`
  - Mock static, dynamic, and merged telemetry payloads for early integration testing.

## Files Modified

- `kavach_ai/backend/app/db/models.py`
  - Added `job_id`.
  - Added `status`.
  - Made `triage_score` optional.
  - Kept BCNF relationships for APKs, Smali slices, SHAP attributions, and CERT-In reports.

- `kavach_ai/backend/app/main.py`
  - Created FastAPI app.
  - Added CORS for Streamlit:
    - `http://localhost:8501`
    - `http://127.0.0.1:8501`
  - Added lifespan startup database initialization.
  - Added `/health`.

- `kavach_ai/backend/workers/queue.py`
  - Added ARQ enqueue helper.
  - If Redis or ARQ is unavailable, upload still succeeds and the job remains `QUEUED`.

- `kavach_ai/backend/workers/arq_worker.py`
  - Added mock worker functions:
    - `run_triage_and_static_job`
    - `run_dynamic_sandbox_job`
    - `run_report_synthesis_job`
  - Worker sets status to `PROCESSING`, `COMPLETED`, or `FAILED`.
  - Mock report generation is idempotent, so running it twice for the same job does not violate the unique report constraint.

- `kavach_ai/pyproject.toml`
  - Added backend dependencies:
    - `fastapi`
    - `uvicorn[standard]`
    - `sqlmodel`
    - `aiosqlite`
    - `asyncpg`
    - `arq`
    - `python-multipart`
  - Added dev dependencies:
    - `pytest`
    - `pytest-asyncio`
    - `httpx`

## Implemented API Behavior

### `GET /health`

Returns:

```json
{"status": "ok"}
```

### `POST /upload`

Accepts an APK upload and returns immediately:

```json
{
  "job_id": "uuid",
  "status": "QUEUED",
  "apk_hash": "sha256"
}
```

What it does:

- Reads uploaded bytes.
- Rejects empty uploads.
- Computes SHA-256.
- Generates UUID job ID.
- Saves the APK under `kavach_ai/backend/uploads/`.
- Inserts an `apks` row with `QUEUED` status.
- Tries to enqueue ARQ work.
- If Redis is not running, upload still succeeds.

### `GET /status/{job_id}`

Returns DB-backed state:

```json
{
  "job_id": "uuid",
  "status": "QUEUED",
  "apk_hash": "sha256",
  "filename": "sample.apk",
  "triage_score": null,
  "final_score": null
}
```

Allowed statuses:

- `QUEUED`
- `PROCESSING`
- `COMPLETED`
- `FAILED`

### `GET /report/{job_id}`

If report is not ready:

```json
{"detail": "Report is not ready for this job."}
```

If mock worker completed the job:

```json
{
  "job_id": "uuid",
  "apk_hash": "sha256",
  "status": "COMPLETED",
  "report": {
    "final_score": 0,
    "contradiction_label": "LIKELY_BENIGN"
  },
  "report_pdf_path": "",
  "compliance_status": "MOCK_READY"
}
```

## Verification Completed

Dependencies were installed into local `.venv` with:

```bash
py -m pip --python .venv\Scripts\python.exe install -e '.\kavach_ai[dev]'
```

Syntax check passed:

```bash
py -m compileall kavach_ai\backend
```

Manual smoke checks passed:

- `/health` returned `200`.
- `/upload` returned `200` with `job_id`, `QUEUED`, and `apk_hash`.
- `/status/{job_id}` returned the queued DB row.
- `/report/{job_id}` returned `404` before report generation.
- Running `run_report_synthesis_job({}, job_id)` changed status to `COMPLETED`.
- `/report/{job_id}` returned mock merged telemetry after worker completion.
- Running mock report synthesis twice for the same job did not crash.
- Stage 6 merger labels:
  - Static low + dynamic IP evidence => `PACKED_DROPPER`, score `85`.
  - Static low + evasion signal => `SANDBOX_EVASION_DETECTED`, score `75`.

Pytest suite passed:

```bash
.\.venv\Scripts\python.exe -B -m pytest kavach_ai\backend\tests
```

Result:

```text
6 passed
```

## How To Run Locally

Run commands from the repository root:

```bash
D:\Projects\Kavach
```

Install dependencies:

```bash
py -m pip --python .venv\Scripts\python.exe install -e '.\kavach_ai[dev]'
```

Start the API:

```bash
.\.venv\Scripts\python.exe -m uvicorn kavach_ai.backend.app.main:app --host 127.0.0.1 --port 8000
```

Check health:

```bash
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
```

## Known Caveats

- Redis is optional during local mock development. If Redis is not running, uploaded jobs remain `QUEUED` until a worker is invoked manually.
- The worker currently uses mock static/dynamic data. Track 1 and Track 2 integrations still need to replace these mocks.
- Duplicate uploads return the existing `job_id` for the same APK hash.
- The local SQLite DB is `kavach_dev.db` at the repo root and is ignored by git.
- Uploaded APKs are saved under `kavach_ai/backend/uploads/` and are ignored by git.
- Initial pytest coverage exists, but Siri should extend it for full Track 4 QA.

## Next Checklist

1. Decide with the team whether `/jobs/{id}` should exist as an alias, or whether `/status/{job_id}` remains the only canonical polling endpoint.

2. Replace mock worker internals once Track 1 and Track 2 modules exist:
   - Track 2 static/ML/SHAP output feeds `StaticAnalysisResult`.
   - Track 1 sandbox output feeds `DynamicAnalysisResult`.
   - Stage 6 merged output feeds report generation.

3. Coordinate with Siri to extend pytest coverage for transaction rollback, failure states, and dependency overrides.

4. Before PR:

```bash
git status
py -m compileall kavach_ai\backend
git add ROADMAP.md TRACK3_HANDOFF.md kavach_ai
git commit -m "feat(backend): add track 3 API and database foundation"
git push origin feature/track-3-fastapi-backend
```

6. Open PR into:

```text
pranavrajgali/Kavach main
```

## Current Completion Summary

Done:

- Branch created.
- Roadmap created.
- Contracts implemented.
- DB models corrected.
- DB session implemented.
- FastAPI app created.
- Upload/status/report endpoints implemented.
- Queue helper implemented.
- ARQ worker skeleton implemented.
- Stage 6 merger implemented.
- Mock worker path verified.
- Basic smoke verification passed.

Remaining:

- Decide `/jobs/{id}` alias policy.
- Coordinate with Siri for expanded formal QA.
- Commit.
- Push.
- Open PR.
